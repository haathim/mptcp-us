#include <assert.h>
#include <time.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "tcp_util.h"
#include "tcp_in.h"
#include "tcp_out.h"
#include "tcp_ring_buffer.h"
#include "eventpoll.h"
#include "debug.h"
#include "timer.h"
#include "ip_in.h"
#include "clock.h"
#include "mptcp.h"
#include "config.h"
#include "mtcp.h"

#if USE_CCP
#include "ccp.h"
#endif

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define VERIFY_RX_CHECKSUM TRUE
#define RECOVERY_AFTER_LOSS TRUE
#define SELECTIVE_WRITE_EVENT_NOTIFY TRUE

static inline
int CopyFromSubflowToMpcb(mtcp_manager_t mtcp, tcp_stream *mpcb_stream, tcp_stream *subflow_stream, uint32_t subflow_seq, int payloadlen, uint32_t data_seq);

/*----------------------------------------------------------------------------*/
static inline int 
FilterSYNPacket(mtcp_manager_t mtcp, uint32_t ip, uint16_t port)
{
	struct sockaddr_in *addr;
	struct tcp_listener *listener;

	/* TODO: This listening logic should be revised */

	/* if not the address we want, drop */
	listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &port);
	if (listener == NULL)	return FALSE;

	addr = &listener->socket->saddr;

	if (addr->sin_port == port) {
		if (addr->sin_addr.s_addr != INADDR_ANY) {
			if (ip == addr->sin_addr.s_addr) {
				return TRUE;
			}
			return FALSE;
		} else {
			int i;

			for (i = 0; i < CONFIG.eths_num; i++) {
				if (ip == CONFIG.eths[i].ip_addr) {
					return TRUE;
				}
			}
			return FALSE;
		}
	}

	return FALSE;
}
/*----------------------------------------------------------------------------*/
static inline tcp_stream *
HandlePassiveOpen(mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph, 
		const struct tcphdr *tcph, uint32_t seq, uint16_t window)
{
	tcp_stream *cur_stream = NULL;

	/* create new stream and add to flow hash table */
	cur_stream = CreateTCPStream(mtcp, NULL, MTCP_SOCK_STREAM, 
			iph->daddr, tcph->dest, iph->saddr, tcph->source);
	if (!cur_stream) {
		TRACE_ERROR("INFO: Could not allocate tcp_stream!\n");
		return FALSE;
	}
	cur_stream->rcvvar->irs = seq;
	cur_stream->sndvar->peer_wnd = window;
	cur_stream->rcv_nxt = cur_stream->rcvvar->irs;
	cur_stream->sndvar->cwnd = 1;
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);

	return cur_stream;
}
/*----------------------------------------------------------------------------*/
static inline int
HandleActiveOpen(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
		struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, uint16_t window)
{
	cur_stream->rcvvar->irs = seq;
	cur_stream->snd_nxt = ack_seq;
	cur_stream->sndvar->peer_wnd = window;
	cur_stream->rcvvar->snd_wl1 = cur_stream->rcvvar->irs - 1;
	cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
	cur_stream->rcvvar->last_ack_seq = ack_seq;
	ParseTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);
	cur_stream->sndvar->cwnd = ((cur_stream->sndvar->cwnd == 1)? 
			(cur_stream->sndvar->mss * TCP_INIT_CWND): cur_stream->sndvar->mss);
	cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;
	UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);

	return TRUE;
}
/*----------------------------------------------------------------------------*/
/* ValidateSequence: validates sequence number of the segment                 */
/* Return: TRUE if acceptable, FALSE if not acceptable                        */
/*----------------------------------------------------------------------------*/
static inline int
ValidateSequence(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
		struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, int payloadlen)
{
	/* Protect Against Wrapped Sequence number (PAWS) */
	if (!tcph->rst && cur_stream->saw_timestamp) {
		struct tcp_timestamp ts;
		
		if (!ParseTCPTimestamp(cur_stream, &ts, 
				(uint8_t *)tcph + TCP_HEADER_LEN, 
				(tcph->doff << 2) - TCP_HEADER_LEN)) {
			/* if there is no timestamp */
			/* TODO: implement here */
			TRACE_DBG("No timestamp found.\n");
			return FALSE;
		}

		/* RFC1323: if SEG.TSval < TS.Recent, drop and send ack */
		if (TCP_SEQ_LT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
			/* TODO: ts_recent should be invalidated 
					 before timestamp wraparound for long idle flow */
			TRACE_DBG("PAWS Detect wrong timestamp. "
					"seq: %u, ts_val: %u, prev: %u\n", 
					seq, ts.ts_val, cur_stream->rcvvar->ts_recent);
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			return FALSE;
		} else {
			/* valid timestamp */
			if (TCP_SEQ_GT(ts.ts_val, cur_stream->rcvvar->ts_recent)) {
				TRACE_TSTAMP("Timestamp update. cur: %u, prior: %u "
					"(time diff: %uus)\n", 
					ts.ts_val, cur_stream->rcvvar->ts_recent, 
					TS_TO_USEC(cur_ts - cur_stream->rcvvar->ts_last_ts_upd));
				cur_stream->rcvvar->ts_last_ts_upd = cur_ts;
			}

			cur_stream->rcvvar->ts_recent = ts.ts_val;
			cur_stream->rcvvar->ts_lastack_rcvd = ts.ts_ref;
		}
	}

	/* TCP sequence validation */
	if (!TCP_SEQ_BETWEEN(seq + payloadlen, cur_stream->rcv_nxt, 
				cur_stream->rcv_nxt + cur_stream->rcvvar->rcv_wnd)) {

		/* if RST bit is set, ignore the segment */
		if (tcph->rst)
			return FALSE;

		if (cur_stream->state == TCP_ST_ESTABLISHED) {
			/* check if it is to get window advertisement */
			if (seq + 1 == cur_stream->rcv_nxt) {
#if 0
				TRACE_DBG("Window update request. (seq: %u, rcv_wnd: %u)\n", 
						seq, cur_stream->rcvvar->rcv_wnd);
#endif
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
				return FALSE;

			}

			if (TCP_SEQ_LEQ(seq, cur_stream->rcv_nxt)) {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
			} else {
				EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			}
		} else {
			if (cur_stream->state == TCP_ST_TIME_WAIT) {
				TRACE_DBG("Stream %d: tw expire update to %u\n", 
						cur_stream->id, cur_stream->rcvvar->ts_tw_expire);
				AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
		return FALSE;
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/
static inline void 
NotifyConnectionReset(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	TRACE_DBG("Stream %d: Notifying connection reset.\n", cur_stream->id);
	/* TODO: implement this function */
	/* signal to user "connection reset" */
}
/*----------------------------------------------------------------------------*/
static inline int 
ProcessRST(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t ack_seq)
{
	/* TODO: we need reset validation logic */
	/* the sequence number of a RST should be inside window */
	/* (in SYN_SENT state, it should ack the previous SYN */

	TRACE_DBG("Stream %d: TCP RESET (%s)\n", 
			cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
	DumpStream(mtcp, cur_stream);
#endif
	
	if (cur_stream->state <= TCP_ST_SYN_SENT) {
		/* not handled here */
		return FALSE;
	}

	if (cur_stream->state == TCP_ST_SYN_RCVD) {
		if (ack_seq == cur_stream->snd_nxt) {
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_RESET;
			DestroyTCPStream(mtcp, cur_stream);
		}
		return TRUE;
	}

	/* if the application is already closed the connection, 
	   just destroy the it */
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2 || 
			cur_stream->state == TCP_ST_LAST_ACK || 
			cur_stream->state == TCP_ST_CLOSING || 
			cur_stream->state == TCP_ST_TIME_WAIT) {
		cur_stream->state = TCP_ST_CLOSED;
		cur_stream->close_reason = TCP_ACTIVE_CLOSE;
		DestroyTCPStream(mtcp, cur_stream);
		return TRUE;
	}

	if (cur_stream->state >= TCP_ST_ESTABLISHED && 
			cur_stream->state <= TCP_ST_CLOSE_WAIT) {
		/* ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT */
		/* TODO: flush all the segment queues */
		//NotifyConnectionReset(mtcp, cur_stream);
	}

	if (!(cur_stream->sndvar->on_closeq || cur_stream->sndvar->on_closeq_int || 
				cur_stream->sndvar->on_resetq || cur_stream->sndvar->on_resetq_int)) {
		//cur_stream->state = TCP_ST_CLOSED;
		//DestroyTCPStream(mtcp, cur_stream);
		cur_stream->state = TCP_ST_CLOSE_WAIT;
		cur_stream->close_reason = TCP_RESET;
		RaiseCloseEvent(mtcp, cur_stream);
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/
inline void 
EstimateRTT(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t mrtt)
{
	/* This function should be called for not retransmitted packets */
	/* TODO: determine tcp_rto_min */
#define TCP_RTO_MIN 0
	long m = mrtt;
	uint32_t tcp_rto_min = TCP_RTO_MIN;
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;

	if (m == 0) {
		m = 1;
	}
	if (rcvvar->srtt != 0) {
		/* rtt = 7/8 rtt + 1/8 new */
		m -= (rcvvar->srtt >> 3);
		rcvvar->srtt += m;
		if (m < 0) {
			m = -m;
			m -= (rcvvar->mdev >> 2);
			if (m > 0) {
				m >>= 3;
			}
		} else {
			m -= (rcvvar->mdev >> 2);
		}
		rcvvar->mdev += m;
		if (rcvvar->mdev > rcvvar->mdev_max) {
			rcvvar->mdev_max = rcvvar->mdev;
			if (rcvvar->mdev_max > rcvvar->rttvar) {
				rcvvar->rttvar = rcvvar->mdev_max;
			}
		}
		if (TCP_SEQ_GT(cur_stream->sndvar->snd_una, rcvvar->rtt_seq)) {
			if (rcvvar->mdev_max < rcvvar->rttvar) {
				rcvvar->rttvar -= (rcvvar->rttvar - rcvvar->mdev_max) >> 2;
			}
			rcvvar->rtt_seq = cur_stream->snd_nxt;
			rcvvar->mdev_max = tcp_rto_min;
		}
	} else {
		/* fresh measurement */
		rcvvar->srtt = m << 3;
		rcvvar->mdev = m << 1;
		rcvvar->mdev_max = rcvvar->rttvar = MAX(rcvvar->mdev, tcp_rto_min);
		rcvvar->rtt_seq = cur_stream->snd_nxt;
	}

	TRACE_RTT("mrtt: %u (%uus), srtt: %u (%ums), mdev: %u, mdev_max: %u, "
			"rttvar: %u, rtt_seq: %u\n", mrtt, mrtt * TIME_TICK, 
			rcvvar->srtt, TS_TO_MSEC((rcvvar->srtt) >> 3), rcvvar->mdev, 
			rcvvar->mdev_max, rcvvar->rttvar, rcvvar->rtt_seq);
}

/*----------------------------------------------------------------------------*/
static inline void
ProcessACK(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, 
		struct tcphdr *tcph, uint32_t seq, uint32_t ack_seq, 
		uint16_t window, int payloadlen)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint32_t cwindow, cwindow_prev;
	uint32_t rmlen;
	uint32_t snd_wnd_prev;
	uint32_t right_wnd_edge;
	uint8_t dup;
	int ret;

	cwindow = window;
	if (!tcph->syn) {
		cwindow = cwindow << sndvar->wscale_peer;
	}
	right_wnd_edge = sndvar->peer_wnd + cur_stream->rcvvar->snd_wl2;

	/* If ack overs the sending buffer, return */
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2 ||
			cur_stream->state == TCP_ST_CLOSING || 
			cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_LAST_ACK) {
		if (sndvar->is_fin_sent && ack_seq == sndvar->fss + 1) {
			ack_seq--;
		}
	}
	
	if (TCP_SEQ_GT(ack_seq, sndvar->sndbuf->head_seq + sndvar->sndbuf->len)) {
		TRACE_DBG("Stream %d (%s): invalid acknologement. "
				"ack_seq: %u, possible max_ack_seq: %u\n", cur_stream->id, 
				TCPStateToString(cur_stream), ack_seq, 
				sndvar->sndbuf->head_seq + sndvar->sndbuf->len);
		return;
	}

	/* Update window */
	if (TCP_SEQ_LT(cur_stream->rcvvar->snd_wl1, seq) ||
			(cur_stream->rcvvar->snd_wl1 == seq && 
			TCP_SEQ_LT(cur_stream->rcvvar->snd_wl2, ack_seq)) ||
			(cur_stream->rcvvar->snd_wl2 == ack_seq && 
			cwindow > sndvar->peer_wnd)) {
		cwindow_prev = sndvar->peer_wnd;
		sndvar->peer_wnd = cwindow;
		cur_stream->rcvvar->snd_wl1 = seq;
		cur_stream->rcvvar->snd_wl2 = ack_seq;
#if 0
		TRACE_CLWND("Window update. "
				"ack: %u, peer_wnd: %u, snd_nxt-snd_una: %u\n", 
				ack_seq, cwindow, cur_stream->snd_nxt - sndvar->snd_una);
#endif
		if (cwindow_prev < cur_stream->snd_nxt - sndvar->snd_una && 
				sndvar->peer_wnd >= cur_stream->snd_nxt - sndvar->snd_una) {
			TRACE_CLWND("%u Broadcasting client window update! "
					"ack_seq: %u, peer_wnd: %u (before: %u), "
					"(snd_nxt - snd_una: %u)\n", 
					cur_stream->id, ack_seq, sndvar->peer_wnd, cwindow_prev, 
					cur_stream->snd_nxt - sndvar->snd_una);
			RaiseWriteEvent(mtcp, cur_stream);
		}
	}

	/* Check duplicated ack count */
	/* Duplicated ack if 
	   1) ack_seq is old
	   2) payload length is 0.
	   3) advertised window not changed.
	   4) there is outstanding unacknowledged data
	   5) ack_seq == snd_una
	 */

	dup = FALSE;
	if (TCP_SEQ_LT(ack_seq, cur_stream->snd_nxt)) {
		if (ack_seq == cur_stream->rcvvar->last_ack_seq && payloadlen == 0) {
			if (cur_stream->rcvvar->snd_wl2 + sndvar->peer_wnd == right_wnd_edge) {
				if (cur_stream->rcvvar->dup_acks + 1 > cur_stream->rcvvar->dup_acks) {
					cur_stream->rcvvar->dup_acks++;
#if USE_CCP
					ccp_record_event(mtcp, cur_stream, EVENT_DUPACK,
							 (cur_stream->snd_nxt - ack_seq));
#endif
				}
				dup = TRUE;
			}
		}
	}
	if (!dup) {
#if USE_CCP
		if (cur_stream->rcvvar->dup_acks >= 3) {
			TRACE_DBG("passed dup_acks, ack=%u, snd_nxt=%u, last_ack=%u len=%u wl2=%u peer_wnd=%u right=%u\n",
				  ack_seq-sndvar->iss, cur_stream->snd_nxt-sndvar->iss, cur_stream->rcvvar->last_ack_seq-sndvar->iss,
				  payloadlen, cur_stream->rcvvar->snd_wl2-sndvar->iss, sndvar->peer_wnd / sndvar->mss,
				  right_wnd_edge - sndvar->iss);
		}
#endif
		cur_stream->rcvvar->dup_acks = 0;
		cur_stream->rcvvar->last_ack_seq = ack_seq;
	}
#if USE_CCP
	if(cur_stream->wait_for_acks) {
		TRACE_DBG("got ack, but waiting to send... ack=%u, snd_next=%u cwnd=%u\n",
			  ack_seq-sndvar->iss, cur_stream->snd_nxt-sndvar->iss,
			  sndvar->cwnd / sndvar->mss);
	}
#endif
	/* Fast retransmission */
	if (dup && cur_stream->rcvvar->dup_acks == 3) {
		TRACE_LOSS("Triple duplicated ACKs!! ack_seq: %u\n", ack_seq);
		TRACE_CCP("tridup ack %u (%u)!\n", ack_seq - cur_stream->sndvar->iss, ack_seq);
		if (TCP_SEQ_LT(ack_seq, cur_stream->snd_nxt)) {
			TRACE_LOSS("Reducing snd_nxt from %u to %u\n",
                                        cur_stream->snd_nxt-sndvar->iss,
                                        ack_seq - cur_stream->sndvar->iss);

#if RTM_STAT
			sndvar->rstat.tdp_ack_cnt++;
			sndvar->rstat.tdp_ack_bytes += (cur_stream->snd_nxt - ack_seq);
#endif

#if USE_CCP
			ccp_record_event(mtcp, cur_stream, EVENT_TRI_DUPACK, ack_seq);
#endif
			if (ack_seq != sndvar->snd_una) {
				TRACE_DBG("ack_seq and snd_una mismatch on tdp ack. "
						"ack_seq: %u, snd_una: %u\n", 
						ack_seq, sndvar->snd_una);
			}
#if USE_CCP
			sndvar->missing_seq = ack_seq;
#else
			cur_stream->snd_nxt = ack_seq;
#endif
		}

		/* update congestion control variables */
		/* ssthresh to half of min of cwnd and peer wnd */
		sndvar->ssthresh = MIN(sndvar->cwnd, sndvar->peer_wnd) / 2;
		if (sndvar->ssthresh < 2 * sndvar->mss) {
			sndvar->ssthresh = 2 * sndvar->mss;
		}
		sndvar->cwnd = sndvar->ssthresh + 3 * sndvar->mss;

		TRACE_CONG("fast retrans: cwnd = ssthresh(%u)+3*mss = %u\n",
                                sndvar->ssthresh / sndvar->mss,
                                sndvar->cwnd / sndvar->mss);

		/* count number of retransmissions */
		if (sndvar->nrtx < TCP_MAX_RTX) {
			sndvar->nrtx++;
		} else {
			TRACE_DBG("Exceed MAX_RTX.\n");
		}

		AddtoSendList(mtcp, cur_stream);

	} else if (cur_stream->rcvvar->dup_acks > 3) {
		/* Inflate congestion window until before overflow */
		if ((uint32_t)(sndvar->cwnd + sndvar->mss) > sndvar->cwnd) {
			sndvar->cwnd += sndvar->mss;
			TRACE_CONG("Dupack cwnd inflate. cwnd: %u, ssthresh: %u\n", 
					sndvar->cwnd, sndvar->ssthresh);
		}
	}

#if TCP_OPT_SACK_ENABLED
	ParseSACKOption(cur_stream, ack_seq, (uint8_t *)tcph + TCP_HEADER_LEN, 
			(tcph->doff << 2) - TCP_HEADER_LEN);
#endif /* TCP_OPT_SACK_ENABLED */

#if RECOVERY_AFTER_LOSS
#if USE_CCP
	/* updating snd_nxt (when recovered from loss) */
	if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt) ||
	    (cur_stream->wait_for_acks && TCP_SEQ_GT(ack_seq, cur_stream->seq_at_last_loss)
#if TCP_OPT_SACK_ENABLED 
		&& cur_stream->rcvvar->sacked_pkts == 0
#endif
	))
#else
        if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt))
#endif /* USE_CCP */
	{
#if RTM_STAT
		sndvar->rstat.ack_upd_cnt++;
		sndvar->rstat.ack_upd_bytes += (ack_seq - cur_stream->snd_nxt);
#endif
		// fast retransmission exit: cwnd=ssthresh
		cur_stream->sndvar->cwnd = cur_stream->sndvar->ssthresh;

		TRACE_LOSS("Updating snd_nxt from %u to %u\n", cur_stream->snd_nxt, ack_seq);
#if USE_CCP
		cur_stream->wait_for_acks = FALSE;
#endif
		cur_stream->snd_nxt = ack_seq;
		TRACE_DBG("Sending again..., ack_seq=%u sndlen=%u cwnd=%u\n",
                        ack_seq-sndvar->iss,
                        sndvar->sndbuf->len,
                        sndvar->cwnd / sndvar->mss);
		if (sndvar->sndbuf->len == 0) {
			RemoveFromSendList(mtcp, cur_stream);
		} else {
			AddtoSendList(mtcp, cur_stream);
		}
	}
#endif /* RECOVERY_AFTER_LOSS */

	rmlen = ack_seq - sndvar->sndbuf->head_seq;
	uint16_t packets = rmlen / sndvar->eff_mss;
	if (packets * sndvar->eff_mss > rmlen) {
		packets++;
	}

#if USE_CCP
	ccp_cong_control(mtcp, cur_stream, ack_seq, rmlen, packets);
#else
	// log_cwnd_rtt(cur_stream);
#endif

	/* If ack_seq is previously acked, return */
	if (TCP_SEQ_GEQ(sndvar->sndbuf->head_seq, ack_seq)) {
		return;
	}

	/* Remove acked sequence from send buffer */
	if (rmlen > 0) {
		/* Routine goes here only if there is new payload (not retransmitted) */
		
		/* Estimate RTT and calculate rto */
		if (cur_stream->saw_timestamp) {
			EstimateRTT(mtcp, cur_stream, 
					cur_ts - cur_stream->rcvvar->ts_lastack_rcvd);
			sndvar->rto = (cur_stream->rcvvar->srtt >> 3) + cur_stream->rcvvar->rttvar;
			assert(sndvar->rto > 0);
		} else {
			//TODO: Need to implement timestamp estimation without timestamp
			TRACE_RTT("NOT IMPLEMENTED.\n");
		}

		// TODO CCP should comment this out? 
		/* Update congestion control variables */
		if (cur_stream->state >= TCP_ST_ESTABLISHED) {
			if (sndvar->cwnd < sndvar->ssthresh) {
				if ((sndvar->cwnd + sndvar->mss) > sndvar->cwnd) {
					sndvar->cwnd += (sndvar->mss * packets);
				}
				TRACE_CONG("slow start cwnd: %u, ssthresh: %u\n", 
						sndvar->cwnd, sndvar->ssthresh);
			} else {
				uint32_t new_cwnd = sndvar->cwnd + 
						packets * sndvar->mss * sndvar->mss / 
						sndvar->cwnd;
				if (new_cwnd > sndvar->cwnd) {
					sndvar->cwnd = new_cwnd;
				}
				//TRACE_CONG("congestion avoidance cwnd: %u, ssthresh: %u\n", 
				//		sndvar->cwnd, sndvar->ssthresh);
			}
		}

		if (SBUF_LOCK(&sndvar->write_lock)) {
			if (errno == EDEADLK)
				perror("ProcessACK: write_lock blocked\n");
			assert(0);
		}
		ret = SBRemove(mtcp->rbm_snd, sndvar->sndbuf, rmlen);
		sndvar->snd_una = ack_seq;
		snd_wnd_prev = sndvar->snd_wnd;
		sndvar->snd_wnd = sndvar->sndbuf->size - sndvar->sndbuf->len;

		/* If there was no available sending window */
		/* notify the newly available window to application */
#if SELECTIVE_WRITE_EVENT_NOTIFY
		if (snd_wnd_prev <= 0) {
#endif /* SELECTIVE_WRITE_EVENT_NOTIFY */
			RaiseWriteEvent(mtcp, cur_stream);
#if SELECTIVE_WRITE_EVENT_NOTIFY
		}
#endif /* SELECTIVE_WRITE_EVENT_NOTIFY */

		SBUF_UNLOCK(&sndvar->write_lock);
		UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
	}

	UNUSED(ret);
}
/*----------------------------------------------------------------------------*/
/* ProcessTCPPayload: merges TCP payload using receive ring buffer            */
/* Return: TRUE (1) in normal case, FALSE (0) if immediate ACK is required    */
/* CAUTION: should only be called at ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2      */
/*----------------------------------------------------------------------------*/
static inline int 
ProcessTCPPayload(mtcp_manager_t mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *payload, uint32_t seq, int payloadlen)
{	
	struct tcp_recv_vars *rcvvar = cur_stream->rcvvar;
	uint32_t prev_rcv_nxt;
	int ret;

	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(seq + payloadlen, cur_stream->rcv_nxt)) {
		return FALSE;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	if (TCP_SEQ_GT(seq + payloadlen, cur_stream->rcv_nxt + rcvvar->rcv_wnd)) {
		return FALSE;
	}

	/* allocate receive buffer if not exist */
	if (!rcvvar->rcvbuf) {
		rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, rcvvar->irs + 1);
		if (!rcvvar->rcvbuf) {
			TRACE_ERROR("Stream %d: Failed to allocate receive buffer.\n", 
					cur_stream->id);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);

			return ERROR;
		}
	}

	// if (SBUF_LOCK(&rcvvar->read_lock)) {
	// 	if (errno == EDEADLK)
	// 		perror("ProcessTCPPayload: read_lock blocked\n");
	// 	assert(0);
	// }

	prev_rcv_nxt = cur_stream->rcv_nxt;
	ret = RBPut(mtcp->rbm_rcv, 
			rcvvar->rcvbuf, payload, (uint32_t)payloadlen, seq);
	if (ret < 0) {
		TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
	}

	/* discard the buffer if the state is FIN_WAIT_1 or FIN_WAIT_2, 
	   meaning that the connection is already closed by the application */
	if (cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2) {
		RBRemove(mtcp->rbm_rcv, 
				rcvvar->rcvbuf, rcvvar->rcvbuf->merged_len, AT_MTCP);
	}
	cur_stream->rcv_nxt = rcvvar->rcvbuf->head_seq + rcvvar->rcvbuf->merged_len;
	rcvvar->rcv_wnd = rcvvar->rcvbuf->size - rcvvar->rcvbuf->merged_len;

	// SBUF_UNLOCK(&rcvvar->read_lock);

	if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, prev_rcv_nxt)) {
		/* There are some lost packets */
		return FALSE;
	}

	TRACE_EPOLL("Stream %d data arrived. "
			"len: %d, ET: %u, IN: %u, OUT: %u\n", 
			cur_stream->id, payloadlen, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLET : 0, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLIN : 0, 
			cur_stream->socket? cur_stream->socket->epoll & MTCP_EPOLLOUT : 0);
	
	if (cur_stream->state == TCP_ST_ESTABLISHED) {
		RaiseReadEvent(mtcp, cur_stream);
		// printf("ProcessTCPPayload: Raised Read Event\n");
	}

	return TRUE;
}
/*----------------------------------------------------------------------------*/

static inline int 
ProcessMPTCPPayload(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts, uint8_t *payload, uint32_t seq, int payloadlen, uint32_t dataSeq)
{
	struct tcp_recv_vars *subflow_rcvvar = cur_stream->rcvvar;
	struct tcp_recv_vars *mpcb_rcvvar = cur_stream->mptcp_cb->mpcb_stream->rcvvar;
	uint32_t subflow_prev_rcv_nxt;
	int ret;

	/*SUBFLOW LEVEL CHECKS*/
	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(seq + payloadlen, cur_stream->rcv_nxt)) {
		// printf("ProcessMPTCPPayload: seq + payloadlen < cur_stream->rcv_nxt\n");
		return FALSE;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	if (TCP_SEQ_GT(seq + payloadlen, cur_stream->rcv_nxt + subflow_rcvvar->rcv_wnd)) {
		// printf("ProcessMPTCPPayload: seq + payloadlen > cur_stream->rcv_nxt + subflow_rcvvar->rcv_wnd\n");
		return FALSE;
	}

	/*MPTCP CONNECTION LEVEL CHECKS*/
	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(dataSeq + payloadlen, cur_stream->mptcp_cb->mpcb_stream->rcv_nxt)) {
		// printf("ProcessMPTCPPayload: dataSeq + payloadlen < cur_stream->mptcp_cb->mpcb_stream->rcv_nxt\n");
		return FALSE;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	if (TCP_SEQ_GT(dataSeq + payloadlen, cur_stream->mptcp_cb->mpcb_stream->rcv_nxt + mpcb_rcvvar->rcv_wnd)) {
		// printf("ProcessMPTCPPayload: dataSeq + payloadlen > cur_stream->mptcp_cb->mpcb_stream->rcv_nxt + mpcb_rcvvar->rcv_wnd\n");
		return FALSE;
	}

	/*SUBFLOW*/
	/* allocate receive buffer if not exist */
	if (!subflow_rcvvar->rcvbuf) {
		subflow_rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, subflow_rcvvar->irs + 1);
		if (!subflow_rcvvar->rcvbuf) {
			TRACE_ERROR("Stream %d: Failed to allocate receive buffer.\n", 
					cur_stream->id);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream);
			// printf("ProcessMPTCPPayload: Failed to allocate receive buffer\n");
			return ERROR;
		}
	}

	/*MPTCP CONNECTION*/
	/* allocate receive buffer if not exist */
	if (!mpcb_rcvvar->rcvbuf) {
		mpcb_rcvvar->rcvbuf = RBInit(mtcp->rbm_rcv, mpcb_rcvvar->irs + 1);
		if (!mpcb_rcvvar->rcvbuf) {
			TRACE_ERROR("Stream %d: Failed to allocate receive buffer.\n", 
					cur_stream->mptcp_cb->mpcb_stream->id);
			cur_stream->mptcp_cb->mpcb_stream->state = TCP_ST_CLOSED;
			cur_stream->mptcp_cb->mpcb_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, cur_stream->mptcp_cb->mpcb_stream);
			// printf("ProcessMPTCPPayload: Failed to allocate receive buffer 2\n");
			return ERROR;
		}
	}

	if (SBUF_LOCK(&subflow_rcvvar->read_lock)) {
		if (errno == EDEADLK)
			perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	if (SBUF_LOCK(&mpcb_rcvvar->read_lock)) {
		if (errno == EDEADLK)
			perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	/*SUBFLOW*/
	subflow_prev_rcv_nxt = cur_stream->rcv_nxt;

	ret = RBPut(mtcp->mptcp_rbm_rcv, 
			mpcb_rcvvar->rcvbuf, payload, (uint32_t)payloadlen, dataSeq);
	
	if (ret < 0) {
		TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
	}

	/*Haathim_TODO: Removing from buffer if FIN WAIT*/

	/*SUBFLOW*/
	// cur_stream->rcv_nxt = subflow_rcvvar->rcvbuf->head_seq + subflow_rcvvar->rcvbuf->merged_len;
	cur_stream->rcv_nxt = seq + (uint32_t)payloadlen;
	subflow_rcvvar->rcv_wnd = subflow_rcvvar->rcvbuf->size - subflow_rcvvar->rcvbuf->merged_len;

	/*MPTCP CONNECTION*/
	cur_stream->mptcp_cb->mpcb_stream->rcv_nxt = mpcb_rcvvar->rcvbuf->head_seq + mpcb_rcvvar->rcvbuf->merged_len;
	mpcb_rcvvar->rcv_wnd = mpcb_rcvvar->rcvbuf->size - mpcb_rcvvar->rcvbuf->merged_len;

	SBUF_UNLOCK(&mpcb_rcvvar->read_lock);
	SBUF_UNLOCK(&subflow_rcvvar->read_lock);

	if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, subflow_prev_rcv_nxt)) {
		/* There are some lost packets */
		// printf("ProcessMPTCPPayload: TCP_SEQ_LEQ(cur_stream->rcv_nxt, subflow_prev_rcv_nxt)\n");
		return FALSE;
	}

	if (cur_stream->state == TCP_ST_ESTABLISHED) {
		RaiseReadEvent(mtcp, cur_stream);
	}


	return TRUE;
}

/*----------------------------------------------------------------------------*/
static inline tcp_stream *
CreateNewFlowHTEntry(mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph, 
		int ip_len, const struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		int payloadlen, uint16_t window)
{
	tcp_stream *cur_stream;
	int ret; 
	
	if (tcph->syn && !tcph->ack) {
		/* handle the SYN */
		ret = FilterSYNPacket(mtcp, iph->daddr, tcph->dest);
		if (!ret) {
			TRACE_DBG("Refusing SYN packet.\n");
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);

			return NULL;
		}

		/* now accept the connection */
		cur_stream = HandlePassiveOpen(mtcp, 
				cur_ts, iph, tcph, seq, window);
		if (!cur_stream) {
			TRACE_DBG("Not available space in flow pool.\n");
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);

			return NULL;
		}

		return cur_stream;
	} else if (tcph->rst) {
		TRACE_DBG("Reset packet comes\n");
#ifdef DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
		/* for the reset packet, just discard */
		return NULL;
	} else {
		TRACE_DBG("Weird packet comes.\n");
#ifdef DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
		/* TODO: for else, discard and send a RST */
		/* if the ACK bit is off, respond with seq 0: 
		   <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>
		   else (ACK bit is on):
		   <SEQ=SEG.ACK><CTL=RST>
		   */
		if (tcph->ack) {
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					ack_seq, 0, 0, TCP_FLAG_RST, NULL, 0, cur_ts, 0);
		} else {
			SendTCPPacketStandalone(mtcp, 
					iph->daddr, tcph->dest, iph->saddr, tcph->source, 
					0, seq + payloadlen, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
					NULL, 0, cur_ts, 0);
		}
		return NULL;
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_LISTEN (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, struct tcphdr* tcph) {
	
	// Have to check for MP options here
	// use something like ParseMPTCP options
	uint8_t mptcp_option = ParseMPTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
	uint64_t peerKey = GetPeerKey(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
	if (mptcp_option == MPTCP_OPTION_CAPABLE && peerKey) {
		cur_stream->isReceivedMPCapableSYN = 1;
		cur_stream->mptcp_cb = (mptcp_cb *)calloc(1, sizeof(mptcp_cb));
		cur_stream->mptcp_cb->peerKey = peerKey;
		uint64_t random_number = 0;
		for (int i = 0; i < 8; ++i) {
			random_number = (random_number << 8) | (rand() & 0xFF);
		}
		cur_stream->mptcp_cb->myKey = random_number;
		uint32_t myToken = GetToken(cur_stream->mptcp_cb->myKey);
		mtcp->mptcp_conns.token[mtcp->mptcp_conns.num_connections] = myToken;
		mtcp->mptcp_conns.mptcp_cbs[mtcp->mptcp_conns.num_connections++] = cur_stream->mptcp_cb;


	}
	// Haathim_TODO:Check for MP_JOIN option
	if (mptcp_option == MPTCP_OPTION_JOIN) {
		
		uint32_t token = GetTokenFromMPJoinSYN(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
		uint32_t peerRandomNumber = GetPeerRandomNumberFromMPJoinSYN(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
		// Have to check if ok ot proceed
		// check in the table if we have a mptcp connection for that token
		cur_stream->isReceivedMPJoinSYN = 1;
		cur_stream->isMPJOINStream = 1; //Haathim_TODO: Check if this is needed and if correct
		cur_stream->peerRandomNumber = peerRandomNumber;
		// using token add the relevenat motco_cb to it
		for(int i=0;i<mtcp->mptcp_conns.num_connections;i++){
			if(mtcp->mptcp_conns.token[i] == token){
				cur_stream->mptcp_cb = mtcp->mptcp_conns.mptcp_cbs[i];
				// cur_stream->mptcp_cb->tcp_streams[cur_stream->mptcp_cb->num_streams++] = cur_stream;
				cur_stream->isMPJOINStream = 1;
				break;
			}
		}

	}

	if (tcph->syn) {
		if (cur_stream->state == TCP_ST_LISTEN)
			cur_stream->rcv_nxt++;
		cur_stream->state = TCP_ST_SYN_RCVD;
		TRACE_STATE("Stream %d: TCP_ST_SYN_RCVD\n", cur_stream->id);
		AddtoControlList(mtcp, cur_stream, cur_ts);
	} else {
		CTRACE_ERROR("Stream %d (TCP_ST_LISTEN): "
				"Packet without SYN.\n", cur_stream->id);
	}

}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_SYN_SENT (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, const struct iphdr* iph, struct tcphdr* tcph,
		uint32_t seq, uint32_t ack_seq, int payloadlen, uint16_t window)
{

	// creating the structures in case of MP_CAPABLE reply
	// tcp_stream first_subflow = *cur_stream;
	// tcp_stream *meta_sock; 
	// int ret;
	uint64_t peerKey;
	uint64_t truncatedHMAC;

	/* when active open */
	if (tcph->ack) {
		/* filter the unacceptable acks */
		if (TCP_SEQ_LEQ(ack_seq, cur_stream->sndvar->iss) || 
				TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt)) {
			if (!tcph->rst) {
				SendTCPPacketStandalone(mtcp, 
						iph->daddr, tcph->dest, iph->saddr, tcph->source, 
						ack_seq, 0, 0, TCP_FLAG_RST, NULL, 0, cur_ts, 0);
			}
			return;
		}
		/* accept the ack */
		cur_stream->sndvar->snd_una++;
	}
	
	if (tcph->rst) {
		if (tcph->ack) {
			cur_stream->state = TCP_ST_CLOSE_WAIT;
			cur_stream->close_reason = TCP_RESET;
			if (cur_stream->socket) {
				RaiseErrorEvent(mtcp, cur_stream);
			} else {
				DestroyTCPStream(mtcp, cur_stream);
			}
		}
		return;
	}

	if (tcph->syn) {
		if (tcph->ack) {

			// Can we use ParseMPTCPOptions??
			// peerKey = ParseMPTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
			// Here GetPeerKey check first if there is a MP_CAPABLE option and then for the key in it
			peerKey = GetPeerKey(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
			
			if(peerKey != 0){
				cur_stream->peerKey = peerKey;
				// Which means can that peer supports MPTCP
				// cur_stream->mptcp_cb = (mptcp_cb *)calloc(1, sizeof(mptcp_cb));
				// Have to initialize the tcp_stream of mpcb here
				// and set the variables
				socket_map_t socket;
				socket = cur_stream->socket;
				cur_stream->mptcp_cb->mpcb_stream = CreateMpcbTCPStream(mtcp, socket, socket->socktype, socket->saddr.sin_addr.s_addr, socket->saddr.sin_port, cur_stream->daddr, cur_stream->dport);

				
				cur_stream->mptcp_cb->tcp_streams[0] = cur_stream;
				cur_stream->mptcp_cb->peer_idsn = GetPeerIdsnFromKey(peerKey);
				cur_stream->mptcp_cb->mpcb_stream->rcvvar->irs = GetPeerIdsnFromKey(peerKey);
				cur_stream->mptcp_cb->mpcb_stream->sndvar->iss = GetPeerIdsnFromKey(cur_stream->mptcp_cb->myKey);
				cur_stream->mptcp_cb->my_idsn = GetPeerIdsnFromKey(cur_stream->mptcp_cb->myKey);
				cur_stream->mptcp_cb->peerKey = peerKey;
				cur_stream->mptcp_cb->mpcb_stream->snd_nxt = cur_stream->mptcp_cb->my_idsn + 1;
				cur_stream->mptcp_cb->mpcb_stream->rcv_nxt = cur_stream->mptcp_cb->peer_idsn + 1;
				cur_stream->mptcp_cb->mpcb_stream->state = TCP_ST_ESTABLISHED;
				cur_stream->mptcp_cb->num_streams = 1;
				cur_stream->mptcp_cb->isSentMPJoinSYN = 0;
			}
		
			// Need to check for the MP_JOIN option
			if (cur_stream->isMPJOINStream)
			{
				truncatedHMAC = checkMP_JOIN_SYN_ACK(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
				// Haathim_TODO: Need to check if Server's response is correct
				cur_stream->mptcp_cb->tcp_streams[cur_stream->mptcp_cb->num_streams++] = cur_stream;
			}
			
			

			int ret = HandleActiveOpen(mtcp, 
					cur_stream, cur_ts, tcph, seq, ack_seq, window);
			if (!ret) {
				return;
			}
			
			cur_stream->sndvar->nrtx = 0;
			cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
			RemoveFromRTOList(mtcp, cur_stream);
			cur_stream->state = TCP_ST_ESTABLISHED;
			TRACE_STATE("Stream %d: TCP_ST_ESTABLISHED\n", cur_stream->id);

			if (cur_stream->socket) {
				RaiseWriteEvent(mtcp, cur_stream);
			} else {
				TRACE_STATE("Stream %d: ESTABLISHED, but no socket\n", cur_stream->id);
				SendTCPPacketStandalone(mtcp, 
						iph->daddr, tcph->dest, iph->saddr, tcph->source, 
						0, seq + payloadlen + 1, 0, TCP_FLAG_RST | TCP_FLAG_ACK, 
						NULL, 0, cur_ts, 0);
				cur_stream->close_reason = TCP_ACTIVE_CLOSE;
				DestroyTCPStream(mtcp, cur_stream);
				return;
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
			if (CONFIG.tcp_timeout > 0)
				AddtoTimeoutList(mtcp, cur_stream);

		} else {
			cur_stream->state = TCP_ST_SYN_RCVD;
			TRACE_STATE("Stream %d: TCP_ST_SYN_RCVD\n", cur_stream->id);
			cur_stream->snd_nxt = cur_stream->sndvar->iss;
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_SYN_RCVD (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t ack_seq) 
{





	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint64_t peerKey = 0, myKey = 0;
	uint8_t mptcp_option;
	int ret;
	if (tcph->ack) {
		struct tcp_listener *listener;
		uint32_t prior_cwnd;
		/* check if ACK of SYN */
		if (ack_seq != sndvar->iss + 1) {
			CTRACE_ERROR("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			TRACE_DBG("Stream %d (TCP_ST_SYN_RCVD): "
					"weird ack_seq: %u, iss: %u\n", 
					cur_stream->id, ack_seq, sndvar->iss);
			return;
		}

		sndvar->snd_una++;
		cur_stream->snd_nxt = ack_seq;
		prior_cwnd = sndvar->cwnd;
		sndvar->cwnd = ((prior_cwnd == 1)? 
				(sndvar->mss * TCP_INIT_CWND): sndvar->mss);
		TRACE_DBG("sync_recvd: updating cwnd from %u to %u\n", prior_cwnd, sndvar->cwnd);
		
		//UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
		sndvar->nrtx = 0;
		cur_stream->rcv_nxt = cur_stream->rcvvar->irs + 1;
		RemoveFromRTOList(mtcp, cur_stream);

		cur_stream->state = TCP_ST_ESTABLISHED;
		TRACE_STATE("Stream %d: TCP_ST_ESTABLISHED\n", cur_stream->id);
		// Haathim_TODO: Here only need to make to Multipath TCP connection (but did i store the peer key that i sent?)
		// check if keys are correct
		mptcp_option = ParseMPTCPOptions(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
		peerKey = GetPeerKey(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
		// print mptcp option
		if (mptcp_option == MPTCP_OPTION_CAPABLE && peerKey && cur_stream->mptcp_cb != NULL) {
			if(peerKey == cur_stream->mptcp_cb->peerKey){
				myKey = GetMyKeyFromMPCapbleACK(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
				if(myKey == cur_stream->mptcp_cb->myKey){
					// socket_map_t socket;
					// socket = cur_stream->socket; 
					//Above is problem
					// Still a socket has not been assigned to this
					// only when issue the accept call the socket will be assigned
					// so either have to do all this in the accept call or replace manually all the socket values

					// Maybe do what we can do here and the rest in the accept call
					// cur_stream->mptcp_cb->mpcb_stream = CreateMpcbTCPStream(mtcp, socket, socket->socktype, socket->saddr.sin_addr.s_addr, socket->saddr.sin_port, cur_stream->daddr, cur_stream->dport);
					cur_stream->mptcp_cb->mpcb_stream = CreateMpcbTCPStream(mtcp, NULL, MTCP_SOCK_STREAM, cur_stream->saddr, cur_stream->sport, cur_stream->daddr, cur_stream->dport);
					

					// Another problem
					// we are doing all for the listener and not the accepted stream
					// Have to think a lot
					
					cur_stream->mptcp_cb->tcp_streams[0] = cur_stream;
					cur_stream->mptcp_cb->peer_idsn = GetPeerIdsnFromKey(peerKey);
					cur_stream->mptcp_cb->mpcb_stream->rcvvar->irs = GetPeerIdsnFromKey(peerKey);
					cur_stream->mptcp_cb->mpcb_stream->sndvar->iss = GetPeerIdsnFromKey(myKey);
					cur_stream->mptcp_cb->my_idsn = GetPeerIdsnFromKey(myKey);
					cur_stream->mptcp_cb->peerKey = peerKey;
					cur_stream->mptcp_cb->mpcb_stream->snd_nxt = cur_stream->mptcp_cb->my_idsn + 1;
					cur_stream->mptcp_cb->mpcb_stream->rcv_nxt = cur_stream->mptcp_cb->peer_idsn + 1;
					cur_stream->mptcp_cb->mpcb_stream->state = TCP_ST_ESTABLISHED;
					cur_stream->mptcp_cb->num_streams = 1;


				}
			}
										
		}
		else if (mptcp_option == (uint8_t)1)
		{

			if(cur_stream->mptcp_cb != NULL){
				// check if the HMAC is correct
				// uint8_t isHMACCorrect = checkHMAC(cur_stream, cur_ts, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
				uint8_t isHMACCorrect = 1; //assume true for now
				// Haathim_TODO: check if the current packet is a MP_JOIN_ACK (is there a better wau to check this?)
				// if yes then check if the response is correct
				// and then enqueue an ack becuase client is waiting for it
				if (isHMACCorrect){
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
					// AddtoControlList(mtcp, cur_stream, cur_ts);
				}
			}
		}
		else{
			// struct iphdr *iph = (struct iphdr *)((uint8_t *)tcph - sizeof(struct iphdr));
		}
		
		/* update listening socket */
		listener = (struct tcp_listener *)ListenerHTSearch(mtcp->listeners, &tcph->dest);

		ret = StreamEnqueue(listener->acceptq, cur_stream);
		if (ret < 0) {
			TRACE_ERROR("Stream %d: Failed to enqueue to "
					"the listen backlog!\n", cur_stream->id);
			cur_stream->close_reason = TCP_NOT_ACCEPTED;
			cur_stream->state = TCP_ST_CLOSED;
			TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", cur_stream->id);
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
		//TRACE_DBG("Stream %d inserted into acceptq.\n", cur_stream->id);
		if (CONFIG.tcp_timeout > 0)
			AddtoTimeoutList(mtcp, cur_stream);

		/* raise an event to the listening socket */
		if (listener->socket && (listener->socket->epoll & MTCP_EPOLLIN)) {
			AddEpollEvent(mtcp->ep, 
					MTCP_EVENT_QUEUE, listener->socket, MTCP_EPOLLIN);
		}

		// //Haathim_TODO: Try to send MP_JOIN here (instead of at mtcp_write)
		// // Tried. Problem with passing mctx arg as it does not exist in the current function scope

		// // *************************************************************************************
		// if(cur_stream->mptcp_cb != NULL){
		// 	mctx_t mctx = (mctx_t) malloc(sizeof(struct mtcp_context));
		// 	int i = 0;
		// 	while(i < MAX_CPUS && g_mtcp[i] != mtcp) i++; //finding the mctx for the given mtcp_manager
		// 	mctx->cpu = i;
		// 	int new_subflow_sockid = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);

		// 	struct sockaddr_in my_addr;
		// 	my_addr.sin_family = AF_INET;
		// 	char my_var[] = "192.168.61.12";
		// 	my_addr.sin_addr.s_addr = inet_addr(my_var);
		// 	my_addr.sin_port = cur_stream->dport+1;

		// 	mtcp_bind(mctx, new_subflow_sockid, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in));
			
		// 	socket_map_t new_subflow_socket = &mtcp->smap[new_subflow_sockid];
		// 	struct sockaddr_in addr;
		// 	addr.sin_family = AF_INET;
		// 	char var[] = "192.168.63.12";
		// 	addr.sin_addr.s_addr = inet_addr(var);
		// 	addr.sin_port = cur_stream->dport;
		// 	int new_subflow_ret = commence_mpjoin(mctx, new_subflow_sockid, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), cur_stream->mptcp_cb);
		// }
		// // *************************************************************************************


	} else {
		TRACE_DBG("Stream %d (TCP_ST_SYN_RCVD): No ACK.\n", 
				cur_stream->id);
		/* retransmit SYN/ACK */
		cur_stream->snd_nxt = sndvar->iss;
		AddtoControlList(mtcp, cur_stream, cur_ts);
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_ESTABLISHED (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		uint8_t *payload, int payloadlen, uint16_t window) 
{
	
	if (tcph->syn) {
		TRACE_DBG("Stream %d (TCP_ST_ESTABLISHED): weird SYN. "
				"seq: %u, expected: %u, ack_seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt, 
				ack_seq, cur_stream->snd_nxt);
		cur_stream->snd_nxt = ack_seq;
		AddtoControlList(mtcp, cur_stream, cur_ts);
		return;
	}

	// get data seq if avaible
	uint32_t dataSeq;
	if(cur_stream->mptcp_cb != NULL){
		// dataSeq = GetDataSeq(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
		// if (dataSeq > 0){
		// }

		// check if DATA-FIN is there
		if(isDataFINPresent(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN)){
			// Store that info in the mptcp_cb
			cur_stream->mptcp_cb->isDataFINReceived = 1;
		}

	}
	
	// Haathim_TODO: Need to add the data into the mpcb rcv buf after adding to normal rcv buf
	// which is done in the ProcessTCPPayload function
	// after adding to mpcb rcv buf need to send a DATAACK through any ofthe subflows
	// Just like senfing a normal data

	if (payloadlen > 0) {
		/*FIRST TRY*/
		// if (cur_stream->mptcp_cb != NULL)
		// {
		// 	/*This is a MPTCP connection*/
		// 	if (ProcessMPTCPPayload(mtcp, cur_stream, 
		// 		cur_ts, payload, seq, payloadlen, dataSeq)) {
		// 		/* if return is TRUE, send ACK */
		// 		printf("ACK 1\n");
		// 		EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);

		// 	} else {
		// 		printf("ACK 2\n");
		// 		EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);

		// 	}
		// }
		// else
		// {
		// 	/*Not a MPTCP Connection*/
		// 	if (ProcessTCPPayload(mtcp, cur_stream, 
		// 		cur_ts, payload, seq, payloadlen)) {
		// 	/* if return is TRUE, send ACK */
		// 		EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);

		// 	} else {
		// 		EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		// 	}
		// }
		/*END OF FIRST TRY*/

		/*SECOND TRY*/
		if (ProcessTCPPayload(mtcp, cur_stream, 
				cur_ts, payload, seq, payloadlen)) {
			/* if return is TRUE, send ACK */
				if (cur_stream->mptcp_cb != NULL)
				{
					dataSeq = GetDataSeq(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
					uint16_t dataLevelLength = GetDataLevelLength(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
					// printf("The data level length is %d\n", (int) dataLevelLength);
					if(payloadlen == (int)dataLevelLength || cur_stream->mptcp_cb->isDataFINReceived == 1){CopyFromSubflowToMpcb(mtcp, cur_stream->mptcp_cb->mpcb_stream, cur_stream, seq, payloadlen, dataSeq);}
					// else printf("Mismatch: payloadlen: %d, dataLevelLength: %d\n", payloadlen, (int) dataLevelLength);

					// //enqueu ACK for both subflows
					// for(int i = 0; i < cur_stream->mptcp_cb->num_streams; i++){
					// 	EnqueueACK(mtcp, cur_stream->mptcp_cb->tcp_streams[i], cur_ts, ACK_OPT_AGGREGATE);
					// }

				
				}
				// else
				// {
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
				// }
				
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		}
		/*END OF SECOND TRY*/
		
		
	}

	if (tcph->ack) {
		// check if ACK is > 1 && should do only once
		if(cur_stream->mptcp_cb != NULL  && cur_stream->mptcp_cb->isSentMPJoinSYN == 0){
			// send MP_JOIN_SYN
			

			tcp_stream* new_mpjoin_stream = CreateTCPStream(mtcp, NULL, SOCK_STREAM, inet_addr("192.168.61.12"), cur_stream->sport, cur_stream->daddr, cur_stream->dport);
			
			if (!new_mpjoin_stream) {
				TRACE_ERROR("Failed to create mpjoin tcp_stream!\n");
				errno = ENOMEM;
				return;
			}

			new_mpjoin_stream->isMPJOINStream = 1;
			new_mpjoin_stream->mptcp_cb = cur_stream->mptcp_cb;

			/*Dont know if below will work or is correct*/
			new_mpjoin_stream->socket = cur_stream->socket;

			new_mpjoin_stream->sndvar->cwnd = 1;
			new_mpjoin_stream->sndvar->ssthresh = new_mpjoin_stream->sndvar->mss * 10;
			new_mpjoin_stream->state = TCP_ST_SYN_SENT;
			TRACE_STATE("Stream %d: TCP_ST_SYN_SENT\n", new_mpjoin_stream->id);
			SQ_LOCK(&mtcp->ctx->connect_lock);
			int ret = StreamEnqueue(mtcp->connectq, new_mpjoin_stream);
			SQ_UNLOCK(&mtcp->ctx->connect_lock);
			mtcp->wakeup_flag = TRUE;

			if (ret < 0) {

				TRACE_ERROR("mpjoin stream failed to enqueue to conenct queue!\n");
				SQ_LOCK(&mtcp->ctx->destroyq_lock);
				StreamEnqueue(mtcp->destroyq, new_mpjoin_stream);
				SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
				errno = EAGAIN;
				
			}
		
			cur_stream->mptcp_cb->isSentMPJoinSYN = 1;
		}

		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}
	}

	// Haathim_TODO: In a similar way have to process DATA_ACK
	// uint32_t dataAck = GetDataAck(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
	
	if (tcph->fin) {
		// struct iphdr *iph = (struct iphdr *)((uint8_t *)tcph - sizeof(struct iphdr));

		/* process the FIN only if the sequence is valid */
		/* FIN packet is allowed to push payload (should we check for PSH flag)? */
		if (seq + payloadlen == cur_stream->rcv_nxt) {
			cur_stream->state = TCP_ST_CLOSE_WAIT;
			TRACE_STATE("Stream %d: TCP_ST_CLOSE_WAIT\n", cur_stream->id);
			cur_stream->rcv_nxt++;
			AddtoControlList(mtcp, cur_stream, cur_ts);

			/* notify FIN to application */
			RaiseReadEvent(mtcp, cur_stream);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
			return;
		}
	}

}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_CLOSE_WAIT (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq, 
		int payloadlen, uint16_t window) 
{
	if (TCP_SEQ_LT(seq, cur_stream->rcv_nxt)) {
		TRACE_DBG("Stream %d (TCP_ST_CLOSE_WAIT): "
				"weird seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt);
		// printf("Going to call ..........................\n");
		AddtoControlList(mtcp, cur_stream, cur_ts);
		return;
	}

	if (cur_stream->sndvar->sndbuf) {
		ProcessACK(mtcp, cur_stream, cur_ts, 
				tcph, seq, ack_seq, window, payloadlen);
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_LAST_ACK (mtcp_manager_t mtcp, uint32_t cur_ts, const struct iphdr *iph,
		int ip_len, tcp_stream* cur_stream, struct tcphdr* tcph, 
		uint32_t seq, uint32_t ack_seq, int payloadlen, uint16_t window) 
{

	if (TCP_SEQ_LT(seq, cur_stream->rcv_nxt)) {
		TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): "
				"weird seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt);
		return;
	}

	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

		if (!cur_stream->sndvar->is_fin_sent) {
			/* the case that FIN is not sent yet */
			/* this is not ack for FIN, ignore */
			TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): "
					"No FIN sent yet.\n", cur_stream->id);
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
#if DUMP_STREAM
			DumpStream(mtcp, cur_stream);
			DumpControlList(mtcp, mtcp->n_sender[0]);
#endif
			return;
		}

		/* check if ACK of FIN */
		if (ack_seq == cur_stream->sndvar->fss + 1) {
			cur_stream->sndvar->snd_una++;
			UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
			cur_stream->state = TCP_ST_CLOSED;
			cur_stream->close_reason = TCP_PASSIVE_CLOSE;
			TRACE_STATE("Stream %d: TCP_ST_CLOSED\n", 
					cur_stream->id);
			DestroyTCPStream(mtcp, cur_stream);
		} else {
			TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): Not ACK of FIN. "
					"ack_seq: %u, expected: %u\n", 
					cur_stream->id, ack_seq, cur_stream->sndvar->fss + 1);
			//cur_stream->snd_nxt = cur_stream->sndvar->fss;
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
	} else {
		CTRACE_ERROR("Stream %d (TCP_ST_LAST_ACK): No ACK\n", 
				cur_stream->id);
		//cur_stream->snd_nxt = cur_stream->sndvar->fss;
		AddtoControlList(mtcp, cur_stream, cur_ts);
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_FIN_WAIT_1 (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq, 
		uint8_t *payload, int payloadlen, uint16_t window) 
{

	if (TCP_SEQ_LT(seq, cur_stream->rcv_nxt)) {
		TRACE_DBG("Stream %d (TCP_ST_LAST_ACK): "
				"weird seq: %u, expected: %u\n", 
				cur_stream->id, seq, cur_stream->rcv_nxt);
		AddtoControlList(mtcp, cur_stream, cur_ts);
		return;
	}

	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

		if (cur_stream->sndvar->is_fin_sent && 
				ack_seq == cur_stream->sndvar->fss + 1) {
			cur_stream->sndvar->snd_una = ack_seq;
			if (TCP_SEQ_GT(ack_seq, cur_stream->snd_nxt)) {
				TRACE_DBG("Stream %d: update snd_nxt to %u\n", 
						cur_stream->id, ack_seq);
				cur_stream->snd_nxt = ack_seq;
			}
			//cur_stream->sndvar->snd_una++;
			//UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);
			cur_stream->sndvar->nrtx = 0;
			RemoveFromRTOList(mtcp, cur_stream);
			cur_stream->state = TCP_ST_FIN_WAIT_2;
			TRACE_STATE("Stream %d: TCP_ST_FIN_WAIT_2\n", 
					cur_stream->id);
		}

	} else {
		TRACE_DBG("Stream %d: does not contain an ack!\n", 
				cur_stream->id);
		return;
	}

	if (payloadlen > 0) {
		if (ProcessTCPPayload(mtcp, cur_stream, 
				cur_ts, payload, seq, payloadlen)) {
			/* if return is TRUE, send ACK */
			if (cur_stream->mptcp_cb != NULL)
			{
				uint32_t dataSeq = GetDataSeq(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
				CopyFromSubflowToMpcb(mtcp, cur_stream->mptcp_cb->mpcb_stream, cur_stream, seq, payloadlen, dataSeq);
			}
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		}
	}

	if (tcph->fin) {
		/* process the FIN only if the sequence is valid */
		/* FIN packet is allowed to push payload (should we check for PSH flag)? */
		if (seq + payloadlen == cur_stream->rcv_nxt) {
			cur_stream->rcv_nxt++;

			if (cur_stream->state == TCP_ST_FIN_WAIT_1) {
				cur_stream->state = TCP_ST_CLOSING;
				TRACE_STATE("Stream %d: TCP_ST_CLOSING\n", cur_stream->id);

			} else if (cur_stream->state == TCP_ST_FIN_WAIT_2) {
				cur_stream->state = TCP_ST_TIME_WAIT;
				TRACE_STATE("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);
				AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			}
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
	}
}
/*----------------------------------------------------------------------------*/
static inline void 
Handle_TCP_ST_FIN_WAIT_2 (mtcp_manager_t mtcp, uint32_t cur_ts,
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		uint8_t *payload, int payloadlen, uint16_t window)
{
	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}
	} else {
		TRACE_DBG("Stream %d: does not contain an ack!\n", 
				cur_stream->id);
		return;
	}

	if (payloadlen > 0) {
		if (ProcessTCPPayload(mtcp, cur_stream, 
				cur_ts, payload, seq, payloadlen)) {
			/* if return is TRUE, send ACK */

			if (cur_stream->mptcp_cb != NULL)
			{
				uint32_t dataSeq = GetDataSeq(cur_stream, (uint8_t *)tcph + TCP_HEADER_LEN, (tcph->doff << 2) - TCP_HEADER_LEN);
				CopyFromSubflowToMpcb(mtcp, cur_stream->mptcp_cb->mpcb_stream, cur_stream, seq, payloadlen, dataSeq);
			}

			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_AGGREGATE);
		} else {
			EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_NOW);
		}
	}

	if (tcph->fin) {
		/* process the FIN only if the sequence is valid */
		/* FIN packet is allowed to push payload (should we check for PSH flag)? */
		if (seq + payloadlen == cur_stream->rcv_nxt) {
			cur_stream->state = TCP_ST_TIME_WAIT;
			cur_stream->rcv_nxt++;
			TRACE_STATE("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);

			AddtoTimewaitList(mtcp, cur_stream, cur_ts);
			AddtoControlList(mtcp, cur_stream, cur_ts);
		}
#if 0
	} else {
		TRACE_DBG("Stream %d (TCP_ST_FIN_WAIT_2): No FIN. "
				"seq: %u, ack_seq: %u, snd_nxt: %u, snd_una: %u\n", 
				cur_stream->id, seq, ack_seq, 
				cur_stream->snd_nxt, cur_stream->sndvar->snd_una);
#if DBGMSG
		DumpIPPacket(mtcp, iph, ip_len);
#endif
#endif
	}

}
/*----------------------------------------------------------------------------*/
static inline void
Handle_TCP_ST_CLOSING (mtcp_manager_t mtcp, uint32_t cur_ts, 
		tcp_stream* cur_stream, struct tcphdr* tcph, uint32_t seq, uint32_t ack_seq,
		int payloadlen, uint16_t window) {

	if (tcph->ack) {
		if (cur_stream->sndvar->sndbuf) {
			ProcessACK(mtcp, cur_stream, cur_ts, 
					tcph, seq, ack_seq, window, payloadlen);
		}

		if (!cur_stream->sndvar->is_fin_sent) {
			TRACE_DBG("Stream %d (TCP_ST_CLOSING): "
					"No FIN sent yet.\n", cur_stream->id);
			return;
		}

		// check if ACK of FIN
		if (ack_seq != cur_stream->sndvar->fss + 1) {
#if 0
			CTRACE_ERROR("Stream %d (TCP_ST_CLOSING): Not ACK of FIN. "
					"ack_seq: %u, snd_nxt: %u, snd_una: %u, fss: %u\n", 
					cur_stream->id, ack_seq, cur_stream->snd_nxt, 
					cur_stream->sndvar->snd_una, cur_stream->sndvar->fss);
			DumpIPPacketToFile(stderr, iph, ip_len);
			DumpStream(mtcp, cur_stream);
#endif
			//assert(0);
			/* if the packet is not the ACK of FIN, ignore */
			return;
		}
		
		cur_stream->sndvar->snd_una = ack_seq;
		cur_stream->snd_nxt = ack_seq;
		UpdateRetransmissionTimer(mtcp, cur_stream, cur_ts);

		cur_stream->state = TCP_ST_TIME_WAIT;
		TRACE_STATE("Stream %d: TCP_ST_TIME_WAIT\n", cur_stream->id);
		
		AddtoTimewaitList(mtcp, cur_stream, cur_ts);

	} else {
		CTRACE_ERROR("Stream %d (TCP_ST_CLOSING): Not ACK\n", 
				cur_stream->id);
		return;
	}
}
/*----------------------------------------------------------------------------*/
int
ProcessTCPPacket(mtcp_manager_t mtcp, 
		 uint32_t cur_ts, const int ifidx, const struct iphdr *iph, int ip_len)
{
	struct tcphdr* tcph = (struct tcphdr *) ((u_char *)iph + (iph->ihl << 2));
	uint8_t *payload    = (uint8_t *)tcph + (tcph->doff << 2);
	int payloadlen = ip_len - (payload - (u_char *)iph);
	tcp_stream s_stream;
	tcp_stream *cur_stream = NULL;
	uint32_t seq = ntohl(tcph->seq);
	uint32_t ack_seq = ntohl(tcph->ack_seq);
	uint16_t window = ntohs(tcph->window);
	uint16_t check;
	int ret;
	int rc = -1;

	/* Check ip packet invalidation */	
	if (ip_len < ((iph->ihl + tcph->doff) << 2))
		return ERROR;

#if VERIFY_RX_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, ifidx,
					  PKT_RX_TCP_CSUM, NULL);
#endif
	if (rc == -1) {
		check = TCPCalcChecksum((uint16_t *)tcph, 
					(tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr);
		if (check) {
			TRACE_DBG("Checksum Error: Original: 0x%04x, calculated: 0x%04x\n", 
				  tcph->check, TCPCalcChecksum((uint16_t *)tcph, 
				  (tcph->doff << 2) + payloadlen, iph->saddr, iph->daddr));
			tcph->check = 0;
			return ERROR;
		}
	}
#endif

#if defined(NETSTAT) && defined(ENABLELRO)
	mtcp->nstat.rx_gdptbytes += payloadlen;
#endif /* NETSTAT */

	s_stream.saddr = iph->daddr;
	s_stream.sport = tcph->dest;
	s_stream.daddr = iph->saddr;
	s_stream.dport = tcph->source;

	if (!(cur_stream = StreamHTSearch(mtcp->tcp_flow_table, &s_stream))) {
		/* not found in flow table */
		cur_stream = CreateNewFlowHTEntry(mtcp, cur_ts, iph, ip_len, tcph, 
				seq, ack_seq, payloadlen, window);
		if (!cur_stream)
			return TRUE;
	}


	/* Validate sequence. if not valid, ignore the packet */
	if (cur_stream->state > TCP_ST_SYN_RCVD) {
		ret = ValidateSequence(mtcp, cur_stream, 
				cur_ts, tcph, seq, ack_seq, payloadlen);
		if (!ret) {
			TRACE_DBG("Stream %d: Unexpected sequence: %u, expected: %u\n",
					cur_stream->id, seq, cur_stream->rcv_nxt);
#ifdef DBGMSG
			DumpIPPacket(mtcp, iph, ip_len);
#endif
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
			return TRUE;
		}
	}

	/* Update receive window size */
	if (tcph->syn) {
		cur_stream->sndvar->peer_wnd = window;
	} else {
		cur_stream->sndvar->peer_wnd = 
				(uint32_t)window << cur_stream->sndvar->wscale_peer;
	}
				
	cur_stream->last_active_ts = cur_ts;
	UpdateTimeoutList(mtcp, cur_stream);

	/* Process RST: process here only if state > TCP_ST_SYN_SENT */
	if (tcph->rst) {
		cur_stream->have_reset = TRUE;
		if (cur_stream->state > TCP_ST_SYN_SENT) {
			if (ProcessRST(mtcp, cur_stream, ack_seq)) {
				return TRUE;
			}
		}
	}

	switch (cur_stream->state) {
	case TCP_ST_LISTEN:
		Handle_TCP_ST_LISTEN(mtcp, cur_ts, cur_stream, tcph);
		break;

	case TCP_ST_SYN_SENT:
		Handle_TCP_ST_SYN_SENT(mtcp, cur_ts, cur_stream, iph, tcph, 
				seq, ack_seq, payloadlen, window);
		break;

	case TCP_ST_SYN_RCVD:
		/* SYN retransmit implies our SYN/ACK was lost. Resend */
		if (tcph->syn && seq == cur_stream->rcvvar->irs)
			Handle_TCP_ST_LISTEN(mtcp, cur_ts, cur_stream, tcph);
		else {
			Handle_TCP_ST_SYN_RCVD(mtcp, cur_ts, cur_stream, tcph, ack_seq);
			if (payloadlen > 0 && cur_stream->state == TCP_ST_ESTABLISHED) {
				Handle_TCP_ST_ESTABLISHED(mtcp, cur_ts, cur_stream, tcph,
							  seq, ack_seq, payload,
							  payloadlen, window);
			}
		}
		break;

	case TCP_ST_ESTABLISHED:
		Handle_TCP_ST_ESTABLISHED(mtcp, cur_ts, cur_stream, tcph, 
				seq, ack_seq, payload, payloadlen, window);
		break;

	case TCP_ST_CLOSE_WAIT:
		Handle_TCP_ST_CLOSE_WAIT(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payloadlen, window);
		break;

	case TCP_ST_LAST_ACK:
		Handle_TCP_ST_LAST_ACK(mtcp, cur_ts, iph, ip_len, cur_stream, tcph, 
				seq, ack_seq, payloadlen, window);
		break;
	
	case TCP_ST_FIN_WAIT_1:
		Handle_TCP_ST_FIN_WAIT_1(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payload, payloadlen, window);
		break;

	case TCP_ST_FIN_WAIT_2:
		Handle_TCP_ST_FIN_WAIT_2(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq, 
				payload, payloadlen, window);
		break;

	case TCP_ST_CLOSING:
		Handle_TCP_ST_CLOSING(mtcp, cur_ts, cur_stream, tcph, seq, ack_seq,
				payloadlen, window);
		break;

	case TCP_ST_TIME_WAIT:
		/* the only thing that can arrive in this state is a retransmission 
		   of the remote FIN. Acknowledge it, and restart the 2 MSL timeout */
		if (cur_stream->on_timewait_list) {
			RemoveFromTimewaitList(mtcp, cur_stream);
			AddtoTimewaitList(mtcp, cur_stream, cur_ts);
		}
		AddtoControlList(mtcp, cur_stream, cur_ts);
		break;

	case TCP_ST_CLOSED:
		break;

	}

	return TRUE;
}

static inline
int CopyFromSubflowToMpcb(mtcp_manager_t mtcp, tcp_stream *mpcb_stream, tcp_stream *subflow_stream, uint32_t subflow_seq, int payloadlen, uint32_t data_seq){

	struct tcp_recv_vars *subflow_rcvvar = subflow_stream->rcvvar;
	// uint32_t subflow_prev_rcv_wnd;

	// SBUF_LOCK(&subflow_rcvvar->read_lock);

	// subflow_prev_rcv_wnd = subflow_rcvvar->rcv_wnd;

	//copy into mpcb rcvbuf
	struct tcp_recv_vars *mpcb_rcvvar = mpcb_stream->rcvvar;
	// uint32_t mpcb_prev_rcv_nxt;
	int ret;

	/* if seq and segment length is lower than rcv_nxt, ignore and send ack */
	if (TCP_SEQ_LT(data_seq + payloadlen, mpcb_stream->rcv_nxt)) {
		// printf("Data seq is less than rcv_nxt, DATA-SEQ: %u, rcv_nxt: %u\n", data_seq, mpcb_stream->rcv_nxt);
		return FALSE;
	}
	/* if payload exceeds receiving buffer, drop and send ack */
	if (TCP_SEQ_GT(data_seq + payloadlen, mpcb_stream->rcv_nxt + mpcb_rcvvar->rcv_wnd)) {
		// printf("Data seq is greater than rcv_nxt + rcv_wnd, DATA-SEQ: %u, rcv_nxt: %u, rcv_wnd: %u\n", data_seq, mpcb_stream->rcv_nxt, mpcb_rcvvar->rcv_wnd);
		return FALSE;
	}

	/* allocate receive buffer if not exist */
	if (!mpcb_rcvvar->rcvbuf) {
		mpcb_rcvvar->rcvbuf = RBInit(mtcp->mptcp_rbm_rcv, mpcb_rcvvar->irs + 1);
		if (!mpcb_rcvvar->rcvbuf) {
			TRACE_ERROR("Stream %d: Failed to allocate receive buffer.\n", 
					mpcb_stream->id);
			mpcb_stream->state = TCP_ST_CLOSED;
			mpcb_stream->close_reason = TCP_NO_MEM;
			RaiseErrorEvent(mtcp, mpcb_stream);
			// SBUF_UNLOCK(&subflow_rcvvar->read_lock);
			return ERROR;
		}
	}

	if (SBUF_LOCK(&mpcb_rcvvar->read_lock)) {
		if (errno == EDEADLK)
			perror("ProcessTCPPayload: read_lock blocked\n");
		assert(0);
	}

	// mpcb_prev_rcv_nxt = mpcb_stream->rcv_nxt;

	// find the location in the subflow buffer where the current seq packet is strored
	int putx = subflow_seq - subflow_rcvvar->rcvbuf->head_seq;
	// printf("Going to call RBPut in CopyFromSubflow\n");

	// // print content of subflow buf
	// printf("Subflow buffer content before RBPut\n");
	// for(int i = 0; i < payloadlen; i++){
	// 	printf("%c", subflow_rcvvar->rcvbuf->buf[i]);
	// }
	ret = RBPut(mtcp->mptcp_rbm_rcv, 
			mpcb_rcvvar->rcvbuf, subflow_rcvvar->rcvbuf->head + putx, (uint32_t)payloadlen, data_seq);
	if (ret < 0) {
		TRACE_ERROR("Cannot merge payload. reason: %d\n", ret);
	}
	
	// printf("Going to call RBRemove in CopyFromSubflow\n");
	// Haathim_TODO: Remove only if RBPut was successfull
	// Haathim_TODO: Don't send subflow level ACK if Copy was unseccessfull
	// Haathim_TODO: 
	// int len = RBRemove(mtcp->rbm_rcv, subflow_rcvvar->rcvbuf, subflow_rcvvar->rcvbuf->merged_len, AT_APP);
	RBRemove(mtcp->rbm_rcv, subflow_rcvvar->rcvbuf, subflow_rcvvar->rcvbuf->merged_len, AT_APP);

	// printf("length removed from subflow buffer = %d\n", len);
	subflow_rcvvar->rcv_wnd = subflow_rcvvar->rcvbuf->size - subflow_rcvvar->rcvbuf->merged_len;

	mpcb_stream->rcv_nxt = mpcb_rcvvar->rcvbuf->head_seq + mpcb_rcvvar->rcvbuf->merged_len;
	if(subflow_stream->mptcp_cb->isDataFINReceived == 1) {mpcb_stream->rcv_nxt++; }
	mpcb_rcvvar->rcv_wnd = mpcb_rcvvar->rcvbuf->size - mpcb_rcvvar->rcvbuf->merged_len;
	ret  = mpcb_rcvvar->rcvbuf->merged_len;
	SBUF_UNLOCK(&mpcb_rcvvar->read_lock);
	// SBUF_UNLOCK(&subflow_rcvvar->read_lock);

	// if(ret > 0) {RaiseReadEvent(mtcp, subflow_stream); printf("Raised Read Event\n");}
	return 1;
}

// int 
// commence_mpjoin(mctx_t mctx, int sockid, 
// 		const struct sockaddr *addr, socklen_t addrlen, mptcp_cb *mptcp_cb)
// {
// 	mtcp_manager_t mtcp;
// 	socket_map_t socket;
// 	tcp_stream *cur_stream;
// 	struct sockaddr_in *addr_in;
// 	in_addr_t dip;
// 	in_port_t dport;
// 	int is_dyn_bound = FALSE;
// 	int ret, nif;

// 	mtcp = GetMTCPManager(mctx);
// 	if (!mtcp) {
// 		return -1;
// 	}

// 	if (sockid < 0 || sockid >= CONFIG.max_concurrency) {
// 		TRACE_API("Socket id %d out of range.\n", sockid);
// 		errno = EBADF;
// 		return -1;
// 	}

// 	if (mtcp->smap[sockid].socktype == MTCP_SOCK_UNUSED) {
// 		TRACE_API("Invalid socket id: %d\n", sockid);
// 		errno = EBADF;
// 		return -1;
// 	}
	
// 	if (mtcp->smap[sockid].socktype != MTCP_SOCK_STREAM) {
// 		TRACE_API("Not an end socket. id: %d\n", sockid);
// 		errno = ENOTSOCK;
// 		return -1;
// 	}

// 	if (!addr) {
// 		TRACE_API("Socket %d: empty address!\n", sockid);
// 		errno = EFAULT;
// 		return -1;
// 	}
// 	/* we only allow bind() for AF_INET address */
// 	if (addr->sa_family != AF_INET || addrlen < sizeof(struct sockaddr_in)) {
// 		TRACE_API("Socket %d: invalid argument!\n", sockid);
// 		errno = EAFNOSUPPORT;
// 		return -1;
// 	}

// 	socket = &mtcp->smap[sockid];
// 	if (socket->stream) {
// 		TRACE_API("Socket %d: stream already exist!\n", sockid);
// 		if (socket->stream->state >= TCP_ST_ESTABLISHED) {
// 			errno = EISCONN;
// 		} else {
// 			errno = EALREADY;
// 		}
// 		return -1;
// 	}
// 	addr_in = (struct sockaddr_in *)addr;
// 	dip = addr_in->sin_addr.s_addr;
// 	dport = addr_in->sin_port;

// 	/* address binding */
// 	if ((socket->opts & MTCP_ADDR_BIND) && 
// 	    socket->saddr.sin_port != INPORT_ANY &&
// 	    socket->saddr.sin_addr.s_addr != INADDR_ANY) {
		
// 		int rss_core;
// 		uint8_t endian_check = FetchEndianType();
		
// 		rss_core = GetRSSCPUCore(socket->saddr.sin_addr.s_addr, dip, 
// 					 socket->saddr.sin_port, dport, num_queues, endian_check);
		
// 		if (rss_core != mctx->cpu) {
// 			errno = EINVAL;
// 			return -1;
// 		}
// 	} else {
// 		if (mtcp->ap) {
// 			ret = FetchAddressPerCore(mtcp->ap, 
// 						  mctx->cpu, num_queues, addr_in, &socket->saddr);
// 		} else {
// 			uint8_t is_external;
// 			nif = GetOutputInterface(dip, socket->saddr.sin_addr.s_addr, &is_external);
// 			if (nif < 0) {
// 				errno = EINVAL;
// 				return -1;
// 			}
// 			ret = FetchAddress(ap[nif], 
// 					   mctx->cpu, num_queues, addr_in, &socket->saddr);
// 			UNUSED(is_external);
// 		}
// 		if (ret < 0) {
// 			errno = EAGAIN;
// 			return -1;
// 		}
// 		socket->opts |= MTCP_ADDR_BIND;
// 		is_dyn_bound = TRUE;
// 	}
// 	cur_stream = CreateTCPStream(mtcp, socket, socket->socktype, 
// 			socket->saddr.sin_addr.s_addr, socket->saddr.sin_port, dip, dport);
	
// 	if (mptcp_cb)
// 	{
// 		cur_stream->isMPJOINStream = 1;
// 		cur_stream->mptcp_cb = mptcp_cb;
// 	}
	
// 	if (!cur_stream) {
// 		TRACE_ERROR("Socket %d: failed to create tcp_stream!\n", sockid);
// 		errno = ENOMEM;
// 		return -1;
// 	}
// 	if (is_dyn_bound)
// 		cur_stream->is_bound_addr = TRUE;
// 	cur_stream->sndvar->cwnd = 1;
// 	cur_stream->sndvar->ssthresh = cur_stream->sndvar->mss * 10;
// 	cur_stream->state = TCP_ST_SYN_SENT;
// 	TRACE_STATE("Stream %d: TCP_ST_SYN_SENT\n", cur_stream->id);
// 	SQ_LOCK(&mtcp->ctx->connect_lock);
// 	ret = StreamEnqueue(mtcp->connectq, cur_stream);
// 	SQ_UNLOCK(&mtcp->ctx->connect_lock);
// 	mtcp->wakeup_flag = TRUE;
// 	if (ret < 0) {

// 		TRACE_ERROR("Socket %d: failed to enqueue to conenct queue!\n", sockid);
// 		SQ_LOCK(&mtcp->ctx->destroyq_lock);
// 		StreamEnqueue(mtcp->destroyq, cur_stream);
// 		SQ_UNLOCK(&mtcp->ctx->destroyq_lock);
// 		errno = EAGAIN;
// 		return -1;
// 	}
// 	/* if nonblocking socket, return EINPROGRESS */
// 	if (socket->opts & MTCP_NONBLOCK) {

// 		errno = EINPROGRESS;
// 		return -1;

// 	} else {

// 		while (1) {
// 			// This place looping indefintely
// 			if (!cur_stream) {
// 				TRACE_ERROR("STREAM DESTROYED\n");
// 				errno = ETIMEDOUT;
// 				return -1;
// 			}
// 			if (cur_stream->state > TCP_ST_ESTABLISHED) {
// 				TRACE_ERROR("Socket %d: weird state %s\n", 
// 						sockid, TCPStateToString(cur_stream));
// 				// Haathim_TODO: how to handle this?
// 				errno = ENOSYS;
// 				return -1;
// 			}

// 			if (cur_stream->state == TCP_ST_ESTABLISHED) {
// 				// add the mpcb here instead of the above place
// 				if(mptcp_cb) cur_stream->mptcp_cb = mptcp_cb;
// 				break;
// 			}
// 			usleep(1000);
// 		}
// 	}

// 	return 0;
// }

