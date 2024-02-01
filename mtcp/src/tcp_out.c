#include <unistd.h>
#include "tcp_out.h"
#include "tcp_util.h"
#include "mtcp.h"
#include "ip_out.h"
#include "tcp_in.h"
#include "tcp_stream.h"
#include "eventpoll.h"
#include "timer.h"
#include "debug.h"
#include "mptcp.h"
#include <endian.h>
#if RATE_LIMIT_ENABLED || PACING_ENABLED
#include "pacing.h"
#endif

#define TCP_CALCULATE_CHECKSUM      TRUE
#define ACK_PIGGYBACK				TRUE
#define TRY_SEND_BEFORE_QUEUE		FALSE

#define TCP_MAX_WINDOW 65535

/*----------------------------------------------------------------------------*/
static inline uint16_t
CalculateOptionLength(uint8_t flags)
{
	uint16_t optlen = 0;

	if (flags & TCP_FLAG_SYN) {
		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;	// insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;



	} else {

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
	}

	assert(optlen % 4 == 0);

	return optlen;
}
/*----------------------------------------------------------------------------*/
static inline uint16_t
CalculateOptionLengthMPTCP(uint8_t flags, uint8_t mptcp_option, uint16_t payloadlen)
{
	// //printf("++++++++++++++++++++++\n");
	uint16_t optlen = 0;

// 	if (flags & TCP_FLAG_SYN) {
// 		optlen += TCP_OPT_MSS_LEN;
// #if TCP_OPT_SACK_ENABLED
// 		optlen += TCP_OPT_SACK_PERMIT_LEN;
// #if !TCP_OPT_TIMESTAMP_ENABLED
// 		optlen += 2;  // insert NOP padding
// #endif /* TCP_OPT_TIMESTAMP_ENABLED */
// #endif /* TCP_OPT_SACK_ENABLED */

// #if TCP_OPT_TIMESTAMP_ENABLED
// 		optlen += TCP_OPT_TIMESTAMP_LEN;
// #if !TCP_OPT_SACK_ENABLED
// 		optlen += 2;  // insert NOP padding
// #endif /* TCP_OPT_SACK_ENABLED */
// #endif /* TCP_OPT_TIMESTAMP_ENABLED */

// 		optlen += TCP_OPT_WSCALE_LEN + 1;

// 		if (mptcp_option & MPTCP_OPTION_CAPABLE) {
// 			// Add the length of the MP_CAPABLE option
// 			optlen += MPTCP_OPT_CAPABLE_SYN_LEN;
// 			// // If its a SYN/ACK
// 			// if (flags & TCP_FLAG_ACK){
// 			// 	optlen += 8;
// 			// }
// 		}

// 		// if (mptcp_option & MPTCP_OPTION_JOIN) {
// 		// 	// Add the length of the MP_JOIN option
// 		// 	optlen += MPTCP_OPT_JOIN_SYN_LEN;
// 		// 	// // If its a SYN/ACK
// 		// 	// if (flags & TCP_FLAG_ACK){
// 		// 	// 	optlen += 4;
// 		// 	// }
// 		// }

// 	} else {

// #if TCP_OPT_TIMESTAMP_ENABLED
// 		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
// #endif

// #if TCP_OPT_SACK_ENABLED
// 		if (flags & TCP_FLAG_SACK) {
// 			optlen += TCP_OPT_SACK_LEN + 2;
// 		}
// #endif
// 		// If its a ACK
// 		if(flags & TCP_FLAG_ACK){
// 			if (mptcp_option & MPTCP_OPTION_CAPABLE) {
// 				// Add the length of the MP_CAPABLE option
// 				optlen += MPTCP_OPT_CAPABLE_ACK_LEN;
// 			}

// 			if (mptcp_option & MPTCP_OPTION_JOIN) {
// 					// Add the length of the MP_JOIN option
// 					optlen += MPTCP_OPT_JOIN_ACK_LEN;
// 			}
// 		}
// 	}


	// ----------------------------------------------------------------

	if(flags == TCP_FLAG_SYN){


		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;  // insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;  // insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

		if(mptcp_option == MPTCP_OPTION_CAPABLE){
			optlen += MPTCP_OPT_CAPABLE_SYN_LEN;
		}
		else if(mptcp_option == MPTCP_OPTION_JOIN){
			optlen += 12;
		}
		else{

		}
	}
	else if(flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)){

		optlen += TCP_OPT_MSS_LEN;
#if TCP_OPT_SACK_ENABLED
		optlen += TCP_OPT_SACK_PERMIT_LEN;
#if !TCP_OPT_TIMESTAMP_ENABLED
		optlen += 2;  // insert NOP padding
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
#endif /* TCP_OPT_SACK_ENABLED */

#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN;
#if !TCP_OPT_SACK_ENABLED
		optlen += 2;  // insert NOP padding
#endif /* TCP_OPT_SACK_ENABLED */
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		optlen += TCP_OPT_WSCALE_LEN + 1;

		optlen += TCP_OPT_WSCALE_LEN + 1;

		if(mptcp_option == MPTCP_OPTION_CAPABLE){
			optlen += MPTCP_OPT_CAPABLE_SYNACK_LEN;
		}
		else if(mptcp_option == MPTCP_OPTION_JOIN){
			optlen += 16;
		}
		else{

		}

	}
	else if (flags == TCP_FLAG_ACK && payloadlen == 0)
	{
		//printf("ACK with no payload\n");
#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif

		if (mptcp_option == MPTCP_OPTION_CAPABLE) {
			optlen += MPTCP_OPT_CAPABLE_ACK_LEN;

			// For the DATA ACK sent along with this
			optlen += 8;
		}
		else if(mptcp_option == MPTCP_OPTION_JOIN){
			optlen += 24;
			printf("ACK MP_JOIN arrived\n");
		}


	}
	else{
		
		//printf("ACK with payload\n");
#if TCP_OPT_TIMESTAMP_ENABLED
		optlen += TCP_OPT_TIMESTAMP_LEN + 2;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_FLAG_SACK) {
			optlen += TCP_OPT_SACK_LEN + 2;
		}
#endif
		if(payloadlen > 0){
			//printf("Payload is present\n");
			optlen += 20;
		}
	}
	


	assert(optlen % 4 == 0);
	// //printf("----------------------------\n");

	return optlen;
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPTimestamp(tcp_stream *cur_stream, uint8_t *tcpopt, uint32_t cur_ts)
{
	uint32_t *ts = (uint32_t *)(tcpopt + 2);

	tcpopt[0] = TCP_OPT_TIMESTAMP;
	tcpopt[1] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(cur_stream->rcvvar->ts_recent);
}
/*----------------------------------------------------------------------------*/
static inline void
GenerateTCPOptions(tcp_stream *cur_stream, uint32_t cur_ts, 
		uint8_t flags, uint8_t *tcpopt, uint16_t optlen, uint8_t isControlMsg, uint8_t mptcp_option, uint16_t payloadlen)
{
	int i = 0;

	if (flags == TCP_FLAG_SYN){

		uint16_t mss;

		
		/* MSS option */
		mss = cur_stream->sndvar->mss;
		tcpopt[i++] = TCP_OPT_MSS;
		tcpopt[i++] = TCP_OPT_MSS_LEN;
		tcpopt[i++] = mss >> 8;
		tcpopt[i++] = mss % 256;

		// MPTCP
		if(mptcp_option == MPTCP_OPTION_CAPABLE){

			/* MPTCP Option Kind */
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length
			tcpopt[i++] = MPTCP_OPT_CAPABLE_SYN_LEN;

			// MPTCP MP_CAPABLE Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_CAPABLE << 4) | TCP_MPTCP_VERSION);
		
			// Add Checksum required & HMAC-SHA1 (A, H set) -> 0x81
			// Later i changed to no Checksum (Because DSS have to do later)
			// TODO: (above)
			tcpopt[i++] = 0x01;

			// Add Sender's Key (64 bit)
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00; 
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x10; 

		}
		else if(mptcp_option == MPTCP_OPTION_JOIN){

			/* MPTCP Option Kind */
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length
			tcpopt[i++] = 12;

			// MPTCP MP_JOIN Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_JOIN << 4) | TCP_MPTCP_VERSION);
		
			//Address ID
			tcpopt[i++] = 0x02;

			// Reciver's Token (32 bits)
			
			uint32_t token = GetToken(cur_stream->mptcp_cb->peerKey);
			
			tcpopt[i++] = token >> 24;
			tcpopt[i++] = token >> 16;
			tcpopt[i++] = token >> 8;
			tcpopt[i++] = token;

			// Sender's Random Number (32 bits)
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x20;

			cur_stream->myRandomNumber = 32;
		}
		else{

		}

		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
		TRACE_SACK("Local SACK permited.\n");
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = cur_stream->sndvar->wscale_mine;
		
	}
	else if(flags == (TCP_FLAG_SYN | TCP_FLAG_ACK) && cur_stream->isReceivedMPCapableSYN){

		// MPTCP
		if(mptcp_option == MPTCP_OPTION_CAPABLE){

			/* MPTCP Option Kind */
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length
			tcpopt[i++] = MPTCP_OPT_CAPABLE_SYNACK_LEN;

			// MPTCP MP_CAPABLE Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_CAPABLE << 4) | TCP_MPTCP_VERSION);
		
			// Add Checksum required & HMAC-SHA1 (A, H set)
			tcpopt[i++] = 0x01;

			// Add Sender's Key (64 bit)
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00; 
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x00;
			tcpopt[i++] = 0x10; 
			
		}
		else if(mptcp_option == MPTCP_OPTION_JOIN){

			/* MPTCP Option Kind */
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length
			tcpopt[i++] = MPTCP_OPT_CAPABLE_SYNACK_LEN;

			// MPTCP MP_JOIN Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_JOIN << 4) | TCP_MPTCP_VERSION);
		
			// ....rest needs to fill in
		}
		else{

		}
		
		/* SACK permit */
#if TCP_OPT_SACK_ENABLED
#if !TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */
		tcpopt[i++] = TCP_OPT_SACK_PERMIT;
		tcpopt[i++] = TCP_OPT_SACK_PERMIT_LEN;
		TRACE_SACK("Local SACK permited.\n");
#endif /* TCP_OPT_SACK_ENABLED */

		/* Timestamp */
#if TCP_OPT_TIMESTAMP_ENABLED
#if !TCP_OPT_SACK_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
#endif /* TCP_OPT_SACK_ENABLED */
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif /* TCP_OPT_TIMESTAMP_ENABLED */

		/* Window scale */
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_WSCALE;
		tcpopt[i++] = TCP_OPT_WSCALE_LEN;
		tcpopt[i++] = cur_stream->sndvar->wscale_mine;
		
	}
	else if(flags == TCP_FLAG_ACK && payloadlen == 0){


		// MPTCP
		if(mptcp_option == MPTCP_OPTION_CAPABLE){

			/* MPTCP Option Kind */
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length
			tcpopt[i++] = MPTCP_OPT_CAPABLE_ACK_LEN;

			// MPTCP MP_CAPABLE Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_CAPABLE << 4) | TCP_MPTCP_VERSION);

			// Add Checksum required & HMAC-SHA1 (A, H set)
			tcpopt[i++] = 0x01;
		
			// Sender's 64 bit Key (changed endianness)
			*((uint64_t*)(tcpopt + (i))) = 0x1000000000000000;

			i += 8;

			// Reciver's 64 bit Key
			// TODO: Have to check first if the key is already set
			*((uint64_t*)(tcpopt + (i))) = htobe64(cur_stream->peerKey);

			i += 8;


			// Add Data ACK option as well
			// Add MPTCP option Kind
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length = 8 (for ACK only)
			tcpopt[i++] = 8;

			// MPTCP DSS Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_DSS << 4) | 0);

			// Flags (Data ACK present)
			tcpopt[i++] = 0x01;

			// Data ACK
			*((uint32_t*)(tcpopt + (i))) = htobe32(cur_stream->mptcp_cb->mpcb_stream->rcv_nxt);

			i += 4;

		}
		else if(mptcp_option == MPTCP_OPTION_JOIN){

			/* MPTCP Option Kind */
			tcpopt[i++] = TCP_OPT_MPTCP;

			// Length
			tcpopt[i++] = 24;

			// MPTCP MP_JOIN Subtype
			tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_JOIN << 4) | TCP_MPTCP_VERSION);
		
			//Address ID
			tcpopt[i++] = 0x00;

			// Sender's HMAC 160 bits
			unsigned char hash[20];
			
			mp_join_hmac_generator(htobe64((uint64_t)(16)), htobe64(cur_stream->mptcp_cb->peerKey), htobe32(cur_stream->myRandomNumber), htobe32(cur_stream->peerRandomNumber), hash);

			// print peerkey, myrandomnumber, peerRandomNumber
			printf("PeerKey: %lu\n", cur_stream->mptcp_cb->peerKey);
			printf("MyRandomNumber: %u\n", cur_stream->myRandomNumber);
			printf("PeerRandomNumber: %u\n", cur_stream->peerRandomNumber);

			//print the hash in hex
			printf("Hash: ");
			for(int j = 0; j < 20; j++){
				printf("%02x", hash[j]);
			}
			printf("\n");

			for(int j = 0; j < 20; j++){
				tcpopt[i++] = hash[j];
			}
		}
		else{
			
		}
		

#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// i += GenerateSACKOption(cur_stream, tcpopt + i);
		}
#endif
		
		
	}
	else{
		
#if TCP_OPT_TIMESTAMP_ENABLED
		tcpopt[i++] = TCP_OPT_NOP;
		tcpopt[i++] = TCP_OPT_NOP;
		GenerateTCPTimestamp(cur_stream, tcpopt + i, cur_ts);
		i += TCP_OPT_TIMESTAMP_LEN;
#endif

#if TCP_OPT_SACK_ENABLED
		if (flags & TCP_OPT_SACK) {
			// i += GenerateSACKOption(cur_stream, tcpopt + i);
		}
#endif
	}



	// Check if no SYN, because no SYN means data right?
	// or just check payload length?
	if(payloadlen > 0){
		
		if (cur_stream->isMPJOINStream)
		{
			printf("Sending from MPJOIN stream with some payload\n");
		}
		// Add DSS option

		// Add MPTCP option Kind
		tcpopt[i++] = TCP_OPT_MPTCP;

		// Length = 18 (if using 4 octets for Data Sequence No) & No Checksum
		tcpopt[i++] = 20;

		// MPTCP DSS Subtype
		tcpopt[i++] = ((TCP_MPTCP_SUBTYPE_DSS << 4) | 0);

		// Flags (Data sequence and ACK present)
		tcpopt[i++] = 0x05;

		// Data ACK
		*((uint32_t*)(tcpopt + (i))) = htobe32(cur_stream->mptcp_cb->mpcb_stream->rcv_nxt);

		i += 4;

		// Data Sequence Number
		*((uint32_t*)(tcpopt + (i))) = htobe32(cur_stream->mptcp_cb->mpcb_stream->snd_nxt);

		cur_stream->mptcp_cb->mpcb_stream->snd_nxt += payloadlen;
		
		i += 4;

		// Subflow Sequence Number
		*((uint32_t*)(tcpopt + (i))) = htobe32(cur_stream->snd_nxt - cur_stream->sndvar->iss);
		// *((uint32_t*)(tcpopt + (i))) = htobe32(1);

		i += 4;

		// Data Level Length
		*((uint16_t*)(tcpopt + (i))) = htobe16(payloadlen);

		i += 2;


		// Put some dummy values for the checksum
		*((uint16_t*)(tcpopt + (i))) = htobe16(0x0000);

		i += 2;


	}
	assert (i == optlen);
}
/*----------------------------------------------------------------------------*/
int
SendTCPPacketStandalone(struct mtcp_manager *mtcp, 
		uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport, 
		uint32_t seq, uint32_t ack_seq, uint16_t window, uint8_t flags, 
		uint8_t *payload, uint16_t payloadlen, 
		uint32_t cur_ts, uint32_t echo_ts)
{
	//printf("SendTCPPacketStandalone is being used...\n");
	struct tcphdr *tcph;
	uint8_t *tcpopt;
	uint32_t *ts;
	uint16_t optlen;
	int rc = -1;

	optlen = CalculateOptionLength(flags);
	if (payloadlen + optlen > TCP_DEFAULT_MSS) {
		TRACE_ERROR("Payload size exceeds MSS.\n");
		assert(0);
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutputStandalone(mtcp, IPPROTO_TCP, 0, 
			saddr, daddr, TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return ERROR;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = sport;
	tcph->dest = dport;

	if (flags & TCP_FLAG_SYN)
		tcph->syn = TRUE;
	if (flags & TCP_FLAG_FIN)
		tcph->fin = TRUE;
	if (flags & TCP_FLAG_RST)
		tcph->rst = TRUE;
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	tcph->seq = htonl(seq);
	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(ack_seq);
	}

	tcph->window = htons(MIN(window, TCP_MAX_WINDOW));

	tcpopt = (uint8_t *)tcph + TCP_HEADER_LEN;
	ts = (uint32_t *)(tcpopt + 4);

	tcpopt[0] = TCP_OPT_NOP;
	tcpopt[1] = TCP_OPT_NOP;
	tcpopt[2] = TCP_OPT_TIMESTAMP;
	tcpopt[3] = TCP_OPT_TIMESTAMP_LEN;
	ts[0] = htonl(cur_ts);
	ts[1] = htonl(echo_ts);

	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}
		
#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	uint8_t is_external;
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, GetOutputInterface(daddr, saddr, &is_external),
					  PKT_TX_TCPIP_CSUM, NULL);
	UNUSED(is_external);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen,
					      saddr, daddr);
#endif

	if (tcph->syn || tcph->fin) {
		payloadlen++;
	}

	return payloadlen;
}
/*----------------------------------------------------------------------------*/
int
SendTCPPacket(struct mtcp_manager *mtcp, tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t flags, uint8_t *payload, uint16_t payloadlen, uint8_t isControlMsg)
{
	struct tcphdr *tcph;
	uint16_t optlen;
	uint8_t wscale = 0;
	uint32_t window32 = 0;
	int rc = -1;

	uint8_t mptcp_option = MPTCP_OPTION_CAPABLE;

	if (cur_stream->isMPJOINStream)
	{
		mptcp_option = MPTCP_OPTION_JOIN;
	}
	

	// first check if sending MP_CAPABLE OR MP_JOIN
	// if(cur_stream->socket->stream != (struct tcp_stream*)(&cur_stream)){
	// 	// this is not the first subflow
	// 	mptcp_option = MPTCP_OPTION_JOIN;
	// }

	// If sending a SYN/ACK have to check if first SYN was with MP_CAPABLE OR NOT
	// Can we use isControlMsg for that also? as in set isControlMsg to 0 if its is a normal SYN/ACK
	if(isControlMsg){
		// //printf("Control message\n");
		optlen = CalculateOptionLengthMPTCP(flags, mptcp_option, payloadlen);
	}else{
		// //printf("Normal packet\n");
		optlen = CalculateOptionLength(flags);
	}
	

	if (payloadlen + optlen > cur_stream->sndvar->mss) {
		TRACE_ERROR("Payload size exceeds MSS\n");
		sleep(5);
		return ERROR;
	}

	tcph = (struct tcphdr *)IPOutput(mtcp, cur_stream, 
			TCP_HEADER_LEN + optlen + payloadlen);
	if (tcph == NULL) {
		return -2;
	}
	memset(tcph, 0, TCP_HEADER_LEN + optlen);

	tcph->source = cur_stream->sport;
	tcph->dest = cur_stream->dport;

	if (flags & TCP_FLAG_SYN) {
		tcph->syn = TRUE;
		if (cur_stream->snd_nxt != cur_stream->sndvar->iss) {
			TRACE_DBG("Stream %d: weird SYN sequence. "
					"snd_nxt: %u, iss: %u\n", cur_stream->id, 
					cur_stream->snd_nxt, cur_stream->sndvar->iss);
		}
#if 0
		TRACE_FIN("Stream %d: Sending SYN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
#endif
	}
	if (flags & TCP_FLAG_RST) {
		TRACE_FIN("Stream %d: Sending RST.\n", cur_stream->id);
		tcph->rst = TRUE;
	}
	if (flags & TCP_FLAG_PSH)
		tcph->psh = TRUE;

	if (flags & TCP_FLAG_WACK) {
		tcph->seq = htonl(cur_stream->snd_nxt - 1);
		TRACE_CLWND("%u Sending ACK to get new window advertisement. "
				"seq: %u, peer_wnd: %u, snd_nxt - snd_una: %u\n", 
				cur_stream->id,
				cur_stream->snd_nxt - 1, cur_stream->sndvar->peer_wnd, 
				cur_stream->snd_nxt - cur_stream->sndvar->snd_una);
	} else if (flags & TCP_FLAG_FIN) {
		tcph->fin = TRUE;
		
		if (cur_stream->sndvar->fss == 0) {
			TRACE_ERROR("Stream %u: not fss set. closed: %u\n", 
					cur_stream->id, cur_stream->closed);
		}
		tcph->seq = htonl(cur_stream->sndvar->fss);
		cur_stream->sndvar->is_fin_sent = TRUE;
		TRACE_FIN("Stream %d: Sending FIN. seq: %u, ack_seq: %u\n", 
				cur_stream->id, cur_stream->snd_nxt, cur_stream->rcv_nxt);
	} else {
		tcph->seq = htonl(cur_stream->snd_nxt);
	}

	if (flags & TCP_FLAG_ACK) {
		tcph->ack = TRUE;
		tcph->ack_seq = htonl(cur_stream->rcv_nxt);
		cur_stream->sndvar->ts_lastack_sent = cur_ts;
		cur_stream->last_active_ts = cur_ts;
		UpdateTimeoutList(mtcp, cur_stream);
	}

	if (flags & TCP_FLAG_SYN) {
		wscale = 0;
	} else {
		wscale = cur_stream->sndvar->wscale_mine;
	}

	//TODO: This is where window value is set, need to set window of mpcb?
	window32 = cur_stream->rcvvar->rcv_wnd >> wscale;
	tcph->window = htons((uint16_t)MIN(window32, TCP_MAX_WINDOW));
	/* if the advertised window is 0, we need to advertise again later */
	if (window32 == 0) {
		cur_stream->need_wnd_adv = TRUE;
	}



	//printf("Sequence number: %u\n", tcph->seq);
	//printf("Optlen: %d\n", optlen);

	GenerateTCPOptions(cur_stream, cur_ts, flags, 
			(uint8_t *)tcph + TCP_HEADER_LEN, optlen, isControlMsg, mptcp_option, payloadlen);
	
	tcph->doff = (TCP_HEADER_LEN + optlen) >> 2;
	// copy payload if exist
	if (payloadlen > 0) {
		memcpy((uint8_t *)tcph + TCP_HEADER_LEN + optlen, payload, payloadlen);
#if defined(NETSTAT) && defined(ENABLELRO)
		mtcp->nstat.tx_gdptbytes += payloadlen;
#endif /* NETSTAT */
	}

#if TCP_CALCULATE_CHECKSUM
#ifndef DISABLE_HWCSUM
	if (mtcp->iom->dev_ioctl != NULL)
		rc = mtcp->iom->dev_ioctl(mtcp->ctx, cur_stream->sndvar->nif_out,
					  PKT_TX_TCPIP_CSUM, NULL);
#endif
	if (rc == -1)
		tcph->check = TCPCalcChecksum((uint16_t *)tcph, 
					      TCP_HEADER_LEN + optlen + payloadlen, 
					      cur_stream->saddr, cur_stream->daddr);
#endif
	
	cur_stream->snd_nxt += payloadlen;

	if (tcph->syn || tcph->fin) {
		cur_stream->snd_nxt++;
		payloadlen++;
	}

	if (payloadlen > 0) {
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Payload after ESTABLISHED: length: %d, snd_nxt: %u\n", 
					payloadlen, cur_stream->snd_nxt);
		}

		/* update retransmission timer if have payload */
		cur_stream->sndvar->ts_rto = cur_ts + cur_stream->sndvar->rto;
		TRACE_RTO("Updating retransmission timer. "
				"cur_ts: %u, rto: %u, ts_rto: %u\n", 
				cur_ts, cur_stream->sndvar->rto, cur_stream->sndvar->ts_rto);
		AddtoRTOList(mtcp, cur_stream);
	}
		
	return payloadlen;
}
/*----------------------------------------------------------------------------*/
static int
FlushTCPSendingBuffer(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
#if 0
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	const uint32_t maxlen = sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK);
	uint8_t *data;
	uint32_t buffered_len;
	uint32_t seq;
	uint16_t len;
	int16_t sndlen;
	uint32_t window;
	int packets = 0;
	uint8_t wack_sent = 0;

	if (!sndvar->sndbuf) {
		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
		assert(0);
		return 0;
	}

	SBUF_LOCK(&sndvar->write_lock);

	if (sndvar->sndbuf->len == 0) {
		packets = 0;
		goto out;
	}

	window = MIN(sndvar->cwnd, sndvar->peer_wnd);

	while (1) {
		seq = cur_stream->snd_nxt;

		if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
					"state: %s, seq: %u, head_seq: %u.\n", 
					cur_stream->id, TCPStateToString(cur_stream), 
					seq, sndvar->sndbuf->head_seq);
			assert(0);
			break;
		}
		buffered_len = sndvar->sndbuf->head_seq + sndvar->sndbuf->len - seq;
		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("head_seq: %u, len: %u, seq: %u, "
					"buffered_len: %u\n", sndvar->sndbuf->head_seq, 
					sndvar->sndbuf->len, seq, buffered_len);
		}
		if (buffered_len == 0)
			break;

		data = sndvar->sndbuf->head + 
				(seq - sndvar->sndbuf->head_seq);

		if (buffered_len > maxlen) {
			len = maxlen;
		} else {
			len = buffered_len;
		}
		
		if (len > window)
			len = window;

		if (len <= 0)
			break;

		if (cur_stream->state > TCP_ST_ESTABLISHED) {
			TRACE_FIN("Flushing after ESTABLISHED: seq: %u, len: %u, "
					"buffered_len: %u\n", seq, len, buffered_len);
		}

		if (seq - sndvar->snd_una + len > window) {
			/* Ask for new window advertisement to peer */
			if (seq - sndvar->snd_una + len > sndvar->peer_wnd) {
#if 0
				TRACE_CLWND("Full peer window. "
						"peer_wnd: %u, (snd_nxt-snd_una): %u\n", 
						sndvar->peer_wnd, seq - sndvar->snd_una);
#endif
				if (!wack_sent && TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500) {
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
				}
				else
					wack_sent = 1;
			}
			packets = -3;
			goto out;
		}
	
		sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_ACK, data, len);
		if (sndlen < 0) {
			packets = sndlen;
			goto out;
		}
		packets++;

		window -= len;
	}

 out:
	SBUF_UNLOCK(&sndvar->write_lock);
	return packets;
#else
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	uint8_t *data;
	uint32_t pkt_len;
	uint32_t len;
	uint32_t seq = 0;
	int remaining_window;
	int sndlen;
	int packets = 0;
	uint8_t wack_sent = 0;
	
	if (!sndvar->sndbuf) {
		TRACE_ERROR("Stream %d: No send buffer available.\n", cur_stream->id);
		assert(0);
		return 0;
	}
	
	SBUF_LOCK(&sndvar->write_lock);

	if (sndvar->sndbuf->len == 0) {
		packets = 0;
		goto out;
	}
	
	while (1) {
#if USE_CCP
		if (sndvar->missing_seq) {
			seq = sndvar->missing_seq;
		} else {
#endif
			seq = cur_stream->snd_nxt;
#if USE_CCP
		}
#endif
		//seq = cur_stream->snd_nxt;
		data = sndvar->sndbuf->head + (seq - sndvar->sndbuf->head_seq);
		len = sndvar->sndbuf->len - (seq - sndvar->sndbuf->head_seq);
#if USE_CCP
		// Without this, mm continually drops packets (not sure why, bursting?) -> mtcp sees lots of losses -> throughput dies
		if(cur_stream->wait_for_acks &&
		   TCP_SEQ_GT(cur_stream->snd_nxt, cur_stream->rcvvar->last_ack_seq)) {
			goto out;
		}
#endif
		/* sanity check */
		if (TCP_SEQ_LT(seq, sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
						"state: %s, seq: %u, head_seq: %u.\n",
						cur_stream->id, TCPStateToString(cur_stream),
						seq, sndvar->sndbuf->head_seq);
			assert(0);
			break;
		}
		if (TCP_SEQ_LT(seq, sndvar->snd_una)) {
			TRACE_ERROR("Stream %d: Invalid sequence to send. "
						"state: %s, seq: %u, snd_una: %u.\n",
						cur_stream->id, TCPStateToString(cur_stream),
						seq, sndvar->snd_una);
			assert(0);
			break;
		}
		if (sndvar->sndbuf->len < (seq - sndvar->sndbuf->head_seq)) {
			TRACE_ERROR("Stream %d: len < 0\n",
						cur_stream->id);
			assert(0);
			break;
		}

		/* if there is no buffered data */
		if (len == 0)
			break;

#if TCP_OPT_SACK_ENABLED
		if (SeqIsSacked(cur_stream, seq)) {
			TRACE_DBG("!! SKIPPING %u\n", seq - sndvar->iss);
			cur_stream->snd_nxt += len;
			continue;
		}
#endif

		remaining_window = MIN(sndvar->cwnd, sndvar->peer_wnd)
			               - (seq - sndvar->snd_una);
		/* if there is no space in the window */
		if (remaining_window <= 0 ||
		    (remaining_window < sndvar->mss && seq - sndvar->snd_una > 0)) {
			/* if peer window is full, send ACK and let its peer advertises new one */
			if (sndvar->peer_wnd <= sndvar->cwnd) {
#if 0
				TRACE_CLWND("Full peer window. "
							"peer_wnd: %u, (snd_nxt-snd_una): %u\n",
							sndvar->peer_wnd, seq - sndvar->snd_una);
#endif
				if (!wack_sent && TS_TO_MSEC(cur_ts - sndvar->ts_lastack_sent) > 500)
					EnqueueACK(mtcp, cur_stream, cur_ts, ACK_OPT_WACK);
				else
					wack_sent = 1;
			}
			packets = -3;
			goto out;
		}
		
		/* payload size limited by remaining window space */
		len = MIN(len, remaining_window);
		/* payload size limited by TCP MSS */
		// pkt_len = MIN(len, sndvar->mss - CalculateOptionLength(TCP_FLAG_ACK));
		pkt_len = MIN(len, sndvar->mss - CalculateOptionLengthMPTCP(TCP_FLAG_ACK, MPTCP_OPTION_CAPABLE, len));

#if RATE_LIMIT_ENABLED
		// update rate
		if (cur_stream->rcvvar->srtt) {
			cur_stream->bucket->rate = 
                (uint32_t)(
                    SECONDS_TO_USECS(                                                      // bits / s = mbps
                        BYTES_TO_BITS(                                                     // bits / us 
                            (double)sndvar->cwnd / UNSHIFT_SRTT(cur_stream->rcvvar->srtt)  // bytes / us
                        )
                    )
                );
		}
		if (cur_stream->bucket->rate != 0 && (SufficientTokens(cur_stream->bucket, pkt_len*8) < 0)) {
			packets = -3;
			goto out;
		}
#endif
    
#if PACING_ENABLED
                if (!CanSendNow(cur_stream->pacer)) {
                    packets = -3;
                    goto out;
                }
#endif
		uint8_t isMPTCP = 0;
		if (cur_stream->mptcp_cb != NULL){
			isMPTCP = 1;
		}
		
		if ((sndlen = SendTCPPacket(mtcp, cur_stream, cur_ts,
					    TCP_FLAG_ACK, data, pkt_len, isMPTCP)) < 0) {
			/* there is no available tx buf */
			packets = -3;
			goto out;
		}
#if USE_CCP
		if (sndvar->missing_seq) {
			sndvar->missing_seq = 0;
		}
#endif
		packets++;
	}

 out:
	SBUF_UNLOCK(&sndvar->write_lock);	
	return packets;	
#endif
}
/*----------------------------------------------------------------------------*/
static inline int 
SendControlPacket(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
	struct tcp_send_vars *sndvar = cur_stream->sndvar;
	int ret = 0;

	if (cur_stream->state == TCP_ST_SYN_SENT) {
		/* Send SYN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_SYN, NULL, 0, 1);

	} else if (cur_stream->state == TCP_ST_SYN_RCVD) {
		/* Send SYN/ACK here */
		cur_stream->snd_nxt = sndvar->iss;
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
				TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0, 1);

	} else if (cur_stream->state == TCP_ST_ESTABLISHED) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0, 1);

	} else if (cur_stream->state == TCP_ST_CLOSE_WAIT) {
		/* Send ACK for the FIN here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0, 1);

	} else if (cur_stream->state == TCP_ST_LAST_ACK) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, 1);
		}
	} else if (cur_stream->state == TCP_ST_FIN_WAIT_1) {
		/* if it is on ack_list, send it after sending ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			/* Send FIN/ACK here */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, 1);
		}

	} else if (cur_stream->state == TCP_ST_FIN_WAIT_2) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0, 1);

	} else if (cur_stream->state == TCP_ST_CLOSING) {
		if (sndvar->is_fin_sent) {
			/* if the sequence is for FIN, send FIN */
			if (cur_stream->snd_nxt == sndvar->fss) {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, 1);
			} else {
				ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
						TCP_FLAG_ACK, NULL, 0, 1);
			}
		} else {
			/* if FIN is not sent, send fin with ack */
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, 
					TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, 1);
		}

	} else if (cur_stream->state == TCP_ST_TIME_WAIT) {
		/* Send ACK here */
		ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_ACK, NULL, 0, 1);

	} else if (cur_stream->state == TCP_ST_CLOSED) {
		/* Send RST here */
		TRACE_DBG("Stream %d: Try sending RST (TCP_ST_CLOSED)\n", 
				cur_stream->id);
		/* first flush the data and ack */
		if (sndvar->on_send_list || sndvar->on_ack_list) {
			ret = -1;
		} else {
			ret = SendTCPPacket(mtcp, cur_stream, cur_ts, TCP_FLAG_RST, NULL, 0, 1);
			if (ret >= 0) {
				DestroyTCPStream(mtcp, cur_stream);
			}
		}
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPControlList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	thresh = MIN(thresh, sender->control_list_cnt);

	/* Send TCP control messages */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->control_list);
	last = TAILQ_LAST(&sender->control_list, control_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside control loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->control_link);

		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;

		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			//TRACE_DBG("Stream %u: Sending control packet\n", cur_stream->id);
			ret = SendControlPacket(mtcp, cur_stream, cur_ts);
			if (ret == -2) {
				TAILQ_INSERT_HEAD(&sender->control_list, 
						cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
				/* since there is no available write buffer, break */
				break;
			} else if (ret < 0) {
				/* try again after handling other streams */
				TAILQ_INSERT_TAIL(&sender->control_list,
						  cur_stream, sndvar->control_link);
				cur_stream->sndvar->on_control_list = TRUE;
				sender->control_list_cnt++;
			}
		} else {
			TRACE_ERROR("Stream %d: not on control list.\n", cur_stream->id);
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPDataList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int cnt = 0;
	int ret;

	/* Send data */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->send_list);
	last = TAILQ_LAST(&sender->send_list, send_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside send loop. cnt: %u, stream: %d\n", 
				cnt, cur_stream->id);
		next = TAILQ_NEXT(cur_stream, sndvar->send_link);

		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		if (cur_stream->sndvar->on_send_list) {
			ret = 0;

			/* Send data here */
			/* Only can send data when ESTABLISHED or CLOSE_WAIT */
			if (cur_stream->state == TCP_ST_ESTABLISHED) {
				if (cur_stream->sndvar->on_control_list) {
					/* delay sending data after until on_control_list becomes off */
					//TRACE_DBG("Stream %u: delay sending data.\n", cur_stream->id);
					ret = -1;
				} else {
					ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
				}
			} else if (cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_LAST_ACK) {
				ret = FlushTCPSendingBuffer(mtcp, cur_stream, cur_ts);
			} else {
				TRACE_DBG("Stream %d: on_send_list at state %s\n", 
						cur_stream->id, TCPStateToString(cur_stream));
#if DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (ret < 0) {
				TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
				/* since there is no available write buffer, break */
				break;

			} else {
				cur_stream->sndvar->on_send_list = FALSE;
				sender->send_list_cnt--;
				/* the ret value is the number of packets sent. */
				/* decrease ack_cnt for the piggybacked acks */
#if ACK_PIGGYBACK
				if (cur_stream->sndvar->ack_cnt > 0) {
					if (cur_stream->sndvar->ack_cnt > ret) {
						cur_stream->sndvar->ack_cnt -= ret;
					} else {
						cur_stream->sndvar->ack_cnt = 0;
					}
				}
#endif
#if 1
				if (cur_stream->control_list_waiting) {
					if (!cur_stream->sndvar->on_ack_list) {
						cur_stream->control_list_waiting = FALSE;
						AddtoControlList(mtcp, cur_stream, cur_ts);
					}
				}
#endif
			}
		} else {
			TRACE_ERROR("Stream %d: not on send list.\n", cur_stream->id);
#ifdef DUMP_STREAM
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last) 
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline int 
WriteTCPACKList(mtcp_manager_t mtcp, 
		struct mtcp_sender *sender, uint32_t cur_ts, int thresh)
{
	tcp_stream *cur_stream;
	tcp_stream *next, *last;
	int to_ack;
	int cnt = 0;
	int ret;

	/* Send aggregated acks */
	cnt = 0;
	cur_stream = TAILQ_FIRST(&sender->ack_list);
	last = TAILQ_LAST(&sender->ack_list, ack_head);
	while (cur_stream) {
		if (++cnt > thresh)
			break;

		TRACE_LOOP("Inside ack loop. cnt: %u\n", cnt);
		next = TAILQ_NEXT(cur_stream, sndvar->ack_link);

		if (cur_stream->sndvar->on_ack_list) {
			/* this list is only to ack the data packets */
			/* if the ack is not data ack, then it will not process here */
			to_ack = FALSE;
			if (cur_stream->state == TCP_ST_ESTABLISHED || 
					cur_stream->state == TCP_ST_CLOSE_WAIT || 
					cur_stream->state == TCP_ST_FIN_WAIT_1 || 
					cur_stream->state == TCP_ST_FIN_WAIT_2 || 
					cur_stream->state == TCP_ST_TIME_WAIT) {
				/* TIMEWAIT is possible since the ack is queued 
				   at FIN_WAIT_2 */
				if (cur_stream->rcvvar->rcvbuf) {
					if (TCP_SEQ_LEQ(cur_stream->rcv_nxt, 
								cur_stream->rcvvar->rcvbuf->head_seq + 
								cur_stream->rcvvar->rcvbuf->merged_len)) {
						to_ack = TRUE;
					}
				}
			} else {
				TRACE_DBG("Stream %u (%s): "
						"Try sending ack at not proper state. "
						"seq: %u, ack_seq: %u, on_control_list: %u\n", 
						cur_stream->id, TCPStateToString(cur_stream), 
						cur_stream->snd_nxt, cur_stream->rcv_nxt, 
						cur_stream->sndvar->on_control_list);
#ifdef DUMP_STREAM
				DumpStream(mtcp, cur_stream);
#endif
			}

			if (to_ack) {
				/* send the queued ack packets */
				while (cur_stream->sndvar->ack_cnt > 0) {
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK, NULL, 0, 1);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						break;
					}
					cur_stream->sndvar->ack_cnt--;
				}

				/* if is_wack is set, send packet to get window advertisement */
				if (cur_stream->sndvar->is_wack) {
					cur_stream->sndvar->is_wack = FALSE;
					ret = SendTCPPacket(mtcp, cur_stream, 
							cur_ts, TCP_FLAG_ACK | TCP_FLAG_WACK, NULL, 0, 1);
					if (ret < 0) {
						/* since there is no available write buffer, break */
						cur_stream->sndvar->is_wack = TRUE;
					}
				}

				if (!(cur_stream->sndvar->ack_cnt || cur_stream->sndvar->is_wack)) {
					cur_stream->sndvar->on_ack_list = FALSE;
					TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
					sender->ack_list_cnt--;
				}
			} else {
				cur_stream->sndvar->on_ack_list = FALSE;
				cur_stream->sndvar->ack_cnt = 0;
				cur_stream->sndvar->is_wack = 0;
				TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
				sender->ack_list_cnt--;
			}

			if (cur_stream->control_list_waiting) {
				if (!cur_stream->sndvar->on_send_list) {
					cur_stream->control_list_waiting = FALSE;
					AddtoControlList(mtcp, cur_stream, cur_ts);
				}
			}
		} else {
			TRACE_ERROR("Stream %d: not on ack list.\n", cur_stream->id);
			TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
			sender->ack_list_cnt--;
#ifdef DUMP_STREAM
			thread_printf(mtcp, mtcp->log_fp, 
					"Stream %u: not on ack list.\n", cur_stream->id);
			DumpStream(mtcp, cur_stream);
#endif
		}

		if (cur_stream == last)
			break;
		cur_stream = next;
	}

	return cnt;
}
/*----------------------------------------------------------------------------*/
inline struct mtcp_sender *
GetSender(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	if (cur_stream->sndvar->nif_out < 0) {
		return mtcp->g_sender;
	}

	int eidx = CONFIG.nif_to_eidx[cur_stream->sndvar->nif_out];
	if (eidx < 0 || eidx >= CONFIG.eths_num) {
		TRACE_ERROR("(NEVER HAPPEN) Failed to find appropriate sender.\n");
		return NULL;
	}

	return mtcp->n_sender[eidx];
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream, uint32_t cur_ts)
{
#if TRY_SEND_BEFORE_QUEUE
	int ret;
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	ret = SendControlPacket(mtcp, cur_stream, cur_ts);
	if (ret < 0) {
#endif
		if (!cur_stream->sndvar->on_control_list) {
			struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
			assert(sender != NULL);

			cur_stream->sndvar->on_control_list = TRUE;
			TAILQ_INSERT_TAIL(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt++;
			//TRACE_DBG("Stream %u: added to control list (cnt: %d)\n", 
			//		cur_stream->id, sender->control_list_cnt);
		}
#if TRY_SEND_BEFORE_QUEUE
	} else {
		if (cur_stream->sndvar->on_control_list) {
			cur_stream->sndvar->on_control_list = FALSE;
			TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
			sender->control_list_cnt--;
		}
	}
#endif
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if(!cur_stream->sndvar->sndbuf) {
		TRACE_ERROR("[%d] Stream %d: No send buffer available.\n", 
				mtcp->ctx->cpu,
				cur_stream->id);
		assert(0);
		return;
	}

	if (!cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->send_list, cur_stream, sndvar->send_link);
		sender->send_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
AddtoACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (!cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = TRUE;
		TAILQ_INSERT_TAIL(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt++;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromControlList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_control_list) {
		cur_stream->sndvar->on_control_list = FALSE;
		TAILQ_REMOVE(&sender->control_list, cur_stream, sndvar->control_link);
		sender->control_list_cnt--;
		//TRACE_DBG("Stream %u: Removed from control list (cnt: %d)\n", 
		//		cur_stream->id, sender->control_list_cnt);
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromSendList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_send_list) {
		cur_stream->sndvar->on_send_list = FALSE;
		TAILQ_REMOVE(&sender->send_list, cur_stream, sndvar->send_link);
		sender->send_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
RemoveFromACKList(mtcp_manager_t mtcp, tcp_stream *cur_stream)
{
	struct mtcp_sender *sender = GetSender(mtcp, cur_stream);
	assert(sender != NULL);

	if (cur_stream->sndvar->on_ack_list) {
		cur_stream->sndvar->on_ack_list = FALSE;
		TAILQ_REMOVE(&sender->ack_list, cur_stream, sndvar->ack_link);
		sender->ack_list_cnt--;
	}
}
/*----------------------------------------------------------------------------*/
inline void 
EnqueueACK(mtcp_manager_t mtcp, 
		tcp_stream *cur_stream, uint32_t cur_ts, uint8_t opt)
{
	if (!(cur_stream->state == TCP_ST_ESTABLISHED || 
			cur_stream->state == TCP_ST_CLOSE_WAIT || 
			cur_stream->state == TCP_ST_FIN_WAIT_1 || 
			cur_stream->state == TCP_ST_FIN_WAIT_2)) {
		TRACE_DBG("Stream %u: Enqueueing ack at state %s\n", 
				cur_stream->id, TCPStateToString(cur_stream));
	}

	if (opt == ACK_OPT_NOW) {
		if (cur_stream->sndvar->ack_cnt < cur_stream->sndvar->ack_cnt + 1) {
			cur_stream->sndvar->ack_cnt++;
		}
	} else if (opt == ACK_OPT_AGGREGATE) {
		if (cur_stream->sndvar->ack_cnt == 0) {
			cur_stream->sndvar->ack_cnt = 1;
		}
	} else if (opt == ACK_OPT_WACK) {
		cur_stream->sndvar->is_wack = TRUE;
	}
	AddtoACKList(mtcp, cur_stream);
}
/*----------------------------------------------------------------------------*/
inline void 
DumpControlList(mtcp_manager_t mtcp, struct mtcp_sender *sender)
{
	tcp_stream *stream;

	TRACE_DBG("Dumping control list (count: %d):\n", sender->control_list_cnt);
	TAILQ_FOREACH(stream, &sender->control_list, sndvar->control_link) {
		TRACE_DBG("Stream id: %u in control list\n", stream->id);
	}
}
