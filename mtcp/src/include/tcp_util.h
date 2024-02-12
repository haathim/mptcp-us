#ifndef TCP_UTIL_H
#define TCP_UTIL_H

#include "mtcp.h"
#include "tcp_stream.h"

#define MSS 1448
#define INIT_CWND_PKTS 10

#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))

#define SECONDS_TO_USECS(seconds) ((seconds) / 1000000.0)
#define USECS_TO_MS(us) ((us) / 1000)
#define BYTES_TO_BITS(bytes) ((bytes) / 8.0)
#define BPS_TO_MBPS(bps) ((bps) / 8000000.0)
#define UNSHIFT_RTT(srtt) ((srtt) * 125.0)

struct tcp_timestamp
{
	uint32_t ts_val;
	uint32_t ts_ref;
};

void ParseTCPOptions(tcp_stream *cur_stream,
		        uint32_t cur_ts, uint8_t *tcpopt, int len);

uint8_t 
ParseMPTCPOptions(tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *tcpopt, int len);

extern inline int
ParseTCPTimestamp(tcp_stream *cur_stream,
		        struct tcp_timestamp *ts, uint8_t *tcpopt, int len);

#if TCP_OPT_SACK_ENABLED
int
SeqIsSacked(tcp_stream *cur_stream, uint32_t seq);

void
ParseSACKOption(tcp_stream *cur_stream,
		        uint32_t ack_seq, uint8_t *tcpopt, int len);
#endif

uint16_t
TCPCalcChecksum(uint16_t *buf, uint16_t len, uint32_t saddr, uint32_t daddr);

void
PrintTCPOptions(uint8_t *tcpopt, int len);

uint64_t 
GetPeerKey(tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *tcpopt, int len);

uint64_t 
GetMyKeyFromMPCapbleACK(tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *tcpopt, int len);

uint32_t 
GetTokenFromMPJoinSYN(tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *tcpopt, int len);

uint32_t 
GetPeerRandomNumberFromMPJoinSYN(tcp_stream *cur_stream, 
		uint32_t cur_ts, uint8_t *tcpopt, int len);

uint32_t
GetToken(uint64_t key);

uint32_t
GetPeerIdsnFromKey(uint64_t key);

uint32_t
GetDataAck(tcp_stream *cur_stream, uint8_t *tcpopt, int len);

uint32_t
GetDataSeq(tcp_stream *cur_stream, uint8_t *tcpopt, int len);

void hmac_sha1(const unsigned char *key, int key_len, const unsigned char *message, int message_len, unsigned char *digest);

void mp_join_hmac_generator(uint64_t key1, uint64_t key2, uint32_t num1, uint32_t num2, unsigned char* hash);

uint64_t checkMP_JOIN_SYN_ACK(tcp_stream *cur_stream, uint32_t cur_ts, uint8_t *tcpopt, int len);

#endif /* TCP_UTIL_H */	
