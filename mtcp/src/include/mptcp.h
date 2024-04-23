#ifndef MPTCP_H
#define MPTCP_H

#include <stdint.h>
#include "tcp_stream.h"


#define TCP_OPT_MPTCP 30 // You can choose an appropriate value not conflicting with existing TCP options

#define TCP_MPTCP_VERSION 0
#define TCP_MPTCP_SUBTYPE_CAPABLE 0
#define TCP_MPTCP_SUBTYPE_JOIN 1
#define TCP_MPTCP_SUBTYPE_DSS 2

#define MPTCP_OPT_CAPABLE_SYN_LEN 12
#define MPTCP_OPT_CAPABLE_SYNACK_LEN 12
#define MPTCP_OPT_CAPABLE_ACK_LEN 20
#define MPTCP_OPT_JOIN_SYNACK_LEN 16

typedef struct mptcp_cb mptcp_cb;

struct mptcp_cb{

    uint32_t my_idsn;
    uint32_t peer_idsn;
    uint64_t peerKey;
    uint64_t myKey;
    uint32_t ack_to_send;
    uint32_t seq_no_to_send;
    struct tcp_stream *mpcb_stream;
    uint8_t isSentMPJoinSYN; /*This should ideally be an array for each of the additional tcp_streams, here only for 2nd tcp_stream*/
    uint8_t isDataFINReceived; //Haathim_TODO: initialize this to 0
    struct tcp_stream *tcp_streams[10];
    int num_streams;
};

#endif /* MPTCP_H */