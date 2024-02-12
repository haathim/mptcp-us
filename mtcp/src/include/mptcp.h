#ifndef MPTCP_H
#define MPTCP_H

#include <stdint.h>
#include "tcp_stream.h"

// Constants and macros
// #define MPTCP_PORT 860  // You can choose an appropriate port number
// #define MAX_SUBFLOWS 4  // Maximum number of subflows you want to support

// Multipath TCP option types
// #define MPTCP_OPTION_KIND_ADD_ADDR 0x0A
// #define MPTCP_OPTION_KIND_RM_ADDR 0x09
// #define MPTCP_OPTION_KIND_MP_CAPABLE 0x00
// #define MPTCP_OPTION_KIND_MP_JOIN 0x0E //check if correct value

#define TCP_OPT_MPTCP 30 // You can choose an appropriate value not conflicting with existing TCP options
#define TCP_OPT_MPTCP_LEN 4 // You can choose an appropriate value not conflicting with existing TCP options

#define TCP_MPTCP_SUBTYPE_CAPABLE 0
#define TCP_MPTCP_SUBTYPE_JOIN 1
#define TCP_MPTCP_VERSION 0
#define MPTCP_OPTION_CAPABLE 0
#define MPTCP_OPTION_JOIN 1
#define TCP_MPTCP_SUBTYPE_DSS 2

#define MPTCP_OPT_CAPABLE_SYN_LEN 12
#define MPTCP_OPT_CAPABLE_SYNACK_LEN 12
#define MPTCP_OPT_CAPABLE_ACK_LEN 20
#define MPTCP_OPT_JOIN_SYN_LEN  12
#define MPTCP_OPT_JOIN_SYNACK_LEN 16
#define MPTCP_OPT_JOIN_ACK_LEN 24

// forward declaration (mptcp_tcp_sock has mptcp_cb as a field)
typedef struct mptcp_cb mptcp_cb;

typedef struct mptcp_tcp_sock{
    // these are just some random stuff i dont know why they are used
    uint8_t mptcp_enabled;
    uint8_t mptcp_version;
    uint8_t mptcp_subtype;
    uint8_t mptcp_sender_key;
    uint8_t mptcp_receiver_key;
    uint64_t mptcp_sender_token;
    uint64_t mptcp_receiver_token;
    uint64_t mptcp_data_ack;
    uint64_t mptcp_data_seq;
    uint64_t mptcp_data_fin_seq;
    uint64_t mptcp_data_fin_ack;
    uint64_t mptcp_data_len;
    uint64_t mptcp_data_fin_len;
    uint64_t mptcp_data_fin;

    mptcp_cb *mptcp_cb;

} mptcp_tcp_sock;

struct mptcp_cb{
    // these are just some random stuff i dont know why they are used
    uint32_t my_idsn;
    uint32_t peer_idsn;
    uint64_t peerKey;
    uint64_t myKey;
    uint32_t ack_to_send;
    uint32_t seq_no_to_send;
    struct tcp_stream *mpcb_stream;
    
    // why do I have to put struct in front of tcp_stream (else getting compiler error)
    struct tcp_stream *tcp_streams[10];
    int num_streams;
};

// struct mptcp_connections {
//     uint32_t token[10];
//     struct mptcp_cb* mptcp_cbs[10];
//     int num_connections;
// };

// MPTCP header structure
// struct mptcp_hdr {
//     uint8_t flags;
//     uint8_t subflow_seqnum;
//     uint16_t checksum;
//     // Add more fields as needed
// };

// MPTCP option header structure
struct mptcp_option {
    uint8_t kind;
    uint8_t length;
    // Add more fields as needed
};

// MPTCP subflow information structure
// struct mptcp_subflow {
//     // Subflow-specific data and state
//     // Add more fields as needed
// };

// MPTCP connection structure
// struct mptcp_connection {
//     struct mptcp_subflow subflows[MAX_SUBFLOWS];
//     // Connection-specific data and state
//     // Add more fields as needed
// };

// Function prototypes
// void mptcp_init(struct mptcp_connection *conn);
// int mptcp_add_subflow(struct mptcp_connection *conn, const char *subflow_ip, uint16_t subflow_port);
// int mptcp_send(struct mptcp_connection *conn, const void *data, size_t length);
// int mptcp_receive(struct mptcp_connection *conn, void *buffer, size_t buffer_size);

#endif /* MPTCP_H */