#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <mtcp_api.h>
#include <mtcp_epoll.h>

#define MAX_EVENTS 10000
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    char *server_ip = argv[2];

    int ret;
    mctx_t mctx;

    // Initialize mTCP
    ret = mtcp_init("client.conf");
    if (ret) {
        fprintf(stderr, "mtcp_init failed: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    // Create mTCP context
    mctx = mtcp_create_context(0);
    if (!mctx) {
        fprintf(stderr, "mtcp_create_context failed\n");
        exit(EXIT_FAILURE);
    }

    // Create a socket
    int sockfd = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "mtcp_socket failed: %s\n", strerror(-sockfd));
        exit(EXIT_FAILURE);
    }

    // ret = mtcp_setsock_nonblock(mctx, sockfd);
    // if (ret < 0)
    // {
    //     printf("mtcp_setsock_nonblock failed\n");
    // }
    
    // Connect to the server
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address or address not supported\n");
        exit(EXIT_FAILURE);
    }

    ret = mtcp_connect(mctx, sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr), 0);
    if (ret) {
        fprintf(stderr, "mtcp_connect failed: %s\n", strerror(-ret));
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", server_ip, port);

    // Create epoll and add sockfd to the epoll set
    struct mtcp_epoll_event ev, events[MAX_EVENTS];
    int ep = mtcp_epoll_create(mctx, MAX_EVENTS);
    ev.events = MTCP_EPOLLIN;
    ev.data.sockid = sockfd;
    mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, sockfd, &ev);

    // Main loop
    while (1) {
        int nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);

        if (nevents < 0) {
            fprintf(stderr, "mtcp_epoll_wait failed: %s\n", strerror(-nevents));
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nevents; i++) {
            if (events[i].events & MTCP_EPOLLIN) {
                char buffer[BUFFER_SIZE];
                int bytes_received = mtcp_read(mctx, sockfd, buffer, BUFFER_SIZE);
                if (bytes_received > 0) {
                    printf("Received from server: %.*s\n", bytes_received, buffer);
                } else if (bytes_received == 0) {
                    printf("Server closed the connection\n");
                    exit(EXIT_SUCCESS);
                } else {
                    fprintf(stderr, "mtcp_read failed: %s\n", strerror(-bytes_received));
                    exit(EXIT_FAILURE);
                }
            }
        }
    }

    // Close the socket and destroy the mTCP context
    mtcp_close(mctx, sockfd);
    mtcp_destroy_context(mctx);

    return 0;
}
