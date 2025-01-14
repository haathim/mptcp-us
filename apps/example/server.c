
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <mtcp_api.h>
#include <mtcp_epoll.h>
#include <stdio.h>
#include <unistd.h>

#define PORT_NUM 12345
#define MAX_CONNECTIONS 3
#define MAX_EVENTS 10000


int main() {
    int ret;
    mctx_t mctx;

    // Initialize mTCP
    ret = mtcp_init("server.conf");
    if (ret) {
        fprintf(stderr, "mtcp_init failed: %s\n", strerror(-ret));
        return -1; 
    }   

    // Create mTCP context
    mctx = mtcp_create_context(0);
    if (!mctx) {
        fprintf(stderr, "mtcp_create_context failed\n");
        return -1; 
    }   

    // Create a socket
    int listen_sock = mtcp_socket(mctx, AF_INET, SOCK_STREAM, 0); 
    if (listen_sock < 0) {
        fprintf(stderr, "mtcp_socket failed: %s\n", strerror(-listen_sock));
        return -1; 
    }   

    // Bind the socket
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT_NUM);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    ret = mtcp_bind(mctx, listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret) {
        fprintf(stderr, "mtcp_bind failed: %s\n", strerror(-ret));
        return -1; 
    }   

    // Listen for incoming connections
    ret = mtcp_listen(mctx, listen_sock, MAX_CONNECTIONS);
    if (ret) {
        fprintf(stderr, "mtcp_listen failed: %s\n", strerror(-ret));
        return -1; 
    }   

    printf("Server listening on port %d...\n", PORT_NUM);
        int ep, i;
        struct mtcp_epoll_event ev, events[MAX_EVENTS];
        ep = mtcp_epoll_create(mctx, MAX_EVENTS);
        ev.events = MTCP_EPOLLIN; ev.data.sockid = listen_sock;
        mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, listen_sock, &ev);

    while (1) {

        // Accept a new client connection
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        //EPOLL stuff
        int nevents = mtcp_epoll_wait(mctx, ep, events, MAX_EVENTS, -1);

        // check if returns error and if so print error message and exit
        if (nevents < 0) {
            fprintf(stderr, "mtcp_epoll_wait failed: %s\n", strerror(-nevents));
            exit(1);
        }
        // print number of events
        // printf("Number of events: %d\n", nevents);
        int acceptedOneConnection = 0;
        for (i = 0; i < nevents; i++) {
                // printf("EVENT: %x\n", events[i].events);
                if (events[i].data.sockid == listen_sock && acceptedOneConnection == 0) {                    
                        acceptedOneConnection = 1;
                        int client_sock = mtcp_accept(mctx, listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
                        ev.events = MTCP_EPOLLIN;
                        ev.data.sockid = client_sock;
                        mtcp_setsock_nonblock(mctx, client_sock);
                        mtcp_epoll_ctl(mctx, ep, MTCP_EPOLL_CTL_ADD, client_sock, &ev);
                        printf("Accepted a new connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                        // sleep(5);
                        if (client_sock < 0) {
                            fprintf(stderr, "mtcp_accept failed: %s\n", strerror(-client_sock));
                            continue;
                            // exit(1);

                        }
                        
                }
                else if (events[i].events & MTCP_EPOLLOUT){
                    // printf("GOT AN EPOLLOUT!\n");
                    char *response = "Hello, client I am server (FROM EPOLLOUT)!\n";
                    mtcp_write(mctx, events[i].data.sockid, response, strlen(response));
                    // delay for 5 seconds
                    // sleep(5);
                } 
                else if (events[i].events & MTCP_EPOLLIN){
                    // printf("GOT AN EPOLLIN! i = %d\n", i);
                    char request[100];
                    mtcp_read(mctx, events[i].data.sockid, request, 100);
                    printf("Request: %s\n", request);
                    // char *response = "Hello, client I am server (FROM EPOLLIN)!\n";
                    char response[100];
                    sprintf(response, "Hello, client I am server (FROM EPOLLIN)! i = %d\n", i);
                    mtcp_write(mctx, events[i].data.sockid, response, strlen(response));
                    // delay for 5 seconds
                    // sleep(5);
                }
                else{
                    // printf("GOT AN UNKNOWN EVENT! %x\n", events[i].events);

                }
                
                
        }
    }

    // Close the listening socket and destroy the mTCP context
    mtcp_close(mctx, listen_sock);
    mtcp_destroy_context(mctx);

    return 0;
}


