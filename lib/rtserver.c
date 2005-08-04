#include "rtserver.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>


/** Structure containing all the information necessary to run an rtserver */
struct rtserver_t {
	/** fd describing the listening socket */
	int connect_fd;
	/** set of client fds */
	fd_set rt_fds;
	/** the highest numbered fd */
	int max_rtfds;
	/** sockaddr used to accept incoming connections */
	struct sockaddr_in * remote;
};

struct rtserver_t * rtserver_create (char * hostname, short port) {
	struct rtserver_t * rtserver = malloc(sizeof(struct rtserver_t));
	struct hostent *he;
	int yes = 1;
	
        FD_ZERO(&rtserver->rt_fds);

	if (hostname) {
        	if ((he=gethostbyname(hostname)) == NULL) {
		        perror("gethostbyname");
        	        return 0;
		}
	}
	
        if ((rtserver->connect_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket");
                return 0;
        }
        if (setsockopt(rtserver->connect_fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
                perror("setsockopt");
                return 0;
        }
	rtserver->remote = calloc(1,sizeof(struct sockaddr_in));
        // Need to set up a listening server here
        bzero((char *) rtserver->remote, sizeof(rtserver->remote));
	rtserver->remote->sin_family = AF_INET;
	if (hostname)
		rtserver->remote->sin_addr = *((struct in_addr *)he->h_addr);
	else 
		rtserver->remote->sin_addr.s_addr = INADDR_ANY;
        rtserver->remote->sin_port = htons(port);

	if (bind(rtserver->connect_fd, (struct sockaddr *) rtserver->remote, sizeof(struct sockaddr_in)) < 0) {
        	perror("bind");
		return 0;
	}

        if (listen(rtserver->connect_fd, 10) == -1) {
        	perror("listen");
                return 0;
	}
	
        rtserver->max_rtfds = rtserver->connect_fd;

	return rtserver;
}

void rtserver_destroy (struct rtserver_t * rtserver) {
	int i;
	close(rtserver->connect_fd);

	for (i=1; i <= rtserver->max_rtfds; i++) {
		if (FD_ISSET(i, &rtserver->rt_fds)) {
			close(i);
		}
	}
	
	free(rtserver->remote);
	free(rtserver);
}

int rtserver_checklisten (struct rtserver_t * rtserver) {
	struct timeval tv;
	int rt_fd = 0;
	fd_set current;
	int i;
	int sin_size = sizeof(struct sockaddr_in);
	
        tv.tv_sec = 0;
        tv.tv_usec = 10;
	
	FD_ZERO(&current);
	FD_SET(rtserver->connect_fd, &current);
	
        do {
	        if (select(rtserver->max_rtfds + 1, &current, NULL, NULL,&tv) >=0 ) {
	                break;
        	}
        }
        while (errno == EINTR);
        for (i = 0; i <= rtserver->max_rtfds; i++) {
	        if (FD_ISSET(i, &current)) {
	                // Got something on the listening socket
                        if (i == rtserver->connect_fd) {
        	                if ((rt_fd = accept(i, (struct sockaddr *) rtserver->remote,
								&sin_size)) == -1) {
	                                perror("accept");
					return -1;
                                } else {
                                        printf("Client connected\n");
                                        FD_SET(rt_fd, &rtserver->rt_fds);
                                        if (rt_fd > rtserver->max_rtfds)
	                                        rtserver->max_rtfds = rt_fd;
                                }
                        }
                }
	}
	return rt_fd;
}

int rtserver_sendclients (struct rtserver_t * rtserver, char * buffer, size_t len) {
	fd_set current;
	int i;
	int numbytes = 0;
	struct timeval tv;
	
	tv.tv_sec = 0;
	tv.tv_usec = 10;
	current = rtserver->rt_fds;

	if (select(rtserver->max_rtfds + 1, NULL, &current, NULL, &tv) == -1 ) {
	        perror("select");
                return -1;
                
       	}

        // Send the data to each ready client
        for (i = 0; i <= rtserver->max_rtfds; i++) {
        	if (FD_ISSET(i, &current)) {
	                
                        // do write
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

                        if ((numbytes = send(i, buffer, len, MSG_NOSIGNAL)) == -1) {
                		perror("send");
				FD_CLR(i, &rtserver->rt_fds);
				close(i);
				numbytes = 0;                                
                        }
		}
	}
	return numbytes;
}
