#include <stdio.h>

#ifndef RTSERVER_H
#define RT_SERVER_H

struct rtserver_t;

/** Creates an rtserver_t object and sets up a port to listen for incoming connections
 *
 *  @param hostname	the address on which the server will operate
 *  @param port		the port on which the server will operate
 *
 *  @returns a pointer to the newly created rtserver_t object
 */
struct rtserver_t * rtserver_create(char * hostname, short port);

/** Destroys an rtserver_t object, freeing any memory it might be using
 */
void rtserver_destroy(struct rtserver_t * rtserver);

/** Checks the listening port for incoming connections. If a connection attempt is detected, accepts
 *  the connection and adds it to the list of clients.
 *
 *  @returns -1 if an error occurs, 0 if no clients connect, otherwise the fd of the last client to connect
 */
int rtserver_checklisten(struct rtserver_t * rtserver);

/** Sends the given packet to all the connected clients
 *  
 *  @param rtserver	the rtserver
 *  @param buffer	the packet to be sent
 *  @param len		the size of the packet in bytes
 *  
 *  @returns -1 if an error occurs, otherwise the number of bytes sent to the last client
 */
int rtserver_sendclients(struct rtserver_t * rtserver, char * buffer, size_t len);


#endif
