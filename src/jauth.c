/*
 * jauth.c
 *
 *  Created on: Apr 30, 2019
 *      Author: jerome
 */
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"
#include "jconfig.h"
#include "debug.h"
#include "jauth.h"


void thread_authsvr(void *args);
authrequest *authGetConnection(authsvr *server, struct timeval *timeout);
int authReadRequest(authsvr * server, authrequest * r);
void authEndRequest(authrequest * r);
void authProcessRequest(authsvr * server, authrequest * r);


authsvr *
authsvrCreate(host, port)
char *host;
int port;
{
	authsvr *new;
    int sock, opt;
    struct sockaddr_in addr;

    /*
     ** Create the handle and setup it's basic config
     */
    new = malloc(sizeof(authsvr));
    if (new == NULL)
        return (NULL);
    bzero(new, sizeof(authsvr));
    new->port = port;
    if (host == HTTP_ANY_ADDR)
        new->host = HTTP_ANY_ADDR;
    else
        new->host = strdup(host);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        free(new);
        return (NULL);
    }

    new->serverSock = sock;
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    if (new->host == HTTP_ANY_ADDR) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        addr.sin_addr.s_addr = inet_addr(new->host);
    }
    addr.sin_port = htons((u_short) new->port);
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        free(new);
        return (NULL);
    }
    listen(sock, 128);
    new->startTime = time(NULL);
    return (new);
}


/*Adapter callback func of mainloop select for hpptd API func of httpdGetConnection*/
int jauthconnect(authsvr *server, int index){
	authrequest *r;
    void **params;
    int result;
    pthread_t tid;

    r = authGetConnection(server, NULL);

    /* We can't convert this to a switch because there might be
     * values that are not -1, 0 or 1. */
	/*Jerome: seems will not happen to be -1*/
    if (server->lastError == -1) {
        /* Interrupted system call */

    } else if (server->lastError < -1) {
        /*
         * FIXME
         * An error occurred - should we abort?
         * reboot the device ?
         */
        debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.");
        termination_handler(0);
    } else if (r != NULL) {
        /*
         * We got a connection
         *
         * We should create another thread
         */
        debug(LOG_INFO, "Received connection from %s, spawning worker thread", r->clientAddr);
        /* The void**'s are a simulation of the normal C
         * function calling sequence. */
        params = safe_malloc(2 * sizeof(void *));
        *params = server;
        *(params + 1) = r;

        result = pthread_create(&tid, NULL, (void *)thread_authsvr, (void *)params);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid);
    } else {
        /* webserver->lastError should be 2 */
        /* XXX We failed an ACL.... No handling because
         * we don't set any... */
    }

    return 0;
}


/** Main request handling thread.
@param args Two item array of void-cast pointers to the httpd and request struct
*/
void
thread_authsvr(void *args)
{
	void	**params;
	authsvr	*webserver;
	authrequest	*r;
	s_config *config = config_get_config();

	params = (void **)args;
	webserver = *params;
	r = *(params + 1);
	free(params); /* XXX We must release this ourselves. */

	if (authReadRequest(webserver, r) == 0) {
		/*
		 * We read the request fine
		 */
		debug(LOG_DEBUG, "Processing request from %s", r->clientAddr);
		authProcessRequest(webserver, r);

	}
	else {
		debug(LOG_DEBUG, "No valid request received from %s", r->clientAddr);
	}
	debug(LOG_DEBUG, "Closing connection with %s", r->clientAddr);
	authEndRequest(r);
}



authrequest *
authGetConnection(server, timeout)
authsvr *server;
struct timeval *timeout;
{
    int result;
    struct sockaddr_in addr;
    socklen_t addrLen;
    char *ipaddr;
    authrequest *r;
    /* Reset error */
    server->lastError = 0;
    result = 0;

    /* Allocate request struct */
    r = (authrequest *) malloc(sizeof(authrequest));
    if (r == NULL) {
        server->lastError = -3;
        return (NULL);
    }
    memset((void *)r, 0, sizeof(authrequest));
    /* Get on with it */
    bzero(&addr, sizeof(addr));
    addrLen = sizeof(addr);
    r->clientSock = accept(server->serverSock, (struct sockaddr *)&addr, &addrLen);
    ipaddr = inet_ntoa(addr.sin_addr);
    if (ipaddr) {
        strncpy(r->clientAddr, ipaddr, HTTP_IP_ADDR_LEN);
        r->clientAddr[HTTP_IP_ADDR_LEN - 1] = 0;
    } else
        *r->clientAddr = 0;
    r->readBufRemain = 0;
    r->readBufPtr = NULL;

    return (r);
}


int
authReadRequest(authsvr * server, authrequest * r)
{

    return (0);
}

void
authEndRequest(authrequest * r)
{
    shutdown(r->clientSock, 2);
    close(r->clientSock);
    free(r);
}


void
authProcessRequest(authsvr * server, authrequest * r)
{


}

