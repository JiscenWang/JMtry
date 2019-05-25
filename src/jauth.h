/*
 * jauth.h
 *
 *  Created on: Apr 30, 2019
 *      Author: jerome
 */

#ifndef SRC_JAUTH_H_
#define SRC_JAUTH_H_

#include "httpd.h"

    typedef struct {
        int port, serverSock, startTime, lastError;
        char fileBasePath[HTTP_MAX_URL], *host;
        FILE *accessLog, *errorLog;
        void (*errorFunction304) (), (*errorFunction403) (), (*errorFunction404) ();
    } authsvr;

    typedef struct {
        int clientSock, readBufRemain;
        char readBuf[HTTP_READ_BUF_LEN + 1], *readBufPtr, clientAddr[HTTP_IP_ADDR_LEN];
    } authrequest;

    authsvr* authsvrCreate(char *host, int port);
    int jauthconnect(authsvr *server, int index);


#endif /* SRC_JAUTH_H_ */
