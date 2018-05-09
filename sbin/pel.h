#ifndef _PEL_H
#define _PEL_H

#define BUFSIZE 4096    /* maximum message length */

#define PEL_SUCCESS 1
#define PEL_FAILURE 0

#define PEL_SYSTEM_ERROR        -1
#define PEL_CONN_CLOSED         -2
#define PEL_WRONG_CHALLENGE     -3
#define PEL_BAD_MSG_LENGTH      -4
#define PEL_CORRUPTED_DATA      -5
#define PEL_UNDEFINED_ERROR     -6

extern int pel_errno;

int pel_client_init( int server, char *key );
int pel_server_init( int client, char *key );

int pel_send_msg( int sockfd, unsigned char *msg, int  length );
int pel_recv_msg( int sockfd, unsigned char *msg, int *length );

#endif /* pel.h */
