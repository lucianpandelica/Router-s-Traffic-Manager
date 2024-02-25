#ifndef _ARP_FUNC_H_
#define _ARP_FUNC_H_

#include "util_func.h"
#include "routing_func.h"

int send_arp_req(int ind_next_hop);
int send_arp_reply(char *buf, int interface);
int handle_arp_recv(char *buf, int interface);

#endif