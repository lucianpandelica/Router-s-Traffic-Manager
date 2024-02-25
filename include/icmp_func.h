#ifndef _ICMP_FUNC_H_
#define _ICMP_FUNC_H_

#include "util_func.h"
#include "routing_func.h"

void prepare_icmp(char *icmp_msg,
				  char *buf,
				  int ind_next_hop,
				  int ind_mac_addr,
				  uint32_t sender_ip_no,
				  uint8_t type);
int send_icmp_err(int ind_mac_addr,
				  int ind_next_hop,
				  uint32_t sender_ip_no,
				  char *buf,
				  uint8_t type);
int send_icmp_reply(int ind_mac_addr,
					int ind_next_hop,
					uint32_t sender_ip_no,
					char *buf);
int handle_icmp_send(uint32_t sender_ip_no, char* buf, size_t len, uint8_t type);
int is_icmp_req(char *buf);

#endif