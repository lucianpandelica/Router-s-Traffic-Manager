#ifndef _ROUTING_FUNC_H_
#define _ROUTING_FUNC_H_

#include "icmp_func.h"
#include "arp_func.h"
#include "util_func.h"

/* datele pe care le retinem cand
 * suspendam trimiterea unui pachet */
typedef struct Packet {
	int index_next_hop;
	uint32_t sender_ip; // ICMP
	char *buffer;
	uint8_t op_type;
	size_t buf_len; // forward
} Packet;

queue packet_queue;
int packet_q_len;

struct route_table_entry *route_table;
int rtable_len;

struct arp_entry *arp_table;
int arp_table_len;
int arp_table_cap;

Trie *rtable_trie;

void store_packet(int ind_next_hop,
				  uint32_t s_ip,
				  char *buf,
				  uint8_t type,
				  size_t len);
int forward_packet(int ind_mac_addr,
				   int ind_next_hop,
				   char *buf,
				   int len);
void send_packet(Packet *pack);
void send_queued_packets(uint32_t ip_next_hop);
int get_mac(uint32_t ip_addr, struct arp_entry *arp_table, int arp_table_len);
void add_arp_entry(uint32_t ip_addr, uint8_t *mac_addr);
int find_next_hop_t(Trie *rtable_trie, uint32_t ip_addr);
void build_trie(Trie *rtable_trie,
				struct route_table_entry *route_table,
				int rtable_len);

#endif