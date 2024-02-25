#ifndef _UTIL_FUNC_H_
#define _UTIL_FUNC_H_

#include "lib.h"
#include "protocols.h"
#include "queue.h"
#include "trie.h"
#include <string.h>
#include <arpa/inet.h>

/* dupa cum s-a specificat in enunt */
#define MAX_RTABLE_LEN 100000
#define MAX_ARPTABLE_LEN 6
#define IPv4 0x0800
#define ARP 0x0806
#define MAC_LEN 6
#define IP_LEN 4
#define ICMP_PROT 1
#define IP_BIT_LEN 32

#define ICMP_ER_TYPE 0
#define ICMP_TE_TYPE 11
#define ICMP_DU_TYPE 3
#define FORWARD_TYPE 22

void fill_eth_header(struct ether_header *eth_hdr,
					 uint8_t *source_mac,
					 uint8_t *dest_mac,
					 uint16_t eth_type);
void fill_ip_header(struct iphdr *ip_hdr, uint8_t protocol);
void fill_icmp_header(struct icmphdr *icmp_hdr,
					  struct icmphdr *req_icmp_hdr,
					  uint8_t type,
					  uint8_t code);
int count_ones(uint32_t mask);
void bin_string(uint32_t ip_prefix, char *bit_string);
int is_brd_addr(uint8_t* mac_addr);
int same_addr(uint8_t* mac_addr_1, uint8_t* mac_addr_2);
void copy_mac(uint8_t* dest, uint8_t* src);

#endif