#include "util_func.h"

void fill_eth_header(struct ether_header *eth_hdr,
					 uint8_t *source_mac,
					 uint8_t *dest_mac,
					 uint16_t eth_type) {

	memset(eth_hdr, 0, sizeof(struct ether_header));

	copy_mac(eth_hdr->ether_shost, source_mac);
	copy_mac(eth_hdr->ether_dhost, dest_mac);
	eth_hdr->ether_type = htons(eth_type);
}

void fill_ip_header(struct iphdr *ip_hdr, uint8_t protocol) {

	memset(ip_hdr, 0, sizeof(struct iphdr));

	ip_hdr->ihl = 5;
	ip_hdr->version = 4;
	ip_hdr->tos = ((uint8_t) 0);
	ip_hdr->id = htons(((uint16_t) 1));
	ip_hdr->frag_off = htons(((uint16_t) 0));
	ip_hdr->ttl = ((uint8_t) 255);
	ip_hdr->protocol = protocol;
	ip_hdr->check = ((uint16_t) 0);
}

void fill_icmp_header(struct icmphdr *icmp_hdr,
					  struct icmphdr *req_icmp_hdr,
					  uint8_t type,
					  uint8_t code) {

	memset(icmp_hdr, 0, sizeof(struct icmphdr));

	icmp_hdr->type = type;
	icmp_hdr->code = code;

	if(req_icmp_hdr != NULL) {

		/* type = ICMP_ER_TYPE */
		icmp_hdr->un.echo.id = req_icmp_hdr->un.echo.id;
		icmp_hdr->un.echo.sequence = req_icmp_hdr->un.echo.sequence;
	}
}

int count_ones(uint32_t mask) {

	int ct = 0;
	uint32_t i;

	for(i = 1 << 31; i > 0; i = i / 2)
		if(mask & i)
			ct++;
	
	return ct;
}

void bin_string(uint32_t ip_prefix, char *bit_string) {

	memset(bit_string, 0, 32);

	int ct = 0;
	uint32_t i;
	for(i = 1 << 31; i > 0; i = i / 2) {
		if(ip_prefix & i)
			bit_string[ct] = '1';
		else
			bit_string[ct] = '0';

		ct++;
	}
}

int is_brd_addr(uint8_t* mac_addr) {
	
	int i;
	int is_brd = 1;

	for(i = 0; i < MAC_LEN; i++) {
		if(mac_addr[i] != 0xff) {
			is_brd = 0;
		}
	}

	return is_brd;
}

int same_addr(uint8_t* mac_addr_1, uint8_t* mac_addr_2) {

	int i;
	int is_eq = 1;

	for(i = 0; i < MAC_LEN; i++) {
		if(mac_addr_1[i] != mac_addr_2[i]) {
			is_eq = 0;
		}
	}

	return is_eq;
}

void copy_mac(uint8_t* dest, uint8_t* src) {

	int i;

	for(i = 0; i < MAC_LEN; i++) {
		dest[i] = src[i];
	}
}