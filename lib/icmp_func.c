#include "icmp_func.h"

/* for IPv4 protocol */
void prepare_icmp(char *icmp_msg,
				  char *buf,
				  int ind_next_hop,
				  int ind_mac_addr,
				  uint32_t sender_ip_no,
				  uint8_t type) {

	struct ether_header *eth_hdr_tem = (struct ether_header *) icmp_msg;

	uint8_t *interface_mac = malloc(sizeof(uint8_t) * MAC_LEN);
	DIE(interface_mac == NULL, "malloc");

	get_interface_mac(route_table[ind_next_hop].interface, interface_mac);
	
	fill_eth_header(eth_hdr_tem,
					interface_mac,
					arp_table[ind_mac_addr].mac,
					IPv4);
	
	struct iphdr *ip_hdr_tem = (struct iphdr *) (icmp_msg +
												 sizeof(struct ether_header));
	fill_ip_header(ip_hdr_tem, ICMP_PROT);

	uint32_t interface_ip_no;
	inet_pton(AF_INET,
			  get_interface_ip(route_table[ind_next_hop].interface),
			  &interface_ip_no);

	ip_hdr_tem->saddr = interface_ip_no;
	ip_hdr_tem->daddr = sender_ip_no;

	struct icmphdr *icmp_hdr_tem = (struct icmphdr *) (icmp_msg + 
													   sizeof(struct ether_header) + 
													   sizeof(struct iphdr));
	
	if(type == ICMP_ER_TYPE) {
		struct icmphdr *req_icmp_hdr = (struct icmphdr *) (buf +
	 												   	   sizeof(struct ether_header) + 
	 												   	   sizeof(struct iphdr));
		
		fill_icmp_header(icmp_hdr_tem, req_icmp_hdr, type, 0);

	} else {

		fill_icmp_header(icmp_hdr_tem, NULL, type, 0);
	}
	
	free(interface_mac);
}

int send_icmp_err(int ind_mac_addr,
				  int ind_next_hop,
				  uint32_t sender_ip_no,
				  char *buf,
				  uint8_t type) {

	/* sender_ip_no in network order */

	char icmp_err[MAX_PACKET_LEN];

	prepare_icmp(icmp_err, buf, ind_next_hop, ind_mac_addr, sender_ip_no, type);

	/* copiem IP header-ul mesajului initial,
	 * impreuna cu urmatorii 64 de biti */
	char *payload_src = (char *) (buf +
								  sizeof(struct ether_header));

	char *payload_dst = (char *) (icmp_err +
								  sizeof(struct ether_header) + 
								  sizeof(struct iphdr) +
								  sizeof(struct icmphdr));

	memcpy(payload_dst, payload_src, sizeof(struct iphdr) + 8);

	/* calculam checksum IP */
	struct iphdr *ip_hdr_err = (struct iphdr *) (icmp_err +
												 sizeof(struct ether_header));

	ip_hdr_err->tot_len = htons(sizeof(struct iphdr) +
								sizeof(struct icmphdr) +
								sizeof(struct iphdr) +
								8);

	uint16_t len_aux = ntohs(ip_hdr_err->tot_len);
	uint16_t comp_checksum = checksum((uint16_t*) ip_hdr_err, sizeof(struct iphdr));

	ip_hdr_err->check = htons(comp_checksum);
	
	/* calculam checksum ICMP */
	struct icmphdr *icmp_hdr_tem = (struct icmphdr *) (icmp_err + 
													   sizeof(struct ether_header) + 
													   sizeof(struct iphdr));

	icmp_hdr_tem->checksum = htons(0);

	uint16_t checksum_hdr;
	checksum_hdr = checksum((uint16_t*) icmp_hdr_tem, sizeof(struct icmphdr) +
													  sizeof(struct iphdr) +
													  sizeof(struct icmphdr));

	icmp_hdr_tem->checksum = htons(checksum_hdr);

	/* trimitem mesajul */
	len_aux = len_aux + sizeof(struct ether_header);
	send_to_link(route_table[ind_next_hop].interface, (char *) icmp_err, len_aux);

	return 0;
}

int send_icmp_reply(int ind_mac_addr,
					int ind_next_hop,
					uint32_t sender_ip_no,
					char *buf) {

	/* sender_ip_no in network order */

	char icmp_reply[MAX_PACKET_LEN];

	prepare_icmp(icmp_reply,
				 buf,
				 ind_next_hop,
				 ind_mac_addr,
				 sender_ip_no,
				 ICMP_ER_TYPE);

	/* completam campurile din IP header
	 * care nu au fost specificate inca */
	struct iphdr *ip_hdr_reply = (struct iphdr *)
								 (icmp_reply +
								  sizeof(struct ether_header));
	struct iphdr *ip_hdr_req = (struct iphdr *)
							   (buf +
							    sizeof(struct ether_header));

	ip_hdr_reply->tot_len = ip_hdr_req->tot_len;

	uint16_t comp_checksum = checksum((uint16_t*) ip_hdr_reply,
									  sizeof(struct iphdr));
	ip_hdr_reply->check = htons(comp_checksum);

	/* copiem payload-ul ICMP request-ului corespunzator */
	uint16_t payload_len = ntohs(ip_hdr_reply->tot_len) -
						   sizeof(struct iphdr) - 
						   sizeof(struct icmphdr);
	
	char *payload_src = (char *) (buf +
								  sizeof(struct ether_header) +
								  sizeof(struct iphdr) +
								  sizeof(struct icmphdr));

	char *payload_dst = (char *) (icmp_reply +
								  sizeof(struct ether_header) + 
								  sizeof(struct iphdr) +
								  sizeof(struct icmphdr));
	
	memcpy(payload_dst, payload_src, payload_len);

	/* calculam checksum-ul pentru ICMP reply */
	struct icmphdr *icmp_reply_hdr = (struct icmphdr *) 
									 (icmp_reply +
	 								  sizeof(struct ether_header) + 
	 								  sizeof(struct iphdr));

	uint16_t tot_len_icmp = sizeof(struct icmphdr) + payload_len;
	uint16_t comp_checksum_icmp = checksum((uint16_t*) icmp_reply_hdr,
										   tot_len_icmp);
	icmp_reply_hdr->checksum = htons(comp_checksum_icmp);

	/* trimitem mesajul */
	uint16_t len_aux = ntohs(ip_hdr_reply->tot_len) +
					   sizeof(struct ether_header);
	send_to_link(route_table[ind_next_hop].interface,
				 (char *) icmp_reply,
				 len_aux);

	return 0;	
}

int handle_icmp_send(uint32_t sender_ip_no, char* buf, size_t len, uint8_t type) {

	/* index urmatorul hop */
	int ind_next_hop = find_next_hop_t(rtable_trie, sender_ip_no);
	if(ind_next_hop == -1) {
		return -1;
	}

	/* MAC urmatorul hop */
	int ind_mac_addr = get_mac(route_table[ind_next_hop].next_hop,
							   arp_table,
							   arp_table_len);
	if(ind_mac_addr == -1) {

		store_packet(ind_next_hop, sender_ip_no, buf, type, len);
		send_arp_req(ind_next_hop);
		return -2;

	} else {

		if(type == ICMP_ER_TYPE) {
			send_icmp_reply(ind_mac_addr,
							ind_next_hop,
							sender_ip_no,
							buf);
		} else {
			send_icmp_err(ind_mac_addr,
					  	  ind_next_hop,
					  	  sender_ip_no,
					  	  buf,
					  	  type);
		}
	}

	return 0;
}

int is_icmp_req(char *buf) {

	struct icmphdr *icmp_hdr = (struct icmphdr *) (buf + 
	 											   sizeof(struct ether_header) + 
	 											   sizeof(struct iphdr));
	
	if(icmp_hdr->type != ((uint8_t) 8)) {
		perror("ICMP message isn't an echo request. Thrown away.\n");
		return 0;
	}

	return 1;
}