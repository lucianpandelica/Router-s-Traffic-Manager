#include "routing_func.h"

void store_packet(int ind_next_hop,
				  uint32_t s_ip,
				  char *buf,
				  uint8_t type,
				  size_t len) {

	Packet *new_pack = (Packet *) malloc(sizeof(Packet));
	DIE(new_pack == NULL, "malloc");
	
	new_pack->buffer = malloc(sizeof(char) * MAX_PACKET_LEN);
	DIE(new_pack->buffer == NULL, "malloc");

	new_pack->index_next_hop = ind_next_hop;
	new_pack->sender_ip = s_ip;
	new_pack->op_type = type;
	new_pack->buf_len = len;

	/* copiem continutul bufferului primit */
	memcpy(new_pack->buffer, buf, len);

	/* adaugam la coada */
	queue_enq(packet_queue, new_pack);
	/* actualizam lungimea cozii */
	packet_q_len++;
}

int forward_packet(int ind_mac_addr,
				   int ind_next_hop,
				   char *buf,
				   int len) {
	
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *) (buf +
											 sizeof(struct ether_header));
	uint16_t len_ip_pack = ntohs(ip_hdr->tot_len);

	uint8_t* interf_mac;
	interf_mac = malloc(sizeof(uint8_t) * MAC_LEN);
	DIE(interf_mac == NULL, "malloc");

	/* actualizam TTL */
	ip_hdr->ttl = ip_hdr->ttl - 1;

	/* actualizam checksum */
	ip_hdr->check = 0;

	uint16_t new_checksum;
	new_checksum = checksum((uint16_t*) ip_hdr, len_ip_pack);

	ip_hdr->check = htons(new_checksum);

	/* actualizam adresele MAC sursa si destinatie din ether header */
	get_interface_mac(route_table[ind_next_hop].interface, interf_mac);

	copy_mac(eth_hdr->ether_shost, interf_mac);
	copy_mac(eth_hdr->ether_dhost, arp_table[ind_mac_addr].mac);

	/* trimitem pachetul la urmatorul hop */
	send_to_link(route_table[ind_next_hop].interface, buf, len);

	free(interf_mac);

	return 0;
}

void send_packet(Packet *pack) {

	/* trimitem un pachet care astepta in coada sosirea unui
	 * ARP reply cu adresa MAC corespunzatoare urmatorului hop */

	int ind_mac_addr;
	ind_mac_addr = get_mac(route_table[pack->index_next_hop].next_hop,
						   arp_table,
						   arp_table_len);

	/* nu mai este necesara verificarea valorii lui 'ind_mac_addr' */

	/* identificam tipul de operatie necesara */
	if(pack->op_type == FORWARD_TYPE) {
		forward_packet(ind_mac_addr,
					   pack->index_next_hop,
					   pack->buffer,
					   pack->buf_len);
	} else {
		handle_icmp_send(pack->sender_ip,
						 pack->buffer,
						 pack->buf_len,
						 pack->op_type);
	}
}

void send_queued_packets(uint32_t ip_next_hop) {

	int ct = 0;
	Packet *crt_pack;

	/* parcurgem pachetele care asteapta in coada */
	while(!queue_empty(packet_queue) && (ct < packet_q_len)) {
		
		/* crestem contorul de pachete verificate */
		ct++;
		/* scoatem din coada un pachet */
		crt_pack = queue_deq(packet_queue);

		/* verificam daca ultimul ARP reply primit
		 * deblocheaza trimiterea acestui pachet */
		if(route_table[crt_pack->index_next_hop].next_hop ==
			ip_next_hop) {
				
				/* in caz afirmativ, il trimitem */
				send_packet(crt_pack);

				/* eliberam resursele alocate retinerii pachetului */
				free(crt_pack->buffer);
				free(crt_pack);

				/* actualizam numarul de elemente din coada */
				packet_q_len--;

				/* resetam contorul de elemente verificate */
				ct = 0;

			} else {

				/* altfel, reintroducem pachetul in coada */
				queue_enq(packet_queue, crt_pack);
			}
		
		/* daca am verificat un numar de pachete egal cu numarul de
		 * elemente din coada fara sa trimitem niciunul, incheiem parcurgerea */
	}
}

int get_mac(uint32_t ip_addr, struct arp_entry *arp_table, int arp_table_len) {

	int i;
	int index = -1;

	for(i = 0; i < arp_table_len; i++) {
		if(ip_addr == arp_table[i].ip) {
			index = i;
		}
	}

	return index;
}

void add_arp_entry(uint32_t ip_addr, uint8_t *mac_addr) {

	/* adaugam o noua intrare in tabela dinamica ARP */

	/* daca tabela are capacitate nula */
	if(arp_table_cap == 0) {

		/* alocam spatiu pentru un element */
		arp_table = (struct arp_entry *) malloc(sizeof(struct arp_entry));
		DIE(arp_table == NULL, "malloc");

		/* actualizam capacitatea */
		arp_table_cap = 1;
	}

	/* daca tabela este plina */
	if(arp_table_len == arp_table_cap) {

		/* realocam pentru a mari capacitatea */
		arp_table_cap = (2 * arp_table_cap);
		arp_table = realloc(arp_table, sizeof(struct arp_entry) * arp_table_cap);
		DIE(arp_table == NULL, "realloc");
	}

	/* introducem noua pereche (IP, MAC) in tabela */
	arp_table[arp_table_len].ip = ip_addr;
	copy_mac(arp_table[arp_table_len].mac, mac_addr);

	/* actualizam numarul curent de elemente */
	arp_table_len++;
}

int find_next_hop_t(Trie *rtable_trie, uint32_t ip_addr) {

	/* ip_addr in network order */

	int ct = 0;
	int index = -1, bit;
	Trie *aux_trie = rtable_trie;

	char *bit_string = (char *) malloc(sizeof(char) * IP_BIT_LEN);
	DIE(bit_string == NULL, "malloc");

	bin_string(ntohl(ip_addr), bit_string);

	while(ct < 32) {
		
		bit = index_char(bit_string[ct]);

		if(aux_trie->child[bit] != NULL) {

			aux_trie = aux_trie->child[bit];

			if(aux_trie->index != -1) {
				index = aux_trie->index;
			}

			ct++;

		} else {
			break;
		}
	}

	free(bit_string);

	return index;
}

void build_trie(Trie *rtable_trie,
				struct route_table_entry *route_table,
				int rtable_len) {

	int i;
	int len_mask;
	char *bit_string;

	bit_string = (char *) malloc(sizeof(char) * IP_BIT_LEN);
	DIE(bit_string == NULL, "malloc");

	for(i = 0; i < rtable_len; i++) {
		
		len_mask = count_ones(ntohl(route_table[i].mask));
		bin_string(ntohl(route_table[i].prefix), bit_string);
		insert(rtable_trie, bit_string, len_mask, i);
	}

	free(bit_string);
}