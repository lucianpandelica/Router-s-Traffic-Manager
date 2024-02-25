#include "arp_func.h"

int send_arp_req(int ind_next_hop) {

	int i;
	
	/* contruim ARP request-ul */
	char arp_req[MAX_PACKET_LEN];
	memset(arp_req, 0, MAX_PACKET_LEN);

	/* header-ul ethernet, cu adresa de broadcast ca destinatie */
	struct ether_header *eth_hdr = (struct ether_header *) arp_req;

	uint8_t *interface_mac = malloc(sizeof(uint8_t) * MAC_LEN);
	DIE(interface_mac == NULL, "malloc");

	get_interface_mac(route_table[ind_next_hop].interface, interface_mac);

	uint8_t *broadcast_mac = malloc(sizeof(uint8_t) * MAC_LEN);
	DIE(broadcast_mac == NULL, "malloc");

	for(i = 0; i < MAC_LEN; i++) {
		broadcast_mac[i] = 255;
	}
	
	fill_eth_header(eth_hdr, interface_mac, broadcast_mac, ARP);

	/* header ARP */
	struct arp_header *arp_hdr = (struct arp_header *) (arp_req +
														sizeof(struct ether_header));
	
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(IPv4);
	arp_hdr->hlen = MAC_LEN;
	arp_hdr->plen = IP_LEN;
	/* ARP request */
	arp_hdr->op = htons(1);
	copy_mac(arp_hdr->sha, interface_mac);

	uint32_t interface_ip_no;
	inet_pton(AF_INET,
			  get_interface_ip(route_table[ind_next_hop].interface),
			  &interface_ip_no);

	/* setam adresa IP sursa */
	arp_hdr->spa = interface_ip_no;

	uint8_t *target_mac = malloc(sizeof(uint8_t) * MAC_LEN);
	DIE(target_mac == NULL, "malloc");

	for(i = 0; i < MAC_LEN; i++) {
		target_mac[i] = 0;
	}
	
	/* setam adresa MAC destinatie pe 0 */
	copy_mac(arp_hdr->tha, target_mac);

	/* setam adresa IP destinatie cea a urmatorului hop,
	 * pentru care realizam ARP request-ul */
	arp_hdr->tpa = route_table[ind_next_hop].next_hop;

	/* trimitem mesajul */
	int len_arp_req = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(route_table[ind_next_hop].interface, arp_req, len_arp_req);

	free(interface_mac);
	free(broadcast_mac);
	free(target_mac);

	return 0;
}

int send_arp_reply(char *buf, int interface) {

	/* contruim ARP reply pe baza unui ARP request
	 * retinut in bufferul 'buf' */

	/* actualizam ethernet header-ul */
	struct ether_header *eth_hdr = (struct ether_header *) buf;

	uint8_t *interface_mac = malloc(sizeof(uint8_t) * MAC_LEN);
	DIE(interface_mac == NULL, "malloc");

	get_interface_mac(interface, interface_mac);

	uint8_t *dest_mac = malloc(sizeof(char) * MAC_LEN);
	DIE(dest_mac == NULL, "malloc");

	copy_mac(dest_mac, eth_hdr->ether_shost);

	fill_eth_header(eth_hdr, interface_mac, dest_mac, ARP);

	/* actualizam ARP header-ul, unde completam adresa
	 * MAC a interfetei pe care am primit ARP request-ul */
	struct arp_header *arp_hdr = (struct arp_header *) 
								 (buf +
								  sizeof(struct ether_header));
	
	/* ARP reply */
	arp_hdr->op = htons(2);

	uint8_t *mac_aux = malloc(sizeof(char) * MAC_LEN);
	DIE(mac_aux == NULL, "malloc");

	copy_mac(mac_aux, arp_hdr->sha);
	copy_mac(arp_hdr->sha, interface_mac);

	uint32_t ip_aux;
	ip_aux = arp_hdr->spa;
	arp_hdr->spa = arp_hdr->tpa;
	arp_hdr->tpa = ip_aux;

	copy_mac(arp_hdr->tha, mac_aux);

	/* trimitem mesajul */
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);
	send_to_link(interface, buf, len);

	free(interface_mac);
	free(dest_mac);
	free(mac_aux);

	return 0;
}

int handle_arp_recv(char *buf, int interface) {

	struct arp_header *arp_hdr = (struct arp_header *) 
								 (buf +
								  sizeof(struct ether_header));
	
	uint32_t interface_ip_no;
	inet_pton(AF_INET, get_interface_ip(interface), &interface_ip_no);
	
	/* verificam ca este un mesaj ARP destinat noua */
	if(interface_ip_no == arp_hdr->tpa) {

		if(arp_hdr->op == htons(2)) {

			/* este un ARP reply */

			/* adaugam o noua intrare in tabela ARP */
			add_arp_entry(arp_hdr->spa, arp_hdr->sha);
			/* trimitem pachetele care asteptau acest reply */
			send_queued_packets(arp_hdr->spa);
		} else {

			/* este un ARP request */
			send_arp_reply(buf, interface); 
		}

		return 0;
	}

	return -1;
}