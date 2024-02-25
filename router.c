#include "include/routing_func.h"
#include "string.h"

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	route_table = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_LEN);
	DIE(route_table == NULL, "malloc");

	rtable_len = read_rtable(argv[1], route_table);
	DIE(rtable_len <= 0, "read_rtable"); 

	/* tabela ARP este vida */
	arp_table_cap = 0;
	arp_table_len = 0;

	/* initializam si construim tria aferenta tabelei de rutare */
	init_trie(&rtable_trie);
	build_trie(rtable_trie, route_table, rtable_len);

	/* initializam coada de pachete */
	packet_queue = queue_create();
	DIE(packet_queue == NULL, "queue_create");
	packet_q_len = 0;

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		uint8_t* interf_mac;
		interf_mac = malloc(sizeof(uint8_t) * MAC_LEN);
		DIE(interf_mac == NULL, "malloc");

		/* extragem adresa MAC a interfetei pe care am primit mesajul */
		get_interface_mac(interface, interf_mac);

		/* verificam daca pachetul ne este destinat,
		 * daca adresa sa MAC destinatie este cea a interfetei / broadcast */
		if(same_addr(eth_hdr->ether_dhost, interf_mac) || 
			is_brd_addr(eth_hdr->ether_dhost)) {
			
			uint16_t ether_t = ntohs(eth_hdr->ether_type);

			/* impartim firul de executie in functie
			 * de valoarea campului ether_type */
			if(ether_t == IPv4) {
				
				/* pachet IPv4 */
				struct iphdr *ip_hdr = (struct iphdr *)
									   (buf +
										sizeof(struct ether_header));

				/* verificam integritatea pachetului */
				uint16_t spec_checksum = ntohs(ip_hdr->check);
				uint16_t len_ip_pack = ntohs(ip_hdr->tot_len);
				ip_hdr->check = 0;
				uint16_t comp_checksum = checksum((uint16_t*) ip_hdr,
												  len_ip_pack);

				if(spec_checksum == comp_checksum) {
					
					/* checksum-ul este corect */
					
					/* reconstituim pachetul */
					ip_hdr->check = htons(spec_checksum);

					uint8_t spec_ttl = ip_hdr->ttl;

					/* verificam campul Time To Live */
					if(spec_ttl > 1) { 
						
						/* pachetul mai are durata de viata */

						/* verificam destinatia pachetului */
						uint32_t dest_ip_no = ip_hdr->daddr;
						uint32_t interf_ip_no;
						inet_pton(AF_INET,
								  get_interface_ip(interface),
								  &interf_ip_no);

						if(dest_ip_no == interf_ip_no) {

							/* pachet destinat routerului */
							
							/* verificam daca mesajul este de tip ICMP */
							if(ip_hdr->protocol == ICMP_PROT) {
								
								/* daca este un ICMP request,
								 * trimitem ICMP reply inapoi */
								if(is_icmp_req(buf)){
									handle_icmp_send(ip_hdr->saddr,
													 buf,
													 len,
													 ICMP_ER_TYPE);
								}

								/* altfel, aruncam pachetul */
							}

						} else {

							/* pachet ce tranziteaza router-ul */

							/* cautam indicele din tabela de rutare corespunzator
							 * urmatorului hop catre destinatia pachetului */
							int ind_next_hop;
							ind_next_hop = find_next_hop_t(rtable_trie,
														   ip_hdr->daddr);

							if(ind_next_hop == -1) {

								/* daca nu am gasit un urmator hop, trimitem
								 * un mesaj ICMP tip "Destination unreachable"
								 * la expeditor */
								perror("Destination unreachable.\n");
								handle_icmp_send(ip_hdr->saddr, 
											     buf,
												 len,
												 ICMP_DU_TYPE);

							} else {

								/* am gasit un urmator hop,
								 * trimitem pachetul mai departe */
								
								/* cautam indicele din tabela ARP corespondent
								 * adresei IP a urmatorului hop */
								int ind_mac_addr = get_mac(route_table[ind_next_hop].next_hop,
														   arp_table,
														   arp_table_len);

								if(ind_mac_addr == -1) {
									
									/* daca nu exista, stocam pachetul 
									 * intr-o coada si trimitem un ARP request */
									store_packet(ind_next_hop,
												 0,
												 buf,
												 FORWARD_TYPE,
												 len);
									send_arp_req(ind_next_hop);

								} else {

									/* altfel, trimitem pachetul */
									forward_packet(ind_mac_addr,
												   ind_next_hop,
												   buf,
												   len);
								}
							}
						}
					} else {
						
						/* trimitem mesaj ICMP la emitator de tip
						 * "Time Limit Exceeded" */
						perror("Time limit exceeded.\n");
						handle_icmp_send(ip_hdr->saddr, buf, len, ICMP_TE_TYPE);
					}
				} else {
					perror("Bad checksum.\n");
				}
			} else if(ether_t == ARP) {

				/* am primit un pachet ARP */
				handle_arp_recv(buf, interface);
			} else {

				/* ether_type diferit de IPv4 / ARP */
				perror("Unidentified ether type. Thrown away.\n");
			}
		} else {

			/* pachetul nu ne este destinat, il aruncam */
		}

		free(interf_mac);	
	}

	free_trie(&rtable_trie);
	free(arp_table);
	free(packet_queue);
}
