/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#include <stdlib.h>
#include <string.h>
#include "sr_nat.h"

#define DEBUG

#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ICMP_ECHO_REP_TYPE 0
#define ICMP_ECHO_REP_CODE 0

#define ICMP_ECHO_REQ_TYPE 8

#define ICMP_PORT_UNREACHABLE_TYPE 3
#define ICMP_PORT_UNREACHABLE_CODE 3

#define ICMP_DST_NET_UNREACHABLE_TYPE 3
#define ICMP_DST_NET_UNREACHABLE_CODE 0

#define ICMP_DST_HOST_UNREACHABLE_TYPE 3
#define ICMP_DST_HOST_UNREACHABLE_CODE 1

#define DEFAULT_IP_TTL 64
#define NOTHING 0
#define REPLY 1
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


void send_arp_request(struct sr_instance* sr,
											struct sr_if* output_interface,
											uint32_t ip_dst)
{

	uint8_t* pkt_req = calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
	
	/* Update Ethernet frame */
	sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)pkt_req;
	uint8_t i;
	for(i = 0; i < ETHER_ADDR_LEN; i++) {
		ethernet_hdr->ether_dhost[i] = 0xFF;
	}
	memcpy(ethernet_hdr->ether_shost, output_interface->addr, ETHER_ADDR_LEN);
	ethernet_hdr->ether_type = htons(ethertype_arp);

	/* Update ARP frame */
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(pkt_req + sizeof(sr_ethernet_hdr_t));
	arp_hdr->ar_hrd = htons(1);
	arp_hdr->ar_pro = htons(2048);
	arp_hdr->ar_hln = ETHER_ADDR_LEN;
	arp_hdr->ar_pln = 4;
	arp_hdr->ar_op = htons(ARP_OP_REQUEST);
	memcpy(arp_hdr->ar_sha, output_interface->addr, ETHER_ADDR_LEN);
	arp_hdr->ar_sip = output_interface->ip;
	arp_hdr->ar_tip = htonl(ip_dst);
	
	sr_send_packet(sr, pkt_req, 
								 sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), 
								 output_interface->name);

}

/** If this ARP request packet is valid
	* 	it will update ARP reply packet to packet buffer
*/
int handle_arp_request(struct sr_instance* sr, 
                        uint8_t* packet, 
                        unsigned int len, 
                        struct sr_if* interface_ins) {

  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get IP addr of this router at interface */
  uint32_t router_interface_ip_addr = ntohl(interface_ins->ip);

  /* Check target IP addr of ARP request */
  uint32_t target_ip_addr = ntohl(arp_hdr->ar_tip);

  /* Check router interface IP address with target IP address of ARP packet */
  if(router_interface_ip_addr != target_ip_addr) {
    return NOTHING;
  }

  /* Reply MAC addr of this router interface to client */
  /* Update data in ARP request packet to ARP reply packet */
  arp_hdr->ar_op = htons(ARP_OP_REPLY);

  arp_hdr->ar_tip = arp_hdr->ar_sip;
  memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);

  arp_hdr->ar_sip = htonl(router_interface_ip_addr);
  memcpy(arp_hdr->ar_sha, interface_ins->addr, ETHER_ADDR_LEN);
 	
  return REPLY;
}

void handle_arp_reply(struct sr_instance* sr, 
                      uint8_t* packet, 
                      unsigned int len, 
                      struct sr_if* interface_ins) {
	sr_arp_hdr_t* recv_arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

	struct sr_arpreq* arp_req = sr_arpcache_insert(&(sr->cache), 
																								 recv_arp_hdr->ar_sha, 
																								 recv_arp_hdr->ar_sip);
	if(arp_req != NULL) {
		/* Forward request */
		struct sr_packet* forward_packets = arp_req->packets;
		struct sr_packet* forward_packet = forward_packets;
		while(forward_packet != NULL) {
			sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)(forward_packet->buf);
			memcpy(ethernet_hdr->ether_shost, interface_ins->addr, ETHER_ADDR_LEN);
			memcpy(ethernet_hdr->ether_dhost, recv_arp_hdr->ar_sha, ETHER_ADDR_LEN);


			/* Update TTL */ 
			sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(forward_packet->buf + sizeof(sr_ethernet_hdr_t));
			ip_hdr->ip_ttl --;
			/* Update checksum */
			ip_hdr->ip_sum = 0;
			ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr, sizeof(sr_ip_hdr_t));

			sr_send_packet(sr, forward_packet->buf, forward_packet->len, forward_packet->iface);

			forward_packet = forward_packet->next;
		}
	}
	
}


void handle_arp_packet(struct sr_instance* sr, 
                        uint8_t* packet, 
                        unsigned int len, 
                        struct sr_if* interface_ins) {

  /* Check ARP packet is valid or not */
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    return;
  }

  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  /* Check ARP packet is request or reply */
  if(ntohs(arp_hdr->ar_op) == ARP_OP_REQUEST) {
    if(handle_arp_request(sr, packet, len, interface_ins) == REPLY) {

    	/* Update header of ethernet */
    	sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t *)packet;
    	memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    	memcpy(ethernet_hdr->ether_shost, interface_ins->addr, ETHER_ADDR_LEN);

    	sr_send_packet(sr, packet, len, (const char*)(interface_ins->name));
    }
  }else if(ntohs(arp_hdr->ar_op) == ARP_OP_REPLY) {
    handle_arp_reply(sr, packet, len, interface_ins);
  }
}



struct sr_if* longest_prefix(struct sr_instance* sr, uint32_t ip_dst) {
	struct sr_rt* routing_table = sr->routing_table;
	if(routing_table == NULL) {
		return NULL;
	}

	struct sr_rt* longest_prefix_routing_entry = NULL;
	struct sr_rt* rt_walker = routing_table;
	uint32_t max = 0;

  while(rt_walker != NULL)
  {
  	uint32_t ip_gw = ntohl(rt_walker->gw.s_addr);
  	uint32_t mask = ntohl(rt_walker->mask.s_addr);
  	uint32_t sub = ip_gw & mask;
  	uint32_t temp = ~(ip_dst ^ sub);

  	if(temp >= mask && temp > max) {
  		max = temp;
  		longest_prefix_routing_entry = rt_walker;
  	}

    rt_walker = rt_walker->next; 
  }
  if(longest_prefix_routing_entry == NULL) {
  	return NULL;
  }
  return sr_get_interface(sr, longest_prefix_routing_entry->interface);
}

uint8_t is_packet_for_router(uint32_t dest_ip, struct sr_if* output_interface) {
	if(dest_ip == ntohl(output_interface->ip)) {
		return 1;
	}
	return 0;
}

struct sr_if* find_router_interface(struct sr_instance* sr, uint32_t dest_ip) {

  struct sr_if* if_walker = sr->if_list;
  while(if_walker != NULL) {
  	if(ntohl(if_walker->ip) == dest_ip) {
  		return if_walker;
  	}
  	if_walker = if_walker->next;
  }
  return NULL;
}

/** `payload` is data of ICMP packet 
	* `len` is size of ICMP packet
	*/
sr_icmp_hdr_t* create_icmp_packet(uint8_t type, uint8_t code, uint8_t* payload, uint16_t len) {
	sr_icmp_hdr_t* icmp = (sr_icmp_hdr_t*)malloc(len);
	icmp->icmp_type = type;
	icmp->icmp_code = code;
	if(payload != NULL) {
		memcpy((uint8_t*)icmp + sizeof(sr_icmp_hdr_t), payload, len - sizeof(sr_icmp_hdr_t));	
	}
	icmp->icmp_sum = 0;
	icmp->icmp_sum = cksum(icmp, len);
	return icmp;
}

/** `len` is length of ip packet */
sr_icmp_hdr_t* handle_ip_packet_for_router(uint8_t* ip_pkt, uint16_t len) {
	
	/* Check this packet is ICMP packet or not */
	uint8_t ip_proto = ip_protocol(ip_pkt);
	if (ip_proto == ip_protocol_icmp) { /* ICMP */
		if(len < sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
			return NULL;
		}	
  }

  uint16_t ip_payload_len = len - sizeof(sr_ip_hdr_t);
  /* Check this packet is ICMP echo request or not */
  sr_icmp_hdr_t* icmp_recv = (sr_icmp_hdr_t*)(ip_pkt + sizeof(sr_ip_hdr_t));

  sr_icmp_hdr_t* icmp_reply = NULL;

  if(icmp_recv->icmp_type == ICMP_ECHO_REQ_TYPE) {
  	icmp_reply = 
  				create_icmp_packet(ICMP_ECHO_REP_TYPE, ICMP_ECHO_REP_CODE, 
  										 			 ip_pkt + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t),
  										 			 ip_payload_len);
  }else {
  	icmp_reply = 
  				create_icmp_packet(ICMP_PORT_UNREACHABLE_TYPE, ICMP_PORT_UNREACHABLE_CODE, 
  										 			 ip_pkt + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t),
  										 			 ip_payload_len);
  }
  return icmp_reply;
}

sr_ip_hdr_t* create_ip_hdr(uint8_t ttl, uint8_t ip_p, uint32_t ip_src, uint32_t ip_dst, uint16_t payload_len) {
	sr_ip_hdr_t* ip_hdr = calloc(1, sizeof(sr_ip_hdr_t));

	ip_hdr->ip_v = 4;
	ip_hdr->ip_hl = 5; /* IP header has 20 bytes */

	ip_hdr->ip_id = 0;
	ip_hdr->ip_off = htons(0 | IP_DF);

	ip_hdr->ip_ttl = ttl;
	ip_hdr->ip_p = ip_p;
	
	ip_hdr->ip_src = htonl(ip_src); 
	ip_hdr->ip_dst = htonl(ip_dst);

	
	ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + payload_len);
	ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

	return ip_hdr;
}

sr_ethernet_hdr_t* create_ethernet_hdr(uint8_t* ether_shost, 
																			 uint8_t* ether_dhost,
																			 uint16_t ether_type) 
{
	sr_ethernet_hdr_t* ethernet_hdr = calloc(1, sizeof(sr_ethernet_hdr_t));
	memcpy(ethernet_hdr->ether_dhost, ether_dhost, ETHER_ADDR_LEN);
	memcpy(ethernet_hdr->ether_shost, ether_shost, ETHER_ADDR_LEN);
	ethernet_hdr->ether_type = htons(ether_type);

	return ethernet_hdr;
}


void handle_packet_for_router(struct sr_instance* sr, 
													 		struct sr_if* output_interface, 
													 		uint8_t* recv_packet, uint32_t len) 
{
	/* Ethernet header and IP header of packet receive */
	sr_ethernet_hdr_t* ethernet_hdr_recv = (sr_ethernet_hdr_t *)recv_packet;
	sr_ip_hdr_t* ip_hdr_recv = (sr_ip_hdr_t*)(recv_packet + sizeof(sr_ethernet_hdr_t));

	/* Create ICMP reply packet */
	sr_icmp_hdr_t* icmp_reply = 
  				handle_ip_packet_for_router((uint8_t*)ip_hdr_recv, 
  																		(uint16_t)(len - sizeof(sr_ethernet_hdr_t)));

	if(icmp_reply != NULL) {
		/* Create IP header */
		sr_ip_hdr_t* ip_hdr_reply = 
					create_ip_hdr(DEFAULT_IP_TTL, ip_protocol_icmp,
												ntohl(ip_hdr_recv->ip_dst), ntohl(ip_hdr_recv->ip_src),
												len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

		/* Create Ethernet header */
		sr_ethernet_hdr_t* ethernet_hdr_reply = 
					create_ethernet_hdr(output_interface->addr, 
															ethernet_hdr_recv->ether_shost, 
															ethertype_ip);


		/* Merge ethernet hdr, ip hdr and icmp msg */
		uint8_t* reply_pkt = calloc(1, len);
		
		memcpy(reply_pkt, ethernet_hdr_reply, sizeof(sr_ethernet_hdr_t));
		memcpy(reply_pkt + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
		memcpy(reply_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 
					 icmp_reply, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

		free(ethernet_hdr_reply);
		free(ip_hdr_reply);
		free(icmp_reply);

		sr_send_packet(sr, reply_pkt, len, output_interface->name);
		free(reply_pkt);
	}
}

void send_packet_net_unreachable(struct sr_instance* sr, 
																	 struct sr_if* output_interface, 
																	 uint8_t* recv_packet) {
	/* Define header recv */
	sr_ethernet_hdr_t* ethernet_hdr_recv = (sr_ethernet_hdr_t *)recv_packet;
	sr_ip_hdr_t* ip_hdr_recv = (sr_ip_hdr_t*)(recv_packet + sizeof(sr_ethernet_hdr_t));

	/* Create ICMP packet */
	sr_icmp_t3_hdr_t* icmp_net_unreachable = calloc(1, sizeof(sr_icmp_t3_hdr_t));
	icmp_net_unreachable->icmp_type = ICMP_DST_NET_UNREACHABLE_TYPE;
	icmp_net_unreachable->icmp_code = ICMP_DST_NET_UNREACHABLE_CODE;
	memcpy(icmp_net_unreachable->data, (uint8_t*)ip_hdr_recv, ICMP_DATA_SIZE);
	icmp_net_unreachable->icmp_sum = cksum((uint8_t*)icmp_net_unreachable, sizeof(sr_icmp_t3_hdr_t));

	/* Create IP packet */
	sr_ip_hdr_t* ip_hdr_reply = 
			create_ip_hdr(DEFAULT_IP_TTL, ip_protocol_icmp,
										ntohl(output_interface->ip), ntohl(ip_hdr_recv->ip_src),
										sizeof(sr_icmp_t3_hdr_t));

	/* Create Ethernet header */
	sr_ethernet_hdr_t* ethernet_hdr_reply = 
				create_ethernet_hdr(output_interface->addr, 
														ethernet_hdr_recv->ether_shost, 
														ethertype_ip);

	/* Merge ethernet hdr, ip hdr and icmp msg */
	uint16_t net_unreachable_packet_len = 
				sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

	uint8_t* reply_pkt = calloc(1, net_unreachable_packet_len);
	/* Update other header */
	memcpy(reply_pkt, ethernet_hdr_reply, sizeof(sr_ethernet_hdr_t));
	memcpy(reply_pkt + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
	memcpy(reply_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 
				 icmp_net_unreachable, sizeof(sr_icmp_t3_hdr_t));

	free(ethernet_hdr_reply);
	free(ip_hdr_reply);
	free(icmp_net_unreachable);

	sr_send_packet(sr, reply_pkt, net_unreachable_packet_len, output_interface->name);

	free(reply_pkt);
	return;
}

void send_packet_host_unreachable(struct sr_instance* sr, 
																	 struct sr_if* output_interface, 
																	 uint8_t* recv_packet) {
	/* Define header recv */
	sr_ethernet_hdr_t* ethernet_hdr_recv = (sr_ethernet_hdr_t *)recv_packet;
	sr_ip_hdr_t* ip_hdr_recv = (sr_ip_hdr_t*)(recv_packet + sizeof(sr_ethernet_hdr_t));

	/* Create ICMP packet */
	sr_icmp_t3_hdr_t* icmp_net_unreachable = calloc(1, sizeof(sr_icmp_t3_hdr_t));
	icmp_net_unreachable->icmp_type = ICMP_DST_HOST_UNREACHABLE_TYPE;
	icmp_net_unreachable->icmp_code = ICMP_DST_HOST_UNREACHABLE_CODE;
	memcpy(icmp_net_unreachable->data, (uint8_t*)ip_hdr_recv, ICMP_DATA_SIZE);
	icmp_net_unreachable->icmp_sum = cksum((uint8_t*)icmp_net_unreachable, sizeof(sr_icmp_t3_hdr_t));

	/* Create IP packet */
	sr_ip_hdr_t* ip_hdr_reply = 
			create_ip_hdr(DEFAULT_IP_TTL, ip_protocol_icmp,
										ntohl(output_interface->ip), ntohl(ip_hdr_recv->ip_src),
										sizeof(sr_icmp_t3_hdr_t));

	/* Create Ethernet header */
	sr_ethernet_hdr_t* ethernet_hdr_reply = 
				create_ethernet_hdr(output_interface->addr, 
														ethernet_hdr_recv->ether_shost, 
														ethertype_ip);

	/* Merge ethernet hdr, ip hdr and icmp msg */
	uint16_t net_unreachable_packet_len = 
				sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

	uint8_t* reply_pkt = calloc(1, net_unreachable_packet_len);
	/* Update other header */
	memcpy(reply_pkt, ethernet_hdr_reply, sizeof(sr_ethernet_hdr_t));
	memcpy(reply_pkt + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
	memcpy(reply_pkt + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 
				 icmp_net_unreachable, sizeof(sr_icmp_t3_hdr_t));

	free(ethernet_hdr_reply);
	free(ip_hdr_reply);
	free(icmp_net_unreachable);

	sr_send_packet(sr, reply_pkt, net_unreachable_packet_len, output_interface->name);
	free(reply_pkt);
	return;
}

void handle_arpreq(struct sr_instance* sr, struct sr_arpreq* arp_req) {
	time_t now = time(NULL);	
  if(now - arp_req->sent >= 1.0) {
  	if(arp_req->times_sent >= 5) {
  		/* send icmp host unreachable to source addr of all pkts waiting
              on this request */
			struct sr_packet* packet = arp_req->packets;

			while(packet != NULL) {
				sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet->buf + sizeof(sr_ethernet_hdr_t));

				/* new destination host is source host in recv packet */
				/* Using longest prefit to get output interface acording new destination host */
				struct sr_if* output_interface = longest_prefix(sr, ntohl(ip_hdr->ip_src));
				if(output_interface != NULL) {
					send_packet_host_unreachable(sr, output_interface, packet->buf);
				}	

				packet = packet->next;
			}
  		sr_arpreq_destroy(&(sr->cache), arp_req);
  	}else {
  		/* Use longest prefit to find output interface */
  		uint32_t ip_dst = ntohl(arp_req->ip);
  		struct sr_if* output_interface = longest_prefix(sr, ip_dst);

  		if(output_interface != NULL) {
  			/* Send ARP request */
  			send_arp_request(sr, output_interface, ip_dst);	
  		}
  		arp_req->sent = now;
  		arp_req->times_sent ++;
  	}
  }
}


void handle_icmp_p

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, struct sr_nat* nat,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d in interface %s\n", len, interface);
  /* fill in code here */

  /* Copy buffer to new memory */
  uint8_t* recv_packet = malloc(len);
  memcpy(recv_packet, packet, len);

  char* recv_interface_name = malloc(sr_IFACE_NAMELEN);
  memcpy(recv_interface_name, interface, sr_IFACE_NAMELEN);


  /* Get recv interface instance */
  struct sr_if* recv_interface_ins = sr_get_interface(sr, recv_interface_name);
  if(recv_interface_ins == NULL) {
    free(recv_packet);
  	free(recv_interface_name);
    return;
  }

  struct sr_if* output_interface = NULL;
  /* Check this packet is ARP packet or IP packet */
  uint16_t ethtype = ethertype(recv_packet);
  
  if (ethtype == ethertype_arp) { /* ARP */
  	/* Call function to handle ARP packet */
    handle_arp_packet(sr, recv_packet, len, recv_interface_ins);

  }else if(ethtype == ethertype_ip) { /* IP */
    /* IP header of packet receive */ 
  	sr_ip_hdr_t* ip_hdr_recv = (sr_ip_hdr_t*)(recv_packet + sizeof(sr_ethernet_hdr_t));
  	
  	/* Check this packet for router or not */
  	struct sr_if* router_interface = find_router_interface(sr, ntohl(ip_hdr_recv->ip_dst));
  	if(router_interface != NULL) {/* This packet for router */
  		/* Get output interface which is used to reply packet */
  		output_interface = sr_get_interface(sr, recv_interface_name);
  		handle_packet_for_router(sr, output_interface, recv_packet, len);	
  	}else {
  		/* This packet for other host */
  		/* Find output interface which is used to forward packet */
  		output_interface = longest_prefix(sr, ntohl(ip_hdr_recv->ip_dst));

  		/* Check output interface is valid or not */
  		if(output_interface == NULL) {
  			/* Reply ICMP net unreachable */
  			send_packet_net_unreachable(sr, recv_interface_ins, recv_packet);
  		}else {

  			/* Using NAT table here */
  			/* Check this packet is TCP or ICMP */

				uint8_t ip_proto = ip_protocol(ip_hdr_recv);
				if(ip_proto == ip_protocol_icmp) {
					sr_icmp_hdr_t* icmp_hdr_recv = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr_recv + sizeof(sr_ip_hdr_t));
					/* Check this ICMP is echo or not */

					/* Check this src ip and src aux_int has already in NAT or not */
					struct sr_nat_mapping *int_mapping = 
							sr_nat_lookup_internal(nat, ntohl(ip_hdr_recv->ip_src), uint16_t aux_int, sr_nat_mapping_type type );
				}



				/* ------------------------------ */

  			/* Check ARP cache */
  			struct sr_arpentry* arp_entry = sr_arpcache_lookup(&(sr->cache), ip_hdr_recv->ip_dst);
  			if(arp_entry == NULL) {
  				/* Add packet to queue */
  				struct sr_arpreq* arq_req = 
  							sr_arpcache_queuereq(&(sr->cache), ip_hdr_recv->ip_dst,
  																	 recv_packet, len, output_interface->name);
  				/* Send ARP request */
  				handle_arpreq(sr, arq_req);
  			}else {		

  				sr_ethernet_hdr_t* ethernet_hdr = (sr_ethernet_hdr_t*)(recv_packet);
					memcpy(ethernet_hdr->ether_shost, output_interface->addr, ETHER_ADDR_LEN);
					memcpy(ethernet_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
					

					/* Update TTL */ 
					/*
					sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(recv_packet + sizeof(sr_ethernet_hdr_t));
					ip_hdr->ip_ttl --;
					*/
					/* Update checksum */
					/*
					ip_hdr->ip_sum = 0;
					ip_hdr->ip_sum = cksum((uint8_t*)ip_hdr, sizeof(sr_ip_hdr_t));

					sr_send_packet(sr, recv_packet, len, output_interface->name);
					*/
					free(arp_entry);
  			}
  		}
  	}
  }


  free(recv_packet);
  free(recv_interface_name);
  return;
  
}/* end sr_ForwardPacket */

