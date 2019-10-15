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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
/*  */
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* GET ETHERNET TYPE */
  if (ethertype(packet) == ethertype_ip){
        printf("test1\n");
     process_ip_packet(sr, packet, len, interface);
  } else if (ethertype(packet) == ethertype_arp){
        printf("Test2\n");
      process_arp_packet(sr, packet, len , interface);
  }

}/* end sr_ForwardPacket */



void process_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

printf("ip test 1\n");
    /* Get IP header */
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    /* Get ICMP header */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		
  sr_ethernet_hdr_t* eth_hdr =(sr_ethernet_hdr_t *) packet; 
printf("ip 2\n");
    if (check_len_req(len) == 0) {
        printf("Ethernet header error:  mininum length not met \n");
        return;
    }
printf("ip 3\n");
    /* Decrease ttl by 1 */
    ip_hdr->ip_ttl --;
    /* recompute checksum */
    ip_hdr->ip_sum = cksum(ip_hdr,len);
    if(ip_hdr->ip_ttl == 0) {
        send_ICMP_message(sr, packet, len, (uint8_t)11 , (uint8_t)0, NULL,interface);
        return;
    }
printf("ip 4\n");
    if(sr_get_interface(  sr,interface) == NULL){
        /* Packet is NOT destined for our router  */
        /* Verify checksum */
printf("ip 4.5\n");
        if (check_ip_checksum(ip_hdr) == 0) {
            printf("IP Header checksum fails\n");
        }
 printf("ip 5\n");
         /* lookup destination IP in routing table */
        struct sr_rt* routing_entry = find_longeset_prefix_match(sr, ip_hdr->ip_dst);
        if(!routing_entry) {
	    int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *new_packet = malloc(packet_len);

            /* Create ethernet header */
            create_ethernet_header (eth_hdr, new_packet, eth_hdr->ether_dhost, eth_hdr->ether_shost, htons(ethertype_ip));

            /* Create ip header */
            create_ip_header (ip_hdr, new_packet, sr_get_interface(sr, interface)->ip, ip_hdr->ip_src);

            /* Create icmp header */
            create_icmp_type3_header (ip_hdr, new_packet, 3, 0);

            /* Look up routing table for rt entry that is mapped to the source of received packet */
            struct sr_rt *src_lpm = find_longeset_prefix_match(sr, ip_hdr->ip_src);
		
		
		
            send_ICMP_message(sr, packet, len, (uint8_t)3 , (uint8_t)0, src_lpm, interface) ;
            return;
        }
printf("ip 6\n");
        struct sr_if* routing_interface = sr_get_interface(sr, routing_entry->interface);
printf("ip 7\n");
        if(!routing_interface) {
            printf("Error IP when fowarding: interface not found.\n");
            return;
        }
        /*Check ARP cache for next hop ip */
        send_packet_check_cache(sr, packet, len, routing_interface, routing_entry->gw.s_addr);
    }
    else{
        /* Packet is destined for our router  */
        if(ip_hdr->ip_p == ip_protocol_icmp){
           /* Checksum */
            if (check_icmp_checksum(icmp_hdr, len) == 0) {
                printf("IP Header checksum fails\n");
                return;
            }
            /* If ICMP echo req*/
            if (icmp_hdr->icmp_code == (uint8_t) 0 ) {
                /* send echo reply  */
                send_ICMP_message(sr, packet, len, (uint8_t)0, (uint8_t) NULL, NULL,interface);
            }
        }
        else if (ip_hdr->ip_p == ip_protocol_udp || ip_hdr->ip_p == ip_protocol_tcp) {
           /* Send port Unreachable message */
            send_ICMP_message(sr, packet, len, (uint8_t)3, (uint8_t)3, NULL, interface);
        }
    }
}

void process_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
printf("in arp 1\n");
        /* Get ARP header */
        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)( packet + sizeof(sr_ethernet_hdr_t));
        /* Get Ethernet header */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
         /* ARP Cache */
        struct sr_arpcache *sr_cache = &sr->cache;
printf("before if in arp\n");
        if (check_len_req(len) == 0) {
            printf("Ethernet header error:  mininum length not met \n");
            return;
        }
printf("before interface\n");
        if(sr_get_interface( sr,interface ) == NULL){
            printf("ARP error:  Cannot find dest ip in router, Dropping packet \n");
            return;
        }
printf("after interface\n");
        assert(arp_hdr->ar_op);
        if(ntohs(arp_hdr->ar_op) == arp_op_request){
             printf("ARP request recieved\n");
            /* store the incoming interface */
            struct sr_if* incoming_interface = sr_get_interface(sr, interface);
            assert(incoming_interface);
printf("test 1 in if statement\n");
           /* create new arp rep since packet is lent */
            uint8_t* new_rep =  malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

printf("2\n");

            /* Create Ethernet header */
            create_ethernet_header (eth_hdr, new_rep, sr_get_interface(sr, interface)->addr, eth_hdr->ether_shost, htons(ethertype_arp));
printf("3\n");
            /* Create ARP header */
            create_arp_header (arp_hdr, new_rep, incoming_interface);
printf("4\n");
            /* Send out ARP reply */
            sr_send_packet(sr, new_rep, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), incoming_interface->name);
            printf("Sent an ARP reply packet\n");
            free(new_rep);
            return;

        }

        if(ntohs(arp_hdr->ar_op) == arp_op_reply){
            /* # When servicing an arp reply that gives us an IP->MAC mapping
                req = arpcache_insert(ip, mac)
                if req:
                    send all packets on the req->packets linked list
                    arpreq_destroy(req)
            */
            printf("ARP reply received\n");
            struct sr_arpreq* req = sr_arpcache_insert(sr_cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
            if(req) {
                struct sr_packet* packet = req->packets;
                while(packet) {
                    struct sr_if *incoming_interface = sr_get_interface(sr, packet->iface);
                    if(incoming_interface) {
                        /* construct Ethernet hdr */
                        eth_hdr = (sr_ethernet_hdr_t*)(packet->buf);
                        /* set destination MAC to be received packet's sender MAC */
                        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(unsigned char)* ETHER_ADDR_LEN);
                        /* set source MAC to be incoming interface's MAC */
                        memcpy(eth_hdr->ether_shost, sr_get_interface(sr, packet->iface)->addr, sizeof(unsigned char)* ETHER_ADDR_LEN);
                        sr_send_packet(sr, packet->buf, packet->len, packet->iface);

                        packet = packet->next;
                    }

                }
                sr_arpreq_destroy(&sr->cache, req);
            }
            return;
        }
    return;
}

void send_ICMP_message(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint8_t type, uint8_t code,struct sr_rt* rt_entry, char* intf){

    /* Get Ethernet header */
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*) packet;
    /* construct IP header from packet */
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
	
    struct sr_if* interface = sr_get_interface(sr, interface);

    /* get longest matching prefix of source IP */
    struct sr_rt* routable_entry = find_longeset_prefix_match(sr, ip_hdr->ip_src);
printf("icmp 1\n");
    assert(routable_entry);
printf("icmp 2\n");
    /* Echo Reply  */
    if(type == 0 & code == NULL){
        /* Ethernet: set source & dest Mac */
printf("icmp 0 null\n");
        memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(eth_hdr->ether_shost, interface->addr,  sizeof(uint8_t)*ETHER_ADDR_LEN);
printf("pass memcpy icmp\n");
        /* IP */
        uint32_t src = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_hdr->ip_dst;
        ip_hdr->ip_dst = src;
        ip_hdr->ip_ttl = 5;
        memset(&(ip_hdr->ip_sum), 0, sizeof(uint16_t));
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
printf("icmp 3\n");
        /* ICMP */
        sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        icmp_hdr->icmp_type = type;
        icmp_hdr->icmp_code = code;
        memset(&(icmp_hdr->icmp_sum), 0, sizeof(uint16_t));
        icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) -sizeof(sr_ip_hdr_t));
printf("echo\n");
        send_packet_check_cache(sr, packet, len, interface, src);
        return;
    }
    /* Destinaton not reachable/ host not reachable/ port unreachable   */
    if(type == 3){
        if(rt_entry){
            int packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
            uint8_t *new_packet = malloc(packet_len);
            struct sr_arpcache *sr_cache = &sr->cache;
            struct sr_arpentry *entry = sr_arpcache_lookup(sr_cache, routable_entry->gw.s_addr);
            if (entry){
                printf("Found the ARP entry in the cache\n");
                struct sr_if *out_iface = sr_get_interface(sr, routable_entry->interface);

                /* Modify ethernet header */
                sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
                memcpy(new_eth_hdr->ether_dhost, entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
                memcpy(new_eth_hdr->ether_shost, out_iface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);

                /* Modify ip header */
                sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof (sr_ethernet_hdr_t));
                new_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
                new_ip_hdr->ip_sum = 0;
                new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

                sr_send_packet(sr, new_packet, len, out_iface->name);
                free(entry);
            } else {
                /* If there is no match in our ARP cache, send ARP request. */
                struct sr_arpreq *req = sr_arpcache_queuereq(sr_cache, routable_entry->gw.s_addr, new_packet, len, routable_entry->interface);
                handle_arpreq(req, sr);
            }
            free(new_packet);
        }

    }

    if(type == 11 & code == 0){
        /* Modify ethernet header */
            /* construst new ICMP packet */

        uint8_t* new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
            /* construct ethernet hdr */
        sr_ethernet_hdr_t* new_eth_hdr = (sr_ethernet_hdr_t*)new_packet;
        create_ethernet_header(eth_hdr, new_packet, sr_get_interface(sr, interface)->addr, eth_hdr->ether_shost, htons(ethertype_ip));
        /* construct IP hdr */
        /*-------------------------------------------------------*/
        sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
        new_ip_hdr->ip_v = 4;
        new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
        new_ip_hdr->ip_tos = 0;
        new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
        new_ip_hdr->ip_id = htons(0);
        new_ip_hdr->ip_off = htons(IP_DF);
        new_ip_hdr->ip_ttl = 64;
        new_ip_hdr->ip_dst = ip_hdr->ip_src;
        new_ip_hdr->ip_p = ip_protocol_icmp;
        new_ip_hdr->ip_src = sr_get_interface(sr, interface)->ip;
        new_ip_hdr->ip_sum = 0;
        new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

        /* Make ICMP Header */
        sr_icmp_t11_hdr_t *new_icmp_hdr = (sr_icmp_t11_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        new_icmp_hdr->icmp_type = 11;
        new_icmp_hdr->icmp_code = 0;
        new_icmp_hdr->unused = 0;
        new_icmp_hdr->icmp_sum = 0;
        memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
        new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
        /*-------------------------------------------------------*/
        send_packet_check_cache(sr, new_packet, sizeof(new_packet), interface,ip_hdr->ip_src );
        free(new_packet);
        return;

    }
    return;
}

void create_ethernet_header (sr_ethernet_hdr_t * eth_hdr, uint8_t * new_packet, uint8_t *src_eth_addr, uint8_t *dest_eth_addr, uint16_t ether_type) {
printf("in ethernet head\n");
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
    assert(new_eth_hdr);
    assert( src_eth_addr);
     assert(dest_eth_addr);
    memcpy(new_eth_hdr->ether_shost, src_eth_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_dhost, dest_eth_addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
printf("test 2 ethhead\n");
    new_eth_hdr->ether_type = ether_type;
}

 /* Create ARP header */
void create_arp_header (sr_arp_hdr_t* arp_hdr, uint8_t* new_packet, struct sr_if *src_iface) {
    sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
    new_arp_hdr->ar_pro = arp_hdr->ar_pro;
    new_arp_hdr->ar_hln = arp_hdr->ar_hln;
    new_arp_hdr->ar_pln = arp_hdr->ar_pln;
    new_arp_hdr->ar_op =  htons(arp_op_reply);

    /* Switch sender and receiver hardware address and IP address */
    memcpy(new_arp_hdr->ar_sha, src_iface->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
    new_arp_hdr->ar_sip =  src_iface->ip;
    memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
    new_arp_hdr->ar_tip = arp_hdr->ar_sip;
}
/* Create IP header for ICMP */
void create_ip_header (sr_ip_hdr_t *ip_hdr, uint8_t* new_packet, uint32_t ip_src, uint32_t ip_dst) {
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_hdr->ip_id = htons(0);
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_dst = ip_dst;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_src = ip_src;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
}
/* Create ICMP type 3 header */
void create_icmp_type3_header (sr_ip_hdr_t *ip_hdr, uint8_t* new_packet, uint8_t type, unsigned int code) {
    sr_icmp_t3_hdr_t *new_icmp_header = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_header->icmp_type = type;
    new_icmp_header->icmp_code = code;
    new_icmp_header->unused = 0;
    new_icmp_header->next_mtu = 0;
    new_icmp_header->icmp_sum = 0;
    memcpy(new_icmp_header->data, ip_hdr, ICMP_DATA_SIZE);
    new_icmp_header->icmp_sum = cksum(new_icmp_header, sizeof(sr_icmp_t3_hdr_t));
}
/* Longest prefix matching */
struct sr_rt *find_longeset_prefix_match(struct sr_instance *sr, uint32_t ip) {
        int len = 0;
        struct sr_rt *routing_table = sr->routing_table;
        struct sr_rt *current = routing_table;
        struct sr_rt *lp = NULL;
        while (current) {
                if ((ip & current->mask.s_addr) == (current->dest.s_addr & current->mask.s_addr)){
                        if ((ip & current->mask.s_addr) > len) {
                                len = ip & current->mask.s_addr;
                                lp = current;
                        }
                }
                current = current->next;
        }
        return lp;
}
/* Check ICMP checksum */
int check_icmp_checksum(sr_icmp_hdr_t *hdr, int len){
    uint16_t correct = 0xffff;
    memset(&(hdr->icmp_sum), 0, sizeof(uint16_t));
    uint16_t res = cksum(hdr, len - sizeof(sr_ethernet_hdr_t) -sizeof(sr_ip_hdr_t));
    if (correct != res) {
                return 1;
        }
        return 0;
}
/* Check correct IP checksum */
int check_ip_checksum(sr_ip_hdr_t *hdr){
        uint16_t correct = 0xffff;
        memset(&(hdr->ip_sum), 0, sizeof(uint16_t));
        uint16_t res = cksum(hdr, hdr->ip_len);
        if (correct != res) {
                return 1;
        }
        return 0;
}
/* Check lenght requiremnet of header*/
int check_len_req(unsigned int len){
    if (len < sizeof(sr_ethernet_hdr_t)) {
        printf("Error: Ethernet packet length.\n");
        return 0 ;
    }
    return 1;
}

/* Check the ARP cache, send packet or send ARP request  send packet to next_hop_ip*/
void send_packet_check_cache(struct sr_instance* sr, uint8_t* packet, unsigned int len, struct sr_if* interface, uint32_t dest_ip) {
    printf("send packet test\n");
    struct sr_arpentry* arp_in_cache = sr_arpcache_lookup(&sr->cache, dest_ip);
 printf("send pack 1\n");
    /* if cached, send packet through outgoing interface */
    if(arp_in_cache) {
printf("send pack if\n");
        sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*) packet;
        /* set destination MAC to the mapped MAC */
        memcpy(ehdr->ether_dhost, arp_in_cache->mac, ETHER_ADDR_LEN);
        /* set the source MAC to the outgoing interface's MAC */
        memcpy(ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, interface->name);
        free(arp_in_cache);
    } else {
printf("send pack else\n");
        /* if not cached, use ARP request */
        struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, dest_ip, packet, len, interface->name);
printf("before arpreq\n");
        handle_arpreq(arpreq, sr);
printf("after arpreq\n");
    }
}