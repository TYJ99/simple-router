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

    uint16_t ether_type = ethertype(packet);
    if(ethertype_ip == ether_type) {    
        fprintf(stderr, "handle_ip_packet\n");  
        handle_ip_packet(sr, packet, len, interface);
    }else if(ethertype_arp == ether_type) {
      fprintf(stderr, "handle_arp_packet\n");
        handle_arp_packet(sr, packet, len, interface);
    }else {
        fprintf(stderr, "Packet type error: Neither IP nor ARP. Drop the packet\n");
    }
  

}/* end sr_ForwardPacket */

/*
    If the incoming packet is arp_request_packet, 
    send the arp reply back if incoming_packet_dest_ip == interface_ip.

    If the incoming packet is arp_reply_packet, 
    send all the packets on the waiting queue out.

*/

void handle_arp_packet(struct sr_instance* sr,
                       uint8_t * packet/* lent */,
                       unsigned int len,
                       char* interface/* lent */) {

    /* extract ARP header from packet*/
    sr_arp_hdr_t* packet_arp_header = extract_arp_header(packet, sizeof(sr_ethernet_hdr_t));
    
    /* check if it meets minimum length*/
    uint8_t meet_mini_len = check_arp_packet_mini_len(len);
    if(0 == meet_mini_len) {
        return;
    }
    
    /* 
        check if the arp target ip address match this interface ip address
        if not, ignore this ARP packet.
    */
    struct sr_if *receiving_interface = sr_get_interface(sr, interface);
    if(receiving_interface->ip != packet_arp_header->ar_tip) {
        fprintf(stderr, "the arp target ip address does NOT match this interface ip address\n");
        return;
    }

    unsigned short arp_op = ntohs(packet_arp_header->ar_op);
    if(arp_op_request == arp_op) {
        fprintf(stderr, "handle_arp_packet_request\n");
        handle_arp_packet_request(sr, packet_arp_header, packet, receiving_interface);
    }else if(arp_op_reply == arp_op) {
        fprintf(stderr, "handle_arp_reply\n");
        handle_arp_reply(sr, packet_arp_header, receiving_interface);
    }
    
}

/* send all the packets on the waiting queue out. */
void handle_arp_reply(struct sr_instance* sr, 
                        sr_arp_hdr_t* packet_arp_reply_header, 
                        struct sr_if *receiving_interface) {

    /* 
       List of pkts waiting on this req to finish
       handle one packet on the waiting list at a time.
    */
    /*
        iterate through sr->cache.requests to find the request.
    */
    struct sr_arpreq *arp_request = sr->cache.requests;
    uint32_t target_ip = packet_arp_reply_header->ar_sip;
    struct sr_arpreq *arp_request_next = NULL;
    while (arp_request != NULL) {
        /*
            Since handle_arpreq as defined in the comments above could destroy your
            current request, make sure to save the next pointer before calling
            handle_arpreq when traversing through the ARP requests linked list.
        */
        arp_request_next = arp_request->next;
        if (arp_request->ip == target_ip) {
            break;
        }
        arp_request = arp_request_next;
    }
    struct sr_packet *req_waiting_packet = arp_request->packets;
    
    /*
        send all the packets on the waiting queue out.
    */
    /* int status = 0; */
    while(req_waiting_packet != NULL) {
        uint8_t *waiting_packet_raw_eth_frame = req_waiting_packet->buf;
        unsigned int waiting_packet_raw_eth_frame_len = req_waiting_packet->len;
        send_all_waiting_packet_out(sr, packet_arp_reply_header, 
                                    waiting_packet_raw_eth_frame, 
                                    receiving_interface, 
                                    waiting_packet_raw_eth_frame_len);
        
        req_waiting_packet = req_waiting_packet->next;
    }
    sr_arpreq_destroy(&sr->cache, arp_request);
}

void send_all_waiting_packet_out(struct sr_instance* sr, 
                                 sr_arp_hdr_t* packet_arp_reply_header,
                                 uint8_t *waiting_packet_raw_eth_frame,
                                 struct sr_if *receiving_interface, 
                                 unsigned int waiting_packet_raw_eth_frame_len) {

    sr_ethernet_hdr_t *waiting_packet_ethernet_header = extract_eth_header(waiting_packet_raw_eth_frame, 0);
    build_waiting_packet_eth_header(packet_arp_reply_header, 
                                    waiting_packet_ethernet_header,
                                    receiving_interface);
    sr_send_packet(sr, waiting_packet_raw_eth_frame, waiting_packet_raw_eth_frame_len, receiving_interface->name);
}


/* send the arp reply back if incoming_packet_dest_ip == interface_ip. */
void handle_arp_packet_request(struct sr_instance* sr, 
                        sr_arp_hdr_t* packet_arp_header, 
                        uint8_t * packet, 
                        struct sr_if *receiving_interface) {

    send_arp_reply(sr, packet_arp_header, packet, receiving_interface);
}

void send_arp_reply(struct sr_instance* sr, 
                    sr_arp_hdr_t* original_packet_arp_header, 
                    uint8_t * packet, 
                    struct sr_if *receiving_interface) {
                      
    /* extract ethernet header from packet*/
    sr_ethernet_hdr_t* original_packet_eth_header = extract_eth_header(packet, 0);
    /* create a new ARP packet for sending the reply*/
    unsigned long long new_arp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *new_arp_packet = (uint8_t *)calloc(new_arp_packet_len, sizeof(uint8_t));

    /* extract ethernet header from new ARP packet*/
    sr_ethernet_hdr_t* new_arp_packet_eth_header = extract_eth_header(new_arp_packet, 0);

    /* extract ARP header from new ARP packet*/
    sr_arp_hdr_t* new_arp_packet_arp_header = extract_arp_header(new_arp_packet, sizeof(sr_ethernet_hdr_t));

    /* build new ARP ethernet_header*/
    build_new_arp_reply_packet_eth_header(new_arp_packet_eth_header, original_packet_eth_header, receiving_interface);

    /* build new ARP arp_header*/
    build_new_arp_reply_packet_arp_header(new_arp_packet_arp_header, original_packet_arp_header, receiving_interface);

    /* send out this new ARP packet*/
    sr_send_packet(sr, new_arp_packet, new_arp_packet_len, receiving_interface->name);
    free(new_arp_packet);
}


/* the minimum length of a arp packet is sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)*/
uint8_t check_arp_packet_mini_len(unsigned int total_packet_len) {
    uint8_t res = 1;
    unsigned long long arp_packet_mini_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    if(total_packet_len < arp_packet_mini_len) {
        res = 0;
    }
    return res;
}

/*
    (A.) Given a raw Ethernet frame, if the frame contains an IP packet 
         that is not destined towards one of our router interfaces:

        (1.) Sanity-check the packet (meets minimum length and has correct checksum). 
            The IP checksum is calculated over just the IP header.
        (2.) Decrement the TTL by 1, and recompute the packet checksum over the modified header.
        (3.) Find out which entry in the routing table has the longest prefix match with the
             destination IP address.
                (3.1) If an entry exists, check the ARP cache for the next-hop MAC address
                      corresponding to the next-hop IP. If it's there, send it
                      (3.1.1) If the ARP cache does not have a MAC address entry for the
                              next-hop IP, send an ARP request for the next-hop IP (if one hasn't
                              been sent within the last second), and add the packet to the queue
                              of packets waiting on this ARP request.

        This is a very simplified version of the forwarding process, and the low-level details
        follow. For example, if an error occurs in any of the above steps, you will have to send an
        ICMP message back to the sender notifying them of an error. You may also get an ARP
        request or reply, which has to interact with the ARP cache correctly.

        (4.) If no matching entry is in the routing table or if an ARP response is not received, 
            send an ICMP destination net unreachable message back to the source of the packet.

    (B.) An incoming IP packet may be destined for one of your router's IP addresses, 
         or it may be destined elsewhere. If it is sent to one of your router's IP addresses, 
         you should take the following actions, consistent with the section on protocols below:

         (1.) If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo
              reply to the sending host. The ICMP checksum is calculated over the header and the payload.
        
              (1.1) Note: The data field of an ICMP echo request does not have a fixed length. Its
                    length is determined by the total length field of the IP header. The router should
                    copy the complete data field from an echo request to the corresponding echo reply.
                   
          (2.) Otherwise, ignore the packet.

*/

void handle_ip_packet(struct sr_instance* sr,
                      uint8_t * packet/* lent */,
                      unsigned int len,
                      char* interface/* lent */) {

    /* extract eth header*/    
    /*
    fprintf(stderr, "handle_ip_packet: incoming packet ethernet header: \n");
    print_hdr_eth(packet);
    */
    fprintf(stderr, "handle_ip_packet: interface name: %s\n", interface);
    /* extract ip header*/
    sr_ip_hdr_t* packet_ip_header = extract_ip_header(packet, sizeof(sr_ethernet_hdr_t));
    fprintf(stderr, "handle_ip_packet: incoming packet ip header: \n");
    print_given_hdr_ip(packet_ip_header);
    /*print_hdrs(packet, len);*/

    /* Sanity-check the ip packet(meets minimum length and has correct checksum)*/
    if(0 == sanity_check_ip_packet(packet_ip_header, len)) {
        return;
    }
    fprintf(stderr, "Pass sanity_check_ip_packet\n");

    /* check if an IP packet that is destined towards one*/
    /* of our router interfaces*/
    /*struct sr_if *destined_interface = NULL;*/
    struct sr_if *destined_interface = check_if_ip_packet_destination_is_current_router(sr, packet_ip_header);
    fprintf(stderr, "is destined_interface NULL?: %d\n", NULL == destined_interface);    
    /* The IP packet is sent to one of my router's IP addresses*/
    if(NULL != destined_interface) {
        fprintf(stderr, "destined_interface ip: ");
        print_addr_ip_int(destined_interface->ip);
        fprintf(stderr, "destined_interface MAC address: ");
        print_addr_eth(destined_interface->addr);

        uint8_t curr_protocol = packet_ip_header->ip_p;
        /*
            (1.) If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo
              reply to the sending host. The ICMP checksum is calculated over the header and the payload.
        
              (1.1) Note: The data field of an ICMP echo request does not have a fixed length. Its
                    length is determined by the total length field of the IP header. The router should
                    copy the complete data field from an echo request to the corresponding echo reply.
                   
            (2.) If the packet contains a TCP or UDP payload, send an ICMP port unreachable(type 3, code 3)
                 to the sending host. Otherwise, ignore the packet. Packets destined elsewhere
                 should be forwarded using your normal forwarding logic.
                 (TCP Protocol Number: 6)
                 (UDP Protocol Number: 17)
                 (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
        */
        struct sr_if* connected_interface = sr_get_interface(sr, interface);
        if(ip_protocol_icmp == curr_protocol) {
            fprintf(stderr, "curr_protocol is ICMP\n");
            handle_icmp_echo_reply(sr, packet, len, connected_interface);
        }else if(ip_protocol_tcp == curr_protocol || ip_protocol_udp == curr_protocol) {
            fprintf(stderr, "curr_protocol is TCP or UDP\n");
            uint8_t icmp_type = 3, icmp_code = 3;
            /*
                send an ICMP port unreachable(type 3, code 3) to the sending host.
            */
            send_icmp_with_type_code(sr, 
                                     packet,
                                     connected_interface,
                                     icmp_type, 
                                     icmp_code)
        }
        
        return;
    }

    /* The IP packet is NOT sent to one of your router's IP addresses*/
    if(NULL == destined_interface) {
        /* Decrement the TTL by 1, and recompute the packet checksum over the modified header*/
        --packet_ip_header->ip_ttl;
        packet_ip_header->ip_sum = 0;
        packet_ip_header->ip_sum = cksum(packet_ip_header, sizeof(sr_ip_hdr_t));

        /* 
            if TTL now is 0(invalid), send ICMP(type 11, code 0)
            back to the sending host and return.
        */
        if(0 >= packet_ip_header->ip_ttl) {
            uint8_t icmp_type = 11, icmp_code = 0;
            struct sr_if *dest_interface = sr_get_interface(sr, interface);
            send_icmp_with_type_code(sr, packet, dest_interface, icmp_type, icmp_code);
            return;
        }
        fprintf(stderr, "ttl > 0\n");
        /* Find an entry in the routing table that exactly matches the destination IP address*/
        /*struct sr_rt *next_hop = NULL;*/
        struct sr_rt *next_hop = find_entry_in_routing_table(sr, packet_ip_header->ip_dst);
        fprintf(stderr, "is next_hop NULL?: %d\n", next_hop==NULL);
        /*
            If no matching entry is in the routing table, send an
            ICMP destination net unreachable message(type 3, code 0) back to the sending host.
        */
        if(NULL == next_hop) {
            fprintf(stderr, "no matching entry is in the routing table\n");
            uint8_t icmp_type = 3, icmp_code = 0;
            struct sr_if *dest_interface = sr_get_interface(sr, interface);
            send_icmp_with_type_code(sr, packet, dest_interface, icmp_type, icmp_code);
            return;
        }

        /*
            If an entry exists, send an ARP request for the next-hop IP.
        */
        struct sr_arpreq *arp_request = sr_arpcache_queuereq(&sr->cache, 
                                                             packet_ip_header->ip_dst, 
                                                             packet, 
                                                             len, 
                                                             next_hop->interface);
        fprintf(stderr, "entry exists, send an ARP request for the next-hop IP\n");
        handle_arp_request(sr, arp_request);
        return;
    }

}

void handle_icmp_echo_reply(struct sr_instance* sr,
                          uint8_t * packet,
                          unsigned int total_packet_len,
                          struct sr_if * connected_interface) {
    /* extract icmp header*/
    sr_icmp_t11_hdr_t* packet_icmp_header = extract_icmp_header(packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    /* Sanity-check the icmp packet(meets minimum length and has correct checksum)*/
    if(0 == sanity_check_icmp_packet(packet_icmp_header, total_packet_len)) {
        return;
    }
    uint8_t icmp_request_type = 8;
    if(icmp_request_type == packet_icmp_header->icmp_type) {
        uint8_t icmp_type = 0, icmp_code = 0;
        /*struct sr_if *dest_interface = sr_get_interface(sr, interface);*/
        fprintf(stderr, "icmp_request_type == packet_icmp_header->icmp_type\n");
        send_icmp_echo_reply(sr, packet, connected_interface, icmp_type, icmp_code, total_packet_len);
    }
}

uint8_t sanity_check_icmp_packet(sr_icmp_t11_hdr_t* packet_icmp_header, 
                                 unsigned int total_packet_len) { 
    
    uint8_t res = 0;
    /* check if it meets minimum length*/
    if(0 == check_icmp_packet_mini_len(total_packet_len)) {
        return res;        
    }

    /* check if it has correct checksum*/
    if(0 == check_icmp_packet_checksum(packet_icmp_header, total_packet_len)) {
        return res;
    }
    res = 1;
    return res;
}

/* the minimum length of a ICMP packet is sizeof(ethernet header) + sizeof(ip header) + sizeof(icmp header)*/
uint8_t check_icmp_packet_mini_len(unsigned int total_packet_len) {
    uint8_t res = 1;
    unsigned long long icmp_packet_mini_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    if(total_packet_len < icmp_packet_mini_len) {
        res = 0;
    }
    return res;
}

/*
    Since the ICMP checksum is calculated over the header and the
    payload and an IP packet contains an ICMP packet, the length we use
    to caculate the ICMP checksum is total length of whole packet minus the length of ethernet header and IP header.
    (packet_total_len - sizeof(ethernet header) - sizeof(IP header))
    https://openmaniak.com/ping.php
*/
uint8_t check_icmp_packet_checksum(sr_icmp_t11_hdr_t* packet_icmp_header, unsigned int total_packet_len) { 
    uint8_t res = 0;
    uint16_t original_checksum = packet_icmp_header->icmp_sum;
    uint16_t packet_icmp_len = total_packet_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    packet_icmp_header->icmp_sum = 0;
    packet_icmp_header->icmp_sum = cksum(packet_icmp_header, packet_icmp_len);
    if(packet_icmp_header->icmp_sum == original_checksum) {
        res = 1;
    }else {
        packet_icmp_header->icmp_sum = original_checksum;
    }
    return res;
}


/*
    iterate through all interfaces in the router and compare
    the ip address of interface to the destination ip address of the incoming IP packet
*/
struct sr_if * check_if_ip_packet_destination_is_current_router(struct sr_instance* sr,
                                                                sr_ip_hdr_t* packet_ip_header) {

    struct sr_if *curr_sr_if = sr->if_list;
    uint32_t packet_ip_dest_ip = packet_ip_header->ip_dst;  
    fprintf(stderr, "packet_ip_dest_ip: ");   
    print_addr_ip_int(packet_ip_dest_ip);                                                 
    while(curr_sr_if != NULL) { 
        fprintf(stderr, "curr_sr_if->ip: ");   
        print_addr_ip_int(curr_sr_if->ip);
        if(packet_ip_dest_ip == curr_sr_if->ip) {
            return curr_sr_if;
        }
        curr_sr_if = curr_sr_if->next;
    }                                                              
    return NULL;
}

uint8_t sanity_check_ip_packet(sr_ip_hdr_t* packet_ip_header, unsigned int total_packet_len) {
    uint8_t res = 0;
    /* check if it meets minimum length*/
    if(0 == check_ip_packet_mini_len(total_packet_len)) {
        return res;        
    }

    /* check if it has correct checksum*/
    if(0 == check_ip_packet_checksum(packet_ip_header)) {
        return res;
    }
    res = 1;
    return res;
}

/* the minimum length of a IP packet is sizeof(ethernet header) + sizeof(ip header)*/
uint8_t check_ip_packet_mini_len(unsigned int total_packet_len) {
    uint8_t res = 1;
    unsigned long long ip_packet_mini_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    if(total_packet_len < ip_packet_mini_len) {
        res = 0;
    }
    return res;
}

uint8_t check_ip_packet_checksum(sr_ip_hdr_t* packet_ip_header) {
    uint8_t res = 0;
    uint16_t original_checksum = packet_ip_header->ip_sum;
    packet_ip_header->ip_sum = 0;
    packet_ip_header->ip_sum = cksum(packet_ip_header, sizeof(sr_ip_hdr_t));
    if(packet_ip_header->ip_sum == original_checksum) {
        res = 1;
    }else {
        packet_ip_header->ip_sum = original_checksum;
    }
    return res;
}