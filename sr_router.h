/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
/*
    If the incoming packet is arp_request_packet, 
    send the arp reply back if incoming_packet_dest_ip == interface_ip.

    If the incoming packet is arp_reply_packet, 
    send all the packets on the waiting queue out.

*/

void handle_arp_packet(struct sr_instance* sr,
                       uint8_t * packet/* lent */,
                       unsigned int len,
                       char* interface/* lent */);

/* send all the packets on the waiting queue out.*/
void handle_arp_packet_reply(struct sr_instance* sr, 
                        sr_arp_hdr_t* packet_arp_reply_header, 
                        struct sr_if *outgoing_interface);

send_packet_out_to_next_hop(struct sr_instance* sr, 
                            uint8_t *destination_mac_addr,
                            uint8_t *packet_raw_eth_frame,
                            struct sr_if *outgoing_interface, 
                            unsigned int packet_raw_eth_frame_len);

/* send the arp reply back if incoming_packet_dest_ip == interface_ip.*/
void handle_arp_packet_request(struct sr_instance* sr, 
                        sr_arp_hdr_t* packet_arp_header, 
                        uint8_t * packet, 
                        struct sr_if *connected_interface);

void send_arp_reply(struct sr_instance* sr, 
                    sr_arp_hdr_t* original_packet_arp_header, 
                    uint8_t * packet, 
                    struct sr_if *connected_interface);

/* the minimum length of a arp packet is sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t) */
uint8_t check_arp_packet_mini_len(unsigned int total_packet_len);

/*
    (A.) Given a raw Ethernet frame, if the frame contains an IP packet 
         that is not destined towards one of our router interfaces:

        (1.) Sanity-check the packet (meets minimum length and has correct checksum). 
            The IP checksum is calculated over just the IP header.
        (2.) Decrement the TTL by 1, and recompute the packet checksum over the modified header.
        (3.) Find an entry in the routing table that exactly matches the destination IP address 
            (do not perform longest-prefix matching). Instead, only forward if 
            there is an exact match to the IP address.
                (3.1) If an entry exists, send an ARP request for the next-hop IP.
                    (3.1.1) If the router gets an ARP response within 5 seconds (5 tries), 
                            send the packet out toward its destination. 
                            Do not store the response in an ARP cache.
                            Instead, you will have to send an ARP request for every packet.
                (3.2) If an ARP response is not received within 5 seconds (5 tries), send an
                      ICMP destination host unreachable message back to the source of the packet.
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
                      char* interface/* lent */);

void handle_icmp_echo_reply(struct sr_instance* sr,
                            uint8_t * packet,
                            unsigned int total_packet_len,
                            struct sr_if * connected_interface);

uint8_t sanity_check_icmp_packet(sr_icmp_t11_hdr_t* packet_icmp_header, 
                                 unsigned int total_packet_len);

/* the minimum length of a ICMP packet is sizeof(ethernet header) + sizeof(ip header) + sizeof(icmp header) */
uint8_t check_icmp_packet_mini_len(unsigned int total_packet_len);

/*
    Since the ICMP checksum is calculated over the header and the
    payload and an IP packet contains an ICMP packet, the length we use
    to caculate the ICMP checksum is total length of whole packet minus the length of ethernet header and IP header.
    (packet_total_len - sizeof(ethernet header) - sizeof(IP header))
    https://openmaniak.com/ping.php
*/
uint8_t check_icmp_packet_checksum(sr_icmp_t11_hdr_t* packet_icmp_header, unsigned int total_packet_len);

/*
    iterate through all interfaces in the router and compare
    the ip address of interface to the destination ip address of the incoming IP packet
*/
struct sr_if * check_if_ip_packet_destination_is_current_router(struct sr_instance* sr,
                                                                sr_ip_hdr_t* packet_ip_header);
                                                         

uint8_t sanity_check_ip_packet(sr_ip_hdr_t* packet_ip_header, unsigned int total_packet_len);

/* the minimum length of a IP packet is sizeof(ethernet header) + sizeof(ip header)*/
uint8_t check_ip_packet_mini_len(unsigned int total_packet_len);

uint8_t check_ip_packet_checksum(sr_ip_hdr_t* packet_ip_header);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
