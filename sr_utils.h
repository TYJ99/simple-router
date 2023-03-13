/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

/* forward declare */
struct sr_if;
struct sr_rt;
struct sr_instance;

uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_given_hdr_ip(sr_ip_hdr_t* packet_ip_header);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

/*
    1. ARP requests and ARP Replies have an ethernet and ARP header.
    2. All the packets are ethernet packets, so what headers they contain is dependent on packet type.
       The packets you forward are IP packets, and mainly ICMP echo's, 
       so will likely by "Ethernet Header, IP header, ICMP header, payload"
    3. https://openmaniak.com/ping.php
*/
void send_icmp_with_type_code(struct sr_instance *sr, 
                          uint8_t *original_packet_raw_eth_frame,
                          struct sr_if *dest_interface,
                          uint8_t icmp_type, uint8_t icmp_code);

void send_icmp_echo_reply(struct sr_instance *sr, 
                          uint8_t *packet_raw_eth_frame,
                          struct sr_if *destined_interface,
                          uint8_t icmp_type, uint8_t icmp_code,
                          unsigned int total_packet_len);   

void build_icmp_echo_reply_ip_header(sr_ip_hdr_t* packet_ip_header, 
                                     struct sr_if *outgoing_interface);

void build_icmp_echo_reply_eth_header(sr_ethernet_hdr_t* packet_eth_header, 
                                      struct sr_if *outgoing_interface);

void build_icmp_echo_reply_icmp_header(sr_icmp_t11_hdr_t* packet_icmp_header,
                                       uint8_t icmp_type, 
                                       uint8_t icmp_code,
                                       unsigned int total_packet_len);

void build_new_sending_packet_icmp_header(sr_icmp_t11_hdr_t* new_sending_packet_icmp_header, 
                                  sr_ip_hdr_t* original_packet_ip_header, 
                                  uint8_t icmp_type, 
                                  uint8_t icmp_code);

void build_new_sending_packet_ip_header(sr_ip_hdr_t* new_sending_packet_ip_header, 
                                 sr_ip_hdr_t* original_packet_ip_header, 
                                 unsigned long long new_sending_packet_len,
                                 struct sr_if *dest_interface);

void build_new_sending_packet_eth_header(sr_ethernet_hdr_t* new_sending_packet_eth_header, 
                                 sr_ethernet_hdr_t* original_packet_eth_header, 
                                 struct sr_if *outgoing_interface);

/* extract arp header from packet*/
sr_arp_hdr_t* extract_arp_header(uint8_t *packet, unsigned long long offset);

/* extract ethernet header from packet*/
sr_ethernet_hdr_t* extract_eth_header(uint8_t *packet, unsigned long long offset);

/* extract ip header from packet*/
sr_ip_hdr_t* extract_ip_header(uint8_t *packet, unsigned long long offset);

/* extract icmp header from packet*/
sr_icmp_t11_hdr_t* extract_icmp_header(uint8_t *packet, unsigned long long offset);

/*
    iterate through all entries in the routing table and compare
    the destination ip address of the entry to 
    the destination ip address of the incoming IP packet.
    They have to be exactly matched.
    (do not perform longest-prefix matching)
*/
struct sr_rt * find_entry_in_routing_table(struct sr_instance *sr, 
                                           uint32_t packet_ip_addr);
                                 
                                          

void build_waiting_packet_eth_header(sr_arp_hdr_t *packet_arp_reply_header, 
                                     sr_ethernet_hdr_t *waiting_packet_ethernet_header,
                                     struct sr_if *receiving_interface);

void build_new_arp_reply_packet_arp_header(sr_arp_hdr_t *new_arp_packet_arp_header, 
                                           sr_arp_hdr_t *original_packet_arp_header,
                                           struct sr_if *receiving_interface);

void build_new_arp_reply_packet_eth_header(sr_ethernet_hdr_t *new_arp_packet_eth_header, 
                                           sr_ethernet_hdr_t *original_packet_eth_header,
                                           struct sr_if *receiving_interface);

#endif /* -- SR_UTILS_H -- */
