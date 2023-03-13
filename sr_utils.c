#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_if.h"


uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

void print_given_hdr_ip(sr_ip_hdr_t* packet_ip_header) {
  sr_ip_hdr_t *iphdr = packet_ip_header;
  fprintf(stderr, "Given IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += 4;
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

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
                          uint8_t icmp_type, uint8_t icmp_code) {
    
    /* 
        struct sr_if *dest_interface = sr_get_interface(sr, req_waiting_packet->iface);
        uint8_t *original_packet_raw_eth_frame = req_waiting_packet->buf;
      
        create a new packet for sending back to the senders of packets
        that were waiting on a reply to this ARP request
    */
    unsigned long long new_sending_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t);
    uint8_t *new_sending_packet = (uint8_t *)calloc(new_sending_packet_len, sizeof(uint8_t));

    /* extract ethernet header from both new sending packet and original_packet_raw_eth_frame*/
    sr_ethernet_hdr_t* new_sending_packet_eth_header = extract_eth_header(new_sending_packet, 0);
    sr_ethernet_hdr_t* original_packet_eth_header = extract_eth_header(original_packet_raw_eth_frame, 0);

    /* extract ip header from both new sending packet and original_packet_raw_eth_frame*/
    sr_ip_hdr_t* new_sending_packet_ip_header = extract_ip_header(new_sending_packet, sizeof(sr_ethernet_hdr_t));
    sr_ip_hdr_t* original_packet_ip_header = extract_ip_header(original_packet_raw_eth_frame, sizeof(sr_ethernet_hdr_t));

    /* extract icmp header from both new sending packet*/
    sr_icmp_t11_hdr_t* new_sending_packet_icmp_header = extract_icmp_header(new_sending_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* find outgoing interface*/
    /*struct sr_rt *next_hop = NULL;*/
    /*
        if ttl in original_packet_ip_header is 0, 
        send ICMP(type 11, code 0) back to the sending host.
        (do NOT find an entry in the routing table of the router)            
    */
    /*
    struct sr_rt *next_hop = NULL;
    struct sr_if *outgoing_interface = NULL;
    fprintf(stderr, "original_packet_ip_header->ip_ttl: %d\n", original_packet_ip_header->ip_ttl);
    if(original_packet_ip_header->ip_ttl >= 1) {
        next_hop = find_entry_in_routing_table(sr, original_packet_ip_header);
    }
    if(NULL == next_hop) {
        outgoing_interface = dest_interface;
    }else {
        outgoing_interface = sr_get_interface(sr, next_hop->interface);
    }
    */

    struct sr_if *outgoing_interface = dest_interface;

    /* build new ethernet header from original packet*/
    build_new_sending_packet_eth_header(new_sending_packet_eth_header, original_packet_eth_header, outgoing_interface);

    /* build new ip header from original packet*/
    build_new_sending_packet_ip_header(new_sending_packet_ip_header, original_packet_ip_header, new_sending_packet_len, dest_interface);

    /* 
        build new icmp header
        The payload of an ICMP error should contain the IP header 
        and the first 8 bytes of the original datagram.
    */
    build_new_sending_packet_icmp_header(new_sending_packet_icmp_header, original_packet_ip_header, icmp_type, icmp_code);

    /* send out this new sending packet*/
    sr_send_packet(sr, new_sending_packet, new_sending_packet_len, outgoing_interface->name);
    free(new_sending_packet);

}

void send_icmp_echo_reply(struct sr_instance *sr, 
                          uint8_t *packet_raw_eth_frame,
                          struct sr_if *connected_interface,
                          uint8_t icmp_type, uint8_t icmp_code,
                          unsigned int total_packet_len) {
    
    /* struct sr_if *dest_interface = sr_get_interface(sr, original_packet->iface);*/
    /* uint8_t *packet_raw_eth_frame = original_packet->buf;*/
    
    /* create a new packet for sending back to the senders*/
    /*
    unsigned int new_sending_packet_len = total_packet_len;
    uint8_t *new_sending_packet = (uint8_t *)calloc(new_sending_packet_len, sizeof(uint8_t));
    */
    /* extract ethernet header from packet_raw_eth_frame*/
    /*sr_ethernet_hdr_t* new_sending_packet_eth_header = extract_eth_header(new_sending_packet, 0);*/
    sr_ethernet_hdr_t* packet_eth_header = extract_eth_header(packet_raw_eth_frame, 0);

    /* extract ip header from both new sending packet and packet_raw_eth_frame*/
    /*sr_ip_hdr_t* new_sending_packet_ip_header = extract_ip_header(new_sending_packet, sizeof(sr_ethernet_hdr_t));*/
    sr_ip_hdr_t* packet_ip_header = extract_ip_header(packet_raw_eth_frame, sizeof(sr_ethernet_hdr_t));

    /* extract icmp header from packet_raw_eth_frame*/
    sr_icmp_t11_hdr_t* packet_icmp_header = extract_icmp_header(packet_raw_eth_frame, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    
    /* find outgoing interface*/
    /*
    struct sr_rt *next_hop = NULL;
    struct sr_if *outgoing_interface = NULL;
    if(NULL == next_hop) {
        outgoing_interface = dest_interface;
    }else {
        outgoing_interface = sr_get_interface(sr, next_hop->interface);
    }
    */
    struct sr_if *outgoing_interface = connected_interface;

    /* build icmp echo reply ethernet header*/
    build_icmp_echo_reply_eth_header(packet_eth_header, outgoing_interface);

    /* build icmp echo reply ip header*/
    build_icmp_echo_reply_ip_header( packet_ip_header, outgoing_interface);

    /* build icmp echo reply icmp header */
    build_icmp_echo_reply_icmp_header(packet_icmp_header, icmp_type, icmp_code, total_packet_len);

    /* send out this modified packet*/
    sr_send_packet(sr, packet_raw_eth_frame, total_packet_len, outgoing_interface->name);
    /*free(packet_raw_eth_frame);*/

}

void build_icmp_echo_reply_ip_header(sr_ip_hdr_t* packet_ip_header, 
                                     struct sr_if *outgoing_interface) {
    
    fprintf(stderr, "packet_ip_header->ip_dst: ");
    print_addr_ip_int(packet_ip_header->ip_dst);
    packet_ip_header->ip_dst = packet_ip_header->ip_src;
    packet_ip_header->ip_src = outgoing_interface->ip;
    packet_ip_header->ip_sum = 0;
    packet_ip_header->ip_sum = cksum(packet_ip_header, sizeof(sr_ip_hdr_t));
    fprintf(stderr, "outgoing_interface->ip: ");
    print_addr_ip_int(outgoing_interface->ip);
}

void build_icmp_echo_reply_eth_header(sr_ethernet_hdr_t* packet_eth_header, 
                                      struct sr_if *outgoing_interface) {

    uint8_t *dest_mac_addr = packet_eth_header->ether_shost;
    unsigned char *src_mac_addr= outgoing_interface->addr;
    fprintf(stderr, "\n");
    fprintf(stderr, "outgoing_interface->addr: ");
    print_addr_eth(outgoing_interface->addr);
    fprintf(stderr, "packet_eth_header->ether_dhost: ");    
    print_addr_eth(packet_eth_header->ether_dhost);
    fprintf(stderr, "\n");
    memcpy(packet_eth_header->ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
    memcpy(packet_eth_header->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
}

void build_icmp_echo_reply_icmp_header(sr_icmp_t11_hdr_t* packet_icmp_header,
                                       uint8_t icmp_type, 
                                       uint8_t icmp_code,
                                       unsigned int total_packet_len) {

    packet_icmp_header->icmp_type = icmp_type;
    packet_icmp_header->icmp_code = icmp_code;
    /*packet_icmp_header->unused = 0;*/
    packet_icmp_header->icmp_sum = 0;
    unsigned int len = total_packet_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
    packet_icmp_header->icmp_sum = cksum(packet_icmp_header, len);
    
}

void build_new_sending_packet_icmp_header(sr_icmp_t11_hdr_t* new_sending_packet_icmp_header, 
                                  sr_ip_hdr_t* original_packet_ip_header, 
                                  uint8_t icmp_type, 
                                  uint8_t icmp_code) {

    new_sending_packet_icmp_header->icmp_type = icmp_type;
    new_sending_packet_icmp_header->icmp_code = icmp_code;
    new_sending_packet_icmp_header->unused = 0;
    memcpy(new_sending_packet_icmp_header->data, original_packet_ip_header, ICMP_DATA_SIZE);
    new_sending_packet_icmp_header->icmp_sum = 0;
    new_sending_packet_icmp_header->icmp_sum = cksum(new_sending_packet_icmp_header, sizeof(sr_icmp_t11_hdr_t));
    
}

void build_new_sending_packet_ip_header(sr_ip_hdr_t* new_sending_packet_ip_header, 
                                 sr_ip_hdr_t* original_packet_ip_header, 
                                 unsigned long long new_sending_packet_len,
                                 struct sr_if *dest_interface) {

    new_sending_packet_ip_header->ip_hl = original_packet_ip_header->ip_hl;			
    new_sending_packet_ip_header->ip_v = original_packet_ip_header->ip_v; 			
    new_sending_packet_ip_header->ip_tos = original_packet_ip_header->ip_tos;
    /* https://openmaniak.com/ping.php*/
    new_sending_packet_ip_header->ip_len = htons(new_sending_packet_len - sizeof(sr_ethernet_hdr_t)); 
    new_sending_packet_ip_header->ip_id = original_packet_ip_header->ip_id;
    new_sending_packet_ip_header->ip_off = original_packet_ip_header->ip_off;
    new_sending_packet_ip_header->ip_ttl = INIT_TTL;
    new_sending_packet_ip_header->ip_p = ip_protocol_icmp;
    new_sending_packet_ip_header->ip_src = dest_interface->ip; 
    new_sending_packet_ip_header->ip_dst = original_packet_ip_header->ip_src;
    new_sending_packet_ip_header->ip_sum = 0;
    new_sending_packet_ip_header->ip_sum = cksum(new_sending_packet_ip_header, sizeof(sr_ip_hdr_t));
}

void build_new_sending_packet_eth_header(sr_ethernet_hdr_t* new_sending_packet_eth_header, 
                                 sr_ethernet_hdr_t* original_packet_eth_header, 
                                 struct sr_if *outgoing_interface) {

    uint8_t *dest_mac_addr = original_packet_eth_header->ether_shost;
    unsigned char *src_mac_addr= outgoing_interface->addr;
    memcpy(new_sending_packet_eth_header->ether_dhost, dest_mac_addr, ETHER_ADDR_LEN);
    memcpy(new_sending_packet_eth_header->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
    new_sending_packet_eth_header->ether_type = htons(ethertype_ip);
}

/* extract arp header from packet*/
sr_arp_hdr_t* extract_arp_header(uint8_t *packet, unsigned long long offset) {
    return (sr_arp_hdr_t*)(packet + offset);
}

/* extract ethernet header from packet*/
sr_ethernet_hdr_t* extract_eth_header(uint8_t *packet, unsigned long long offset) {
    return (sr_ethernet_hdr_t*)(packet + offset);
}

/* extract ip header from packet*/
sr_ip_hdr_t* extract_ip_header(uint8_t *packet, unsigned long long offset) {
    return (sr_ip_hdr_t*)(packet + offset);
}

/* extract icmp header from packet*/
sr_icmp_t11_hdr_t* extract_icmp_header(uint8_t *packet, unsigned long long offset) {
    return (sr_icmp_t11_hdr_t*)(packet + offset);
}

/*
    iterate through all entries in the routing table and compare
    the destination ip address of the entry to 
    the destination ip address of the incoming IP packet.
    They have to be exactly matched.
    (do not perform longest-prefix matching)
*/
struct sr_rt * find_entry_in_routing_table(struct sr_instance* sr, 
                                           uint32_t packet_ip_addr) {
                                          
    struct sr_rt *next_hop = NULL;
    /*uint32_t packet_ip_addr = packet_ip_header->ip_dst;*/
    struct sr_rt *curr_routing_table_entry = sr->routing_table;
    fprintf(stderr, "in find_entry_in_routing_table\n");
    fprintf(stderr, "packet_ip_addr: ");   
    print_addr_ip_int(packet_ip_addr); 
    while(NULL != curr_routing_table_entry) {
        fprintf(stderr, "curr_routing_table_entry->dest: ");   
        print_addr_ip_int(curr_routing_table_entry->dest.s_addr); 
        if(packet_ip_addr == curr_routing_table_entry->dest.s_addr) {
            fprintf(stderr, "packet_ip_addr == curr_routing_table_entry->dest.s_addr\n");
            next_hop = curr_routing_table_entry;
            fprintf(stderr, "next_hop != NULL\n");
            break;
        }
        curr_routing_table_entry = curr_routing_table_entry->next;
    }    
    return next_hop;
}

void build_waiting_packet_eth_header(sr_arp_hdr_t* packet_arp_reply_header, 
                                     sr_ethernet_hdr_t *waiting_packet_ethernet_header,
                                     struct sr_if *receiving_interface) {

    unsigned char *src_mac_addr = receiving_interface->addr;
    uint8_t *destination_mac_addr = packet_arp_reply_header->ar_sha;
    /* IP packet waiting for ARP reply forward to next hop.*/
    memcpy(waiting_packet_ethernet_header->ether_dhost, destination_mac_addr, ETHER_ADDR_LEN);
    memcpy(waiting_packet_ethernet_header->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
}

void build_new_arp_reply_packet_arp_header(sr_arp_hdr_t* new_arp_packet_arp_header, 
                                           sr_arp_hdr_t* original_packet_arp_header,
                                           struct sr_if *receiving_interface) { 
                                           
    new_arp_packet_arp_header->ar_hrd = original_packet_arp_header->ar_hrd;                        /* format of hardware address   */
    new_arp_packet_arp_header->ar_pro = original_packet_arp_header->ar_pro;                        /* format of protocol address   */
    new_arp_packet_arp_header->ar_hln = original_packet_arp_header->ar_hln;                        /* length of hardware address   */
    new_arp_packet_arp_header->ar_pln = original_packet_arp_header->ar_pln;                        /* length of protocol address   */
    new_arp_packet_arp_header->ar_op = htons(arp_op_reply);                                        /* ARP opcode (command)         */
    memcpy(new_arp_packet_arp_header->ar_sha, receiving_interface->addr, ETHER_ADDR_LEN);          /* sender hardware address      */
    new_arp_packet_arp_header->ar_sip = receiving_interface->ip;                                   /* sender IP address            */
    memcpy(new_arp_packet_arp_header->ar_tha, original_packet_arp_header->ar_sha, ETHER_ADDR_LEN); /* target hardware address      */
    new_arp_packet_arp_header->ar_tip = original_packet_arp_header->ar_sip;                        /* target IP address            */
}

void build_new_arp_reply_packet_eth_header(sr_ethernet_hdr_t* new_arp_packet_eth_header, 
                                           sr_ethernet_hdr_t* original_packet_eth_header,
                                           struct sr_if *receiving_interface) {
    unsigned char *src_mac_addr = receiving_interface->addr;
    
    /* ARP reply is sent back to the sender.*/
    memcpy(new_arp_packet_eth_header->ether_dhost, original_packet_eth_header->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_arp_packet_eth_header->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
    new_arp_packet_eth_header->ether_type = htons(ethertype_arp);
}
