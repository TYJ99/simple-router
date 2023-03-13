#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/

/*
    void sr_arpcache_sweepreqs(struct sr_instance *sr) {
       for each request on sr->cache.requests:
           handle_arpreq(request)
   }
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    struct sr_arpreq *arp_request = sr->cache.requests;
    struct sr_arpreq *arp_request_next = NULL;
    while (arp_request != NULL) {
        /*
            Since handle_arpreq as defined in the comments above could destroy your
            current request, make sure to save the next pointer before calling
            handle_arpreq when traversing through the ARP requests linked list.
        */
		arp_request_next = arp_request->next;
        handle_arp_request(sr, arp_request);
		arp_request = arp_request_next;
    }
    return;
}

/*
    The handle_arp_request() function is a function you should write, and it should
   handle sending ARP requests if necessary:

   function handle_arp_request(req):
       if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++
*/

void handle_arp_request(struct sr_instance *sr, struct sr_arpreq *arp_request) {
    time_t now = time(NULL);
    if (difftime(now, arp_request->sent) > 1.0) {
        /*
            (1.) If the router gets an ARP response within 5 seconds (5 tries), send the
            packet out toward its destination. Do not store the response in an ARP
            cache. Instead, you will have to send an ARP request for every packet.
            (2.) If an ARP response is not received within 5 seconds (5 tries), send an
            ICMP destination host unreachable message(type 3, code 1) back to the source of the
            packet.
        */
        fprintf(stderr, "arp_request->times_sent: %d\n", arp_request->times_sent);
        if (arp_request->times_sent >= 5) {
            /* 
                List of pkts waiting on this req to finish
                handle one packet on the waiting list at a time.
            */
            struct sr_packet *req_waiting_packet = arp_request->packets;
            
            /*
                send icmp host unreachable(type 3, code 1) to source addr(sender) of 
                all pkts waiting on this request
            */
            uint8_t icmp_type = 3, icmp_code = 1;
            /* int status = 0;*/
            while(req_waiting_packet != NULL) {
                /*struct sr_if *dest_interface = sr_get_interface(sr, req_waiting_packet->iface);*/
                uint8_t *original_packet_raw_eth_frame = req_waiting_packet->buf;
                sr_ip_hdr_t* original_packet_ip_header = extract_ip_header(original_packet_raw_eth_frame, sizeof(sr_ethernet_hdr_t));
                struct sr_rt *next_hop = find_entry_in_routing_table(sr, original_packet_ip_header->ip_src);
                struct sr_if* connected_interface = sr_get_interface(sr, next_hop->interface);
                fprintf(stderr, "send icmp host unreachable(type 3, code 1) to source addr(sender)\n");
                send_icmp_with_type_code(sr, original_packet_raw_eth_frame, connected_interface, icmp_type, icmp_code);
                req_waiting_packet = req_waiting_packet->next;
            }
            sr_arpreq_destroy(&sr->cache, arp_request);
        }else {
            send_arp_request(sr, arp_request);
            arp_request->sent = now;
            arp_request->times_sent++;
        }
    }
        
           
}

/*
    ARP requests and ARP Replies have an ethernet header and ARP header
    If you do not know the target ip mac address, do the following: 
    Set "ethernet" dest addr to :
    FF:FF:FF:FF:FF:FF
    AND
    set "arp" target addr to:
    00:00:00:00:00:00.
    https://baike.baidu.hk/item/ARP/609343
*/
void send_arp_request(struct sr_instance *sr, 
                      struct sr_arpreq *arp_request) {
    
    struct sr_packet *arp_request_packet = arp_request->packets;
    struct sr_if *outgoing_interface = sr_get_interface(sr, arp_request_packet->iface);
    uint32_t target_ip = arp_request->ip;
    /* create a new ARP packet for sending the broadcast MAC address*/
    unsigned long long new_arp_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    uint8_t *new_arp_packet = (uint8_t *)calloc(new_arp_packet_len, sizeof(uint8_t));

    /* extract ethernet header from both new ARP packet*/
    sr_ethernet_hdr_t* new_arp_packet_eth_header = extract_eth_header(new_arp_packet, 0);

    /* extract ARP header from both new ARP packet*/
    sr_arp_hdr_t* new_arp_packet_arp_header = extract_arp_header(new_arp_packet, sizeof(sr_ethernet_hdr_t));

    /* build new ARP ethernet_header*/
    build_new_arp_packet_eth_header(new_arp_packet_eth_header, outgoing_interface);

    /* build new ARP arp_header*/
    build_new_arp_packet_arp_header(new_arp_packet_arp_header, outgoing_interface, target_ip);

    /* send out this new ARP packet*/
    sr_send_packet(sr, new_arp_packet, new_arp_packet_len, outgoing_interface->name);
    free(new_arp_packet);

}

void build_new_arp_packet_arp_header(sr_arp_hdr_t* new_arp_packet_arp_header, struct sr_if *outgoing_interface, uint32_t target_ip) {
    new_arp_packet_arp_header->ar_hrd = htons(arp_hrd_ethernet);                            /* format of hardware address   */
    new_arp_packet_arp_header->ar_pro = htons(ethertype_ip);                                /* format of protocol address   */
    new_arp_packet_arp_header->ar_hln = ETHER_ADDR_LEN;                                     /* length of hardware address   */
    new_arp_packet_arp_header->ar_pln = sizeof(uint32_t);                                   /* length of protocol address   */
    new_arp_packet_arp_header->ar_op = htons(arp_op_request);                               /* ARP opcode (command)         */
    memcpy(new_arp_packet_arp_header->ar_sha, outgoing_interface->addr, ETHER_ADDR_LEN);    /* sender hardware address      */
    new_arp_packet_arp_header->ar_sip = outgoing_interface->ip;                             /* sender IP address            */
    /* set "arp" target addr to: 00:00:00:00:00:00*/
    memset(new_arp_packet_arp_header->ar_tha, 0x00, ETHER_ADDR_LEN);                        /* target hardware address      */
    new_arp_packet_arp_header->ar_tip = target_ip;                                          /* target IP address            */
}

void build_new_arp_packet_eth_header(sr_ethernet_hdr_t* new_arp_packet_eth_header, struct sr_if *outgoing_interface) {
    unsigned char *src_mac_addr = outgoing_interface->addr;
    
    /* ARP requests are sent to the broadcast MAC address (ff-ff-ff-ff-ff-ff).*/
    memset(new_arp_packet_eth_header->ether_dhost, 0xff, ETHER_ADDR_LEN);
    memcpy(new_arp_packet_eth_header->ether_shost, src_mac_addr, ETHER_ADDR_LEN);
    new_arp_packet_eth_header->ether_type = htons(ethertype_arp);
}


/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

