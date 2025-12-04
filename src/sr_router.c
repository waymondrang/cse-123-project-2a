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

#include <assert.h>
#include <stdio.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
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

struct sr_if *sr_find_interface_by_ip(struct sr_instance *sr, uint32_t ip) {
  struct sr_if *curr = sr->if_list;

  while (curr != NULL) {
    if (curr->ip == ip) {
      return curr;
    }

    curr = curr->next;
  }

  return NULL;
}

void sr_handle_ip_packet_for_router(struct sr_instance *sr,
                                    uint8_t *packet /* lent */,
                                    unsigned int len,
                                    char *interface /* lent */,
                                    struct sr_if *target_iface) {

  // ****** INTERFACE ************

  struct sr_if *iface = sr_get_interface(sr, interface);

  uint32_t    iface_ip    = iface->ip;
  uint8_t*    iface_mac   = iface->addr;

  // ****** ETHERNET HEADER ************

  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;

  uint8_t*  eth_dest_mac    = ethernet_hdr->ether_dhost;
  uint8_t*  eth_source_mac  = ethernet_hdr->ether_shost;
  uint16_t  eth_type        = ethernet_hdr->ether_type;

  // ****** IP HEADER ************

  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  uint32_t ip_source_ip = ip_hdr->ip_src;
  uint32_t ip_dest_ip   = ip_hdr->ip_dst;

  // ****** ICMP HEADER ************

  sr_icmp_t08_hdr_t* icmp_hdr = (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  uint8_t   icmp_type       = icmp_hdr->icmp_type;
  uint8_t   icmp_code       = icmp_hdr->icmp_code;
  uint16_t  icmp_checksum   = icmp_hdr->icmp_sum;
  uint16_t  icmp_id         = icmp_hdr->icmp_id;
  uint16_t  icmp_seq        = icmp_hdr->icmp_seq;

  // ****** CREATE REPLY PACKET START ************

  unsigned int ip_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                               sizeof(sr_icmp_t08_hdr_t);
  char *ip_packet = malloc(ip_packet_len);

  populate_ethernet_hdr(ip_packet, iface_mac, eth_source_mac, ethertype_ip);
  populate_ip_hdr(ip_packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_icmp_t08_hdr_t), 
                  target_iface->ip, ip_source_ip, ip_protocol_icmp);
  // about icmp replies:
  // https://web.archive.org/web/20210924173933/http://www.networksorcery.com/enp/protocol/icmp/msg0.htm
  populate_icmp_t08_hdr(ip_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t),
                        icmp_echo_reply, NULL, icmp_id, icmp_seq);

  // ****** CREATE REPLY PACKET END ************

  // debug print
  struct in_addr source_ip_addr;
  source_ip_addr.s_addr = ip_source_ip;
  LOG_INFO("sending icmp reply packet to: %s on interface: %s",
           inet_ntoa(source_ip_addr), interface);

  sr_send_packet(sr, ip_packet, ip_packet_len, interface);
}

void sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                         unsigned int len, char *interface /* lent */) {
  // ****** SANITY CHECK PACKET LENGTH ************

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    LOG_ERROR("recieved ip packet is too short to contain ethernet and ip headers (length: %d)", len);
    return;
  }

  // ****** INTERFACE ************

  struct sr_if *iface = sr_get_interface(sr, interface);
  uint32_t iface_ip   = iface->ip;
  uint8_t *iface_mac  = iface->addr;

  // ****** ETHERNET HEADER ************

  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  uint8_t *eth_dest_mac   = ethernet_hdr->ether_dhost;
  uint8_t *eth_source_mac = ethernet_hdr->ether_shost;
  uint16_t eth_type       = ethernet_hdr->ether_type;

  // ****** IP HEADER ************

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_source_ip = ip_hdr->ip_src;
  uint32_t ip_dest_ip   = ip_hdr->ip_dst;

  // ****** SANITY CHECK IP HEADER *********

  uint16_t received_ip_checksum = ip_hdr->ip_sum;

  ip_hdr->ip_sum = 0;
  uint16_t calculated_ip_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  if (received_ip_checksum != calculated_ip_checksum) {
    LOG_ERROR("ip checksum mismatch (received: %d, calculated: %d)",
             received_ip_checksum, calculated_ip_checksum);
    return;
  }

  // ****** FIND NEXT HOP DEST ************

  struct in_addr ip_addr;
  ip_addr.s_addr = ip_dest_ip;

  LOG_DEBUG("determining destination for dest ip: %s", inet_ntoa(ip_addr));

  // check if ip packet is destined for router interface
  struct sr_if *target_iface = sr_find_interface_by_ip(sr, ip_dest_ip);

  if (target_iface != NULL) {
    LOG_DEBUG("handling ip packet destined for router interface: %s",
              target_iface->name);
    sr_handle_ip_packet_for_router(sr, packet, len, interface, target_iface);
  } else {
    // find next hop ip for dest
    struct sr_rt *rt_entry = sr_find_rt_entry(sr, ntohl(ip_dest_ip));

    if (rt_entry != NULL) {

    } else {
      // uh oh...
    }
  }
}

void sr_handle_ack_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                          unsigned int len, char *interface /* lent */) {
  LOG_DEBUG("received arp request on interface: %s", interface);

  // clang-format off

  // ****** INTERFACE ************

  struct sr_if *iface = sr_get_interface(sr, interface);
  uint32_t  iface_ip  = iface->ip;
  char *    iface_mac = iface->addr;

  // ****** ETHERNET HEADER ************

  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;

  // ****** ARP HEADER ************

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  uint32_t  arp_dest_ip     = arp_hdr->ar_tip;
  char *    arp_dest_mac    = arp_hdr->ar_tha;
  uint32_t  arp_source_ip   = arp_hdr->ar_sip;
  char *    arp_source_mac  = arp_hdr->ar_sha;

  // clang-format on

  // assert: request has a broadcast mac address
  assert(memcmp(arp_dest_mac, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN));

  // check if arp is targeted to interface
  if (arp_dest_ip == iface_ip) {
    // immediately reply with arp reply
    char *arp_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

    populate_ethernet_hdr(arp_packet, iface->addr, ethernet_hdr->ether_shost,
                          ethertype_arp);
    populate_arp_hdr(arp_packet + sizeof(sr_ethernet_hdr_t), arp_op_reply,
                     iface->addr, iface->ip, arp_source_mac, arp_source_ip);

    LOG_DEBUG("replied to arp request for interface: %s", interface);

    sr_send_packet(sr, (char *)arp_packet,
                   sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
  }
}

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

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  LOG_INFO("received ethernet packet on interface: %s with length %d",
           interface, len);

  // print contents of packet
  // print_hdrs(packet, len);

  // get type of ethernet packet
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip) {
    LOG_INFO("received ethernet packet is type: ip");
    sr_handle_ip_packet(sr, packet, len, interface);
  } else if (ethtype == ethertype_arp) {
    LOG_INFO("received ethernet packet is type: arp");
    sr_handle_ack_packet(sr, packet, len, interface);
  } else {
    LOG_WARN("received unrecognized ethernet packet type: %d", ethtype);
  }

} /* end sr_ForwardPacket */
