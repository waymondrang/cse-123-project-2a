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

struct sr_if *sr_find_interface_by_name(struct sr_instance *sr, char *name) {
  struct sr_if *curr = sr->if_list;

  while (curr != NULL) {
    if (strncmp(curr->name, name, sr_IFACE_NAMELEN) == 0) {
      return curr;
    }

    curr = curr->next;
  }

  return NULL;
}

void sr_handle_router_icmp_request(struct sr_instance *sr,
                                   uint8_t *packet /* lent */, unsigned int len,
                                   char *interface /* lent */,
                                   struct sr_if *target_iface) {
  // ****** INCOMING INTERFACE ************

  struct sr_if *iface = sr_get_interface(sr, interface);
  uint32_t iface_ip = iface->ip;
  uint8_t *iface_mac = iface->addr;

  // ****** ETHERNET HEADER ************

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  uint8_t *eth_source_mac = eth_hdr->ether_shost;
  uint8_t *eth_dest_mac = eth_hdr->ether_dhost;

  // ****** IP HEADER ************

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_source_ip = ip_hdr->ip_src;
  uint32_t ip_dest_ip = ip_hdr->ip_dst;
  uint8_t ip_protocol = ip_hdr->ip_p;

  // ****** ICMP HEADER ************

  sr_icmp_t08_hdr_t *icmp_hdr =
      (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
                            sizeof(sr_ip_hdr_t));
  uint8_t icmp_type = icmp_hdr->icmp_type;
  uint16_t icmp_id = icmp_hdr->icmp_id;
  uint16_t icmp_seq = icmp_hdr->icmp_seq;

  // ****** CREATE REPLY PACKET ************

  unsigned int ip_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                               sizeof(sr_icmp_t08_hdr_t);
  char *ip_packet = malloc(ip_packet_len);

  populate_ethernet_hdr(ip_packet, iface_mac, eth_source_mac, ethertype_ip);
  populate_ip_hdr(ip_packet + sizeof(sr_ethernet_hdr_t),
                  sizeof(sr_icmp_t08_hdr_t), target_iface->ip, ip_source_ip,
                  ip_protocol_icmp);
  // about icmp replies:
  // https://web.archive.org/web/20210924173933/http://www.networksorcery.com/enp/protocol/icmp/msg0.htm
  populate_icmp_t08_hdr(ip_packet + sizeof(sr_ethernet_hdr_t) +
                            sizeof(sr_ip_hdr_t),
                        icmp_echo_reply, NULL, icmp_id, icmp_seq);

  // ****** SEND PACKET ************

  // debug print
  struct in_addr source_ip_addr;
  source_ip_addr.s_addr = ip_source_ip;
  LOG_INFO("sending icmp reply packet to: %s on interface: %s",
           inet_ntoa(source_ip_addr), interface);

  sr_send_packet(sr, ip_packet, ip_packet_len, interface);
}

void sr_handle_router_icmp_packet(struct sr_instance *sr,
                                  uint8_t *packet /* lent */, unsigned int len,
                                  char *interface /* lent */,
                                  struct sr_if *target_iface) {
  // ****** SANITY CHECK PACKET LENGTH ************

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
                sizeof(sr_icmp_t08_hdr_t)) {
    LOG_ERROR("recieved ip packet is too short to contain ethernet, ip, and "
              "icmp headers (length: %d)",
              len);
    return;
  }

  // ****** ICMP HEADER ************

  sr_icmp_t08_hdr_t *icmp_hdr =
      (sr_icmp_t08_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) +
                            sizeof(sr_ip_hdr_t));
  uint8_t icmp_type = icmp_hdr->icmp_type;

  // ****** DELEGATE ICMP TYPE ************

  if (icmp_type == icmp_echo_request) {
    LOG_DEBUG("icmp packet is type: request");
    sr_handle_router_icmp_request(sr, packet, len, interface, target_iface);
  } else {
    LOG_WARN("icmp packet has unsupported type: %d", icmp_type);
  }
}

void sr_handle_router_ip_packet(struct sr_instance *sr,
                                uint8_t *packet /* lent */, unsigned int len,
                                char *interface /* lent */,
                                struct sr_if *target_iface) {

  // ****** IP HEADER ************

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint8_t ip_protocol = ip_hdr->ip_p;

  // ****** DELEGATE PROTOCOL HANDLING ************

  if (ip_protocol == ip_protocol_icmp) {
    LOG_DEBUG("ip packet contains protocol: icmp");
    sr_handle_router_icmp_packet(sr, packet, len, interface, target_iface);
  } else {
    LOG_WARN("ip packet has unsupported protocol: %d", ip_protocol);
  }
}

void sr_handle_outbound_ip_packet(struct sr_instance *sr,
                                  uint8_t *packet /* lent */, unsigned int len,
                                  char *interface /* lent */,
                                  struct sr_rt *target_rt) {

  // ****** IP HEADER ************

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_source_ip = ip_hdr->ip_src;
  uint32_t ip_dest_ip = ip_hdr->ip_dst;
  uint16_t ip_checksum = ip_hdr->ip_sum;

  // debug
  LOG_DEBUG("adding outbound ip packet to arp queue");

  // note: interface is the one which the ip packet was received on
  sr_arpcache_queuereq(&sr->cache, ip_dest_ip, packet, len, interface);
}

void sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                         unsigned int len, char *interface /* lent */) {
  // ****** SANITY CHECK PACKET LENGTH ************

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    LOG_ERROR("recieved ip packet is too short to contain ethernet and ip "
              "headers (length: %d)",
              len);
    return;
  }

  // ****** IP HEADER ************

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t ip_source_ip = ip_hdr->ip_src;
  uint32_t ip_dest_ip = ip_hdr->ip_dst;
  uint16_t ip_checksum = ip_hdr->ip_sum;

  // ****** SANITY CHECK IP HEADER *********

  ip_hdr->ip_sum = 0;
  uint16_t calculated_ip_checksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  if (ip_checksum != calculated_ip_checksum) {
    LOG_ERROR("ip checksum mismatch (received: %d, calculated: %d)",
              ip_checksum, calculated_ip_checksum);
    return;
  }

  // restore checksum
  ip_hdr->ip_sum = ip_checksum;

  // ****** CHECK IF PACKET IS FOR ROUTER ************

  // check if ip packet is destined for router interface
  struct sr_if *target_iface = sr_find_interface_by_ip(sr, ip_dest_ip);

  // ****** DELEGATE PACKET HANDLING ************

  if (target_iface != NULL) {
    LOG_DEBUG("ip packet is destined for router interface: %s",
              target_iface->name);
    sr_handle_router_ip_packet(sr, packet, len, interface, target_iface);
  } else {
    // find next hop ip for dest
    struct sr_rt *rt_entry = sr_find_rt_entry(sr, ip_dest_ip);

    if (rt_entry != NULL) {
      // debug
      struct in_addr dest_in_addr;
      dest_in_addr.s_addr = ip_dest_ip;
      LOG_DEBUG("ip packet is destined for outbound host: %s",
                inet_ntoa(dest_in_addr));

      sr_handle_outbound_ip_packet(sr, packet, len, interface, rt_entry);
    } else {
      // uh oh...
    }
  }
}

void sr_handle_arp_request(struct sr_instance *sr, uint8_t *packet /* lent */,
                           unsigned int len, char *interface /* lent */) {
  // ****** INCOMING INTERFACE ************

  struct sr_if *iface = sr_get_interface(sr, interface);
  uint32_t iface_ip = iface->ip;
  char *iface_mac = iface->addr;

  // ****** ETHERNET HEADER ************

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  char *eth_source_mac = eth_hdr->ether_shost;

  // ****** ARP HEADER ************

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t arp_dest_ip = arp_hdr->ar_tip;
  char *arp_dest_mac = arp_hdr->ar_tha;
  uint32_t arp_source_ip = arp_hdr->ar_sip;
  char *arp_source_mac = arp_hdr->ar_sha;

  // ****** SANITY CHECK DESTINATION ************

  if (arp_dest_ip != iface_ip) {
    LOG_WARN("arp request is not destined for receiving interface, ignoring");
    return;
  }

  // ****** CREATE ARP REPLY ************

  char *arp_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

  populate_ethernet_hdr(arp_packet, iface_mac, eth_source_mac, ethertype_arp);
  populate_arp_hdr(arp_packet + sizeof(sr_ethernet_hdr_t), arp_op_reply,
                   iface_mac, iface_ip, arp_source_mac, arp_source_ip);

  // debug
  struct in_addr source_ip_addr;
  source_ip_addr.s_addr = arp_source_ip;
  LOG_INFO("sending arp reply to: %s on interface: %s",
           inet_ntoa(source_ip_addr), interface);

  // ****** SEND ARP REPLY ************

  sr_send_packet(sr, (char *)arp_packet,
                 sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);
}

void sr_handle_arp_reply(struct sr_instance *sr, uint8_t *packet /* lent */,
                         unsigned int len, char *interface /* lent */) {
  // ****** INCOMING INTERFACE ************

  struct sr_if *iface = sr_get_interface(sr, interface);
  uint32_t iface_ip = iface->ip;
  char *iface_mac = iface->addr;

  // ****** ETHERNET HEADER ************

  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  char *eth_source_mac = eth_hdr->ether_shost;

  // ****** ARP HEADER ************

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint32_t arp_dest_ip = arp_hdr->ar_tip;
  char *arp_dest_mac = arp_hdr->ar_tha;
  uint32_t arp_source_ip = arp_hdr->ar_sip;
  char *arp_source_mac = arp_hdr->ar_sha;

  // ****** SEND WAITING PACKETS ************

  struct sr_arpreq *arp_req =
      sr_arpcache_insert(&sr->cache, arp_source_mac, arp_source_ip);

  if (arp_req != NULL) {
    struct sr_packet *curr = arp_req->packets;

    while (curr != NULL) {
      // send packet waiting on this arp
      uint8_t *out_packet = curr->buf;
      unsigned int out_packet_len = curr->len;

      // modify ethernet header to reflect source mac of iface and target mac
      // from arp
      sr_ethernet_hdr_t *out_packet_eth_hdr = out_packet;
      memcpy(out_packet_eth_hdr->ether_shost, iface_mac, ETHER_ADDR_LEN);
      memcpy(out_packet_eth_hdr->ether_dhost, arp_source_mac, ETHER_ADDR_LEN);
      // do not change eth type

      // debug
      struct in_addr arp_ip_addr;
      arp_ip_addr.s_addr = arp_source_ip;
      LOG_DEBUG("sending outbound packet for: %s on interface: %s",
                inet_ntoa(arp_ip_addr), interface);

      // send the packet
      sr_send_packet(sr, out_packet, out_packet_len, interface);

      print_hdrs(out_packet, out_packet_len);

      curr = curr->next;
    }

    sr_arpreq_destroy(&sr->cache, arp_req);
  } else {
    LOG_WARN("received arp reply for which no packets were waiting on");
  }
}

void sr_handle_arp_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                          unsigned int len, char *interface /* lent */) {
  // ****** SANITY CHECK PACKET LENGTH ************

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    LOG_ERROR("recieved arp packet is too short to contain ethernet and arp "
              "headers (length: %d)",
              len);
    return;
  }

  // ****** ARP HEADER ************

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  uint16_t arp_op = ntohs(arp_hdr->ar_op);

  if (arp_op == arp_op_request) {
    LOG_DEBUG("arp packet is type: request");
    sr_handle_arp_request(sr, packet, len, interface);
  } else if (arp_op == arp_op_reply) {
    LOG_DEBUG("arp packet is type: reply");
    sr_handle_arp_reply(sr, packet, len, interface);
  } else {
    LOG_WARN("arp packet has unknown opcode: %d", arp_op);
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

  LOG_INFO("****** received ethernet packet on interface: %s with length %d",
           interface, len);

  // print contents of packet
  print_hdrs(packet, len);

  // get type of ethernet packet
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip) {
    LOG_INFO("received ethernet packet is type: ip");
    sr_handle_ip_packet(sr, packet, len, interface);
  } else if (ethtype == ethertype_arp) {
    LOG_INFO("received ethernet packet is type: arp");
    sr_handle_arp_packet(sr, packet, len, interface);
  } else {
    LOG_WARN("received unrecognized ethernet packet type: %d", ethtype);
  }

} /* end sr_ForwardPacket */
