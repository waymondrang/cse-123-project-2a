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

void sr_handle_ip_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                         unsigned int len, char *interface /* lent */) {
  // todo: implement
}

void sr_handle_ack_packet(struct sr_instance *sr, uint8_t *packet /* lent */,
                          unsigned int len, char *interface /* lent */) {
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

  LOG_INFO("received arp request on interface: %s", interface);

  // assert: request has a broadcast mac address
  assert(memcmp(arp_dest_mac, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN));

  // check if arp is targeted to interface
  if (arp_dest_ip == iface_ip) {
    LOG_INFO("received arp request was intended for interface: %s", interface);

    // immediately reply with arp reply
    char *arp_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
    
    populate_ethernet_hdr(arp_packet, iface->addr, ethernet_hdr->ether_shost,
                          ethertype_arp);
    populate_arp_hdr(arp_packet + sizeof(sr_ethernet_hdr_t), arp_op_reply,
                     iface->addr, iface->ip, arp_source_mac, arp_source_ip);

    sr_send_packet(sr, (char *)arp_packet,
                   sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface);

    LOG_INFO("sent arp reply:");
    print_hdrs((char *)arp_packet,
               sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
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

  printf("*** -> Received packet of length %d \n", len);

  // print contents of packet
  print_hdrs(packet, len);

  // get type of ethernet packet
  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip) {
    // todo: implement
    sr_handle_ip_packet(sr, packet, len, interface);
  } else if (ethtype == ethertype_arp) {
    sr_handle_ack_packet(sr, packet, len, interface);
  } else {
    LOG_WARN("received unrecognized ethernet packet type: %d", ethtype);
  }

} /* end sr_ForwardPacket */
