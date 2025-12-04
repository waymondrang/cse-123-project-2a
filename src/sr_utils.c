#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sr_protocol.h"
#include "sr_utils.h"

uint16_t cksum(const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0; len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons(~sum);
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
    fprintf(stderr, "inet_ntop error on address conversion\n");
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

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_t11_hdr_t *icmp_hdr = (sr_icmp_t11_hdr_t *)(buf);
  if (icmp_hdr->icmp_type == 0 || icmp_hdr->icmp_type == 8) {
    sr_icmp_t08_hdr_t *icmp_t08_hdr = (sr_icmp_t08_hdr_t *)(buf);
    fprintf(stderr, "ICMP Echo header:\n");
    fprintf(stderr, "\ttype: %d\n", icmp_t08_hdr->icmp_type);
    fprintf(stderr, "\tcode: %d\n", icmp_t08_hdr->icmp_code);
    /* Keep checksum in NBO */
    fprintf(stderr, "\tchecksum: %d\n", icmp_t08_hdr->icmp_sum);
    fprintf(stderr, "\tidentifier: %d\n", icmp_t08_hdr->icmp_id);
    fprintf(stderr, "\tsequence number: %d\n", icmp_t08_hdr->icmp_seq);
  } else {
    fprintf(stderr, "ICMP header:\n");
    fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
    fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
    /* Keep checksum in NBO */
    fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
  }
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
  } else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  } else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

// creates a newly malloc'd ethernet header
sr_ethernet_hdr_t *create_ethernet_hdr(uint8_t source_host[ETHER_ADDR_LEN],
                                       uint8_t dest_host[ETHER_ADDR_LEN],
                                       enum sr_ethertype ether_type) {
  sr_ethernet_hdr_t *ethernet_hdr = malloc(sizeof(sr_ethernet_hdr_t));

  // set ethernet source host mac
  memcpy(ethernet_hdr->ether_shost, source_host, ETHER_ADDR_LEN);

  // set ethernet destination host mac
  memcpy(ethernet_hdr->ether_dhost, dest_host, ETHER_ADDR_LEN);

  // set ethernet packet type
  ethernet_hdr->ether_type = htons(ether_type);

  return ethernet_hdr;
}

// populates a ethernet header at a specified location
void populate_ethernet_hdr(sr_ethernet_hdr_t *ethernet_hdr,
                           uint8_t source_host[ETHER_ADDR_LEN],
                           uint8_t dest_host[ETHER_ADDR_LEN],
                           enum sr_ethertype ether_type) {
  // set ethernet source host mac
  memcpy(ethernet_hdr->ether_shost, source_host, ETHER_ADDR_LEN);

  // set ethernet destination host mac
  memcpy(ethernet_hdr->ether_dhost, dest_host, ETHER_ADDR_LEN);

  // set ethernet packet type
  ethernet_hdr->ether_type = htons(ether_type);
}

// note: assumes ip over ethernet
void populate_arp_hdr(sr_arp_hdr_t *arp_hdr, enum sr_arp_opcode opcode,
                      uint8_t source_mac[ETHER_ADDR_LEN], uint32_t source_ip,
                      uint8_t dest_mac[ETHER_ADDR_LEN], uint32_t dest_ip) {
  // see more here:
  // https://web.archive.org/web/20220412004537/http://www.networksorcery.com/enp/protocol/arp.htm#Protocol%20type
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_op = htons(opcode);
  arp_hdr->ar_pln = sizeof(uint32_t);
  arp_hdr->ar_pro = htons(0x800);

  // populate source mac and ip
  memcpy(arp_hdr->ar_sha, source_mac, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = source_ip;

  // populate dest mac and ip
  memcpy(arp_hdr->ar_tha, dest_mac, ETHER_ADDR_LEN);
  arp_hdr->ar_tip = dest_ip;
}

void populate_ip_hdr(sr_ip_hdr_t *ip_hdr, unsigned long body_len,
                     uint32_t source_ip, uint32_t dest_ip, uint8_t protocol) {
  ip_hdr->ip_v = 4;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_tos = 0;
  ip_hdr->ip_id = 0;
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = protocol;

  ip_hdr->ip_off = 0;
  ip_hdr->ip_off |= IP_DF;
  ip_hdr->ip_off = htons(ip_hdr->ip_off);

  ip_hdr->ip_dst = dest_ip;
  ip_hdr->ip_src = source_ip;

  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / sizeof(uint32_t);
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + body_len);
  ip_hdr->ip_sum = 0;

  // important: calculate the checksum last!
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

void populate_icmp_t08_hdr(sr_icmp_t08_hdr_t *icmp_hdr, uint8_t type,
                           uint8_t code, uint16_t id, uint16_t seq) {
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_id = id;
  icmp_hdr->icmp_seq = seq;
  icmp_hdr->icmp_sum = 0;

  // important: calculate checksum over entire header last
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t08_hdr_t));
}

void populate_icmp_t11_hdr(sr_icmp_t11_hdr_t *icmp_hdr, uint8_t type,
                           uint8_t code) {
  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  icmp_hdr->icmp_sum = 0;

  // important: calculate checksum over entire header last
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t11_hdr_t));
}

// ****** LOGGING ************

#include <stdarg.h>

// color codes
#define RESET "\033[0m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"
#define BOLD "\033[1m"
#define DIM "\033[2m"

const char *get_level_color(log_level_t level) {
  switch (level) {
  case LOG_LEVEL_ERROR:
    return RED BOLD;
  case LOG_LEVEL_WARN:
    return YELLOW;
  case LOG_LEVEL_INFO:
    return "";
  case LOG_LEVEL_DEBUG:
    return DIM;
  default:
    return "";
  }
}

const char *get_level_name(log_level_t level) {
  switch (level) {
  case LOG_LEVEL_ERROR:
    return "error";
  case LOG_LEVEL_WARN:
    return "warn";
  case LOG_LEVEL_INFO:
    return "info";
  case LOG_LEVEL_DEBUG:
    return "debug";
  default:
    return "log";
  }
}

void log_message(log_level_t level, int line, const char *fmt, ...) {
  // print colored prefix
  fprintf(stderr, "%s[%s] [line: %d]: ", get_level_color(level),
          get_level_name(level), line);

  // print message
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  fprintf(stderr, "%s\n", RESET);
}