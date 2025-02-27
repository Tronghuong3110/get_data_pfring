/*
 *
 * (C) 2005-23 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lessed General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 *
 */

#include <pfring.h>
#include <pfring_mod_sysdig.h>
#include "pfring_utils.h"

#include <dlfcn.h> /* dlXXXX (e.g. dlopen()) */
#include <linux/if.h>
#ifdef ENABLE_HW_TIMESTAMP
#include <linux/net_tstamp.h>
#endif

#include <sys/ioctl.h>
#include <linux/ethtool.h>

// #define __LITTLE_ENDIAN_BITFIELD /* FIX */

struct iphdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int8_t ihl : 4,
      version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
  u_int8_t version : 4,
      ihl : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
  u_int8_t tos;
  u_int16_t tot_len;
  u_int16_t id;
#define IP_CE 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
  u_int16_t frag_off;
  u_int8_t ttl;
  u_int8_t protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
  /*The options start here. */
};

struct tcphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int32_t seq;
  u_int32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
  u_int16_t res1 : 4,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
  u_int16_t doff : 4,
      res1 : 4,
      cwr : 1,
      ece : 1,
      urg : 1,
      ack : 1,
      psh : 1,
      rst : 1,
      syn : 1,
      fin : 1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
  u_int16_t window;
  u_int16_t check;
  u_int16_t urg_ptr;
};

struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};

#define TH_FIN_MULTIPLIER 0x01
#define TH_SYN_MULTIPLIER 0x02
#define TH_RST_MULTIPLIER 0x04
#define TH_PUSH_MULTIPLIER 0x08
#define TH_ACK_MULTIPLIER 0x10
#define TH_URG_MULTIPLIER 0x20

static u_int32_t pfring_hash_pkt(struct pfring_pkthdr *hdr)
{
  u_int32_t hash = hdr->extended_hdr.parsed_pkt.vlan_id;
  if (hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id == NO_TUNNEL_ID)
  {
    if (hdr->extended_hdr.parsed_pkt.ip_version == 4)
      hash +=
          hdr->extended_hdr.parsed_pkt.ip_src.v4 +
          hdr->extended_hdr.parsed_pkt.ip_dst.v4;
    else
      hash +=
          hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[0] +
          hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[1] +
          hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[2] +
          hdr->extended_hdr.parsed_pkt.ip_src.v6.s6_addr32[3] +
          hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[0] +
          hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[1] +
          hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[2] +
          hdr->extended_hdr.parsed_pkt.ip_dst.v6.s6_addr32[3];
    hash +=
        hdr->extended_hdr.parsed_pkt.l3_proto +
        hdr->extended_hdr.parsed_pkt.l4_src_port +
        hdr->extended_hdr.parsed_pkt.l4_dst_port;
  }
  else
  {
    if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version == 4)
      hash +=
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4 +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4;
    else
      hash +=
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[0] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[1] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[2] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6.s6_addr32[3] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[0] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[1] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[2] +
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6.s6_addr32[3];
    hash +=
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto +
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port +
        hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port;
  }
  return hash;
}

/* ******************************* */

static int __pfring_parse_tunneled_pkt(u_char *data, struct pfring_pkthdr *hdr, u_int16_t ip_version, u_int16_t tunnel_offset)
{
  u_int32_t data_len = hdr->caplen, ip_len = 0;
  u_int16_t fragment_offset = 0;

  if (ip_version == 4 /* IPv4 */)
  {
    struct iphdr *tunneled_ip;

    if (data_len < (tunnel_offset + sizeof(struct iphdr)))
      return 0;

    tunneled_ip = (struct iphdr *)(&data[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version = 4;
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v4 = ntohl(tunneled_ip->saddr);
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v4 = ntohl(tunneled_ip->daddr);
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ip->protocol;

    fragment_offset = tunneled_ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
    ip_len = tunneled_ip->ihl * 4;
    tunnel_offset += ip_len;
  }
  else if (ip_version == 6 /* IPv6 */)
  {
    struct kcompact_ipv6_hdr *tunneled_ipv6;

    if (data_len < (tunnel_offset + sizeof(struct kcompact_ipv6_hdr)))
      return 0;

    tunneled_ipv6 = (struct kcompact_ipv6_hdr *)(&data[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_version = 6;
    /* Values of IPv6 addresses are stored as network byte order */
    memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_src.v6, &tunneled_ipv6->saddr, sizeof(tunneled_ipv6->saddr));
    memcpy(&hdr->extended_hdr.parsed_pkt.tunnel.tunneled_ip_dst.v6, &tunneled_ipv6->daddr, sizeof(tunneled_ipv6->daddr));
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = tunneled_ipv6->nexthdr;

    ip_len = sizeof(struct kcompact_ipv6_hdr);

    /* Note: NEXTHDR_AUTH, NEXTHDR_ESP, NEXTHDR_IPV6, NEXTHDR_MOBILITY are not handled */
    while (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP ||
           hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST ||
           hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING ||
           hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_FRAGMENT)
    {
      struct kcompact_ipv6_opt_hdr *ipv6_opt;

      if (data_len < tunnel_offset + ip_len + sizeof(struct kcompact_ipv6_opt_hdr))
        return 1;

      ipv6_opt = (struct kcompact_ipv6_opt_hdr *)(&data[tunnel_offset + ip_len]);
      ip_len += sizeof(struct kcompact_ipv6_opt_hdr);
      fragment_offset = 0;
      if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_HOP ||
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_DEST ||
          hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_ROUTING)
        ip_len += ipv6_opt->hdrlen * 8;

      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = ipv6_opt->nexthdr;
    }

    if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == NEXTHDR_NONE)
      hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto = 0;

    tunnel_offset += ip_len;
  }
  else
  {
    return 0;
  }

  if (ip_len == 0)
    return 0; /* Bogus IP */

  if (fragment_offset)
    return 1;

  if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_TCP)
  {
    struct tcphdr *tcp;

    if (data_len < tunnel_offset + sizeof(struct tcphdr))
      return 1;

    tcp = (struct tcphdr *)(&data[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(tcp->source),
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(tcp->dest);
  }
  else if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_UDP)
  {
    struct udphdr *udp;

    if (data_len < tunnel_offset + sizeof(struct udphdr))
      return 1;

    udp = (struct udphdr *)(&data[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(udp->source),
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(udp->dest);
  }
  else if (hdr->extended_hdr.parsed_pkt.tunnel.tunneled_proto == IPPROTO_SCTP)
  {
    struct tcphdr *sctp; /* We just want source and dest port here */

    if (data_len < tunnel_offset + 12)
      return 1;

    sctp = (struct tcphdr *)(&data[tunnel_offset]);

    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_src_port = ntohs(sctp->source),
    hdr->extended_hdr.parsed_pkt.tunnel.tunneled_l4_dst_port = ntohs(sctp->dest);
  }

  return 2;
}

/* ******************************* */

int pfring_parse_pkt_ppp(u_char *data, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */,
                         u_int8_t add_timestamp /* 0,1 */, u_int8_t add_hash /* 0,1 */)
{
  struct ethhdr *eh = (struct ethhdr *)data;
  u_int32_t data_len = hdr->caplen, displ = 0, ip_len;
  u_int16_t analyzed = 0, fragment_offset = 0;

  hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = NO_TUNNEL_ID;

  /* Note: in order to optimize the computation, this function expects a zero-ed
   * or partially parsed pkthdr */
  // memset(&hdr->extended_hdr.parsed_pkt, 0, sizeof(struct pkt_parsing_info));

  if (hdr->extended_hdr.parsed_pkt.offset.l3_offset != 0)
    goto L3;

  memcpy(&hdr->extended_hdr.parsed_pkt.dmac, eh->h_dest, sizeof(eh->h_dest));
  memcpy(&hdr->extended_hdr.parsed_pkt.smac, eh->h_source, sizeof(eh->h_source));

  hdr->extended_hdr.parsed_pkt.eth_type = ntohs(eh->h_proto);
  hdr->extended_hdr.parsed_pkt.offset.eth_offset = 0;
  hdr->extended_hdr.parsed_pkt.offset.vlan_offset = 0;
  hdr->extended_hdr.parsed_pkt.vlan_id = 0; /* Any VLAN */

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK 0x0fff
#endif

  if (hdr->extended_hdr.parsed_pkt.eth_type == 0x8100 /* 802.1q (VLAN) */)
  {
    struct eth_vlan_hdr *vh;
    hdr->extended_hdr.parsed_pkt.offset.vlan_offset = sizeof(struct ethhdr);
    vh = (struct eth_vlan_hdr *)&data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
    hdr->extended_hdr.parsed_pkt.vlan_id = ntohs(vh->h_vlan_id) & VLAN_VID_MASK /* 0x0fff */;
    hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
    displ += sizeof(struct eth_vlan_hdr);
    if (hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_8021Q /* 0x8100 802.1q (VLAN) */)
    { /* QinQ */
      hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
      vh = (struct eth_vlan_hdr *)&data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
      hdr->extended_hdr.parsed_pkt.qinq_vlan_id = ntohs(vh->h_vlan_id) & VLAN_VID_MASK;
      hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
      displ += sizeof(struct eth_vlan_hdr);
      while (hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_8021Q /* 802.1q (VLAN) */ && displ <= data_len)
      { /* More QinQ */
        hdr->extended_hdr.parsed_pkt.offset.vlan_offset += sizeof(struct eth_vlan_hdr);
        vh = (struct eth_vlan_hdr *)&data[hdr->extended_hdr.parsed_pkt.offset.vlan_offset];
        hdr->extended_hdr.parsed_pkt.eth_type = ntohs(vh->h_proto);
        displ += sizeof(struct eth_vlan_hdr);
      }
    }
  }

  // code add for vlan and pppoe
  if (hdr->extended_hdr.parsed_pkt.eth_type == ETH_P_PPP_SES /* pppoe */)
  {
    uint16_t pppoe_type_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + sizeof(struct ethhdr) + 6;
    uint16_t pppoe_type = ntohs(*(uint16_t *)&data[pppoe_type_offset]);

    // printf("pppoe_type %04X %u\n",pppoe_type,pppoe_type_offset);
    if (pppoe_type == 0x0021)
      hdr->extended_hdr.parsed_pkt.eth_type = 0x0800; /*IPv4*/
    else if (pppoe_type == 0x0057)
      hdr->extended_hdr.parsed_pkt.eth_type = 0x86DD; /* IPv6 */

    displ += 8; // 8 byte pppoe header
  }

  hdr->extended_hdr.parsed_pkt.offset.l3_offset = hdr->extended_hdr.parsed_pkt.offset.eth_offset + displ + sizeof(struct ethhdr);

L3:

  analyzed = 2;

  if (level < 3)
    goto TIMESTAMP;

  if (hdr->extended_hdr.parsed_pkt.offset.l4_offset != 0)
    goto L4;

  if (hdr->extended_hdr.parsed_pkt.eth_type == 0x0800 /* IPv4 */)
  {
    struct iphdr *ip;

    hdr->extended_hdr.parsed_pkt.ip_version = 4;

    if (data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct iphdr))
      goto TIMESTAMP;

    ip = (struct iphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);

    hdr->extended_hdr.parsed_pkt.ipv4_src = ntohl(ip->saddr);
    hdr->extended_hdr.parsed_pkt.ipv4_dst = ntohl(ip->daddr);
    hdr->extended_hdr.parsed_pkt.l3_proto = ip->protocol;
    hdr->extended_hdr.parsed_pkt.ipv4_tos = ip->tos;
    fragment_offset = ip->frag_off & htons(IP_OFFSET); /* fragment, but not the first */
    ip_len = ip->ihl * 4;
  }
  else if (hdr->extended_hdr.parsed_pkt.eth_type == 0x86DD /* IPv6 */)
  {
    struct kcompact_ipv6_hdr *ipv6;

    hdr->extended_hdr.parsed_pkt.ip_version = 6;

    if (data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + sizeof(struct kcompact_ipv6_hdr))
      goto TIMESTAMP;

    ipv6 = (struct kcompact_ipv6_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset]);
    ip_len = sizeof(struct kcompact_ipv6_hdr);

    /* Values of IPv6 addresses are stored as network byte order */
    memcpy(&hdr->extended_hdr.parsed_pkt.ipv6_src, &ipv6->saddr, sizeof(ipv6->saddr));
    memcpy(&hdr->extended_hdr.parsed_pkt.ipv6_dst, &ipv6->daddr, sizeof(ipv6->daddr));

    hdr->extended_hdr.parsed_pkt.l3_proto = ipv6->nexthdr;
    hdr->extended_hdr.parsed_pkt.ipv6_tos = ipv6->priority; /* IPv6 class of service */

    /* Note: NEXTHDR_AUTH, NEXTHDR_ESP, NEXTHDR_IPV6, NEXTHDR_MOBILITY are not handled */
    while (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP ||
           hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST ||
           hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING ||
           hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_FRAGMENT)
    {
      struct kcompact_ipv6_opt_hdr *ipv6_opt;

      if (data_len < hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len + sizeof(struct kcompact_ipv6_opt_hdr))
        goto TIMESTAMP;

      ipv6_opt = (struct kcompact_ipv6_opt_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len]);
      ip_len += sizeof(struct kcompact_ipv6_opt_hdr);
      if (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_HOP ||
          hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_DEST ||
          hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_ROUTING)
        ip_len += ipv6_opt->hdrlen * 8;

      hdr->extended_hdr.parsed_pkt.l3_proto = ipv6_opt->nexthdr;
    }

    if (hdr->extended_hdr.parsed_pkt.l3_proto == NEXTHDR_NONE)
      hdr->extended_hdr.parsed_pkt.l3_proto = 0;
  }
  else
  {
    hdr->extended_hdr.parsed_pkt.l3_proto = 0;
    goto TIMESTAMP;
  }

  if (ip_len == 0)
    goto TIMESTAMP; /* Bogus IP */

  hdr->extended_hdr.parsed_pkt.offset.l4_offset = hdr->extended_hdr.parsed_pkt.offset.l3_offset + ip_len;

L4:

  analyzed = 3;

  if (level < 4 || fragment_offset)
    goto TIMESTAMP;

  if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_TCP)
  {
    struct tcphdr *tcp;

    if (data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct tcphdr))
      goto TIMESTAMP;

    tcp = (struct tcphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

    hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(tcp->source);
    hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(tcp->dest);
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + (tcp->doff * 4);
    hdr->extended_hdr.parsed_pkt.tcp.seq_num = ntohl(tcp->seq);
    hdr->extended_hdr.parsed_pkt.tcp.ack_num = ntohl(tcp->ack_seq);
    hdr->extended_hdr.parsed_pkt.tcp.flags = (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
                                             (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
                                             (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

    analyzed = 4;
  }
  else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_UDP)
  {
    struct udphdr *udp;

    if (data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr))
      goto TIMESTAMP;

    udp = (struct udphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

    hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(udp->source), hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(udp->dest);
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + sizeof(struct udphdr);

    analyzed = 4;

    if (level < 5)
      goto TIMESTAMP;

    /* GTPv1 */
    if ((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_SIGNALING_PORT) ||
        (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_SIGNALING_PORT) ||
        (hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT) ||
        (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT))
    {
      struct gtp_v1_hdr *gtp;
      u_int16_t gtp_len;

      if (data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + sizeof(struct gtp_v1_hdr)))
        goto TIMESTAMP;

      gtp = (struct gtp_v1_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset]);
      gtp_len = sizeof(struct gtp_v1_hdr);

      if (((gtp->flags & GTP_FLAGS_VERSION) >> GTP_FLAGS_VERSION_SHIFT) == GTP_VERSION_1)
      {
        struct iphdr *tunneled_ip;

        hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(gtp->teid);

        if ((hdr->extended_hdr.parsed_pkt.l4_src_port == GTP_U_DATA_PORT) ||
            (hdr->extended_hdr.parsed_pkt.l4_dst_port == GTP_U_DATA_PORT))
        {
          if (gtp->flags & (GTP_FLAGS_EXTENSION | GTP_FLAGS_SEQ_NUM | GTP_FLAGS_NPDU_NUM))
          {
            struct gtp_v1_opt_hdr *gtpopt;

            if (data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len + sizeof(struct gtp_v1_opt_hdr)))
              goto TIMESTAMP;

            gtpopt = (struct gtp_v1_opt_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);
            gtp_len += sizeof(struct gtp_v1_opt_hdr);

            if ((gtp->flags & GTP_FLAGS_EXTENSION) && gtpopt->next_ext_hdr)
            {
              struct gtp_v1_ext_hdr *gtpext;
              u_int8_t *next_ext_hdr;

              do
              {
                if (data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len + 1 /* 8bit len field */))
                  goto TIMESTAMP;
                gtpext = (struct gtp_v1_ext_hdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);
                gtp_len += (gtpext->len * GTP_EXT_HDR_LEN_UNIT_BYTES);
                if (gtpext->len == 0 || data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len))
                  goto TIMESTAMP;
                next_ext_hdr = (u_int8_t *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len - 1 /* 8bit next_ext_hdr field*/]);
              } while (*next_ext_hdr);
            }
          }

          if (data_len < (hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len + sizeof(struct iphdr)))
            goto TIMESTAMP;

          tunneled_ip = (struct iphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len]);

          analyzed += __pfring_parse_tunneled_pkt(data, hdr, tunneled_ip->version, hdr->extended_hdr.parsed_pkt.offset.payload_offset + gtp_len);
        }
      }
    }
  }
  else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_GRE /* 0x47 */)
  {
    struct gre_header *gre = (struct gre_header *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);
    int gre_offset;

    gre->flags_and_version = ntohs(gre->flags_and_version);
    gre->proto = ntohs(gre->proto);

    gre_offset = sizeof(struct gre_header);

    if ((gre->flags_and_version & GRE_HEADER_VERSION) == 0)
    {
      if (gre->flags_and_version & (GRE_HEADER_CHECKSUM | GRE_HEADER_ROUTING))
        gre_offset += 4;
      if (gre->flags_and_version & GRE_HEADER_KEY)
      {
        u_int32_t *tunnel_id = (u_int32_t *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset + gre_offset]);
        gre_offset += 4;
        hdr->extended_hdr.parsed_pkt.tunnel.tunnel_id = ntohl(*tunnel_id);
      }
      if (gre->flags_and_version & GRE_HEADER_SEQ_NUM)
        gre_offset += 4;

      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset + gre_offset;

      analyzed = 4;

      if (level < 5)
        goto TIMESTAMP;

      if (gre->proto == ETH_P_IP /* IPv4 */ || gre->proto == ETH_P_IPV6 /* IPv6 */)
        analyzed += __pfring_parse_tunneled_pkt(data, hdr, gre->proto == ETH_P_IP ? 4 : 6, hdr->extended_hdr.parsed_pkt.offset.payload_offset);
    }
    else
    { /* TODO handle other GRE versions */
      hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
    }
  }
  else if (hdr->extended_hdr.parsed_pkt.l3_proto == IPPROTO_SCTP /* 132 */)
  {
    struct tcphdr *sctp; /* We just want source and dest port here */

    if (data_len < hdr->extended_hdr.parsed_pkt.offset.l4_offset + 12)
      goto TIMESTAMP;

    sctp = (struct tcphdr *)(&data[hdr->extended_hdr.parsed_pkt.offset.l4_offset]);

    hdr->extended_hdr.parsed_pkt.l4_src_port = ntohs(sctp->source);
    hdr->extended_hdr.parsed_pkt.l4_dst_port = ntohs(sctp->dest);

    /* No payload offset for SCTP */
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;

    analyzed = 4;
  }
  else
  {
    hdr->extended_hdr.parsed_pkt.offset.payload_offset = hdr->extended_hdr.parsed_pkt.offset.l4_offset;
    hdr->extended_hdr.parsed_pkt.l4_src_port = hdr->extended_hdr.parsed_pkt.l4_dst_port = 0;
  }

TIMESTAMP:

  if (add_timestamp && hdr->ts.tv_sec == 0)
    gettimeofday(&hdr->ts, NULL); /* TODO What about using clock_gettime(CLOCK_REALTIME, ts) ? */

  if (add_hash && hdr->extended_hdr.pkt_hash == 0)
    hdr->extended_hdr.pkt_hash = pfring_hash_pkt(hdr);

  return analyzed;
}
