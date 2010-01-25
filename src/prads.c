/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2009, Kacper Wysocki   <kacper.wysocki@redpill-linpro.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*  I N C L U D E S  *********************************************************/
#include <malloc.h>

#include "common.h"
#include "prads.h"
#include "sys_func.h"
#include "assets.h"
#include "cxt.h"
#include "ipfp/ipfp.h"
#include "servicefp/servicefp.h"
#include "util-cxt.h"
#include "util-cxt-queue.h"

/*  G L O B A L E S  *********************************************************/
uint64_t cxtrackerid;
globalconfig config;
time_t tstamp;
connection *bucket[BUCKET_SIZE];
connection *cxtbuffer = NULL;
asset *passet[BUCKET_SIZE];
port_t *lports[255];
signature *sig_serv_tcp = NULL;
signature *sig_serv_udp = NULL;
signature *sig_client_tcp = NULL;
signature *sig_client_udp = NULL;
char src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
int inpacket, gameover, intr_flag;
uint64_t hash;
int nets = 1;

struct fmask network[MAX_NETS];

// static strings for comparison
struct tagbstring tUNKNOWN = bsStatic("unknown");
bstring UNKNOWN = & tUNKNOWN;

/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
void check_vlan (packetinfo *pi);
void prepare_eth (packetinfo *pi);
void prepare_ip4 (packetinfo *pi);
void prepare_ip4ip (packetinfo *pi);
void prepare_ip6 (packetinfo *pi);
void prepare_ip6ip (packetinfo *pi);
void prepare_tcp (packetinfo *pi);
void prepare_udp (packetinfo *pi);
void prepare_icmp (packetinfo *pi);
void prepare_gre (packetinfo *pi);
void prepare_greip (packetinfo *pi);
void prepare_other (packetinfo *pi);
void parse_ip4 (packetinfo *pi);
void parse_ip6 (packetinfo *pi);
void parse_tcp4 (packetinfo *pi);
void parse_tcp6 (packetinfo *pi);
void parse_udp (packetinfo *pi);
void parse_icmp (packetinfo *pi);
void parse_gre (packetinfo *pi);
void parse_other (packetinfo *pi);
void parse_arp (packetinfo *pi);
int  parse_network (char *net_s, struct in6_addr *network);
int  parse_netmask (char *f, int type, struct in6_addr *netmask);
void parse_nets(const char *s_net, struct fmask *network);

void set_pkt_end_ptr (packetinfo *pi);
static inline int filter_packet(const int af, const struct in6_addr *ip_s);

/* F U N C T I O N S  ********************************************************/

void got_packet(u_char * useless, const struct pcap_pkthdr *pheader,
                const u_char * packet)
{
    config.pr_s.got_packets++;
    packetinfo pi;
    memset(&pi, 0, sizeof(packetinfo));
    //pi = (packetinfo *) calloc(1, sizeof(packetinfo));
    pi.our = 1;
    pi.packet = packet;
    pi.pheader = pheader;
    set_pkt_end_ptr (&pi);
    tstamp = pi.pheader->ts.tv_sec; // Global
    if (intr_flag != 0) {
        check_interrupt();
    }
    inpacket = 1;
    prepare_eth(&pi);
    check_vlan(&pi);

    if (pi.eth_type == ETHERNET_TYPE_IP) {
        prepare_ip4(&pi);
        parse_ip4(&pi);
    } else if (pi.eth_type == ETHERNET_TYPE_IPV6) {
        prepare_ip6(&pi);
        parse_ip6(&pi);
    } else if (pi.eth_type == ETHERNET_TYPE_ARP) {
        parse_arp(&pi);
        goto packet_end;
    }
    vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi.eth_hdr->eth_ip_type);
  packet_end:
#ifdef DEBUG
    if (!pi.our) vlog(0x3, "Not our network packet. Tracked, but not logged.\n");
#endif
    inpacket = 0;
    //free(pi);
    return;
}

/* does this ip belong to our network? do we care about the packet?
 *
 * unfortunately pcap sends us packets in host order
 * Return value: boolean
 */
static inline int filter_packet(const int af, const struct in6_addr *ip_s)
{
    uint32_t ip;
    ip6v ip_vec;
    ip6v t;

    int i, our = 0;
    char output[MAX_NETS];
    switch (af) {
        case AF_INET:
        {
            ip = ip_s->s6_addr32[0];
            for (i = 0; i < MAX_NETS && i < nets; i++) {
                if (network[i].type != AF_INET)
                    continue;
#if DEBUG == 2
                inet_ntop(af, &network[i].addr.s6_addr32[0], output, MAX_NETS);
                vlog(0x2, "Filter: %s\n", output);
                inet_ntop(af, &network[i].mask.s6_addr32[0], output, MAX_NETS);
                vlog(0x2, "mask: %s\n", output);
                inet_ntop(af, &ip, output, MAX_NETS);
                vlog(0x2, "ip: %s\n", output);
#endif
                if((ip & network[i].mask.s6_addr32[0])
                    == network[i].addr.s6_addr32[0]) {
                    our = 1;
                    break;
                }
            }
        }
        break;
        case AF_INET6:
        {
            /* 32-bit comparison of ipv6 nets.
             * can do better here by using 64-bit or SIMD instructions
             *
             *
             * PS: use same code for ipv4 - 0 bytes and SIMD doesnt care*/

            ip_vec.ip6 = *ip_s;
            for (i = 0; i < MAX_NETS && i < nets; i++) {
                if(network[i].type != AF_INET6)
                    continue;
#if DEBUG == 2
                inet_ntop(af, &network[i].addr, output, MAX_NETS);
                dlog("net:  %s\n", output);
                inet_ntop(af, &network[i].mask, output, MAX_NETS);
                dlog("mask: %s\n", output);
                inet_ntop(af, &ip_s, output, MAX_NETS);
                dlog("ip: %s\n", output);
#endif
                if (network[i].type == AF_INET6) {
#if(1)
                /* apologies for the uglyness */
#ifdef HAVE_SSE2
#define compare128(x,y) __builtin_ia32_pcmpeqd128((x), (y))
                    // the builtin is only available on sse2! 
                    t.v = __builtin_ia32_pcmpeqd128(
                      ip_vec.v & network[i].mask_v,
                      network[i].addr_v);
                    if (t.i[0] & t.i[1])
#else
#define compare128(x,y) memcmp(&(x),&(y),16)
                    t.v = ip_vec.v & network[i].mask_v;
                    // xor(a,b) == 0 iff a==b
                    if (!( (t.i[0] ^ network[i].addr64[0]) & 
                           (t.i[1] ^ network[i].addr64[1]) ))
#endif
                    {
                        our = 1;
                        break;
                    }

#else
                    if ((ip_s.s6_addr32[0] & network[i].mask.s6_addr32[0])
                        == network[i].addr.s6_addr32[0]
                        && (ip_s.s6_addr32[1] & network[i].mask.s6_addr32[1])
                        == network[i].addr.s6_addr32[1]
                        && (ip_s.s6_addr32[2] & network[i].mask.s6_addr32[2])
                        == network[i].addr.s6_addr32[2]
                        && (ip_s.s6_addr32[3] & network[i].mask.s6_addr32[3])
                        == network[i].addr.s6_addr32[3]) {
                        our = 1;
                        break;
                    }
#endif
                }
            }
        }
        break;
        default:
        fprintf(stderr,
            "non-ip packets of type %d aren't filtered by netmask yet\n", af);
            our = 1;
    }
#ifdef DEBUG
    if (af == AF_INET6){
        inet_ntop(af, &ip_s, output, MAX_NETS);
    }else{
        inet_ntop(af, &ip, output, MAX_NETS);
    }
    if (our){
        vlog(0x2, "Address %s is in our network.\n", output);
    } else {
        vlog(0x2, "Address %s is not our network.\n", output);
    }
#endif
    return our;
}

void prepare_eth (packetinfo *pi)
{
    config.pr_s.eth_recv++;
    pi->eth_hdr  = (ether_header *) (pi->packet);
    pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
    pi->eth_hlen = ETHERNET_HEADER_LEN;
    return;
}

void check_vlan (packetinfo *pi)
{
    if (pi->eth_type == ETHERNET_TYPE_8021Q) {
    vlog(0x3, "[*] ETHERNET TYPE 8021Q\n");
    config.pr_s.vlan_recv++;
    pi->vlan = pi->eth_hdr->eth_8_vid;
    pi->eth_type = ntohs(pi->eth_hdr->eth_8_ip_type);
    pi->eth_hlen += 4;

    /* This is b0rked - kwy and ebf fix */
    } else if (pi->eth_type ==
               (ETHERNET_TYPE_802Q1MT | ETHERNET_TYPE_802Q1MT2 |
                ETHERNET_TYPE_802Q1MT3 | ETHERNET_TYPE_8021AD)) {
        vlog(0x3, "[*] ETHERNET TYPE 802Q1MT\n");
        pi->mvlan = pi->eth_hdr->eth_82_mvid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
        pi->eth_hlen += 8;
    }
    return;
}

void prepare_ip4 (packetinfo *pi)
{
    config.pr_s.ip4_recv++;
    pi->af = AF_INET;
    pi->ip4 = (ip4_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = (pi->ip4->ip_len - (IP_HL(pi->ip4) * 4));
    pi->ip_src.s6_addr32[0] = pi->ip4->ip_src;
    pi->ip_dst.s6_addr32[0] = pi->ip4->ip_dst;
    pi->our = filter_packet(pi->af, &pi->ip_src);
    vlog(0x3, "Got %s IPv4 Packet...\n", (pi->our?"our":"foregin"));
    return;
}

void parse_ip4 (packetinfo *pi)
{
    switch (pi->ip4->ip_p) {
        case IP_PROTO_TCP:
            prepare_tcp(pi);
            if (!pi->our)
                break;
            parse_tcp4(pi);
            break;
        case IP_PROTO_UDP:
            prepare_udp(pi);
            if (!pi->our)
                break;
            parse_udp(pi);
            break;
        case IP_PROTO_ICMP:
            prepare_icmp(pi);
            if (!pi->our)
                break;
            parse_icmp(pi);
            break;
        case IP_PROTO_IP4:
            prepare_ip4ip(pi);
            break;
        case IP_PROTO_IP6:
            prepare_ip4ip(pi);
            break;
        case IP_PROTO_GRE:
            prepare_gre(pi);
            parse_gre(pi);
            break;

        default:
        prepare_other(pi);
        if (!pi->our)
            break;
        parse_other(pi);
    }
    return;
}

void prepare_gre (packetinfo *pi)
{
    config.pr_s.gre_recv++;
    if((pi->pheader->caplen - pi->eth_hlen) < GRE_HDR_LEN)    {
        return;
    }
    if (pi->af == AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE GRE:\n");
        pi->greh = (gre_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
    } else if (pi->af == AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE GRE:\n");
        pi->greh = (gre_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
    }
    return;
}

void parse_gre (packetinfo *pi)
{
    uint16_t gre_header_len = GRE_HDR_LEN;
    gre_sre_header *gsre = NULL;
    uint16_t len = (pi->pheader->caplen - pi->eth_hlen);

    switch (GRE_GET_VERSION(pi->greh))
    {
        case GRE_VERSION_0:
            /* Adjust header length based on content */
            if (GRE_FLAG_ISSET_KY(pi->greh))
                gre_header_len += GRE_KEY_LEN;
            if (GRE_FLAG_ISSET_SQ(pi->greh))
                gre_header_len += GRE_SEQ_LEN;
            if (GRE_FLAG_ISSET_CHKSUM(pi->greh) || GRE_FLAG_ISSET_ROUTE(pi->greh))
                gre_header_len += GRE_CHKSUM_LEN + GRE_OFFSET_LEN;
            if (gre_header_len > len)   {
                return;
            }
            if (GRE_FLAG_ISSET_ROUTE(pi->greh))
            {
                gsre = (gre_sre_header *)(pi->greh + gre_header_len);
                if (gsre == NULL) return;
                while (1)
                {
                    if ((gre_header_len+GRE_SRE_HDR_LEN) > len) {
                        break;
                    }
                    gre_header_len += GRE_SRE_HDR_LEN;

                    if (gsre != NULL && (ntohs(gsre->af) == 0) && (gsre->sre_length == 0))
                        break;

                    gre_header_len += gsre->sre_length;
                    gsre = (gre_sre_header *)(pi->greh + gre_header_len);
                    if (gsre == NULL)
                        return;
                }
            }
            break;

        case GRE_VERSION_1:
            /* GRE version 1 doenst support the fields below RFC 1701 */
            if (GRE_FLAG_ISSET_CHKSUM(pi->greh))    {
                return;
            }
            if (GRE_FLAG_ISSET_ROUTE(pi->greh)) {
                return;
            }
            if (GRE_FLAG_ISSET_SSR(pi->greh))   {
                return;
            }
            if (GRE_FLAG_ISSET_RECUR(pi->greh)) {
                return;
            }
            if (GREV1_FLAG_ISSET_FLAGS(pi->greh))   {
                return;
            }
            if (GRE_GET_PROTO(pi->greh) != GRE_PROTO_PPP)  {
                return;
            }
            if (!(GRE_FLAG_ISSET_KY(pi->greh))) {
                return;
            }

            gre_header_len += GRE_KEY_LEN;

            /* Adjust header length based on content */
            if (GRE_FLAG_ISSET_SQ(pi->greh))
                gre_header_len += GRE_SEQ_LEN;
            if (GREV1_FLAG_ISSET_ACK(pi->greh))
                gre_header_len += GREV1_ACK_LEN;
            if (gre_header_len > len)   {
                return;
            }
            break;

        default:
            /* Error */
            return;
    }

    prepare_greip(pi);
    return;
}

void prepare_ip6ip (packetinfo *pi)
{
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    config.pr_s.ip6ip_recv++;
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
    pipi.end_ptr = pi->end_ptr;
    if (pi->ip6->next == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
        return;
    } else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    }
}

void prepare_greip (packetinfo *pi)
{
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + pi->gre_hlen);
    pipi.end_ptr = pi->end_ptr;
    if (GRE_GET_PROTO(pi->greh) == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
        return;
    } else if (GRE_GET_PROTO(pi->greh) == IP_PROTO_IP6) {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    } else {
        /* Not more implemented atm */
        vlog(0x3, "[*] - NOT CHECKING GRE PACKAGE TYPE Other\n");
        return;
    }
}
void prepare_ip4ip (packetinfo *pi)
{
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    config.pr_s.ip4ip_recv++;
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
    pipi.end_ptr = pi->end_ptr;
    if (pi->ip4->ip_p == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
        return;
    } else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    }
}

void prepare_ip6 (packetinfo *pi)
{
    config.pr_s.ip6_recv++;
    pi->af = AF_INET6;
    pi->ip6 = (ip6_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = pi->ip6->len;
    pi->ip_src = pi->ip6->ip_src;
    pi->ip_dst = pi->ip6->ip_dst;
    pi->our = filter_packet(pi->af, &pi->ip_src);
    vlog(0x3, "Got %s IPv6 Packet...\n", (pi->our?"our":"foregin"));
    return;
}

void parse_ip6 (packetinfo *pi)
{
    switch (pi->ip6->next) {
        case IP_PROTO_TCP:
            prepare_tcp(pi);
            if (!pi->our) 
                break;
            parse_tcp6(pi);
            break;
        case IP_PROTO_UDP:
            prepare_udp(pi);
            if (!pi->our)
                break;
            parse_udp(pi);
            break;
        case IP6_PROTO_ICMP:
            prepare_icmp(pi);
            if (!pi->our)
                break;
            parse_icmp(pi);
            break;
        case IP_PROTO_IP4:
            prepare_ip6ip(pi);
            break;
        case IP_PROTO_IP6:
            prepare_ip6ip(pi);
            break;

        default:
        prepare_other(pi);
        /*
         * if (s_check != 0) { 
         * printf("[*] - CHECKING OTHER PACKAGE\n"); 
         * update_asset(AF_INET6,ip6->ip_src); 
         * service_other(*pi->ip4,*tcph) 
         * fp_other(ip, ttl, ipopts, len, id, ipflags, df); 
         * }else{ 
         * printf("[*] - NOT CHECKING OTHER PACKAGE\n"); 
         * } 
         */
        break;
    }
    return;
}

void parse_arp (packetinfo *pi)
{
    vlog(0x3, "[*] Got ARP packet...\n");
    pi->af = AF_INET;
    pi->arph = (ether_arp *) (pi->packet + pi->eth_hlen);

    if (ntohs(pi->arph->ea_hdr.ar_op) == ARPOP_REPLY) {
        memcpy(&pi->ip_src.s6_addr32[0], pi->arph->arp_spa,
               sizeof(u_int8_t) * 4);
        if (filter_packet(pi->af, &pi->ip_src)) {
            update_asset_arp(pi->arph->arp_sha, pi->ip_src);
        }
        /* arp_check(eth_hdr,pi->pheader->ts.tv_sec); */
    } else {
        vlog(0x3, "[*] ARP TYPE: %d\n",ntohs(pi->arph->ea_hdr.ar_op));
    }
}

void set_pkt_end_ptr (packetinfo *pi)
{
    /* Paranoia! */
    if (pi->pheader->len <= SNAPLENGTH) {
        pi->end_ptr = (pi->packet + pi->pheader->len);
    } else {
        pi->end_ptr = (pi->packet + SNAPLENGTH);
    }
    return;
}

void prepare_tcp (packetinfo *pi)
{
    config.pr_s.tcp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);

    }
    pi->s_port = pi->tcph->src_port;
    pi->d_port = pi->tcph->dst_port;
    connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    return; 
}

void parse_tcp6 (packetinfo *pi)
{
    config.pr_s.tcp_recv++;
    if (IS_COSET(&config,CO_SYN)
        && TCP_ISFLAGSET(pi->tcph, (TF_SYN))
        && !TCP_ISFLAGSET(pi->tcph, (TF_ACK))) {
        fp_tcp6(pi->ip6, pi->tcph, pi->end_ptr, TF_SYN, pi->ip6->ip_src);
        vlog(0x3, "[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(pi->tcph->dst_port));
    } else if (IS_COSET(&config,CO_SYNACK)
               && TCP_ISFLAGSET(pi->tcph, (TF_SYN))
               && TCP_ISFLAGSET(pi->tcph, (TF_ACK))) {
        vlog(0x3, "[*] - Got a SYNACK from a SERVER: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp6(pi->ip6, pi->tcph, pi->end_ptr, TF_SYNACK, pi->ip6->ip_src);
    }
    if (pi->s_check != 0) {
        if (IS_COSET(&config,CO_ACK)
            && TCP_ISFLAGSET(pi->tcph, (TF_ACK))
            && !TCP_ISFLAGSET(pi->tcph, (TF_SYN))) {
            fp_tcp6(pi->ip6, pi->tcph, pi->end_ptr, TF_ACK, pi->ip6->ip_src);
        }
        pi->payload =
            (char *)(pi->packet + pi->eth_hlen + IP6_HEADER_LEN + (TCP_OFFSET(pi->tcph)*4));
        if (IS_CSSET(&config,CS_TCP_SERVER) && pi->s_check == 2) {
            vlog(0x3, "[*] - checking tcp server package\n");
            service_tcp6(pi->ip6, pi->tcph, pi->payload,
                         (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)*4) -
                          IP6_HEADER_LEN - pi->eth_hlen));
        } else if (IS_CSSET(&config,CS_TCP_CLIENT) && pi->s_check == 1) {
            vlog(0x3, "[*] - checking tcp client package\n");
            client_tcp6(pi->ip6, pi->tcph, pi->payload,
                        (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)*4) -
                         IP6_HEADER_LEN - pi->eth_hlen));
        }
    } else {
        vlog(0x3, "[*] - NOT CHECKING TCP PACKAGE\n");
    }
}

void parse_tcp4 (packetinfo *pi)
{
    if (IS_COSET(&config,CO_SYN)
        && TCP_ISFLAGSET(pi->tcph, (TF_SYN))
        && !TCP_ISFLAGSET(pi->tcph, (TF_ACK))) {
        vlog(0x3, "[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(pi->tcph->dst_port));
        fp_tcp4(pi->ip4, pi->tcph, pi->end_ptr, TF_SYN, pi->ip_src);
        update_asset_service(pi->ip_src,
                             pi->tcph->dst_port,
                             pi->ip4->ip_p,
                             UNKNOWN,
                             UNKNOWN, pi->af, CLIENT);
    } else if (IS_COSET(&config,CO_SYNACK)
               && TCP_ISFLAGSET(pi->tcph, (TF_SYN))
               && TCP_ISFLAGSET(pi->tcph, (TF_ACK))) {
        vlog(0x3, "[*] Got a SYNACK from a SERVER: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp4(pi->ip4, pi->tcph, pi->end_ptr, TF_SYNACK, pi->ip_src);
        update_asset_service(pi->ip_src,
                             pi->tcph->src_port,
                             pi->ip4->ip_p,
                             UNKNOWN,
                             UNKNOWN, pi->af, SERVICE);
    } else if (IS_COSET(&config,CO_FIN) && TCP_ISFLAGSET(pi->tcph, (TF_FIN))) {
        vlog(0x3, "[*] Got a FIN: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp4(pi->ip4, pi->tcph, pi->end_ptr, TF_FIN, pi->ip_src);
    } else if (IS_COSET(&config,CO_RST) && TCP_ISFLAGSET(pi->tcph, (TF_RST))) {
        vlog(0x3, "[*] Got a RST: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp4(pi->ip4, pi->tcph, pi->end_ptr, TF_RST, pi->ip_src);
    }

    if (pi->s_check != 0) {
        if (IS_COSET(&config,CO_ACK)
            && TCP_ISFLAGSET(pi->tcph, (TF_ACK))
            && !TCP_ISFLAGSET(pi->tcph, (TF_SYN))
            && !TCP_ISFLAGSET(pi->tcph, (TF_RST))
            && !TCP_ISFLAGSET(pi->tcph, (TF_FIN))) {
            vlog(0x3, "[*] Got a STRAY-ACK: src_port:%d\n",ntohs(pi->tcph->src_port));
            fp_tcp4(pi->ip4, pi->tcph, pi->end_ptr, TF_ACK, pi->ip_src);
        }
        pi->payload =
            (char *)(pi->packet + pi->eth_hlen +
                     (IP_HL(pi->ip4) * 4) + (TCP_OFFSET(pi->tcph) * 4));
        if (IS_CSSET(&config,CS_TCP_SERVER) && pi->s_check == 2) {
            service_tcp4(pi->ip4, pi->tcph, pi->payload,
                         (pi->pheader->caplen -
                          (TCP_OFFSET(pi->tcph)) * 4 - pi->eth_hlen));
        } else if (IS_CSSET(&config,CS_TCP_CLIENT) && pi->s_check == 1) {
            client_tcp4(pi->ip4, pi->tcph, pi->payload,
                        (pi->pheader->caplen -
                         (TCP_OFFSET(pi->tcph)) * 4 - pi->eth_hlen));
        }
    } else {
        vlog(0x3, "[*] - NOT CHECKING TCP PACKAGE\n");
    }
    return;
}

void prepare_udp (packetinfo *pi)
{
    config.pr_s.udp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + + IP6_HEADER_LEN);

    }
    pi->s_port = pi->udph->src_port;
    pi->d_port = pi->udph->dst_port;
    connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    return;
}

void parse_udp (packetinfo *pi)
{
    if (IS_CSSET(&config,CS_UDP_SERVICES) && pi->s_check != 0) {
        if (pi->af == AF_INET) {
            pi->payload =
                (char *)(pi->packet + pi->eth_hlen +
                     (IP_HL(pi->ip4) * 4) + UDP_HEADER_LEN);
            service_udp4(pi->ip4, pi->udph, pi->payload,
                     (pi->pheader->caplen -
                      UDP_HEADER_LEN -
                      (IP_HL(pi->ip4) * 4) - pi->eth_hlen));
            if (IS_COSET(&config,CO_UDP)) fp_udp4(pi->ip4, pi->udph, pi->end_ptr, pi->ip_src);
        } else if (pi->af == AF_INET6) {
            pi->payload =
                (char *)(pi->packet + pi->eth_hlen + IP6_HEADER_LEN + UDP_HEADER_LEN);
            service_udp6(pi->ip6, pi->udph, pi->payload,
                         (pi->pheader->caplen - UDP_HEADER_LEN -
                          IP6_HEADER_LEN - pi->eth_hlen));
            /*
             * fp_udp(ip6, ttl, ipopts, len, id, ipflags, df);
             */
        }
        return;
    } else {
        vlog(0x3, "[*] - NOT CHECKING UDP PACKAGE\n");
        return;
    }
}

void prepare_icmp (packetinfo *pi)
{
    config.pr_s.icmp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE ICMP:\n");
        pi->icmph = (icmp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE ICMP:\n");
        pi->icmp6h = (icmp6_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);

    }
    pi->s_port = 0;
    pi->d_port = 0;
    /*
     * DO change ip6->hop_lmt to 0 or something
     */
    connection_tracking(pi);
    return;
}

void parse_icmp (packetinfo *pi)
{
    if (IS_COSET(&config,CO_ICMP)) {
        if (pi->s_check != 0) {
            if (pi->af==AF_INET) {
                fp_icmp4(pi->ip4, pi->icmph, pi->end_ptr, pi->ip_src);
                // could look for icmp spesific data in package abcde...
                // service_icmp(*pi->ip4,*tcph
            } else if (pi->af==AF_INET6) {
                fp_icmp6(pi->ip6, pi->icmp6h, pi->end_ptr, pi->ip6->ip_src);
            }
        } else {
            vlog(0x3, "[*] - NOT CHECKING ICMP PACKAGE\n");
        }
    }
}

void prepare_other (packetinfo *pi)
{
    config.pr_s.other_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE OTHER: %d\n",pi->ip4->ip_p); 

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE OTHER: %d\n",pi->ip6->next);

    }
    pi->s_port = 0;
    pi->d_port = 0;
    connection_tracking(pi);
    return;
}

void parse_other (packetinfo *pi)
{
    if (pi->s_check != 0) {
        if (IS_COSET(&config,CO_OTHER)) {
            update_asset(pi->af, pi->ip_src);
            // service_other(*pi->ip4,*transporth);
            // fp_other(pi->ipX, ttl, ipopts, len, id, ipflags, df);
        } else {
            vlog(0x3, "[*] - NOT CHECKING *OTHER* PACKAGE\n");
        }
    }
}

int parse_network (char *net_s, struct in6_addr *network)
{
    int type;
    char *t;
    if (NULL != (t = strchr(net_s, ':'))) {
        type = AF_INET6;
        if (!inet_pton(type, net_s, network)) {
            perror("parse_nets6");
            return -1;
        }
        printf("Network6 %-36s \t -> %08x:%08x:%08x:%08x\n",
               net_s,
               network->s6_addr32[0],
               network->s6_addr32[1],
               network->s6_addr32[2],
               network->s6_addr32[3]
              );
    } else {
        type = AF_INET;
        if (!inet_pton(type, net_s, &network->s6_addr32[0])) {
            perror("parse_nets");
            return -1;
        }
        printf("Network4 %16s \t-> 0x%08x\n", net_s, network->s6_addr32[0]);
    }
    return type;
}

int parse_netmask (char *f, int type, struct in6_addr *netmask)
{
    char *t;
    uint32_t mask;
    char output[MAX_NETS];
    // parse netmask into host order
    if (type == AF_INET && (t = strchr(f, '.')) > f && t-f < 4) {
        // full ipv4 netmask : dotted quads
        inet_pton(type, f, &netmask->s6_addr32[0]);
        printf("mask 4 %s \t-> 0x%08x\n", f, netmask->s6_addr32[0]);
    } else if (type == AF_INET6 && NULL != (t = strchr(f, ':'))) {
        // full ipv6 netmasĸ
        printf("mask 6 %s\n", f);
        inet_pton(type, f, netmask);
    } else {
        // cidr form
        sscanf(f, "%u", &mask);
        printf("cidr  %u \t-> ", mask);
        if (type == AF_INET) {
            uint32_t shift = 32 - mask;
            if (mask)
                netmask->s6_addr32[0] = ntohl( ((unsigned int)-1 >> shift)<< shift);
            else
                netmask->s6_addr32[0] = 0;

            printf("0x%08x\n", netmask->s6_addr32[0]);
        } else if (type == AF_INET6) {
            //mask = 128 - mask;
            int j = 0;
            memset(netmask, 0, sizeof(struct in6_addr));

            while (mask > 8) {
                netmask->s6_addr[j++] = 0xff;
                mask -= 8;
            }
            if (mask > 0) {
                netmask->s6_addr[j] = -1 << (8 - mask);
            }
            inet_ntop(type, &netmask->s6_addr32[0], output, MAX_NETS);
            printf("mask: %s\n", output);
            // pcap packets are in host order.
            netmask->s6_addr32[0] = ntohl(netmask->s6_addr32[0]);
            netmask->s6_addr32[1] = ntohl(netmask->s6_addr32[1]);
            netmask->s6_addr32[2] = ntohl(netmask->s6_addr32[2]);
            netmask->s6_addr32[3] = ntohl(netmask->s6_addr32[3]);

        }
    }
    return 0;
}

/* parse strings of the form ip/cidr or ip/mask like:
 * "10.10.10.10/255.255.255.128,10.10.10.10/25" and 
 * "dead:be:eef2:1aa::b5ff:fe96:37a2/64,..."
 *
 * an IPv6 address is 8 x 4 hex digits. missing digits are padded with zeroes.
 */
void parse_nets(const char *s_net, struct fmask *network)
{
    /* f -> for processing
     * p -> frob pointer
     * t -> to pointer */
    char *f, *p, *snet;
    int type, len, i = 0;
    struct in6_addr network6, netmask6;

    // snet is a mutable copy of the args,freed @ nets_end
    len = strlen(s_net);
    //snet = calloc(1, len);
    snet = calloc(1, (len + 1)); /* to have \0 too :-) */
    strncpy(snet, s_net, len);
    f = snet;
    while (f && 0 != (p = strchr(f, '/'))) {
        // convert network address
        *p = '\0';
        type = parse_network(f, &network6);
        if (type != AF_INET && type != AF_INET6) {
            perror("parse_network");
            goto nets_end;
        }
        // convert netmask
        f = p + 1;
        p = strchr(f, ',');
        if (p) {
            *p = '\0';
        }
        parse_netmask(f, type, &netmask6);

        // poke in the gathered information
        switch (type) {
            case AF_INET:
            case AF_INET6:
                network[i].addr = network6;
                network[i].mask = netmask6;
                network[i].type = type;
                break;

            default:
                fprintf(stderr, "parse_nets: invalid address family!\n");
                goto nets_end;
        }

        nets = ++i;

        if (i > MAX_NETS) {
            elog("Max networks reached, stopped parsing at %d nets.\n", i-1);
            goto nets_end;
        }


        // continue parsing at p, which might point to another network range
        f = p;
        if(p) f++;
    }
nets_end:
    free(snet);
    return;
}

void cxt_init()
 {
    /* alloc hash memory */
    cxt_hash = calloc(CXT_DEFAULT_HASHSIZE, sizeof(cxtbucket));
    if (cxt_hash == NULL) {
        printf("calloc failed %s\n", strerror(errno));
        exit(1);
    }
    uint32_t i = 0;

    /* pre allocate conection trackers */
    for (i = 0; i < CXT_DEFAULT_PREALLOC; i++) {
        connection *cxt = connection_alloc();
        if (cxt == NULL) {
            printf("ERROR: connection_alloc failed: %s\n", strerror(errno));
            exit(1);
        }
        cxt_enqueue(&cxt_spare_q,cxt);
     }
}

static void usage()
{
    printf("USAGE:\n");
    printf(" $ prads [options]\n");
    printf("\n");
    printf(" OPTIONS:\n");
    printf("\n");
    printf(" -i             : network device (default: eth0)\n");
    printf(" -b             : berkeley packet filter\n");
    printf(" -d             : path to logdir\n");
    printf(" -u             : user\n");
    printf(" -g             : group\n");
    printf(" -D             : enables daemon mode\n");
    printf(" -h             : this help message\n");
    printf(" -v             : verbose\n");
    printf(" -a             : home nets (eg: '87.238.44.0/25,10.0.0.0/255.0.0.0')\n\n");
}

int preallocate_cxt (void)
{
    int i;
    for (i=0;i<BUCKET_SIZE;i++) {
        bucket[i] = (connection *)calloc(1, sizeof(connection));
        if(bucket[i] == NULL)
            return 0;
    }
    return 1;
}
int main(int argc, char *argv[])
{
    printf("%08x =? %08x, endianness: %s\n\n", 0xdeadbeef, ntohl(0xdeadbeef), (0xdead == ntohs(0xdead)?"big":"little") );
    memset(&config, 0, sizeof(globalconfig));

    // Remind me to get this into a config something!
    config.ctf |= CO_SYN;
    //config.ctf |= CO_RST;
    //config.ctf |= CO_FIN;
    //config.ctf |= CO_ACK;
    config.ctf |= CO_SYNACK;
    config.ctf |= CO_ICMP;
    config.ctf |= CO_UDP;
    //config.ctf |= CO_OTHER;
    config.cof |= CS_TCP_SERVER;
    config.cof |= CS_TCP_CLIENT;
    config.cof |= CS_UDP_SERVICES;
    int ch = 0;
    config.dev = "eth0";
    config.bpff = "";
    config.dpath = "/tmp";
    config.pidfile = "prads.pid";
    config.pidpath = "/var/run";
    cxtbuffer = NULL;
    cxtrackerid = 0;
    inpacket = gameover = intr_flag = 0;
    // default source net owns everything
    config.s_net = "0.0.0.0/0,::/0";

    signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
    signal(SIGQUIT, game_over);
    signal(SIGALRM, set_end_sessions);

    while ((ch = getopt(argc, argv, "b:d:Dg:hi:p:P:u:va:")) != -1)
        switch (ch) {
        case 'a':
            config.s_net = strdup(optarg);
            break;
        case 'i':
            config.dev = strdup(optarg);
            break;
        case 'b':
            config.bpff = strdup(optarg);
            break;
        case 'v':
            config.verbose = 1;
            break;
        case 'd':
            config.dpath = strdup(optarg);
            break;
        case 'h':
            usage();
            exit(0);
            break;
        case 'D':
            config.daemon_flag = 1;
            break;
        case 'u':
            config.user_name = strdup(optarg);
            config.drop_privs_flag = 1;
            break;
        case 'g':
            config.group_name = strdup(optarg);
            config.drop_privs_flag = 1;
            break;
        case 'p':
            config.pidfile = strdup(optarg);
            break;
        case 'P':
            config.pidpath = strdup(optarg);
            break;
        default:
            exit(1);
            break;
        }

    if (getuid()) {
        printf("[*] You must be root..\n");
        return (1);
    }

    parse_nets(config.s_net, network);
    printf("[*] Running prads %s\n", VERSION);
    if (config.verbose) display_config();
    load_servicefp_file(1, "../etc/tcp-service.sig");
    load_servicefp_file(2, "../etc/udp-service.sig");
    load_servicefp_file(3, "../etc/tcp-clients.sig");
    //load_servicefp_file(4,"../etc/udp-client.sig");
    add_known_port(17,1194,bfromcstr("@openvpn"));
    add_known_port(17,123,bfromcstr("@ntp"));
    add_known_port(6,631,bfromcstr("@cups"));

    config.errbuf[0] = '\0';
    /*
     * look up an available device if non specified
     */
    if (config.dev == 0x0)
        config.dev = pcap_lookupdev(config.errbuf);
    printf("[*] Device: %s\n", config.dev);

    if ((config.handle = pcap_open_live(config.dev, SNAPLENGTH, 1, 500, config.errbuf)) == NULL) {
        printf("[*] Error pcap_open_live: %s \n", config.errbuf);
        exit(1);
    } else if ((pcap_compile(config.handle, &config.cfilter, config.bpff, 1, config.net_mask)) == -1) {
        printf("[*] Error pcap_compile user_filter: %s\n",
               pcap_geterr(config.handle));
        exit(1);
    }

    pcap_setfilter(config.handle, &config.cfilter);

    /*
     * B0rk if we see an error...
     */
    if (strlen(config.errbuf) > 0) {
        printf("[*] Error errbuf: %s \n", config.errbuf);
        exit(1);
    }

    if (config.daemon_flag) {
        if (!is_valid_path(config.pidpath))
            printf
                ("[*] PID path \"%s\" is bad, check privilege.", config.pidpath);
        openlog("prads", LOG_PID | LOG_CONS, LOG_DAEMON);
        printf("[*] Daemonizing...\n\n");
        daemonize(NULL);
    }

    if (config.drop_privs_flag) {
        printf("[*] Dropping privs...\n\n");
        drop_privs();
    }

    bucket_keys_NULL();
    alarm(CHECK_TIMEOUT);

    cxt_init();
    printf("[*] Sniffing...\n\n");
    pcap_loop(config.handle, -1, got_packet, NULL);

    pcap_close(config.handle);
    return (0);
}
