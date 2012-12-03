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
#ifdef __APPLE__
#include <sys/malloc.h>
#elseif !defined(__FreeBSD__)
#include <malloc.h>
#endif

#include "common.h"
#include "prads.h"
#include "config.h"
#include "sys_func.h"
#include "assets.h"
#include "cxt.h"
#include "ipfp/ipfp.h"
#include "servicefp/servicefp.h"
#include "sig.h"
#include "mac.h"
#include "tcp.h"
#include "dump_dns.h"
#include "dhcp.h"
//#include "output-plugins/log_init.h"
#include "output-plugins/log.h"

#ifndef CONFDIR
#define CONFDIR "/etc/prads/"
#endif

#define ARGS "C:c:b:d:Dg:hi:p:r:u:va:l:L:f:qtxs:OXFRMSAKUTIZtHPB"

/*  G L O B A L S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;
extern int optind, opterr, optopt; // getopt()

time_t tstamp;
servicelist *services[MAX_PORTS];
int inpacket, gameover, intr_flag;
int nets = 1;

fmask network[MAX_NETS];

// static strings for comparison
// - this is lame and should be a flag!
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
void parse_eth (packetinfo *pi);
void parse_ip4 (packetinfo *pi);
void parse_ip6 (packetinfo *pi);
void parse_tcp (packetinfo *pi);
void parse_udp (packetinfo *pi);
void parse_icmp (packetinfo *pi);
void parse_gre (packetinfo *pi);
void parse_other (packetinfo *pi);
void parse_arp (packetinfo *pi);
int  parse_network (char *net_s, struct in6_addr *network);
int  parse_netmask (char *f, int type, struct in6_addr *netmask);
void parse_nets(const char *s_net, fmask *network);

void udp_guess_direction(packetinfo *pi);
void set_pkt_end_ptr (packetinfo *pi);
inline int filter_packet(const int af, void *ip);

/* F U N C T I O N S  ********************************************************/

void got_packet(u_char * useless, const struct pcap_pkthdr *pheader,
                const u_char * packet)
{
    config.pr_s.got_packets++;
    packetinfo pstruct = {0};
    packetinfo *pi = &pstruct;
    pi->our = 1;
    pi->packet = packet;
    pi->pheader = pheader;
    set_pkt_end_ptr (pi);
    tstamp = pi->pheader->ts.tv_sec; // Global
    if (intr_flag != 0) {
        check_interrupt();
    }
    inpacket = 1;
    prepare_eth(pi);
    check_vlan(pi);
    parse_eth(pi);

    if (pi->eth_type == ETHERNET_TYPE_IP) {
        prepare_ip4(pi);
        parse_ip4(pi);
        goto packet_end;
    } else if (pi->eth_type == ETHERNET_TYPE_IPV6) {
        prepare_ip6(pi);
        parse_ip6(pi);
        goto packet_end;
    } else if (pi->eth_type == ETHERNET_TYPE_ARP) {
        parse_arp(pi);
        goto packet_end;
    }
    config.pr_s.otherl_recv++;
    vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi->eth_hdr->eth_ip_type);
  packet_end:
#ifdef DEBUG
    if (!pi->our) vlog(0x3, "Not our network packet. Tracked, but not logged.\n");
#endif
    inpacket = 0;
    return;
}

/* does this ip belong to our network? do we care about the packet?
 *
 * unfortunately pcap sends us packets in host order
 * Return value: boolean
 */
inline int filter_packet(const int af, void *ipptr)
//const struct in6_addr *ip_s)
{
    ip6v ip_vec;
    ip6v t;

    int i, our = 0;
    char output[INET_ADDRSTRLEN + 1];
    switch (af) {
        case AF_INET:
        {
            struct in6_addr *ip = (struct in6_addr *) ipptr;
            for (i = 0; i < MAX_NETS && i < nets; i++) {
                if (network[i].type != AF_INET)
                    continue;
#ifdef DEBUG_PACKET
            u_ntop(network[i].addr, af, output);
            dlog("Filter: %s\n", output);
            u_ntop(network[i].mask, af, output);
            dlog("mask: %s\n", output);
            u_ntop(*ip, af, output);
            dlog("ip: %s\n", output);
#endif
                if((IP4ADDR(ip) & IP4ADDR(&network[i].mask))
                    == (IP4ADDR(&network[i].addr) & IP4ADDR(&network[i].mask)) ){
                    our = 1;
                    break;
                }
#ifdef DEBUG_PACKET
                else {
                    dlog("%8x %8x %8x\n", IP4ADDR(ip) & IP4ADDR(&network[i].mask), IP4ADDR(&network[i].addr) & IP4ADDR(&network[i].mask), IP4ADDR(&network[i].mask));
                }
#endif
            }
        }
        break;
        case AF_INET6:
        {
            /* 32-bit comparison of ipv6 nets.
             * can do better here by using 64-bit or SIMD instructions
             * this code needs more thought and work
             *
             *
             * PS: use same code for ipv4 - 0 bytes and SIMD doesnt care*/

            // copy the in6_addr pointed to by ipptr into the vector. grr!
            memcpy(&ip_vec.ip6,ipptr, sizeof(struct in6_addr));
            for (i = 0; i < MAX_NETS && i < nets; i++) {
                if(network[i].type != AF_INET6)
                    continue;
#ifdef DEBUG_PACKET
                u_ntop(network[i].addr, af, output);
                dlog("net:  %s\n", output);
                u_ntop(network[i].mask, af, output);
                dlog("mask: %s\n", output);
                u_ntop(ip_vec.ip6, af, output);
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
                    if ((ip_s.__u6_addr.__u6_addr32[0] & network[i].mask.__u6_addr.__u6_addr32[0])
                        == network[i].addr.__u6_addr.__u6_addr32[0]
                        && (ip_s.__u6_addr.__u6_addr32[1] & network[i].mask.__u6_addr.__u6_addr32[1])
                        == network[i].addr.__u6_addr.__u6_addr32[1]
                        && (ip_s.__u6_addr.__u6_addr32[2] & network[i].mask.__u6_addr.__u6_addr32[2])
                        == network[i].addr.__u6_addr.__u6_addr32[2]
                        && (ip_s.__u6_addr.__u6_addr32[3] & network[i].mask.__u6_addr.__u6_addr32[3])
                        == network[i].addr.__u6_addr.__u6_addr32[3]) {
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
        inet_ntop(af, (struct in6addr*) ipptr, output, MAX_NETS);
    }else{
        inet_ntop(af, (uint32_t*)ipptr, output, MAX_NETS);
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
    if (pi->packet + ETHERNET_HEADER_LEN > pi->end_ptr) return;
    config.pr_s.eth_recv++;
    pi->eth_hdr  = (ether_header *) (pi->packet);
    pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
    pi->eth_hlen = ETHERNET_HEADER_LEN;
    return;
}

void parse_eth (packetinfo *pi)
{
    if (!IS_CSSET(&config,CS_MAC)) return;
    /* update_asset_arp(pi->eth_hdr->ether_src, pi);

    uint8_t *mac = pi->eth_hdr->ether_src;

     * XXX: how is mac matching supposed to work?
     * answer: lookup macs on pertinent frames
     * and hash into mac asset database
     * mac assets are like regular assets,
     * and contain references to other assets they involve
    if(! pi->asset->mace)
    mac_entry *match = match_mac(config.sig_mac, mac, 48);
    //pi->asset->mace ;

    print_mac(mac);
    olog("mac matched: %s\n", match->vendor);
    
    // call update_asset_mac or smth?
    // stats?
    //config.pr_s.eth_recv++;
    */
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
    pi->packet_bytes = (ntohs(pi->ip4->ip_len) - (IP_HL(pi->ip4) * 4));
    
    pi->our = filter_packet(pi->af, &PI_IP4SRC(pi));
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
            parse_tcp(pi);
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
    pi->proto = IP_PROTO_GRE;
    return;
}

void parse_gre (packetinfo *pi)
{
    uint16_t gre_header_len = GRE_HDR_LEN;
    gre_sre_header *gsre = NULL;
    uint16_t len = (pi->pheader->caplen - pi->eth_hlen);

    update_asset(pi);

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
    // may be dropped due to macros plus
    //pi->ip_src = PI_IP6SRC(pi);
    //pi->ip_dst = PI_IP6DST(pi);
    pi->our = filter_packet(pi->af, &PI_IP6SRC(pi));
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
            parse_tcp(pi);
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
         * if (check != 0) { 
         * olog("[*] - CHECKING OTHER PACKAGE\n"); 
         * update_asset(AF_INET6,ip6->ip_src); 
         * service_other(*pi->ip4,*tcph) 
         * fp_other(ip, ttl, ipopts, len, id, ipflags, df); 
         * }else{ 
         * olog("[*] - NOT CHECKING OTHER PACKAGE\n"); 
         * } 
         */
        break;
    }
    return;
}

void parse_arp (packetinfo *pi)
{
    vlog(0x3, "[*] Got ARP packet...\n");
    config.pr_s.arp_recv++;
    if (!IS_CSSET(&config,CS_ARP)) return;
    pi->af = AF_INET;
    pi->arph = (ether_arp *) (pi->packet + pi->eth_hlen);

    if (ntohs(pi->arph->ea_hdr.ar_op) == ARPOP_REPLY) {
        if (filter_packet(pi->af, &pi->arph->arp_spa)) {
            update_asset_arp(pi->arph->arp_sha, pi);
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
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - (IP_HL(pi->ip4) * 4) - pi->eth_hlen);
        pi->payload = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4) + (TCP_OFFSET(pi->tcph) * 4));
    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - IP6_HEADER_LEN - pi->eth_hlen);
        pi->payload = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN + (TCP_OFFSET(pi->tcph)*4));
    }
    pi->proto  = IP_PROTO_TCP;
    pi->s_port = pi->tcph->src_port;
    pi->d_port = pi->tcph->dst_port;
    connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    if(config.payload)
       dump_payload(pi->payload, (config.payload < pi->plen)?config.payload:pi->plen);
    return; 
}

void parse_tcp (packetinfo *pi)
{
    update_asset(pi);

    if (TCP_ISFLAGSET(pi->tcph, (TF_SYN))) {
        if (!TCP_ISFLAGSET(pi->tcph, (TF_ACK))) {
            if (IS_COSET(&config,CO_SYN)) {
                vlog(0x3, "[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(pi->tcph->dst_port));
                fp_tcp(pi, CO_SYN);
                return;
            }
        } else {
            if (IS_COSET(&config,CO_SYNACK)) {
                vlog(0x3, "[*] Got a SYNACK from a SERVER: src_port:%d\n", ntohs(pi->tcph->src_port));
                fp_tcp(pi, CO_SYNACK);
                if (pi->sc != SC_SERVER)
                   reverse_pi_cxt(pi);
                return;
            }
        } 
    }

    // Check payload for known magic bytes that defines files!

    if (pi->sc == SC_CLIENT && !ISSET_CXT_DONT_CHECK_CLIENT(pi)) {
        if (IS_CSSET(&config,CS_TCP_CLIENT)
            && !ISSET_DONT_CHECK_CLIENT(pi)) {
            if (pi->af == AF_INET)
               client_tcp4(pi, config.sig_client_tcp);
            else
               client_tcp6(pi, config.sig_client_tcp);
        }
        goto bastard_checks;

    } else if (pi->sc == SC_SERVER && !ISSET_CXT_DONT_CHECK_SERVER(pi)) {
        if (IS_CSSET(&config,CS_TCP_SERVER)
            && !ISSET_DONT_CHECK_SERVICE(pi)) {
            if (pi->af == AF_INET)
               service_tcp4(pi, config.sig_serv_tcp);
            else
               service_tcp6(pi, config.sig_serv_tcp);
        }
        goto bastard_checks;
    }
    vlog(0x3, "[*] - NOT CHECKING TCP PACKAGE\n");
    return;

bastard_checks:
    if (IS_COSET(&config,CO_ACK)
            && TCP_ISFLAGSET(pi->tcph, (TF_ACK))
            && !TCP_ISFLAGSET(pi->tcph, (TF_SYN))
            && !TCP_ISFLAGSET(pi->tcph, (TF_RST))
            && !TCP_ISFLAGSET(pi->tcph, (TF_FIN))) {
        vlog(0x3, "[*] Got a STRAY-ACK: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp(pi, CO_ACK);
        return;
    } else if (IS_COSET(&config,CO_FIN) && TCP_ISFLAGSET(pi->tcph, (TF_FIN))) {
        vlog(0x3, "[*] Got a FIN: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp(pi, CO_FIN);
        return;
    } else if (IS_COSET(&config,CO_RST) && TCP_ISFLAGSET(pi->tcph, (TF_RST))) {
        vlog(0x3, "[*] Got a RST: src_port:%d\n",ntohs(pi->tcph->src_port));
        fp_tcp(pi, CO_RST);
        return;
    }
}

void prepare_udp (packetinfo *pi)
{
    config.pr_s.udp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    (IP_HL(pi->ip4) * 4) - pi->eth_hlen;
        pi->payload = (pi->packet + pi->eth_hlen +
                        (IP_HL(pi->ip4) * 4) + UDP_HEADER_LEN);

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + + IP6_HEADER_LEN);
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    IP6_HEADER_LEN - pi->eth_hlen;
        pi->payload = (pi->packet + pi->eth_hlen +
                        IP6_HEADER_LEN + UDP_HEADER_LEN);
    }
    pi->proto  = IP_PROTO_UDP;
    pi->s_port = pi->udph->src_port;
    pi->d_port = pi->udph->dst_port;
    connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    if(config.payload)
       dump_payload(pi->payload, (config.payload < pi->plen)?config.payload:pi->plen);
    return;
}

void parse_udp (packetinfo *pi)
{
    update_asset(pi);
    //if (is_set_guess_upd_direction(config)) {
    udp_guess_direction(pi); // fix DNS server transfers?
    // Check for Passive DNS
    if ( ntohs(pi->s_port) == 53 ||  ntohs(pi->s_port) == 5353 ) {
        // For now - Proof of Concept! - Fix output way
        if(config.cflags & CONFIG_PDNS) {
            static char ip_addr_s[INET6_ADDRSTRLEN];
            u_ntop_src(pi, ip_addr_s);
            dump_dns(pi->payload, pi->plen, stdout, "\n", ip_addr_s, pi->pheader->ts.tv_sec);
        }
    }
    if (IS_COSET(&config, CO_DHCP) && ntohs(pi->s_port) == 68 && ntohs(pi->d_port) == 67) {
        dhcp_fingerprint(pi); /* basic DHCP parsing*/
    }
    // if (IS_COSET(&config,CO_DNS) && (pi->sc == SC_SERVER && ntohs(pi->s_port) == 53)) passive_dns (pi);

    if (IS_CSSET(&config,CS_UDP_SERVICES)) {
        if (pi->af == AF_INET) {
            
            if (!ISSET_DONT_CHECK_SERVICE(pi)||!ISSET_DONT_CHECK_CLIENT(pi)) {
                // Check for UDP SERVICE
                service_udp4(pi, config.sig_serv_udp);
            }
            // UPD Fingerprinting
            if (IS_COSET(&config,CO_UDP)) fp_udp4(pi, pi->ip4, pi->udph, pi->end_ptr);
        } else if (pi->af == AF_INET6) {
            if (!ISSET_DONT_CHECK_SERVICE(pi)||!ISSET_DONT_CHECK_CLIENT(pi)) {
                service_udp6(pi, config.sig_client_udp);
            }
            /* fp_udp(ip6, ttl, ipopts, len, id, ipflags, df); */
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
        pi->proto  = IP_PROTO_ICMP;

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE ICMP:\n");
        pi->icmp6h = (icmp6_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
        pi->proto  = IP6_PROTO_ICMP;
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
    update_asset(pi);

    if (IS_COSET(&config,CO_ICMP)) {
        if (pi->cxt->check == 0x00) {
            pi->cxt->check = 0x10; //for now - stop icmp fp quick
            if (pi->af==AF_INET) {
                fp_icmp4(pi, pi->ip4, pi->icmph, pi->end_ptr);
                // could look for icmp spesific data in package abcde...
                // service_icmp(*pi->ip4,*tcph
            } else if (pi->af==AF_INET6) {
                add_asset(pi);
                fp_icmp6(pi, pi->ip6, pi->icmp6h, pi->end_ptr);
            }
        } else {
            vlog(0x3, "[*] - NOT CHECKING ICMP PACKAGE\n");
        }
    }
}

void prepare_other (packetinfo *pi)
{
    config.pr_s.othert_recv++;
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
    update_asset(pi);

    if (pi->cxt->check == 0x00) {
        if (IS_COSET(&config,CO_OTHER)) {
            pi->cxt->check = 0x01; // no more checks
            // service_other(*pi->ip4,*transporth);
            // fp_other(pi->ipX, ttl, ipopts, len, id, ipflags, df);
        } else {
            vlog(0x3, "[*] - NOT CHECKING *OTHER* PACKAGE\n");
        }
    }
}

void udp_guess_direction(packetinfo *pi)
{
    /* Stupid hack :( for DNS/port 53 */
    if (ntohs(pi->d_port) == 53) { 
        if (pi->sc == SC_CLIENT) return;
            else pi->sc = SC_CLIENT;

    } else if (ntohs(pi->s_port) == 53) {
        if (pi->sc == SC_SERVER) return;
            else pi->sc = SC_SERVER;
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
        dlog("Network6 %-36s \t -> %08x:%08x:%08x:%08x\n",
               net_s,
               IP6ADDR(network)
              );
    } else {
        type = AF_INET;
        if (!inet_pton(type, net_s, &IP4ADDR(network))) {
            perror("parse_nets");
            return -1;
        }
        dlog("Network4 %16s \t-> 0x%08x\n", net_s, IP4ADDR(network));
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
        inet_pton(type, f, &IP4ADDR(netmask));
        dlog("mask 4 %s \t-> 0x%08x\n", f, IP4ADDR(netmask));
    } else if (type == AF_INET6 && NULL != (t = strchr(f, ':'))) {
        // full ipv6 netmasĸ
        dlog("mask 6 %s\n", f);
        inet_pton(type, f, netmask);
    } else {
        // cidr form
        sscanf(f, "%u", &mask);
        dlog("cidr  %u \t-> ", mask);
        if (type == AF_INET) {
            uint32_t shift = 32 - mask;
            if (mask)
                IP4ADDR(netmask) = ntohl( ((unsigned int)-1 >> shift)<< shift);
            else
                IP4ADDR(netmask) = 0;

            dlog("0x%08x\n", IP4ADDR(netmask));
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
#ifdef DEBUG
            inet_ntop(type, &IP4ADDR(netmask), output, MAX_NETS);
            dlog("mask: %s\n", output);
#endif
            // pcap packets are in host order.
            IP6ADDR0(netmask) = ntohl(IP6ADDR0(netmask));
            IP6ADDR1(netmask) = ntohl(IP6ADDR1(netmask));
            IP6ADDR2(netmask) = ntohl(IP6ADDR2(netmask));
            IP6ADDR3(netmask) = ntohl(IP6ADDR3(netmask));

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
void parse_nets(const char *s_net, fmask *network)
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

void game_over()
{

    if (inpacket == 0) {
        end_sessions(); /* Need to have correct human output when reading -r pcap */
        clear_asset_list();
        end_all_sessions();
        del_known_services();
        del_signature_lists();
        unload_tcp_sigs();
        end_logging();
        if(!ISSET_CONFIG_QUIET(config)){
           print_prads_stats();
           if(!config.pcap_file)
               print_pcap_stats();
        }
        if (config.handle != NULL) pcap_close(config.handle);
        if (ISSET_CONFIG_SYSLOG(config)) closelog();
        free_config();
        olog("[*] prads ended.\n");
        exit(0);
    }
    intr_flag = 1;
}

void reparse_conf()
{
    if(inpacket == 0) {
        olog("Reparsing config file...");
        parse_config_file(config.file);
        end_sessions();
        intr_flag = 0;
        return;
    }
    intr_flag = 4;
}

void check_interrupt()
{

    if (intr_flag == 1) {
        game_over();
    } else if (intr_flag == 2) {
        update_asset_list();
    } else if (intr_flag == 3) {
        set_end_sessions();
    } else if (intr_flag == 4) {
        reparse_conf();
    } else {
        intr_flag = 0;
    }
}

void set_end_sessions()
{
    intr_flag = 3;

    if (inpacket == 0) {
        tstamp = time(NULL);
        end_sessions();
        /* if no cxtracking is turned on - dont log to disk */
        /* if (log_cxt == 1) log_expired_cxt(); */
        /* if no asset detection is turned on - dont log to disk! */
        /* if (log_assets == 1) update_asset_list(); */
        update_asset_list();
        intr_flag = 0;
        alarm(SIG_ALRM);
    }
}

void print_prads_stats()
{
    extern uint64_t cxtrackerid; // cxt.c
    olog("-- prads:\n");
    olog("-- Total packets received from libpcap    :%12u\n",config.pr_s.got_packets);
    olog("-- Total Ethernet packets received        :%12u\n",config.pr_s.eth_recv);
    olog("-- Total VLAN packets received            :%12u\n",config.pr_s.vlan_recv);
    olog("-- Total ARP packets received             :%12u\n",config.pr_s.arp_recv);
    olog("-- Total IPv4 packets received            :%12u\n",config.pr_s.ip4_recv);
    olog("-- Total IPv6 packets received            :%12u\n",config.pr_s.ip6_recv);
    olog("-- Total Other link packets received      :%12u\n",config.pr_s.otherl_recv);
    olog("-- Total IPinIPv4 packets received        :%12u\n",config.pr_s.ip4ip_recv);
    olog("-- Total IPinIPv6 packets received        :%12u\n",config.pr_s.ip6ip_recv);
    olog("-- Total GRE packets received             :%12u\n",config.pr_s.gre_recv);
    olog("-- Total TCP packets received             :%12u\n",config.pr_s.tcp_recv);
    olog("-- Total UDP packets received             :%12u\n",config.pr_s.udp_recv);
    olog("-- Total ICMP packets received            :%12u\n",config.pr_s.icmp_recv);
    olog("-- Total Other transport packets received :%12u\n",config.pr_s.othert_recv);
    olog("--\n");
    olog("-- Total sessions tracked                 :%12lu\n", cxtrackerid);
    olog("-- Total assets detected                  :%12u\n",config.pr_s.assets);
    olog("-- Total TCP OS fingerprints detected     :%12u\n",config.pr_s.tcp_os_assets);
    olog("-- Total UDP OS fingerprints detected     :%12u\n",config.pr_s.udp_os_assets);
    olog("-- Total ICMP OS fingerprints detected    :%12u\n",config.pr_s.icmp_os_assets);
    olog("-- Total DHCP OS fingerprints detected    :%12u\n",config.pr_s.dhcp_os_assets);
    olog("-- Total TCP service assets detected      :%12u\n",config.pr_s.tcp_services);
    olog("-- Total TCP client assets detected       :%12u\n",config.pr_s.tcp_clients);
    olog("-- Total UDP service assets detected      :%12u\n",config.pr_s.udp_services);
    olog("-- Total UDP client assets detected       :%12u\n",config.pr_s.udp_clients);
}


static void usage()
{
    olog("USAGE:\n");
    olog(" $ prads [options]\n");
    olog("\n");
    olog(" OPTIONS:\n");
    olog("\n");
    olog(" -i <iface>      Network device <iface> (default: eth0).\n");
    olog(" -r <file>       Read pcap <file>.\n");
    olog(" -c <file>       Read config from <file>\n");
    olog(" -b <filter>     Apply Berkeley packet filter <filter>.\n");
    olog(" -u <user>       Run as user <user>.\n");
    olog(" -g <group>      Run as group <group>.\n");
    olog(" -d              Do not drop privileges.\n");
    olog(" -a <nets>       Specify home nets (eg: '192.168.0.0/25,10.0.0.0/255.0.0.0').\n");
    olog(" -D              Daemonize.\n");
    //olog(" -d            to logdir\n");
    olog(" -p <pidfile>    Name of pidfile - inside chroot\n");
    olog(" -l <file>       Log assets to <file> (default: '%s')\n", config.assetlog);
    olog(" -f <FIFO>       Log assets to <FIFO>\n");
    olog(" -B              Log connections to ringbuffer\n");
    olog(" -C <dir>        Chroot into <dir> before dropping privs.\n");
    olog(" -XFRMSAK        Flag picker: X - clear flags, F:FIN, R:RST, M:MAC, S:SYN, A:ACK, K:SYNACK\n");
    olog(" -UTtI           Service checks: U:UDP, T:TCP-server, I:ICMP, t:TCP-cLient\n");
    olog(" -P              DHCP fingerprinting.\n");
    olog(" -s <snaplen>    Dump <snaplen> bytes of each payload.\n");
    olog(" -v              Verbose output - repeat for more verbosity.\n");
    olog(" -q              Quiet - try harder not to produce output.\n");
    olog(" -L <dir>        log cxtracker type output to <dir>.\n");
    olog(" -O              Connection tracking [O]utput - per-packet!\n");
    olog(" -x              Conne[x]ion tracking output  - New, expired and ended.\n");
    olog(" -Z              Passive DNS (Experimental).\n");
    olog(" -H              DHCP fingerprinting (Expermiental).\n");
    olog(" -h              This help message.\n");
}

int load_bpf(globalconfig* conf, const char* file)
{
    int sz, i;
    FILE* fs;
    char* lineptr;
    struct stat statbuf;
    fs = fopen(file, "r");
    if(!fs){
        perror("bpf file");
        return 1;
    }
    if(fstat(fileno(fs), &statbuf)){
        perror("oh god my eyes!");
        fclose(fs);
        return 2;
    }
    sz = statbuf.st_size; 
    if(conf->bpff) free(conf->bpff);
    if(!(conf->bpff = calloc(sz, 1))){
        perror("mem alloc");
        fclose(fs);
        return 3;
    }
    lineptr = conf->bpff;
    // read file but ignore comments and newlines
    while(fgets(lineptr, sz-(conf->bpff-lineptr), fs)) {
        // skip spaces
        for(i=0;;i++) 
            if(lineptr[i] != ' ')
               break;
        // scan ahead and kill comments
        for(i=0;lineptr[i];i++)
            switch(lineptr[i]){
                case '#':                // comment on the line
                    lineptr[i] = '\n';   // end line here
                    lineptr[i+1] = '\0'; // ends outer loop & string
                case '\n':               // end-of-line
                case '\0':               // end-of-string
                    break;
            }
        if(i<=1) continue;               // empty line
        lineptr = lineptr+strlen(lineptr);
    }
    fclose(fs);
    olog("[*] BPF file\t\t %s (%d bytes read)\n", conf->bpf_file, sz);
    if(config.verbose) olog("BPF: { %s}\n", conf->bpff);
    return 0;
}


int prads_initialize(globalconfig *conf)
{
    if (conf->bpf_file) {
        if(load_bpf(conf, conf->bpf_file)){
           elog("[!] Failed to load bpf from file.\n");
        }
    }
    if (conf->pcap_file) {
        struct stat sb;
        if(stat(conf->pcap_file, &sb) || !sb.st_size) {
           elog("[!] '%s' not a pcap. Bailing.\n", conf->pcap_file);
           exit(1);
        }

        /* Read from PCAP file specified by '-r' switch. */
        olog("[*] Reading from file %s\n", conf->pcap_file);
        if (!(conf->handle = pcap_open_offline(conf->pcap_file, conf->errbuf))) {
            olog("[*] Unable to open %s.  (%s)\n", conf->pcap_file, conf->errbuf);
        } 

    } else {
        int uid, gid;
        if(conf->drop_privs_flag) {
            if(getuid() != 0) {
                conf->drop_privs_flag = 0;
                elog("[!] Can't drop privileges, not root.\n");
            } else {
                /* getting numerical ids before chroot call */
                gid = get_gid(conf->group_name);
                uid = get_uid(conf->user_name, &gid);
                if(!gid){
                    elog("[!] Problem finding user %s group %s\n", conf->user_name, conf->group_name);
                    exit(ENOENT);
                }
                if (gid && getuid() == 0 && initgroups(conf->user_name, gid) < 0) {
                    elog("[!] Unable to init group names (%s/%u)\n", conf->user_name, gid);
                }
            }
        }

        /* * look up an available device if non specified */
        if (conf->dev == 0x0)
            conf->dev = pcap_lookupdev(conf->errbuf);
        if (conf->dev){
            *conf->errbuf = 0;
        }else{
            elog("[*] Error looking up device: '%s', try setting device with -i flag.\n", conf->errbuf);
            exit(1);
        }

        olog("[*] Device: %s\n", conf->dev);
    
        if ((conf->handle = pcap_open_live(conf->dev, SNAPLENGTH, 1, 500, conf->errbuf)) == NULL) {
            elog("[!] Error pcap_open_live: %s \n", conf->errbuf);
            exit(1);
        }
        /* * B0rk if we see an error... */
        if (strlen(conf->errbuf) > 0) {
            elog("[*] Error errbuf: %s \n", conf->errbuf);
            exit(1);
        }

        if(conf->chroot_dir){

            olog("[*] Chrooting to dir '%s'..\n", conf->chroot_dir);
            if(set_chroot()){
                elog("[!] failed to chroot\n");
                exit(1);
            }
        }
        /* gotta create/chown pidfile before dropping privs */
        if(conf->pidfile)
            touch_pid_file(conf->pidfile, uid, gid);
    
        if (conf->drop_privs_flag && ( uid || gid)) {
            olog("[*] Dropping privileges to %s:%s...\n", 
               conf->user_name?conf->user_name:"", conf->group_name?conf->group_name:"");
            drop_privs(uid, gid);
        }

       if(conf->pidfile){
            if (!is_valid_path(conf->pidfile)){
                elog("[!] Pidfile '%s' is not writable.\n", conf->pidfile);
                exit(ENOENT);
            }
       }
        if (conf->daemon_flag) {
            olog("[*] Daemonizing...\n");
            daemonize(NULL);
        }
        if (conf->pidfile) {
           int rc;
           if((rc=create_pid_file(conf->pidfile))) {
               elog("[!] pidfile error, wrong permissions or prads already running? %s: %s\n", conf->pidfile, strerror(rc));
               exit(ENOENT);
           }
        }
    }
    return 0;
}

void prads_version(void)
{
    olog("[*] prads %s\n", VERSION);
    olog("    Using %s\n", pcap_lib_version());
    olog("    Using PCRE version %s\n", pcre_version());
}

/* magic main */
int main(int argc, char *argv[])
{
    int32_t rc = 0;
    int ch = 0, verbose_already = 0;

    vlog(2, "%08x =? %08x, endianness: %s\n\n", 0xdeadbeef, ntohl(0xdeadbeef), (0xdead == ntohs(0xdead)?"big":"little") );

    memset(&config, 0, sizeof(globalconfig));
    set_default_config_options(&config);

    inpacket = gameover = intr_flag = 0;

    signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
    signal(SIGQUIT, game_over);
    signal(SIGALRM, set_end_sessions);
    signal(SIGHUP, reparse_conf);
    signal(SIGUSR1, set_end_sessions);
#ifdef DEBUG
    signal(SIGUSR1, cxt_log_buckets);
#endif

    // do first-pass args parse for commandline-passed config file
    opterr = 0;
    while ((ch = getopt(argc, argv, ARGS)) != -1)
        switch (ch) {
        case 'c':
            config.file = optarg;
            break;
        case 'v':
            config.verbose++;
            break;
        case 'q':
            config.cflags |= CONFIG_QUIET;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            break;
        }

    if(config.verbose)
        verbose_already = 1;

    parse_config_file(config.file);

    // reset verbosity before 2nd coming, but only if set on cli
    if(verbose_already)
        config.verbose = 0;
    optind = 1;
    prads_version();

    if(parse_args(&config, argc, argv, ARGS) != 0){
        usage();
        exit(0);
    }

    // we're done parsing configs - now initialize prads

    if(ISSET_CONFIG_SYSLOG(config)) {
        openlog("prads", LOG_PID | LOG_CONS, LOG_DAEMON);
    }

    if(config.cxtlogdir){
       char log_prefix[PATH_MAX];
       snprintf(log_prefix, PATH_MAX, "%sstat.%s", config.cxtlogdir, config.dev?
                  config.dev : "pcap");
       rc = init_logging(LOG_SGUIL, log_prefix, 0);
       if (rc)
          perror("Logging to sguil output failed!");
    }

    if (config.ringbuffer) {
        rc = init_logging(LOG_RINGBUFFER, NULL, config.cflags);
        if (rc)
            perror("Logging to ringbuffer failed!");
    }

    if (config.cflags & (CONFIG_VERBOSE | CONFIG_CXWRITE | CONFIG_CONNECT)) {
        rc = init_logging(LOG_STDOUT, NULL, config.cflags);
        if(rc) perror("Logging to standard out failed!");
    }

    if(config.assetlog) {
        olog("logging to file '%s'\n", config.assetlog);
        rc = init_logging(LOG_FILE, config.assetlog, config.cflags);
        if(rc) perror("Logging to file failed!");
    }
    if(config.fifo) {
        olog("logging to FIFO '%s'\n", config.fifo);
        rc = init_logging(LOG_FIFO, config.fifo, config.cflags);
        if(rc) perror("Logging to fifo failed!");
    }
    if(config.s_net){
       parse_nets(config.s_net, network);
    }
    olog("[*] Loading fingerprints:\n");
/* helper macro to avoid duplicate code */
#define load_foo(func, conf, flag, file, hash, len, dump) \
    if(config. conf & flag) { \
        int _rc; \
        olog("  %-11s %s\n", # flag, (config. file)); \
        _rc = func (config. file, & config. hash, config. len); \
        if(_rc) perror( #flag " load failed!"); \
        else if(config.verbose > 1) { \
            printf("[*] Dumping " #flag " signatures:\n"); \
            dump (config. hash, config. len); \
            printf("[*] " #flag " signature dump ends.\n"); \
        } \
    }

    load_foo(load_mac , cof, CS_MAC, sig_file_mac, sig_mac, mac_hashsize, dump_macs);
    load_foo(load_sigs, ctf, CO_SYN, sig_file_syn, sig_syn, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_SYNACK, sig_file_synack, sig_synack, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_ACK, sig_file_ack, sig_ack, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_FIN, sig_file_fin, sig_fin, sig_hashsize, dump_sigs);
    load_foo(load_sigs, ctf, CO_RST, sig_file_rst, sig_rst, sig_hashsize, dump_sigs);
    load_foo(load_dhcp_sigs, ctf, CO_DHCP, sig_file_dhcp, sig_dhcp, sig_hashsize, dump_dhcp_sigs);
    load_foo(load_servicefp_file, cof, CS_TCP_SERVER, sig_file_serv_tcp, sig_serv_tcp, sig_hashsize, dump_sig_service);
    load_foo(load_servicefp_file, cof, CS_UDP_SERVICES, sig_file_serv_udp, sig_serv_udp, sig_hashsize, dump_sig_service);
    load_foo(load_servicefp_file, cof, CS_TCP_CLIENT, sig_file_cli_tcp, sig_client_tcp, sig_hashsize, dump_sig_service);
    init_services();

    display_config(&config);

    prads_initialize(&config);
 
    alarm(SIG_ALRM);

    /** segfaults on empty pcap! */
    struct bpf_program  cfilter;        /**/
    if ((pcap_compile(config.handle, &cfilter, config.bpff, 1, config.net_mask)) == -1) {
            olog("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(config.handle));
            exit(1);
    }

    if (pcap_setfilter(config.handle, &cfilter)) {
            olog("[*] Unable to set pcap filter!  %s", pcap_geterr(config.handle));
    }
    pcap_freecode(&cfilter);

    cxt_init();
    olog("[*] Sniffing...\n");
    pcap_loop(config.handle, -1, got_packet, NULL);

    game_over();
    return (0);
}

