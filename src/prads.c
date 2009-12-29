/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
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
#include "common.h"
#include "prads.h"
#include "sys_func.h"
#include "assets.h"
#include "cxt.h"
#include "ipfp/ipfp.h"
#include "servicefp/servicefp.h"

/*  G L O B A L E S  *********************************************************/
uint64_t cxtrackerid;
time_t timecnt, tstamp;
pcap_t *handle;
connection *bucket[BUCKET_SIZE];
connection *cxtbuffer = NULL;
asset *passet[BUCKET_SIZE];
signature *sig_serv_tcp = NULL;
signature *sig_serv_udp = NULL;
signature *sig_client_tcp = NULL;
signature *sig_client_udp = NULL;
char src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
static char *dev, *dpath;
//bstring      sunknown;
//sunknown  = bformat("unknown");
char *chroot_dir;
char *group_name, *user_name, *true_pid_name;
char *pidfile = "prads.pid";
char *pidpath = "/var/run";
int verbose, inpacket, gameover, use_syslog, intr_flag, s_check;
uint64_t hash;
// default source net owns everything
char *s_net = "0.0.0.0/0";
int nets = 1;
//char *s_net = "87.238.44.0/255.255.255.0,87.238.45.0/26,87.238.44.60/32";
uint32_t network[MAX_NETS];
uint32_t netmask[MAX_NETS];

/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();

/* F U N C T I O N S  ********************************************************/

/* does this ip belong to our network? do we care about the packet?
 * Return value: boolean                                                     */
int filter_packet(int af, struct in6_addr ip_s)
{
    char tmp[MAX_NETS];
    int our = 0;
    if (af == AF_INET) {
        uint32_t ip = ip_s.s6_addr32[0];
        inet_ntop(af, &ip, tmp, MAX_NETS);
        int i;
        our = 0;
        for (i = 0; i < MAX_NETS && i < nets; i++) {
            if ((ip & netmask[i]) == network[i]) {
                our = 1;
            }
        }
#ifdef DEBUG_MUCH
        if (our)
            fprintf(stderr, "Address %s is in our network.\n", tmp);
        else
            fprintf(stderr, "Address %s is not our network.\n", tmp);
#endif
    } else {
        fprintf(stderr, "ipv6 packets aren't filtered by netmask yet\n");
        our = 1;
    }
    return our;
}

void got_packet(u_char * useless, const struct pcap_pkthdr *pheader,
                const u_char * packet)
{
    int our = 1;
    if (intr_flag != 0) {
        // printf("[*] Checking interrupt...\n"); 
        check_interupt();
    }
    inpacket = 1;
    s_check = 0;                // do we need to ?
    tstamp = time(NULL);
    u_short p_bytes;

    // unwrap ethernet
    ether_header *eth_hdr;
    eth_hdr = (ether_header *) (packet);
    u_short eth_type;
    eth_type = ntohs(eth_hdr->eth_ip_type);
    int eth_header_len;
    eth_header_len = ETHERNET_HEADER_LEN;

    /*
     * while (ETHERNET_TYPE_X) check for infinit vlan tags 
     */
    if (eth_type == ETHERNET_TYPE_8021Q) {
        // printf("[*] ETHERNET TYPE 8021Q\n"); 
        eth_type = ntohs(eth_hdr->eth_8_ip_type);
        eth_header_len += 4;
    } else if (eth_type ==
               (ETHERNET_TYPE_802Q1MT | ETHERNET_TYPE_802Q1MT2 |
                ETHERNET_TYPE_802Q1MT3 | ETHERNET_TYPE_8021AD)) {
        // printf("[*] ETHERNET TYPE 802Q1MT\n"); 
        eth_type = ntohs(eth_hdr->eth_82_ip_type);
        eth_header_len += 8;
    }

    if (eth_type == ETHERNET_TYPE_IP) {
        // printf("[*] Got IPv4 Packet...\n"); 
        ip4_header *ip4;
        ip4 = (ip4_header *) (packet + eth_header_len);
        p_bytes = (ip4->ip_len - (IP_HL(ip4) * 4));
        struct in6_addr ip_src, ip_dst;
        ip_src.s6_addr32[0] = ip4->ip_src;
        ip_src.s6_addr32[1] = 0;
        ip_src.s6_addr32[2] = 0;
        ip_src.s6_addr32[3] = 0;
        ip_dst.s6_addr32[0] = ip4->ip_dst;
        ip_dst.s6_addr32[1] = 0;
        ip_dst.s6_addr32[2] = 0;
        ip_dst.s6_addr32[3] = 0;

        /*
         * not our network? 
         */
        our = filter_packet(AF_INET, ip_src);
        if (ip4->ip_p == IP_PROTO_TCP) {
            tcp_header *tcph;
            tcph =
                (tcp_header *) (packet + eth_header_len +
                                (IP_HL(ip4) * 4));
            /*
             * printf("[*] IPv4 PROTOCOL TYPE TCP:\n"); 
             */

            s_check =
                cx_track(ip_src, tcph->src_port, ip_dst,
                         tcph->dst_port, ip4->ip_p, p_bytes,
                         tcph->t_flags, tstamp, AF_INET);
            if (!our)
                goto packet_end;

            if (TCP_ISFLAGSET(tcph, (TF_SYN))
                && !TCP_ISFLAGSET(tcph, (TF_ACK))) {
                // Redundant - fp_tcp4 & update_asset_service will do this!
                //update_asset(AF_INET,ip_src);
                /*
                 * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_tcp4(ip4, tcph, end_ptr, TF_SYN, ip_src);
                //printf("[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(tcph->dst_port));
                update_asset_service(ip_src,
                                     tcph->dst_port,
                                     ip4->ip_p,
                                     bformat("unknown"),
                                     bformat("unknown"), AF_INET);
            } else if (TCP_ISFLAGSET(tcph, (TF_SYN))
                       && TCP_ISFLAGSET(tcph, (TF_ACK))) {
                //printf("[*] Got a SYNACK from a SERVER: src_port:%d\n",ntohs(tcph->src_port));
                //update_asset(AF_INET,ip_src);

                /*
                 * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_tcp4(ip4, tcph, end_ptr, TF_SYNACK, ip_src);
                update_asset_service(ip_src,
                                     tcph->src_port,
                                     ip4->ip_p,
                                     bformat("unknown"),
                                     bformat("unknown"), AF_INET);

            } else if (TCP_ISFLAGSET(tcph, (TF_FIN))) {
                /*
                 * This is for test and phun (RST/FIN etc) 
                 */
                //update_asset(AF_INET,ip_src);
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_tcp4(ip4, tcph, end_ptr, TF_FIN, ip_src);

            } else if (TCP_ISFLAGSET(tcph, (TF_RST))) {
                /*
                 * This is for test and phun (RST/FIN etc) 
                 */
                //update_asset(AF_INET,ip_src);
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_tcp4(ip4, tcph, end_ptr, TF_RST, ip_src);
            }

            if (s_check != 0) {
                //printf("[*] - CHECKING TCP PACKAGE\n");
                //update_asset(AF_INET,ip_src);
                if (TCP_ISFLAGSET(tcph, (TF_ACK))
                    && !TCP_ISFLAGSET(tcph, (TF_ACK))
                    && !TCP_ISFLAGSET(tcph, (TF_RST))
                    && !TCP_ISFLAGSET(tcph, (TF_FIN))) {
                    //printf("[*] Got a STRAY-ACK: src_port:%d\n",ntohs(tcph->src_port));
                    /*
                     * Paranoia! 
                     */
                    const uint8_t *end_ptr;
                    if (pheader->len <= SNAPLENGTH) {
                        end_ptr = (packet + pheader->len);
                    } else {
                        end_ptr = (packet + SNAPLENGTH);
                    }
                    fp_tcp4(ip4, tcph, end_ptr, TF_ACK, ip_src);
                }
                char *payload;
                payload =
                    (char *)(packet + eth_header_len +
                             (IP_HL(ip4) * 4) + TCP_HEADER_LEN);
                if (s_check == 2) {
                    service_tcp4(ip4, tcph, payload,
                                 (pheader->caplen -
                                  (TCP_OFFSET(tcph)) *
                                  4 - eth_header_len));
                }
                /*
                 * if (s_check == 1) { 
                 */
                else {
                    client_tcp4(ip4, tcph, payload,
                                (pheader->caplen -
                                 (TCP_OFFSET(tcph)) * 4 - eth_header_len));
                }
            } else {
                //printf("[*] - NOT CHECKING TCP PACKAGE\n");
            }
            goto packet_end;
        } else if (ip4->ip_p == IP_PROTO_UDP) {
            udp_header *udph;
            udph =
                (udp_header *) (packet + eth_header_len +
                                (IP_HL(ip4) * 4));
            /*
             * printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); 
             */

            s_check =
                cx_track(ip_src, udph->src_port, ip_dst,
                         udph->dst_port, ip4->ip_p, p_bytes, 0,
                         tstamp, AF_INET);
            if (!our)
                goto packet_end;

            if (s_check != 0) {
                //printf("[*] - CHECKING UDP PACKAGE\n");
                //update_asset(AF_INET,ip_src);
                char *payload;
                payload =
                    (char *)(packet + eth_header_len +
                             (IP_HL(ip4) * 4) + UDP_HEADER_LEN);
                service_udp4(ip4, udph, payload,
                             (pheader->caplen -
                              UDP_HEADER_LEN -
                              (IP_HL(ip4) * 4) - eth_header_len));

                /*
                 * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_udp4(ip4, udph, end_ptr, ip_src);
            } else {
                //printf("[*] - NOT CHECKING UDP PACKAGE\n");
            }
            goto packet_end;
        } else if (ip4->ip_p == IP_PROTO_ICMP) {
            icmp_header *icmph;
            icmph =
                (icmp_header *) (packet + eth_header_len +
                                 (IP_HL(ip4) * 4));
            /*
             * printf("[*] IP PROTOCOL TYPE ICMP\n"); 
             */

            s_check =
                cx_track(ip_src, icmph->s_icmp_id, ip_dst,
                         icmph->s_icmp_id, ip4->ip_p, p_bytes,
                         0, tstamp, AF_INET);
            if (!our)
                goto packet_end;

            if (s_check != 0) {
                /*
                 * printf("[*] - CHECKING ICMP PACKAGE\n"); 
                 * * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_icmp4(ip4, icmph, end_ptr, ip_src);
                //update_asset(AF_INET,ip_src);
                /*
                 * service_icmp(*ip4,*tcph) // could look for icmp spesific data in package abcde...
                 */
            } else {
                /*
                 * printf("[*] - NOT CHECKING ICMP PACKAGE\n"); 
                 */
            }
            goto packet_end;
        } else {
            printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n", ip4->ip_p);

            s_check =
                cx_track(ip_src, 0, ip_dst, 0, ip4->ip_p,
                         p_bytes, 0, tstamp, AF_INET);
            if (!our)
                goto packet_end;

            if (s_check != 0) {
                /*
                 * printf("[*] - CHECKING OTHER PACKAGE\n"); 
                 */
                update_asset(AF_INET, ip_src);
                /*
                 * service_other(*ip4,*tcph) 
                 */
                /*
                 * fp_other(ip, ttl, ipopts, len, id, ipflags, df); 
                 */
            } else {
                /*
                 * printf("[*] - NOT CHECKING OTHER PACKAGE\n"); 
                 */
            }
            goto packet_end;
        }
    } else if (eth_type == ETHERNET_TYPE_IPV6) {
        /*
         * printf("[*] Got IPv6 Packet...\n"); 
         */
        ip6_header *ip6;
        ip6 = (ip6_header *) (packet + eth_header_len);
        our = filter_packet(AF_INET6, ip6->ip_src);

        if (ip6->next == IP_PROTO_TCP) {
            tcp_header *tcph;
            tcph =
                (tcp_header *) (packet + eth_header_len + IP6_HEADER_LEN);
            /*
             * printf("[*] IPv6 PROTOCOL TYPE TCP:\n"); 
             */

            s_check =
                cx_track(ip6->ip_src, tcph->src_port,
                         ip6->ip_dst, tcph->dst_port,
                         ip6->next, ip6->len, tcph->t_flags,
                         tstamp, AF_INET6);
            if (!our)
                goto packet_end;

            if (TCP_ISFLAGSET(tcph, (TF_SYN))
                && !TCP_ISFLAGSET(tcph, (TF_ACK))) {
                /*
                 * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_tcp6(ip6, tcph, end_ptr, TF_SYN, ip6->ip_src);
                /*
                 * printf("[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(tcph->dst_port)); 
                 */
            } else if (TCP_ISFLAGSET(tcph, (TF_SYN))
                       && TCP_ISFLAGSET(tcph, (TF_ACK))) {
                /*
                 * printf("[*] - Got a SYNACK from a SERVER: src_port:%d\n",ntohs(tcph->src_port)); 
                 */
                /*
                 * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_tcp6(ip6, tcph, end_ptr, TF_SYNACK, ip6->ip_src);
            }
            if (s_check != 0) {
                /*
                 * printf("[*] - CHECKING TCP PACKAGE\n"); 
                 */
                //update_asset(AF_INET6,ip6->ip_src);
                if (TCP_ISFLAGSET(tcph, (TF_ACK))
                    && !TCP_ISFLAGSET(tcph, (TF_SYN))) {
                    /*
                     * Paranoia! 
                     */
                    const uint8_t *end_ptr;
                    if (pheader->len <= SNAPLENGTH) {
                        end_ptr = (packet + pheader->len);
                    } else {
                        end_ptr = (packet + SNAPLENGTH);
                    }
                    fp_tcp6(ip6, tcph, end_ptr, TF_ACK, ip6->ip_src);
                }
                char *payload;
                payload =
                    (char *)(packet + eth_header_len + sizeof(ip6_header));
                if (s_check == 2) {
                    /*
                     * printf("[*] - CHECKING TCP SERVER PACKAGE\n"); 
                     */
                    service_tcp6(ip6, tcph, payload,
                                 (pheader->caplen -
                                  (TCP_OFFSET(tcph)) *
                                  4 - eth_header_len));
                } else {
                    /*
                     * printf("[*] - CHECKING TCP CLIENT PACKAGE\n"); 
                     */
                    client_tcp6(ip6, tcph, payload,
                                (pheader->caplen -
                                 (TCP_OFFSET(tcph)) * 4 - eth_header_len));
                }
            } else {
                /*
                 * printf("[*] - NOT CHECKING TCP PACKAGE\n"); 
                 */
            }
            goto packet_end;
            return;
        } else if (ip6->next == IP_PROTO_UDP) {
            udp_header *udph;
            udph =
                (udp_header *) (packet + eth_header_len + IP6_HEADER_LEN);
            /*
             * printf("[*] IPv6 PROTOCOL TYPE UDP:\n"); 
             */

            s_check =
                cx_track(ip6->ip_src, udph->src_port,
                         ip6->ip_dst, udph->dst_port,
                         ip6->next, ip6->len, 0, tstamp, AF_INET6);
            if (s_check != 0) {
                /*
                 * printf("[*] - CHECKING UDP PACKAGE\n"); 
                 */
                //update_asset(AF_INET6,ip6->ip_src);
                /*
                 * fp_udp(ip6, ttl, ipopts, len, id, ipflags, df); 
                 */
                char *payload;
                payload =
                    (char *)(packet + eth_header_len + sizeof(ip6_header));
                service_udp6(ip6, udph, payload,
                             (pheader->caplen -
                              sizeof(udp_header) - eth_header_len));
            } else {
                /*
                 * printf("[*] - NOT CHECKING UDP PACKAGE\n"); 
                 */
            }
            goto packet_end;
        } else if (ip6->next == IP6_PROTO_ICMP) {
            icmp6_header *icmph;
            icmph =
                (icmp6_header *) (packet + eth_header_len +
                                  IP6_HEADER_LEN);
            /*
             * printf("[*] IPv6 PROTOCOL TYPE ICMP\n"); 
             */

            /*
             * DO change ip6->hop_lmt to 0 or something! 
             */
            s_check = cx_track(ip6->ip_src, 0, ip6->ip_dst,
                               0, ip6->next, ip6->len, 0,
                               tstamp, AF_INET6);
            if (s_check != 0) {
                /*
                 * printf("[*] - CHECKING ICMP PACKAGE\n"); 
                 */
                //update_asset(AF_INET6,ip6->ip_src);
                /*
                 * service_icmp(*ip6,*tcph) 
                 */

                /*
                 * Paranoia! 
                 */
                const uint8_t *end_ptr;
                if (pheader->len <= SNAPLENGTH) {
                    end_ptr = (packet + pheader->len);
                } else {
                    end_ptr = (packet + SNAPLENGTH);
                }
                fp_icmp6(ip6, icmph, end_ptr, ip6->ip_src);
            } else {
                /*
                 * printf("[*] - NOT CHECKING ICMP PACKAGE\n"); 
                 */
            }
            goto packet_end;
        } else {
            printf("[*] IPv6 PROTOCOL TYPE OTHER: %d\n", ip6->next);
            /*
             * s_check = cx_track(ip6->ip_src, 0, ip6->ip_dst, 0,
             * ip6->next, ip6->len, 0, tstamp, AF_INET6);
             * if (s_check != 0) { 
             * printf("[*] - CHECKING OTHER PACKAGE\n"); 
             * update_asset(AF_INET6,ip6->ip_src); 
             * service_other(*ip4,*tcph) 
             * fp_other(ip, ttl, ipopts, len, id, ipflags, df); 
             * }else{ 
             * printf("[*] - NOT CHECKING OTHER PACKAGE\n"); 
             * } 
             */
            goto packet_end;
        }
    } else if (eth_type == ETHERNET_TYPE_ARP) {
        /*
         * printf("[*] Got ARP Packet...\n"); 
         */
        ether_arp *arph;
        arph = (ether_arp *) (packet + eth_header_len);

        if (ntohs(arph->ea_hdr.ar_op) == ARPOP_REPLY) {
            struct in6_addr ip_addr;
            memcpy(&ip_addr.s6_addr32[0], arph->arp_spa,
                   sizeof(u_int8_t) * 4);
            if (filter_packet(AF_INET, ip_addr)) {
                update_asset_arp(arph->arp_sha, ip_addr);
            }
            /*
             * arp_check(eth_hdr,tstamp); 
             */
        } else {
            /*
             * printf("ARP TYPE: %d\n",ntohs(arph->ea_hdr.ar_op)); 
             */
        }
        goto packet_end;
    }
    /*
     * printf("[*] ETHERNET TYPE : %x\n", eth_hdr->eth_ip_type); 
     */
  packet_end:
#ifdef DEBUG
    if (!our)
        fprintf(stderr,
                "Not our network packet. Tracked, but not logged.\n");
#endif
    inpacket = 0;
    return;
}

/* parse strings of the form "10.10.10.10/255.255.255.128"
 * as well as "10.10.10.10/25"
 */

void parse_nets(char *s_net, uint32_t * network, uint32_t * netmask)
{
    char *f, *p, *t;
    int i = 0;
    uint32_t tmp;
    char snet[MAX_NETS];
    strncpy(snet, s_net, MAX_NETS);
    f = snet;
    /*
     * f -> for processing
     * * p -> frob pointer
     * * t -> to pointer 
     */
    while (f && 0 != (p = strchr(f, '/'))) {
        // convert network address
        *p = '\0';
        if (!inet_pton(AF_INET, f, &network[i])) {
            perror("parse_nets");
            return;
        }
        printf("parse_nets: %s -> %p\n", f, network[i]);
        f = p + 1;
        // terminate netmask
        p = strchr(f, ',');
        if (p) {
            *p = '\0';
        }
        // create inverted netmask
        if ((t = strchr(f, '.')) - f < 4 && t > f) {
            // dotted quads
            printf("parse_nets: Got netmask %s -> ", f);
            inet_pton(AF_INET, f, &netmask[i]);
            //netmask[i] = htonl(netmask[i]);
        } else {
            // 'short' form
            sscanf(f, "%u", &tmp);
            printf("parse_nets: Got netmask %u -> ", tmp);
            netmask[i] = 0;
            tmp = 32 - tmp;
            while (tmp--) {
                netmask[i] <<= 1;
                netmask[i] |= 1;
            }
            netmask[i] = ~netmask[i];
            netmask[i] = ntohl(netmask[i]);
        }
        // easier to create inverted netmask
        printf("%08p\n", netmask[i]);
        nets = ++i;
        f = p;
        if (p)
            f++;
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
    printf
        (" -a             : home nets (eg: '87.238.44.0/25,10.0.0.0/255.0.0.0')\n\n");
}

int main(int argc, char *argv[])
{

    int ch, fromfile, setfilter, version, drop_privs_flag, daemon_flag;
    int use_syslog = 0;
    struct in_addr addr;
    struct bpf_program cfilter;
    char *bpff, errbuf[PCAP_ERRBUF_SIZE], *user_filter;
    char *net_ip_string;
    bpf_u_int32 net_mask;
    ch = fromfile = setfilter = version = drop_privs_flag =
        daemon_flag = 0;
    dev = "eth0";
    bpff = "";
    dpath = "/tmp";
    cxtbuffer = NULL;
    cxtrackerid = 0;
    inpacket = gameover = intr_flag = 0;
    timecnt = time(NULL);

    signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
    signal(SIGQUIT, game_over);
    signal(SIGALRM, set_end_sessions);

    while ((ch = getopt(argc, argv, "b:d:Dg:hi:p:P:u:va:")) != -1)
        switch (ch) {
        case 'a':
            s_net = strdup(optarg);
            break;
        case 'i':
            dev = strdup(optarg);
            break;
        case 'b':
            bpff = strdup(optarg);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            dpath = strdup(optarg);
            break;
        case 'h':
            usage();
            exit(0);
            break;
        case 'D':
            daemon_flag = 1;
            break;
        case 'u':
            user_name = strdup(optarg);
            drop_privs_flag = 1;
            break;
        case 'g':
            group_name = strdup(optarg);
            drop_privs_flag = 1;
            break;
        case 'p':
            pidfile = strdup(optarg);
            break;
        case 'P':
            pidpath = strdup(optarg);
            break;
        default:
            exit(1);
            break;
        }

    if (getuid()) {
        printf("[*] You must be root..\n");
        return (1);
    }

    parse_nets(s_net, network, netmask);
    printf("[*] Running prads %s\n", VERSION);
    load_servicefp_file(1, "../etc/tcp-service.sig");
    load_servicefp_file(2, "../etc/udp-service.sig");
    load_servicefp_file(3, "../etc/tcp-clients.sig");
    //load_servicefp_file(4,"../etc/udp-client.sig");

    errbuf[0] = '\0';
    /*
     * look up an availible device if non specified 
     */
    if (dev == 0x0)
        dev = pcap_lookupdev(errbuf);
    printf("[*] Device: %s\n", dev);

    if ((handle = pcap_open_live(dev, SNAPLENGTH, 1, 500, errbuf)) == NULL) {
        printf("[*] Error pcap_open_live: %s \n", errbuf);
        exit(1);
    } else if ((pcap_compile(handle, &cfilter, bpff, 1, net_mask)) == -1) {
        printf("[*] Error pcap_compile user_filter: %s\n",
               pcap_geterr(handle));
        exit(1);
    }

    pcap_setfilter(handle, &cfilter);

    /*
     * B0rk if we see an error... 
     */
    if (strlen(errbuf) > 0) {
        printf("[*] Error errbuf: %s \n", errbuf);
        exit(1);
    }

    if (daemon_flag) {
        if (!is_valid_path(pidpath))
            printf
                ("[*] PID path \"%s\" is bad, check privilege.", pidpath);
        openlog("prads", LOG_PID | LOG_CONS, LOG_DAEMON);
        printf("[*] Daemonizing...\n\n");
        daemonize(NULL);
    }

    if (drop_privs_flag) {
        printf("[*] Dropping privs...\n\n");
        drop_privs();
    }
    bucket_keys_NULL();
    alarm(TIMEOUT);

    printf("[*] Sniffing...\n\n");
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return (0);
}
