/*
** This file is a part of passivedns.
**
** Copyright (C) 2010-2011, Edward Fjellskål <edwardfjellskaal@gmail.com>
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

/*  I N C L U D E S  **********************************************************/


typedef struct _pdns_stat {
    uint32_t got_packets;   /* number of packets received by prog */
    uint32_t eth_recv;      /* number of Ethernet packets received */
    uint32_t arp_recv;      /* number of ARP packets received */
    uint32_t otherl_recv;   /* number of other Link layer packets received */
    uint32_t vlan_recv;     /* number of VLAN packets received */
    uint32_t ip4_recv;      /* number of IPv4 packets received */
    uint32_t ip6_recv;      /* number of IPv6 packets received */
    uint32_t ip4ip_recv;    /* number of IP4/6 packets in IPv4 packets */
    uint32_t ip6ip_recv;    /* number of IP4/6 packets in IPv6 packets */
    uint32_t gre_recv;      /* number of GRE packets received */
    uint32_t tcp_recv;      /* number of tcp packets received */
    uint32_t udp_recv;      /* number of udp packets received */
    uint32_t icmp_recv;     /* number of icmp packets received */
    uint32_t othert_recv;   /* number of other transport layer packets received */
    uint32_t assets;        /* total number of assets detected */
    uint32_t tcp_os_assets; /* total number of tcp os assets detected */
    uint32_t udp_os_assets; /* total number of udp os assets detected */
    uint32_t icmp_os_assets;/* total number of icmp os assets detected */
    uint32_t dhcp_os_assets;/* total number of dhcp os assets detected */
    uint32_t tcp_services;  /* total number of tcp services detected */
    uint32_t tcp_clients;   /* total number of tcp clients detected */
    uint32_t udp_services;  /* total number of udp services detected */
    uint32_t udp_clients;   /* total number of tcp clients detected */
} pdns_stat;

/* HASH: 
 *     [RESP-CODE_BUCKET]_<-- Error or no error?
 *                         |__[Q-TYPE_BUCKET]_<--- PTR,MX,A... 
 *                                            |__[QNAME] <--- cmp on Query name (gamelinux.org etc.)
 */

typedef struct _pdns_record {
/*    uint8_t qtype;           * Qtype (A/AAAA/MX/PTR/CNAME/NS/SOA/TXT...) */
/*    struct  in6_addr ip;     * IP (IPv4 & IPv6) from record from A or AAAA */
    time_t  first_seen;       /* First seen (unix timestamp) */
    time_t  last_seen;        /* Last seen (unix timestamp) */
    char    *qname;           /* Query name (gamelinux.org) */
/*    char    *class;          * IN,CS,CH,HS - or just IN and drop this? */
                              /* NS message ID */
/*  int32_t ttl;               * Do we need ttl here ? */
                              /* Flags??? (qr|rd|ra) */
    char    *record;          /* (QUERY,NOERROR,qr|rd|ra||1||gamelinux.org,IN,A||1||gamelinux.org,IN,A,361,85.19.221.54||0||0) */
    // \x09gamelinux\x03org
    struct  in6_addr servip;  /* DNS Server IP (v4/6) */
    struct  in6_addr cliip;   /* DNS Client IP (v4/6) */
} pdns_record;


// hash: querytype+DOMAIN+responsecode
/* DNS responses we are interested in:
 *  * CNAME ( domain -> domain )
 *  * A / AAAA ( domain -> ip addr ) 
 *  * PTR ( ip -> domain )
 *  * NS  (domain -> domain + ip)
 *  * SOA ( email address )
 *  * MX  ( domain -> domain )
 *... also interested in dumping other records on change.
 */

// 1314851098||hostname||192.168.43.1||QUERY,NOERROR,55580,qr|rd|ra||1||gamelinux.org,IN,A||1||gamelinux.org,IN,A,3600,85.19.221.54||2||gamelinux.org,IN,NS,3600,ns.hyp.net||gamelinux.org,IN,NS,3600,ns.netimage.no||1||ns.hyp.net,IN,A,7947,194.63.248.53

typedef struct _dns_entry {    
    uint32_t  id;  // id of last message updating this record
    char  name[NS_MAXDNAME];
    uint16_t opcode;       // Query opcode
    uint16_t  rcode;       // Response Code NOERROR etc
    uint16_t  type;        // record type
    u_int16_t   rr_class;  // record class IN,
    u_int32_t   ttl;       // record time to live

    // 1314851098||hostname||192.168.43.1||QUERY,NOERROR,55580,qr||    u_int16_t   rdlength;

} dns_entry;
