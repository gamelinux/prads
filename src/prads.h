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

/*  I N C L U D E S  **********************************************************/
#ifndef PRADS_H
#define PRADS_H
#include "common.h"
#include "bstrlib.h"
#include <netinet/in.h>
#include <pcre.h>

/*  D E F I N E S  ************************************************************/
#ifndef RELEASE
#define RELEASE
#endif
#define VERSION                       "0.3.3"RELEASE
#define SIG_ALRM                      60        /* Time between cxt and asset cleaning/printing */
#define TCP_TIMEOUT                   300       /* When idle IP connections should be timed out */
#define ASSET_TIMEOUT                 86400     /* Time befor an asset is deleted if no updates */
#define BUCKET_SIZE                   31337
#define SNAPLENGTH                    1604
#define MAX_BYTE_CHECK                500000
#define MAX_PKT_CHECK                 10
#define MAX_SERVICE_CHECK             200       /* How many new services we see befor we register */

/* Flags to identify ASSET TYPE */
#define ASSET_ARP                     0x01
#define ASSET_TYPE_OS                 0x02
#define ASSET_TYPE_SERVICE            0x04

#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_802Q1MT         0x9100
#define ETHERNET_TYPE_802Q1MT2        0x9200
#define ETHERNET_TYPE_802Q1MT3        0x9300
#define ETHERNET_TYPE_8021AD          0x88a8
#define ARPOP_REQUEST                 1  /* ARP request.  */
#define ARPOP_REPLY                   2  /* ARP reply.  */
#define ARPOP_RREQUEST                3  /* RARP request.  */
#define ARPOP_RREPLY                  4  /* RARP reply.  */
#define ARPOP_InREQUEST               8  /* InARP request.  */
#define ARPOP_InREPLY                 9  /* InARP reply.  */
#define ARPOP_NAK                     10 /* (ATM)ARP NAK.  */

#define IP_PROTO_ICMP                 1
#define IP_PROTO_TCP                  6
#define IP_PROTO_UDP                  17
#define IP_PROTO_IP6                  41
#define IP_PROTO_GRE                  47
#define IP_PROTO_IP4                  94
#define IP6_PROTO_HOPOPT              0
#define IP6_PROTO_ROUTE               43
#define IP6_PROTO_FRAG                44
#define IP6_PROTO_ICMP                58
#define IP6_PROTO_NONXT               59
#define MAX_IP_PROTO                  255
#define MAX_PORTS                     65536

#define GRE_VERSION_0                 0x0000
#define GRE_VERSION_1                 0x0001
#define GRE_HDR_LEN                   4
#define GREV1_ACK_LEN                 4
#define GREV1_HDR_LEN                 8
#define GRE_CHKSUM_LEN                2
#define GRE_OFFSET_LEN                2
#define GRE_KEY_LEN                   4
#define GRE_SEQ_LEN                   4
#define GRE_SRE_HDR_LEN               4
#define GRE_PROTO_PPP                 0x880b

#define IP4_HEADER_LEN                20
#define IP6_HEADER_LEN                40
#define TCP_HEADER_LEN                20
#define UDP_HEADER_LEN                8
#define ICMP_HEADER_LEN               4
#define GRE_HDR_LEN                   4
#define MAC_ADDR_LEN                  6
#define ETHERNET_HEADER_LEN           14
#define ETHERNET_8021Q_HEADER_LEN     18
#define ETHERNET_802Q1MT_HEADER_LEN   22

#define TF_FIN                        0x01
#define TF_SYN                        0x02
#define TF_RST                        0x04
#define TF_PUSH                       0x08
#define TF_ACK                        0x10
#define TF_URG                        0x20
#define TF_ECE                        0x40
#define TF_CWR                        0x80
#define TF_SYNACK                     0x12 /* dont use for ip flag check :) */
#define TF_NORESERVED (TF_FIN|TF_SYN|TF_RST|TF_PUSH|TF_ACK|TF_URG)
#define TF_FLAGS      (TF_FIN|TF_SYN|TF_RST|TF_ACK|TF_URG|TF_ECE|TF_CWR)

#define MOD_NONE	0
#define MOD_CONST	1
#define MOD_MSS		2
#define MOD_MTU		3

#define QUIRK_PAST                    0x00000001        /* P */
#define QUIRK_ZEROID                  0x00000002        /* Z */
#define QUIRK_IPOPT                   0x00000004        /* I */
#define QUIRK_URG                     0x00000008        /* U */
#define QUIRK_X2                      0x00000010        /* X */
#define QUIRK_ACK                     0x00000020        /* A */
#define QUIRK_T2                      0x00000040        /* T */
#define QUIRK_FLAGS                   0x00000080        /* F */
#define QUIRK_DATA                    0x00000100        /* D */
#define QUIRK_BROKEN                  0x00000200        /* ! */
#define QUIRK_RSTACK                  0x00000400        /* K */
#define QUIRK_SEQEQ                   0x00000800        /* Q */
#define QUIRK_SEQ0                    0x00001000        /* 0 */

#define QUIRK_FINACK                  0x00002000        /* N */
#define QUIRK_FLOWL                   0x00004000        /* L */

/* Some systems really like to put lots of NOPs there */
#define MAXOPT                        16        /* Maximum number of TCP packet options to pars */

/* The meaning of wildcard is, however, hardcoded as 'size > PACKET_BIG' */
#define PACKET_BIG                    100       /* Size limit for size wildcards */

#define TCPOPT_EOL                    0 /* End of options */
#define TCPOPT_NOP                    1 /* Nothing */
#define TCPOPT_MAXSEG                 2 /* MSS */
#define TCPOPT_WSCALE                 3 /* Window scaling */
#define TCPOPT_SACKOK                 4 /* Selective ACK permitted */
#define TCPOPT_TIMESTAMP              8 /* Stamp out timestamping! */
/* various transparent proxy detection fields */
#define TCPOPT_PROXBLUECOAT           0xFD
#define TCPOPT_PROXCISCO              0x21
#define TCPOPT_PROXRIVERBED1          0x4C
#define TCPOPT_PROXRIVERBED2          0x4E
/* seen this before? */
#define TCPOPT_WTF1                   0x32
#define TCPOPT_WTF2                   0x1e 


#define SUCCESS                        0
#define ERROR                          1
#define STDBUF                         1024

#define INSTALL_SYSCONFDIR             ""
#define TCP_SIGNATURE_LIST             CONFDIR "tcp-service.sig"
#define LOGDIR                         "/var/log/"
#define PRADS_ASSETLOG                 "prads-asset.log"
#define MODE_READ                      "r"
#define MODE_WRITE                     "w"

#define MAX_APP                        100
#define MAX_VER                        25
#define MAX_MISC                       100
#define MAX_NETS                       128
#define SERVICE                        1
#define CLIENT                         2
#define FROMSERVER                     0
#define FROMCLIENT                     1
#define CXT_DEFAULT_HASHSIZE           65536
#define CXT_DEFAULT_PREALLOC           10000

/*  D A T A  S T R U C T U R E S  *********************************************/

/*
 * Ethernet header
 */

typedef struct _ether_header {
    uint8_t ether_dst[6];        /* destination MAC */
    uint8_t ether_src[6];        /* source MAC */

    union {
        struct etht {
            uint16_t ether_type; /* ethernet type (normal) */
        } etht;

        struct qt {
            uint16_t eth_t_8021; /* ethernet type/802.1Q tag */
            uint16_t eth_t_8_vid;
            uint16_t eth_t_8_type;
        } qt;

        struct qot {
            uint16_t eth_t_80212;        /* ethernet type/802.1QinQ */
            uint16_t eth_t_82_mvid;
            uint16_t eth_t_82_8021;
            uint16_t eth_t_82_vid;
            uint16_t eth_t_82_type;
        } qot;
    } vlantag;

#define eth_ip_type    vlantag.etht.ether_type

#define eth_8_type     vlantag.qt.eth_t_8021
#define eth_8_vid      vlantag.qt.eth_t_8_vid
#define eth_8_ip_type  vlantag.qt.eth_t_8_type

#define eth_82_type    vlantag.qot.eth_t_80212
#define eth_82_mvid    vlantag.qot.eth_t_82_mvid
#define eth_82_8021    vlantag.qot.eth_t_82_8021
#define eth_82_vid     vlantag.qot.eth_t_82_vid
#define eth_82_ip_type vlantag.qot.eth_t_82_type

} ether_header;

typedef struct _arphdr {
    uint16_t ar_hrd;            /* Format of hardware address.  */
    uint16_t ar_pro;            /* Format of protocol address.  */
    uint8_t ar_hln;             /* Length of hardware address.  */
    uint8_t ar_pln;             /* Length of protocol address.  */
    uint16_t ar_op;             /* ARP opcode (command).  */
#if 0
    /*
     * Ethernet looks like this : This bit is variable sized
     * however...  
     */
    unsigned char __ar_sha[MAC_ADDR_LEN];       /* Sender hardware address.  */
    unsigned char __ar_sip[4];  /* Sender IP address.  */
    unsigned char __ar_tha[MAC_ADDR_LEN];       /* Target hardware address.  */
    unsigned char __ar_tip[4];  /* Target IP address.  */
#endif
} arphdr;

typedef struct _ether_arp {
    arphdr ea_hdr;              /* fixed-size header */
    uint8_t arp_sha[MAC_ADDR_LEN];      /* sender hardware address */
    uint8_t arp_spa[4];         /* sender protocol address */
    uint8_t arp_tha[MAC_ADDR_LEN];      /* target hardware address */
    uint8_t arp_tpa[4];         /* target protocol address */
} ether_arp;

/*
 * IPv4 header
 */

typedef struct _ip4_header {
    uint8_t ip_vhl;             /* version << 4 | header length >> 2 */
    uint8_t ip_tos;             /* type of service */
    uint16_t ip_len;            /* total length */
    uint16_t ip_id;             /* identification */
    uint16_t ip_off;            /* fragment offset field */
    uint8_t ip_ttl;             /* time to live */
    uint8_t ip_p;               /* protocol */
    uint16_t ip_csum;           /* checksum */
    uint32_t ip_src;            /* source address */
    uint32_t ip_dst;            /* dest address */
} ip4_header;

#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
#define IP_HL(ip4_header)                (((ip4_header)->ip_vhl) & 0x0f)
#define IP_V(ip4_header)                 (((ip4_header)->ip_vhl) >> 4)

/*
 * IPv6 header
 */

typedef struct _ip6_header {
    uint32_t vcl;               /* version, class, and label */
    uint16_t len;               /* length of the payload */
    uint8_t next;               /* next header
                                 * Uses the same flags as
                                 * the IPv4 protocol field */
    uint8_t hop_lmt;            /* hop limit */
    struct in6_addr ip_src;     /* source address */
    struct in6_addr ip_dst;     /* dest address */
} ip6_header;

// header is in host order~~!
#define IP6_V(header)                     (htonl(header->vcl) >> 28)
//#define IP6_TC(ip6_header)                (((htonl(ip6_header)->vcl) & 0x0FF00000) >> 20)
#define IP6_TC(ip6_header)                ((htonl((ip6_header)->vcl) & 0x0FF00000) >> 20)
#define IP6_FL(ip6_header)                (htonl((ip6_header)->vcl) & 0x000FFFFF)

/*
 * TCP header
 */

typedef struct _tcp_header {
    uint16_t src_port;          /* source port */
    uint16_t dst_port;          /* destination port */
    uint32_t t_seq;             /* sequence number */
    uint32_t t_ack;             /* acknowledgement number */
    uint8_t t_offx2;            /* data offset, rsvd */
    uint8_t t_flags;            /* tcp flags */
    uint16_t t_win;             /* window */
    uint16_t t_csum;            /* checksum */
    uint16_t t_urgp;            /* urgent pointer */
} tcp_header;

#define TCP_OFFSET(tcp_header)           (((tcp_header)->t_offx2 & 0xf0) >> 4)
#define TCP_X2(tcp_header)               ((tcp_header)->t_offx2 & 0x0f)
#define TCP_ISFLAGSET(tcp_header, flags) (((tcp_header)->t_flags & (flags)) == (flags))
#define GET16(p)                         ((uint16_t) *((uint8_t*)(p)+0) << 8 | \
                                          (uint16_t) *((uint8_t*)(p)+1) )

/*
 * UDP header
 */

typedef struct _udp_header {
    uint16_t src_port;          /* source port */
    uint16_t dst_port;          /* destination port */
    uint16_t len;               /* length of the payload */
    uint16_t csum;              /* checksum */
} udp_header;

/*
 * ICMP header
 */

typedef struct _icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    union {
        uint8_t pptr;

        struct in_addr gwaddr;

        struct idseq {
            uint16_t id;
            uint16_t seq;
        } idseq;

        int sih_void;

        struct pmtu {
            uint16_t ipm_void;
            uint16_t nextmtu;
        } pmtu;

        struct rtradv {
            uint8_t num_addrs;
            uint8_t wpa;
            uint16_t lifetime;
        } rtradv;
    } icmp_hun;

#define s_icmp_pptr       icmp_hun.pptr
#define s_icmp_gwaddr     icmp_hun.gwaddr
#define s_icmp_id         icmp_hun.idseq.id
#define s_icmp_seq        icmp_hun.idseq.seq
#define s_icmp_void       icmp_hun.sih_void
#define s_icmp_pmvoid     icmp_hun.pmtu.ipm_void
#define s_icmp_nextmtu    icmp_hun.pmtu.nextmtu
#define s_icmp_num_addrs  icmp_hun.rtradv.num_addrs
#define s_icmp_wpa        icmp_hun.rtradv.wpa
#define s_icmp_lifetime   icmp_hun.rtradv.lifetime

    union {
        /*
         * timestamp 
         */
        struct ts {
            uint32_t otime;
            uint32_t rtime;
            uint32_t ttime;
        } ts;

        /*
         * IP header for unreach 
         */
        struct ih_ip {
            ip4_header *ip;
            /*
             * options and then 64 bits of data 
             */
        } ip;

        struct ra_addr {
            uint32_t addr;
            uint32_t preference;
        } radv;

        uint32_t mask;

        char data[1];

    } icmp_dun;
#define s_icmp_otime      icmp_dun.ts.otime
#define s_icmp_rtime      icmp_dun.ts.rtime
#define s_icmp_ttime      icmp_dun.ts.ttime
#define s_icmp_ip         icmp_dun.ih_ip
#define s_icmp_radv       icmp_dun.radv
#define s_icmp_mask       icmp_dun.mask
#define s_icmp_data       icmp_dun.data
} icmp_header;

typedef struct _icmp6_header {
    uint8_t type;               /* type field */
    uint8_t code;               /* code field */
    uint16_t csum;              /* checksum field */
    union {
        uint32_t icmp6_data32[1];       /* type-specific field */
        uint16_t icmp6_data16[2];       /* type-specific field */
        uint8_t icmp6_data8[4]; /* type-specific field */
    } icmp6_data;
#define icmp6_id        icmp6_data.icmp6_data16[0]      /* echo request/reply */
#define icmp6_seq       icmp6_data.icmp6_data16[1]      /* echo request/reply */
} icmp6_header;

#define ICMP6_UNREACH 1
#define ICMP6_BIG     2
#define ICMP6_TIME    3
#define ICMP6_PARAMS  4
#define ICMP6_ECHO    128
#define ICMP6_REPLY   129

/* Minus 1 due to the 'body' field  */
#define ICMP6_MIN_HEADER_LEN (sizeof(ICMP6Hdr) )

typedef struct _gre_header
{
    uint8_t flags; /**< GRE packet flags */
    uint8_t version; /**< GRE version */
    uint16_t ether_type; /**< ether type of the encapsulated traffic */
} gre_header;
#define GRE_FLAG_ISSET_CHKSUM(r)  (r->flags & 0x80)
#define GRE_FLAG_ISSET_ROUTE(r)   (r->flags & 0x40)
#define GRE_FLAG_ISSET_KY(r)      (r->flags & 0x20)
#define GRE_FLAG_ISSET_SQ(r)      (r->flags & 0x10)
#define GRE_FLAG_ISSET_SSR(r)     (r->flags & 0x08)
#define GRE_FLAG_ISSET_RECUR(r)   (r->flags & 0x07)
#define GRE_GET_VERSION(r)        (r->version & 0x07)
#define GRE_GET_FLAGS(r)          (r->version & 0xF8)
#define GRE_GET_PROTO(r)          ntohs(r->ether_type)
#define GREV1_FLAG_ISSET_FLAGS(r) (r->version & 0x78)
#define GREV1_FLAG_ISSET_ACK(r)   (r->version & 0x80)

typedef struct _gre_sre_header
{
    uint16_t    af;            
    uint8_t     sre_offset;
    uint8_t     sre_length;
    uint8_t     *routing;
} gre_sre_header;

/* Fingerprint / Signature entry */
typedef struct _fp_entry {
    char *os;                /* OS genre */
    char *desc;              /* OS description */
    uint8_t no_detail;          /* Disable guesstimates */
    uint8_t generic;            /* Generic hit */
    uint8_t userland;           /* Userland stack */
    uint16_t wsize;             /* window size */
    uint8_t wsize_mod;          /* MOD_* for wsize */
    uint8_t ttl, df;            /* TTL and don't fragment bit */
    uint8_t zero_stamp;         /* timestamp option but zero value? */
    uint16_t size;              /* packet size */
    uint8_t optcnt;             /* option count */
    uint8_t opt[MAXOPT];        /* TCPOPT_* */
    uint16_t wsc, mss;          /* value for WSCALE and MSS options */
    uint8_t wsc_mod, mss_mod;   /* modulo for WSCALE and MSS (NONE or CONST) */
    uint32_t quirks;            /* packet quirks and bugs */
    uint32_t line;              /* config file line */
    struct _fp_entry *next;
} fp_entry;

/* mac address database entry */
typedef struct _mac_entry {
  uint8_t o[MAC_ADDR_LEN];
  uint8_t mask; // optional
  char *vendor;
  char *comment;
  struct _mac_entry *next;
} mac_entry;


/* DHCP Fingerprint / Signature entry */
typedef struct _dhcp_fp_entry {
    char *os;                   /* OS genre */
    char *desc;                 /* OS description */
    char *vc;                   /* Vender Code */
    uint8_t type;               /* DHCP type */
    uint8_t ttl;                /* IP TTL */
    uint8_t optcnt;             /* option count */
    uint8_t opt[MAXOPT];        /* DHCP Options */
    uint8_t optreqcnt;          /* request option counter (53) */
    uint8_t optreq[MAXOPT];     /* request option counter  */
    uint32_t line;              /* config file line */
    struct _dhcp_fp_entry *next;
} dhcp_fp_entry;

/*
 * Structure for connections
 */

typedef struct _connection {
    struct   _connection *prev;
    struct   _connection *next;
    time_t   start_time;          /* connection start time */
    time_t   last_pkt_time;       /* last seen packet time */
    uint64_t cxid;                /* connection id */
    uint8_t  reversed;            /* 1 if the connection is reversed */
    uint32_t af;                  /* IP version (4/6) AF_INET */
    uint16_t hw_proto;            /* layer2 protocol */
    uint8_t  proto;               /* IP protocoll type */
    struct   in6_addr s_ip;       /* source address */
    struct   in6_addr d_ip;       /* destination address */
    uint16_t s_port;              /* source port */
    uint16_t d_port;              /* destination port */
    uint64_t s_total_pkts;        /* total source packets */
    uint64_t s_total_bytes;       /* total source bytes */
    uint64_t d_total_pkts;        /* total destination packets */
    uint64_t d_total_bytes;       /* total destination bytes */
    uint8_t  s_tcpFlags;          /* tcpflags sent by source */
    uint8_t  __pad__;             /* pads struct to alignment */
    uint8_t  d_tcpFlags;          /* tcpflags sent by destination */
    uint8_t  check;               /* Flags spesifying checking */
    struct   _asset *c_asset;     /* pointer to src asset */
    struct   _asset *s_asset;     /* pointer to server asset */
} connection;
#define CXT_DONT_CHECK_SERVER     0x01  /* Dont check server packets */
#define CXT_DONT_CHECK_CLIENT     0x02  /* Dont check client packets */
#define CXT_SERVICE_DONT_CHECK    0x04  /* Dont check payload from server */
#define CXT_CLIENT_DONT_CHECK     0x08  /* Dont check payload from client */
#define CXT_SERVICE_UNKNOWN_SET   0x10  /* If service is set as unknown */
#define CXT_CLIENT_UNKNOWN_SET    0x20  /* If client is set as unknown */

#define ISSET_CXT_DONT_CHECK_CLIENT(pi)  (pi->cxt->check & CXT_DONT_CHECK_CLIENT)
#define ISSET_CXT_DONT_CHECK_SERVER(pi)  (pi->cxt->check & CXT_DONT_CHECK_SERVER)
#define ISSET_DONT_CHECK_SERVICE(pi)     (pi->cxt->check & CXT_SERVICE_DONT_CHECK)
#define ISSET_DONT_CHECK_CLIENT(pi)      (pi->cxt->check & CXT_CLIENT_DONT_CHECK)
#define ISSET_SERVICE_UNKNOWN(pi)        (pi->cxt->check & CXT_SERVICE_UNKNOWN_SET)
#define ISSET_CLIENT_UNKNOWN(pi)         (pi->cxt->check & CXT_CLIENT_UNKNOWN_SET)
// good comparison to optimize
// XXX: TODO: comotion: use filter_network 64bit instructions
#ifdef __APPLE__
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#define IP6ADDR0(ip) ((ip)->s6_addr32[0])
#define IP6ADDR1(ip) ((ip)->s6_addr32[1])
#define IP6ADDR2(ip) ((ip)->s6_addr32[2])
#define IP6ADDR3(ip) ((ip)->s6_addr32[3])
#define IP6ADDR(ip) \
    IP6ADDR0(ip), IP6ADDR1(ip), IP6ADDR2(ip), IP6ADDR3(ip)

#define IP4ADDR(ip) ((ip)->s6_addr32[0])

#define CMP_ADDR6(a1,a2) \
    (((a1)->s6_addr32[3] == (a2)->s6_addr32[3] && \
      (a1)->s6_addr32[2] == (a2)->s6_addr32[2] && \
      (a1)->s6_addr32[1] == (a2)->s6_addr32[1] && \
      (a1)->s6_addr32[0] == (a2)->s6_addr32[0]))

// the reason why we can't get rid of pi->s6_addr32
// apples and apples
#define CMP_ADDR4A(a1,a2) \
    ((a1)->s6_addr32[0] == (a2)->s6_addr32[0])
// apples and oranges
#define CMP_ADDR4(apple,orange) \
    (((apple)->s6_addr32[0] ==  (orange)))
#define CMP_PORT(p1,p2) \
    ((p1 == p2))


/* Since two or more connections can have the same hash key, we need to
 * compare the connections with the current hash key. */
#define CMP_CXT4(cxt1, src, sp, dst, dp) \
    (( \
       CMP_PORT((cxt1)->s_port, (sp)) && \
       CMP_PORT((cxt1)->d_port, (dp)) && \
       CMP_ADDR4(&((cxt1)->s_ip), (src)) && \
       CMP_ADDR4(&((cxt1)->d_ip), (dst))    \
    ))

#define CMP_CXT6(cxt1, src, sp, dst, dp) \
    ((CMP_ADDR6(&(cxt1)->s_ip, (src)) && \
       CMP_ADDR6(&(cxt1)->d_ip, (dst)) && \
       CMP_PORT((cxt1)->s_port, (sp)) && CMP_PORT((cxt1)->d_port, (dp))))

/* clear the address structure by setting all fields to 0 */
#define CLEAR_ADDR(a) { \
    (a)->s6_addr32[0] = 0; \
    (a)->s6_addr32[1] = 0; \
    (a)->s6_addr32[2] = 0; \
    (a)->s6_addr32[3] = 0; \
}

/* clears the cxt parts */
#define CLEAR_CXT(cxt) { \
    (cxt)->s_port = 0; \
    (cxt)->d_port = 0; \
    CLEAR_ADDR(&(cxt)->s_ip); \
    CLEAR_ADDR(&(cxt)->d_ip); \
    (cxt)->s_total_pkts = 0; \
    (cxt)->s_total_bytes = 0; \
    (cxt)->d_total_pkts = 0; \
    (cxt)->d_total_bytes = 0; \
    (cxt)->s_tcpFlags = 0; \
    (cxt)->d_tcpFlags = 0; \
    (cxt)->start_time = 0; \
    (cxt)->last_pkt_time = 0; \
    (cxt)->af = 0; \
    (cxt)->proto = 0; \
    (cxt)->cxid = 0; \
}


typedef struct _packetinfo {
    // macro out the need for some of these
    // eth_type(pi) is same as pi->eth_type, no?
    // marked candidates for deletion
    const struct pcap_pkthdr *pheader; /* Libpcap packet header struct pointer */
    const uint8_t *  packet;         /* Unsigned char pointer to raw packet */
    // compute (all) these from packet
    uint32_t        eth_hlen;       /* Ethernet header lenght */
    uint16_t        mvlan;          /* Metro vlan tag */
    uint16_t        vlan;           /* vlan tag */
    uint16_t        eth_type;       /* Ethernet type (IPv4/IPv6/etc) */
    uint32_t        af;             /* IP version (4/6) AF_INET */
    ether_header    *eth_hdr;       /* Ethernet header struct pointer */
    ether_arp       *arph;          /* ARP header struct pointer */
    ip4_header      *ip4;           /* IPv4 header struct pointer */
    ip6_header      *ip6;           /* IPv6 header struct pointer */
    uint16_t        packet_bytes;   /* Lenght of IP payload in packet */
    //struct in6_addr ip_src;         /* source address */
    //struct in6_addr ip_dst;         /* destination address */
    uint16_t        s_port;         /* source port */
    uint16_t        d_port;         /* destination port */
    uint8_t         proto;          /* IP protocoll type */    
    uint8_t         sc;             /* SC_SERVER or SC_CLIENT */
    tcp_header      *tcph;          /* tcp header struct pointer */
    udp_header      *udph;          /* udp header struct pointer */
    icmp_header     *icmph;         /* icmp header struct pointer */
    icmp6_header    *icmp6h;        /* icmp6 header struct pointer */ 
    gre_header      *greh;          /* GRE header struct pointer */
    uint16_t        gre_hlen;       /* Length of dynamic GRE header length */
    const uint8_t   *end_ptr;       /* Paranoid end pointer of packet */
    const uint8_t   *payload;       /* char pointer to transport payload */
    uint32_t        plen;           /* transport payload length */
    uint32_t        our;            /* Is the asset in our defined network */
    uint8_t         up;             /* Set if the asset has been updated */
    connection      *cxt;           /* pointer to the cxt for this packet */
    struct _asset    *asset;         /* pointer to the asset for this (src) packet */
    enum { SIGNATURE, FINGERPRINT } type;
} packetinfo;

// packetinfo accessor macros

#define PI_TOS(pi) ( (pi)->ip4->ip_tos )
#define PI_ECN(pi) ( (pi)->tcph->t_flags & (TF_ECE|TF_CWR) )

#define PI_IP4(pi) ((pi)->ip4)
#define PI_IP4SRC(pi) ( PI_IP4(pi)->ip_src )
#define PI_IP4DST(pi) ( PI_IP4(pi)->ip_dst )

#define PI_IP6(pi) ((pi)->ip6)
#define PI_IP6SRC(pi)  (PI_IP6(pi)->ip_src)
#define PI_IP6DST(pi)  (PI_IP6(pi)->ip_dst)

#define PI_TCP_SP(pi) ( ntohs((pi)->tcph->src_port))
#define PI_TCP_DP(pi) ( ntohs((pi)->tcph->dst_port))
// and more to come

#define SC_CLIENT                 0x01  /* pi for this session is client */
#define SC_SERVER                 0x02  /* pi for this session is server */

typedef struct _serv_asset {
    struct _serv_asset *prev;   /* Prev serv_asset structure */
    struct _serv_asset *next;   /* Next serv_asset structure */
    time_t first_seen;          /* Time at which service_asset was first seen. */
    time_t last_seen;           /* Time at which service_asset was last seen. */
    unsigned short i_attempts;  /* Attempts at identifying the service_asset. */
    unsigned short proto;       /* Asset protocol */
    uint16_t port;              /* Asset port */
    uint8_t ttl;                /* Asset TTL */
    bstring service;            /* Asset service (i.e. SSH, WWW, ICMP etc.) */
    bstring application;        /* Asset application (i.e. Apache, ICMP_TYPE etc.) */
    int role;                   /* server or client */
    int unknown;                /* 1 = Uknown, 0 = Known "Asset application" */
} serv_asset;

typedef struct _os_asset {
    struct _os_asset *prev;     /* Prev os_asset structure */
    struct _os_asset *next;     /* Next os_asset structure */
    time_t first_seen;          /* Time at which os_asset was first detected. */
    time_t last_seen;           /* Time at which os_asset was last detected. */
    unsigned short i_attempts;  /* Failed attempts at identifying the os_asset. (hench just unknown) */
    bstring vendor;             /* Vendor (MS,Linux,Sun,HP...) */
    bstring os;                 /* OS (WinXP SP2, 2.4/2.6, 10.2..) */
    uint8_t detection;          /* Flag describing detection method (SYN/SYNACK/UDP/ICMP...) */
    bstring raw_fp;             /* The raw fingerprint [*:*:*:*:*:*:....] */
    bstring matched_fp;         /* The FP that matched [*:*:*:*.*:*:---] */
    fp_entry fp; 
    //fp_entry *match;            /* Pointer to matching signature */
    char *match_os;
    char *match_desc;
    
    uint16_t port;              /* Asset port detected on */
    uint16_t mtu;               /* IPv4:MTU = MSS + 40 | IPv6:MTU = MSS + 60 */
    uint8_t ttl;                /* Asset ttl */
    uint32_t uptime;            /* Asset uptime */
} os_asset;

/* Holds one entery for an ARP/NDP or IPv4/IPv6 asset */
typedef struct _asset {
    struct _asset *prev;        /* Prev ip_asset structure */
    struct _asset *next;        /* Next ip_asset structure */
    time_t first_seen;          /* Time at which asset was first seen. */
    time_t last_seen;           /* Time at which asset was last seen. */
    unsigned short i_attempts;  /* Attempts at identifying the asset. */
    int af;                     /* IP AF_INET */
    uint16_t        vlan;       /* vlan tag */
    struct in6_addr ip_addr;    /* IP asset address */
    uint8_t mac_addr[MAC_ADDR_LEN];       /* Asset MAC address */
    mac_entry *macentry;        /* Asset MAC vendor name */
    serv_asset *services;       /* Linked list with services detected */
    os_asset *os;               /* Linked list with OSes detected */
} asset;

typedef struct _signature {
    bstring service;            /* Service (i.e. SSH, WWW, etc.) */
    uint16_t port;              /* Port to check for this service, or 0 for all */
    /*
     * Should be able to specify range, and such... 
     */
    /*
     * Snort style : [80,8080,100-200,20-30,!22] 
     */
    /*
     * Not sure how to do that... yet.... 
     */
    struct {                    /* Application Title, broken up into 3 parts. */
        bstring app;            /* Application */
        bstring ver;            /* Version */
        bstring misc;           /* Misc info */
    } title;
    pcre *regex;                /* Signature - Compiled Regular Expression */
    pcre_extra *study;          /* Studied version of the compiled regex. */
    struct {                    /* Signature stats */
        uint32_t    checked;    /* How many times the sig has been matched for */
        uint32_t    matched;    /* How many times it has matched*/
    } stats;
    struct _signature *next;    /* Next record in the list. */
    struct _signature *prev;    /* Next record in the list. */
} signature;

typedef struct _servicelist {
    bstring     service_name;   /* Service (@http) etc. */
    uint8_t     proto;          /* Flags: TCP=0x01 UDP=0x02 */
    uint32_t    stats;          /* stats on how many times it has matched */  
} servicelist;

typedef struct _port_t {
    uint16_t h_port;            /* High port */
    //uint16_t l_port;            /* Low Port */
    bstring service_name;       /* Service */
    struct _port_t *next;       /* Next port_t structure */
} port_t;


typedef struct _prads_stat {
    uint32_t got_packets;   /* number of packets received by prads */
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
} prads_stat;


#ifdef NO_VECTOR_TYPES
typedef struct _fmask {
    int type;
    struct in6_addr addr;
    struct in6_addr mask;
} fmask;
#else
// vector types :-)
typedef int v4si __attribute__((vector_size(16)));
typedef union _i4vector {
    v4si v;
    struct in6_addr ip6;
    uint64_t i[2];
    uint32_t w[4];
    uint16_t s[8];
} ip6v;
typedef struct _fmask { 
    int type;
    union {
        v4si addr_v;
        struct in6_addr addr;
        uint64_t addr64[2];
    };
    union {
        v4si mask_v;
        struct in6_addr mask;
        uint64_t mask64[2];
    };
} fmask;

#endif

#define IS_COSET(config, flags) (((config)->ctf & (flags)) == (flags))
#define IS_CSSET(config, flags) (((config)->cof & (flags)) == (flags))

/*  P R O T O T Y P E S  ******************************************************/
void free_config();
// can't declare in sys_func.h because it does not include prads.h!
const char *u_ntop_src(packetinfo *pi, char* dest);
const char *u_ntop_dst(packetinfo *pi, char* dest);
#endif                          // PRADS_H
