/*
** This file is a part of cxtracker.
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

/*  I N C L U D E S  **********************************************************/
//#include "misc/sys_func.c"
//#include "cxtracking/cxt.c"
//#include "servicefp/tcps.c"

//#include "misc/bstrlib.c"
#ifndef PRADS_H
#define PRADS_H
#include "common.h"
#include "bstrlib.h"
#include <pcre.h>

/*  D E F I N E S  ************************************************************/
#define VERSION                       "0.1.6"
#define TIMEOUT                       30
#define TCP_TIMEOUT                   300 /* When idle IP connections should be timed out */
#define BUCKET_SIZE                   1669 
#define SNAPLENGTH                    1604
#define MAX_BYTE_CHECK                5000000
#define MAX_PKT_CHECK                 20

#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_802Q1MT         0x9100
#define ETHERNET_TYPE_802Q1MT2        0x9200
#define ETHERNET_TYPE_802Q1MT3        0x9300
#define ETHERNET_TYPE_8021AD          0x88a8
#define ARPOP_REQUEST                 1      /* ARP request.  */
#define ARPOP_REPLY                   2      /* ARP reply.  */
#define ARPOP_RREQUEST                3      /* RARP request.  */
#define ARPOP_RREPLY                  4      /* RARP reply.  */
#define ARPOP_InREQUEST               8      /* InARP request.  */
#define ARPOP_InREPLY                 9      /* InARP reply.  */
#define ARPOP_NAK                     10     /* (ATM)ARP NAK.  */

#define IP_PROTO_TCP                  6
#define IP_PROTO_UDP                  17
#define IP_PROTO_ICMP                 1
#define IP6_PROTO_HOPOPT              0
#define IP6_PROTO_ROUTE               43
#define IP6_PROTO_FRAG                44
#define IP6_PROTO_ICMP                58
#define IP6_PROTO_NONXT               59

#define IP4_HEADER_LEN                20
#define IP6_HEADER_LEN                40
#define TCP_HEADER_LEN                20
#define UDP_HEADER_LEN                8
#define ICMP_HEADER_LEN               4
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
#define TF_SYNACK                     0x12
#define TF_NORESERVED (TF_FIN|TF_SYN|TF_RST|TF_PUSH|TF_ACK|TF_URG)
#define TF_FLAGS      (TF_FIN|TF_SYN|TF_RST|TF_ACK|TF_URG|TF_ECE|TF_CWR)

#define QUIRK_PAST                    0x00000001 /* P */
#define QUIRK_ZEROID                  0x00000002 /* Z */
#define QUIRK_IPOPT                   0x00000004 /* I */
#define QUIRK_URG                     0x00000008 /* U */ 
#define QUIRK_X2                      0x00000010 /* X */ 
#define QUIRK_ACK                     0x00000020 /* A */ 
#define QUIRK_T2                      0x00000040 /* T */
#define QUIRK_FLAGS                   0x00000080 /* F */
#define QUIRK_DATA                    0x00000100 /* D */
#define QUIRK_BROKEN                  0x00000200 /* ! */
#define QUIRK_RSTACK                  0x00000400 /* K */
#define QUIRK_SEQEQ                   0x00000800 /* Q */
#define QUIRK_SEQ0                    0x00001000 /* 0 */

#define QUIRK_FLOWL                   0x00000001 /* L */

/* Some systems really like to put lots of NOPs there */
#define MAXOPT                        16 /* Maximum number of TCP packet options to pars */

/* The meaning of wildcard is, however, hardcoded as 'size > PACKET_BIG' */
#define PACKET_BIG                    100 /* Size limit for size wildcards */

#define TCPOPT_EOL                    0 /* End of options */
#define TCPOPT_NOP                    1 /* Nothing */
#define TCPOPT_MAXSEG                 2 /* MSS */
#define TCPOPT_WSCALE                 3 /* Window scaling */
#define TCPOPT_SACKOK                 4 /* Selective ACK permitted */
#define TCPOPT_TIMESTAMP              8 /* Stamp out timestamping! */

#define SUCCESS                        0
#define ERROR                          1
#define STDBUF                         1024

#define INSTALL_SYSCONFDIR             ""
#define TCP_SIGNATURE_LIST             "/../etc/tcp-service.sig" 

#define MAX_APP                        100
#define MAX_VER                        25
#define MAX_MISC                       100

/*  D A T A  S T R U C T U R E S  *********************************************/

/* 
 * Ethernet header
 */

typedef struct _ether_header {
   u_char  ether_dst[6];                 /* destination MAC */
   u_char  ether_src[6];                 /* source MAC */

   union
   {
      struct etht
      {
         u_short ether_type;             /* ethernet type (normal) */
      } etht;

      struct qt
      {
         u_short eth_t_8021;             /* ethernet type/802.1Q tag */
         u_short eth_t_8_vid;
         u_short eth_t_8_type;
      } qt;
   
      struct qot
      {
         u_short eth_t_80212;            /* ethernet type/802.1QinQ */
         u_short eth_t_82_mvid; 
         u_short eth_t_82_8021;
         u_short eth_t_82_vid;
         u_short eth_t_82_type;
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

}       ether_header;

typedef struct _arphdr {
   unsigned short int ar_hrd;      /* Format of hardware address.  */
   unsigned short int ar_pro;      /* Format of protocol address.  */
   unsigned char ar_hln;           /* Length of hardware address.  */
   unsigned char ar_pln;           /* Length of protocol address.  */
   unsigned short int ar_op;       /* ARP opcode (command).  */
#if 0
   /* Ethernet looks like this : This bit is variable sized
      however...  */
   unsigned char __ar_sha[MAC_ADDR_LEN];  /* Sender hardware address.  */
   unsigned char __ar_sip[4];             /* Sender IP address.  */
   unsigned char __ar_tha[MAC_ADDR_LEN];  /* Target hardware address.  */
   unsigned char __ar_tip[4];             /* Target IP address.  */
#endif
}  arphdr;

typedef struct _ether_arp {
   arphdr   ea_hdr;                 /* fixed-size header */
   u_int8_t arp_sha[MAC_ADDR_LEN];  /* sender hardware address */
   u_int8_t arp_spa[4];             /* sender protocol address */
   u_int8_t arp_tha[MAC_ADDR_LEN];  /* target hardware address */
   u_int8_t arp_tpa[4];             /* target protocol address */
}  ether_arp;

/* 
 * IPv4 header
 */

typedef struct _ip4_header {
   uint8_t  ip_vhl;                 /* version << 4 | header length >> 2 */
   uint8_t  ip_tos;                 /* type of service */
   uint16_t ip_len;                 /* total length */
   uint16_t ip_id;                  /* identification */
   uint16_t ip_off;                 /* fragment offset field */
   uint8_t  ip_ttl;                 /* time to live */
   uint8_t  ip_p;                   /* protocol */
   uint16_t ip_csum;                /* checksum */
   uint32_t ip_src;                 /* source address */
   uint32_t ip_dst;                 /* dest address */
}  ip4_header;

#define IP_RF 0x8000                     /* reserved fragment flag */
#define IP_DF 0x4000                     /* dont fragment flag */
#define IP_MF 0x2000                     /* more fragments flag */
#define IP_OFFMASK 0x1fff                /* mask for fragmenting bits */
#define IP_HL(ip4_header)                (((ip4_header)->ip_vhl) & 0x0f)
#define IP_V(ip4_header)                 (((ip4_header)->ip_vhl) >> 4)

/* 
 * IPv6 header
 */

typedef struct _ip6_header {
    uint32_t vcl;                        /* version, class, and label */
    uint16_t len;                        /* length of the payload */
    uint8_t  next;                       /* next header
                                          * Uses the same flags as
                                          * the IPv4 protocol field */
    uint8_t  hop_lmt;                    /* hop limit */
    struct in6_addr ip_src;              /* source address */
    struct in6_addr ip_dst;              /* dest address */
} ip6_header;

#define IP6_V(ip6_header)                 (((ip6_header)->vcl)  >> 28)
//#define IP6_V(ip6_header)                 (((ip6_header)->vcl & 0xF00000000 ) >> 28)
//#define IP6_TC(ip6_header)                ((((ip6_header)->vcl) <<  4) >> 24)
#define IP6_TC(ip6_header)                ((((ip6_header)->vcl) & 0x0FF00000) >> 20)
#define IP6_FL(ip6_header)                (((ip6_header)->vcl) & 0x000FFFFF)
//#define IP6_FL(ip6_header)                ((((ip6_header)->vcl) << 12) >> 12)
//"([ver: 0x%x][len: 0x%x])\n", (ip6h->vcl & 0x0f)>>4

/* 
 * TCP header
 */

typedef struct _tcp_header {
	uint16_t  src_port;              /* source port */
	uint16_t  dst_port;              /* destination port */
	uint32_t  t_seq;                 /* sequence number */
	uint32_t  t_ack;                 /* acknowledgement number */
	uint8_t   t_offx2;               /* data offset, rsvd */
   uint8_t   t_flags;               /* tcp flags */
	uint16_t  t_win;                 /* window */
	uint16_t  t_csum;                /* checksum */
	uint16_t  t_urgp;                /* urgent pointer */
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
	uint16_t src_port;                /* source port */
	uint16_t dst_port;                /* destination port */
	uint16_t len;                     /* length of the payload */
	uint16_t csum;                    /* checksum */
} udp_header;

/* 
 * ICMP header
 */

typedef struct _icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t csum;
    union
    {
        uint8_t pptr;

        struct in_addr gwaddr;

        struct idseq
        {
            uint16_t id;
            uint16_t seq;
        } idseq;

        int sih_void;

        struct pmtu
        {
            uint16_t ipm_void;
            uint16_t nextmtu;
        } pmtu;

        struct rtradv
        {
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

    union
    {
        /* timestamp */
        struct ts
        {
            uint32_t otime;
            uint32_t rtime;
            uint32_t ttime;
        } ts;

        /* IP header for unreach */
        struct ih_ip
        {
            ip4_header *ip;
            /* options and then 64 bits of data */
        } ip;

        struct ra_addr
        {
            uint32_t addr;
            uint32_t preference;
        } radv;

        uint32_t mask;

        char    data[1];

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
    uint8_t  type;       /* type field */
    uint8_t  code;       /* code field */
    uint16_t csum;       /* checksum field */
    union
      {
        uint32_t  icmp6_data32[1]; /* type-specific field */
        uint16_t  icmp6_data16[2]; /* type-specific field */
        uint8_t   icmp6_data8[4];  /* type-specific field */
      } icmp6_data;
    #define icmp6_id        icmp6_data.icmp6_data16[0]  /* echo request/reply */
    #define icmp6_seq       icmp6_data.icmp6_data16[1]  /* echo request/reply */
} icmp6_header;

#define ICMP6_UNREACH 1
#define ICMP6_BIG     2
#define ICMP6_TIME    3
#define ICMP6_PARAMS  4
#define ICMP6_ECHO    128
#define ICMP6_REPLY   129

/* Minus 1 due to the 'body' field  */
#define ICMP6_MIN_HEADER_LEN (sizeof(ICMP6Hdr) )

/* 
 * Structure for connections
 */

typedef struct _connection {
        u_int64_t cxid;                    /* connection id */
        int af;                            /* IP version (4/6) AF_INET*/
        u_int8_t  proto;                   /* IP protocoll type */
        struct in6_addr s_ip;              /* source address */
        struct in6_addr d_ip;              /* destination address */
        u_int16_t s_port;                  /* source port */
        u_int16_t d_port;                  /* destination port */
        u_int64_t s_total_pkts;            /* total source packets */
        u_int64_t s_total_bytes;           /* total source bytes */
        u_int64_t d_total_pkts;            /* total destination packets */
        u_int64_t d_total_bytes;           /* total destination bytes */
        u_int8_t s_tcpFlags;               /* tcpflags sent by source */
        u_int8_t d_tcpFlags;               /* tcpflags sent by destination */
        time_t start_time;                 /* connection start time */
        time_t last_pkt_time;              /* last seen packet time */
        struct _connection *prev;
        struct _connection *next;
} connection;

typedef struct _serv_asset {
   time_t               first_seen;       /* Time at which service_asset was first seen. */
   time_t               last_seen;        /* Time at which service_asset was last seen. */
   unsigned short       proto;            /* Asset protocol */
   u_int16_t            port;             /* Asset port */
   bstring              service;          /* Asset service (i.e. SSH, WWW, ICMP etc.) */
   bstring              application;      /* Asset application (i.e. Apache, ICMP_TYPE etc.) */
   unsigned short       i_attempts;       /* Attempts at identifying the service_asset. */
   struct _serv_asset   *prev;            /* Prev serv_asset structure */
   struct _serv_asset   *next;            /* Next serv_asset structure */
} serv_asset;

typedef struct _os_asset {
   time_t            first_seen;          /* Time at which os_asset was first detected. */
   time_t            last_seen;           /* Time at which os_asset was last detected. */
   bstring           vendor;              /* Vendor (MS,Linux,Sun,HP...) */
   bstring           os;                  /* OS (WinXP SP2, 2.4/2.6, 10.2..) */
   bstring           detection;           /* Detection metod ((TCPSYN/SYNACK/STRAYACK)UDP/ICMP/other) */
   bstring           raw_fp;              /* The raw fingerprint [*:*:*:*:*:*:....] */
   bstring           matched_fp;          /* The FP that matched [*:*:*:*.*:*:---] */
   unsigned short    i_attempts;          /* Failed attempts at identifying the os_asset. (hench just unknown) */
   struct _os_asset  *prev;               /* Prev os_asset structure */
   struct _os_asset  *next;               /* Next os_asset structure */
} os_asset;

/* Holds one entery for an ARP/NDP or IPv4/IPv6 asset */
typedef struct _asset {
   int                  af;               /* IP AF_INET */
   struct in6_addr      ip_addr;          /* IP asset address */
   unsigned char        mac_addr[MAC_ADDR_LEN];/* Asset MAC address */
   bstring              mac_resolved;     /* Asset MAC vendor name */
   serv_asset           *services;        /* Linked list with services detected */
   os_asset             *os;              /* Linked list with OSes detected */
   time_t               first_seen;       /* Time at which asset was first seen. */
   time_t               last_seen;        /* Time at which asset was last seen. */
   unsigned short       i_attempts;       /* Attempts at identifying the asset. */
   struct _asset        *prev;            /* Prev ip_asset structure */
   struct _asset        *next;            /* Next ip_asset structure */
}  asset;

typedef struct _signature {
   bstring           service;     /* Service (i.e. SSH, WWW, etc.) */
   u_int16_t         port;        /* Port to check for this service, or 0 for all */
                                  /* Should be able to spesify range, and such... */
                                  /* Snort style : [80,8080,100-200,20-30,!22] */
                                  /* Not sure how to do that... yet.... */

   struct {                       /* Application Title, broken up into 3 parts. */
      bstring        app;         /* Application */
      bstring        ver;         /* Version */
      bstring        misc;        /* Misc info */
   }  title;
   pcre              *regex;      /* Signature - Compiled Regular Expression */
   pcre_extra        *study;      /* Studied version of the compiled regex. */
   struct _signature *next;       /* Next record in the list. */
}  signature;

typedef struct _vendor {
   unsigned int   mac;                    /* MAC ADDRESS */
   bstring        vendor;                 /* Vendor */
   struct _vendor *next;                  /* Next vendor structure */
}  vendor;

typedef struct _fp_entry {
  uint8_t            *os;              /* OS genre */
  uint8_t            *desc;            /* OS description */
  uint8_t            no_detail;        /* Disable guesstimates */
  uint8_t            generic;          /* Generic hit */
  uint8_t            userland;         /* Userland stack */
  uint16_t           wsize;            /* window size */
  uint8_t            wsize_mod;        /* MOD_* for wsize */
  uint8_t            ttl,df;           /* TTL and don't fragment bit */
  uint8_t            zero_stamp;       /* timestamp option but zero value? */
  uint16_t           size;             /* packet size */
  uint8_t            optcnt;           /* option count */
  uint8_t            opt[MAXOPT];      /* TCPOPT_* */
  uint16_t           wsc,mss;          /* value for WSCALE and MSS options */
  uint8_t            wsc_mod,mss_mod;  /* modulo for WSCALE and MSS (NONE or CONST) */
  uint32_t           quirks;           /* packet quirks and bugs */
  uint32_t           line;             /* config file line */
  struct _fp_entry   *next;
}  fp_entry;


/*  P R O T O T Y P E S  ******************************************************/

#endif // PRADS_H
