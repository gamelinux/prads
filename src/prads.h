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

/*  D E F I N E S  ************************************************************/
#define VERSION                       "0.9.1"
#define TIMEOUT                       60
/* for   5K connectinos -> bucket should be: [min   50 -> max  100] */
/* for  10K connections -> bucket should be: [min  100 -> max  200] */
/* for  20K connections -> bucket should be: [min  200 -> max  400] */
/* for  50K connections -> bucket should be: [min  500 -> max 1000] */
/* for 100K connections -> bucket should be: [min 1000 -> max 2000] */
#define BUCKET_SIZE                   1669 
/* #define BUCKET_SIZE                   101   */
/* #define BUCKET_SIZE                   31321 */

#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_802Q1MT         0x9100
#define ETHERNET_TYPE_802Q1MT2        0x9200
#define ETHERNET_TYPE_802Q1MT3        0x9300
#define ETHERNET_TYPE_8021AD          0x88a8

#define IP_PROTO_TCP                  6
#define IP_PROTO_UDP                  17
#define IP_PROTO_ICMP                 1
#define IP6_PROTO_ICMP                58

#define IP4_HEADER_LEN                20
#define IP6_HEADER_LEN                40
#define TCP_HEADER_LEN                20
#define UDP_HEADER_LEN                8
#define ICMP_HEADER_LEN               4
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

#define SUCCESS     0
#define ERROR       1
#define STDBUF      1024

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
}       ip4_header;

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
        int ipversion;                     /* IP version (4/6) */
        u_int8_t  proto;                   /* IP protocoll type */
        uint32_t s_ip4;                    /* source address */
        uint32_t d_ip4;                    /* destination address */
        struct in6_addr s_ip6;             /* source address */
        struct in6_addr d_ip6;             /* destination address */
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
        u_int64_t cxid;                    /* connection id */
        struct _connection *prev;
        struct _connection *next;
} connection;

/*  P R O T O T Y P E S  ******************************************************/

