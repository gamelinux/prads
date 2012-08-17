#ifndef DHCP_H
#define DHCP_H

#define DHCP_CLIENT_IP           "0.0.0.0"
#define DHCP_CLIENT_PORT               68
#define DHCP_SERVER_IP   "255.255.255.255"
#define DHCP_SERVER_PORT               67

#define MAXLINE 1024
#define MAXDHCPOPTS 20
#define DHCP_SIG_HASHSIZE 1024

/* SIGHASH(type, asig.optcnt, asig.optreqcnt) */
#define DHCP_SIGHASH(type,optcnt) \
        ( (type) * (optcnt) )

#define DHCP_OPTION_PAD                 0
#define BOOTP_OPTION_NETMASK            1  // RFC 2132, 3.3
#define BOOTP_OPTION_TIME_OFFSET        2
#define BOOTP_OPTION_GATEWAY            3  // RFC 2132, 3.5
#define BOOTP_OPTION_NTP                4
#define BOOTP_OPTION_NAMESRVS           5
#define BOOTP_OPTION_DNS                6  // RFC 2132, 3.8
#define DHCP_OPTION_LOGSRVS             7  // RFC 2132, 3.9
#define DHCP_OPTION_COOKIESRVS          8
#define DHCP_OPTION_LPRSRVS             9  // RFC 2132, 3.11
#define DHCP_OPTION_IMPRESSSRVS         10
#define BOOTP_OPTION_RESLOCSRVS         11
#define BOOTP_OPTION_HOSTNAME           12 // RFC 2132, 3.14
#define BOOTP_OPTION_BOOTFILE_SIZE      13 // RFC 2132, 3.15
#define BOOTP_OPTION_DOMAIN             15 // RFC 2132, 3.17
#define BOOTP_OPTION_BROADCAST          28 // RFC 2132, 5.3
#define DHCP_OPTION_ARPCACHETIMEOUT     35
#define BOOTP_OPTION_NISDOMAIN          40 // RFC 2132, 8.1
#define DHCP_OPTION_NTPSRVS             42 // RFC 2132, 8.3
#define DHCP_OPTION_XFNTSRVS            48 // RFC 2132, 8.9
#define DHCP_OPTION_XDMSRVS             49 // RFC 2132, 8.10
#define DHCP_OPTION_REQADDR             50 // RFC 2132, 9.1
#define DHCP_OPTION_LEASE               51 // RFC 2132, 9.2
#define DHCP_OPTION_OVERLOAD            52 // RFC 2132, 9.3
#define DHCP_OPTION_TYPE                53 // RFC 2132, 9.6
#define DHCP_OPTION_SERVER              54 // RFC 2132, 9.7
#define DHCP_OPTION_OPTIONREQ           55 // RFC 2132, 9.8
#define DHCP_OPTION_MAXSIZE             57 // RFC 2132, 9.10
#define DHCP_OPTION_T1                  58 // RFC 2132, 9.11
#define DHCP_OPTION_T2                  59 // RFC 2132, 9.12
#define DHCP_OPTION_CLASS_IDENTIFIER    60 // RFC 2132, 9.13
#define DHCP_OPTION_CLIENT_IDENTIFIER   61 // RFC 2132, 9.14
#define DHCP_OPTION_RAPID_COMMIT        80 // RFC 4039
#define DHCP_OPTION_END                255

#define BOOTP_OPCODE_REQUEST    1
#define BOOTP_OPCODE_REPLY      2

#define NORESPONSE              -10
#define DHCP_TYPE_DISCOVER      1 // a client broadcasts to locate servers
#define DHCP_TYPE_OFFER         2 // a server offers an IP address to the device
#define DHCP_TYPE_REQUEST       3 // client accepts offers from DHCP server
#define DHCP_TYPE_DECLINE       4 // client declines the offer from this DHCP server
#define DHCP_TYPE_ACK           5 // server to client + committed IP address
#define DHCP_TYPE_NAK           6 // server to client to state net address incorrect
#define DHCP_TYPE_RELEASE       7 // graceful shutdown from client to Server
#define DHCP_TYPE_INFORM        8 // client to server asking for local info

#define MAXOPTS 3
#define MAX_OPT_LEN 512 // RFC 2131 Minimumsize: 312 FIXME: add OPTION_MAXSIZE to use additional bytes

typedef struct _dhcp_header {
#if defined(WORDS_BIGENDIAN)
    uint8_t hops;
    uint8_t hlen;
    uint8_t htype;
    uint8_t op;
#else
    uint8_t op;                  // Op code: 1 = bootRequest, 2 = BootReply
    uint8_t htype;               // Hardware Address Type: 1 = 10MB ethernet
    uint8_t hlen;                // hardware address length: length of MACID
    uint8_t hops;                // Hw options
#endif
    uint32_t xid;                // transaction id (5)
    uint16_t secs;               // elapsed time from trying to boot (3)
    uint16_t flags;              // flags (3)
    uint32_t ciaddr;             // client IP (5)
    uint32_t yiaddr;             // your client IP (5)
    uint32_t siaddr;             // Server IP (5)
    uint32_t giaddr;             // relay agent IP (5)
    char chaddr [16];            // Client HW address (16)
    char sname [64];             // Optional server host name (64)
    char file [128];             // Boot file name (128)
} dhcp_header;


/* OPTION PAYLOAD:
 * -------------------------------------------------
 * |A|LEN|MESSAGE|a|len|Message|........|END_OPTION|
 * -------------------------------------------------
 * = A signifies the option message code as defined above
 * = LEN is the length of the message in bytes
 * = MESSAGE is the message that is passed over, whose length is determined by len
 * = END_OPTION shall signify the end of the option message
*/


int load_dhcp_sigs(const char *file, dhcp_fp_entry **dhcpsp[], int hashsize);
dhcp_fp_entry *dhcp_fingerprint(packetinfo *pi);
void print_data(const uint8_t* data, uint16_t dlen);
void print_dhcp_sig(dhcp_fp_entry * e);
void dump_dhcp_sigs(dhcp_fp_entry *mysig[], int max);
void dump_dhcp_sigs(dhcp_fp_entry *mysig[], int max);
dhcp_fp_entry *find_dhcp_match(dhcp_fp_entry *dhcpfp, packetinfo *pi);

#endif
