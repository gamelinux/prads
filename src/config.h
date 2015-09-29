#ifndef CONFIG_H
#define CONFIG_H

#define CONFIG_VERBOSE 0x01
#define CONFIG_UPDATES 0x02
#define CONFIG_SYSLOG  0x04
#define CONFIG_QUIET   0x08
#define CONFIG_CONNECT 0x10
#define CONFIG_CXWRITE 0x20
#define CONFIG_PDNS    0x40

#define DEFAULT_NETS "0.0.0.0/0,::/0"

/* Flags to set for enabling different OS Fingerprinting checks.
 * Make these compatible with TCP flags!*/
#define CO_FIN                        0x01      /* Check FIN packets */
#define CO_SYN                        0x02      /* Check SYN packets */
#define CO_RST                        0x04      /* Check RST packets */
// push                               0x08
#define CO_SYNACK                     0x08      /* Check SYNACK packets */
#define CO_ACK                        0x10      /* Check Stray-ACK packets */
// urg                                0x20
// ece                                0x40
// cwr                                0x80
#define CO_ICMP                       0x20      /* Check ICMP Packets */
#define CO_UDP                        0x40      /* Check UDP Packets */
#define CO_DHCP                       0x80      /* Check DHCP Packets */
#define CO_OTHER                      0x7f      /* Check Other Packets - need a flag! */

/* Flags to set for enabling different service/client checks */
#define CS_TCP_SERVER                 0x01
#define CS_TCP_CLIENT                 0x02
#define CS_UDP_SERVICES               0x04  /* Currently implying server+client*/
#define CS_UDP_CLIENT                 0x08
#define CS_MAC                        0x10
#define CS_ICMP                       0x20
#define CS_ARP                        0x80

typedef struct _globalconfig {
    pcap_t              *handle;        /* Pointer to libpcap handle */
    struct pcap_stat    ps;             /* libpcap stats */
    prads_stat          pr_s;           /* prads stats */
    bpf_u_int32         net_mask;       /**/
    uint8_t     cflags;                 /* config flags */
    uint8_t     verbose;                /* Verbose or not */
    uint8_t     print_updates;          /* Prints updates */
    uint8_t     setfilter;
    uint8_t     drop_privs_flag;
    uint8_t     daemon_flag;
    uint8_t     ctf;                    /* Flags for TCP checks, SYN,RST,FIN.... */
    uint8_t     cof;                    /* Flags for other; icmp,udp,other,.... */
    uint32_t    payload;                /* dump how much of the payload ?  */
    char        errbuf[PCAP_ERRBUF_SIZE];   /**/
    char        *bpff;                  /**/
    char        *user_filter;           /**/
    char        *net_ip_string;         /**/
    connection  *bucket[BUCKET_SIZE];   /* Pointer to list of ongoing connections */
    connection  *cxtbuffer;             /* Pointer to list of expired connections */
    asset       *passet[BUCKET_SIZE];   /* Pointer to list of assets */
    port_t      *lports[MAX_IP_PROTO];  /* Pointer to list of known ports */
    char        cxtfname[4096];         /* cxtracker/sancp like output file */
    char        cxtlogdir[2048];        /* log dir for sancp/cxtracker output */
    char       *file;                   /* config file location, if known */
    char       *assetlog;               /* Filename of prads-asset.log */
    char       *fifo;                   /* Path to FIFO output */
    uint8_t    ringbuffer;              /* Enable logging to ringbuffer */
    char       *pcap_file;              /* Filename to pcap too read */
    char       *sig_file_syn;           /* Filename of TCP SYN sig file */
    char       *sig_file_synack;        /* Filename of TCP SYNACK sig file */
    char       *sig_file_ack;           /* Filename of TCP Stray-ACK sig file */
    char       *sig_file_fin;           /* Filename of TCP FIN sig file */
    char       *sig_file_rst;           /* Filename of TCP RST sig file */
    char       *sig_file_mac;           /* Filename of MAC signature file */
    char       *sig_file_dhcp;          /* Filename of DHCP signature file */
    char       *sig_file_serv_tcp;      /* Filename of tcp server sig file */
    char       *sig_file_cli_tcp;       /* Filename of tcp client sig file */
    char       *sig_file_serv_udp;      /* Filename of udp server sig file */
    char       *sig_file_cli_udp;       /* Filename of udp client sig file */
    signature   *sig_serv_tcp;          /* Pointer to list of tcp service signatures */
    signature   *sig_serv_udp;          /* Pointer to list of udp service signatures */
    signature   *sig_client_tcp;        /* Pointer to list of tcp client signatures */
    signature   *sig_client_udp;        /* Pointer to list of udp client signatures */
    fmask       *network[MAX_NETS];     /* Struct for fmask */
    char        *dev;                   /* Device name to use for sniffing */
    char        *chroot_dir;            /* Directory to chroot to */
    char        *group_name;            /* Groupe to drop privileges too */
    char        *user_name;             /* User to drop privileges too */
    char        *pidfile;               /* pidfile */
    char        *configpath;            /* Path to config dir */
    char        *s_net;                 /* Nets to collect assets for */
    uint32_t     sig_hashsize;          /* size of signature hash */
    uint32_t     mac_hashsize;          /* size of mac hash */
    fp_entry   **sig_syn;               /* SYN signature hash */
    fp_entry   **sig_synack;            /* SYNACK signature hash */
    fp_entry   **sig_ack;               /* Stray-ACK signature hash */
    fp_entry   **sig_fin;               /* FIN signature hash */
    fp_entry   **sig_rst;               /* RST signature hash */
    mac_entry  **sig_mac;               /* Pointer to hash of mac signatures */
    dhcp_fp_entry **sig_dhcp;           /* DHCP signature hash */
    char        *bpf_file;              /* filename of BPF file to load */
    uint8_t      tcpopt_parsable;

} globalconfig;
#define ISSET_CONFIG_VERBOSE(config)    ((config).cflags & CONFIG_VERBOSE)
#define ISSET_CONFIG_UPDATES(config)    ((config).cflags & CONFIG_UPDATES)
#define ISSET_CONFIG_SYSLOG(config)     ((config).cflags & CONFIG_SYSLOG)
#define ISSET_CONFIG_QUIET(config)      ((config).cflags & CONFIG_QUIET)

void display_config(globalconfig *conf);
void set_default_config_options(globalconfig *conf);
void parse_line (globalconfig *conf, bstring line);
void parse_config_file(const char *fname);
int parse_args(globalconfig *conf, int argc, char *argv[], char *args);
int brtrim (bstring string);
int bltrim (bstring string);
void free_config();

#endif                          // CONFIG_H
