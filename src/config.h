#include "common.h"

typedef struct _globalconfig {
    pcap_t              *handle;        /* Pointer to libpcap handle */
    struct pcap_stat    ps;             /* libpcap stats */
    prads_stat          pr_s;          /* prads stats */
    struct bpf_program  cfilter;        /**/
    bpf_u_int32         net_mask;       /**/
    uint8_t     cflags;                 /* config flags */
    uint8_t     verbose;                /* Verbose or not */
    uint8_t     print_updates;          /* Prints updates */
    uint8_t     use_syslog;             /* Use syslog or not */
    uint8_t     setfilter;
    uint8_t     drop_privs_flag;
    uint8_t     daemon_flag;
    uint8_t     ctf;                    /* Flags for TCP checks, SYN,RST,FIN.... */
    uint8_t     cof;                    /* Flags for other; icmp,udp,other,.... */
    char        errbuf[PCAP_ERRBUF_SIZE];   /**/
    char        *bpff;                  /**/
    char        *user_filter;           /**/
    char        *net_ip_string;         /**/
    connection  *bucket[BUCKET_SIZE];   /* Pointer to list of ongoing connections */
    connection  *cxtbuffer;             /* Pointer to list of expired connections */
    asset       *passet[BUCKET_SIZE];   /* Pointer to list of assets */
    port_t      *lports[MAX_IP_PROTO];  /* Pointer to list of known ports */
    bstring     sig_file_mac;           /* Filename of MAC signature file */
    bstring     sig_file_serv_tcp;      /* Filename of tcp server sig file */
    bstring     sig_file_cli_tcp;       /* Filename of tcp client sig file */
    bstring     sig_file_serv_udp;      /* Filename of udp server sig file */
    bstring     sig_file_cli_udp;       /* Filename of udp client sig file */
    char       *sig_file_syn;           /* Filename of TCP SYN sig file */
    char       *sig_file_synack;        /* Filename of TCP SYNACK sig file */
    char       *sig_file_ack;           /* Filename of TCP Stray-ACK sig file */
    char       *sig_file_fin;           /* Filename of TCP FIN sig file */
    char       *sig_file_rst;           /* Filename of TCP RST sig file */
    signature   *sig_serv_tcp;          /* Pointer to list of tcp service signatures */
    signature   *sig_serv_udp;          /* Pointer to list of udp service signatures */
    signature   *sig_client_tcp;        /* Pointer to list of tcp client signatures */
    signature   *sig_client_udp;        /* Pointer to list of udp client signatures */
    fmask       *network[MAX_NETS];     /* Struct for fmask */
    char        *dev;                   /* Device name to use for sniffing */
    char        *dpath;                 /* ... ??? ... */
    char        *chroot_dir;            /* Directory to chroot to */
    char        *group_name;            /* Groupe to drop privileges too */
    char        *user_name;             /* User to drop privileges too */
    char        *true_pid_name;         /* Pid name */
    char        *pidfile;               /* pidfile */
    char        *pidpath;               /* Path to pidfile */
    char        *configpath;            /* Path to config dir */
    char        *s_net;                 /* Nets to collect assets for */
    uint32_t     sig_hashsize;          /* size of signature hash */
    fp_entry   **sig_syn;               /* SYN signature hash */
    fp_entry   **sig_synack;            /* SYNACK signature hash */
    fp_entry   **sig_ack;               /* Stray-ACK signature hash */
    fp_entry   **sig_fin;               /* FIN signature hash */
    fp_entry   **sig_rst;               /* RST signature hash */
} globalconfig;
#define ISSET_CONFIG_VERBOSE(config)    (config->cflags & 0x01)
#define ISSET_CONFIG_UPDATES(config)    (config->cflags & 0x02)
#define ISSET_CONFIG_SYSLOG(config)     (config->cflags & 0x04)
//#define ISSET_CONFIG_SYSLOG(config)     (config->cflags & 0x08)

void display_config();
void set_default_config_options();
void parse_line (bstring line);
void parse_config_file(bstring fname);
int brtrim (bstring string);
int bltrim (bstring string);
void free_config();
