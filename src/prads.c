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

/*  I N C L U D E S  **********************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h> 
#include <signal.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include "prads.h"
#include "misc/sys_func.c"
#include "cxtracking/cxt.c"
#include "servicefp/servicefp.c"
#include "servicefp/tcps.c"
#include "servicefp/tcpc.c"
#include "servicefp/udps.c"

/*  G L O B A L E S  **********************************************************/
u_int64_t    cxtrackerid;
time_t       timecnt,tstamp;
pcap_t       *handle;
connection   *bucket[BUCKET_SIZE];
connection   *cxtbuffer = NULL;
signature    *sig_serv_tcp = NULL;
signature    *sig_serv_udp = NULL;
signature    *sig_client_tcp = NULL;
signature    *sig_client_udp = NULL;
char  src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
static char  *dev,*dpath;
char         *chroot_dir;
char  *group_name, *user_name, *true_pid_name;
char  *pidfile = "prads.pid";
char  *pidpath = "/var/run";
int   verbose,inpacket,gameover,use_syslog,intr_flag,s_check;

/*  I N T E R N A L   P R O T O T Y P E S  ************************************/
static void usage();
static void check_interupt();

/* F U N C T I O N S  *********************************************************/

void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
   if ( intr_flag != 0 ) { check_interupt(); }
   inpacket = 1;
   s_check = 0; // do we need to ?
   tstamp = time(NULL);
   u_short p_bytes;

   /* printf("[*] Got network packet...\n"); */
   ether_header *eth_hdr;
   eth_hdr = (ether_header *) (packet);
   u_short eth_type;
   eth_type = ntohs(eth_hdr->eth_ip_type);
   int eth_header_len;
   eth_header_len = ETHERNET_HEADER_LEN;

   /* while (ETHERNET_TYPE_X) check for infinit vlan tags */
   if ( eth_type == ETHERNET_TYPE_8021Q ) {
      /* printf("[*] ETHERNET TYPE 8021Q\n"); */
      eth_type = ntohs(eth_hdr->eth_8_ip_type); 
      eth_header_len +=4;
   }

   else if ( eth_type == (ETHERNET_TYPE_802Q1MT|ETHERNET_TYPE_802Q1MT2|ETHERNET_TYPE_802Q1MT3|ETHERNET_TYPE_8021AD) ) {
      /* printf("[*] ETHERNET TYPE 802Q1MT\n"); */
      eth_type = ntohs(eth_hdr->eth_82_ip_type);
      eth_header_len +=8;
   }

   if ( eth_type == ETHERNET_TYPE_IP ) {
      //printf("[*] Got IPv4 Packet...\n"); 
      ip4_header *ip4;
      ip4 = (ip4_header *) (packet + eth_header_len);
      p_bytes = (ip4->ip_len - (IP_HL(ip4)*4));
      struct in6_addr ip_src, ip_dst;
      ip_src.s6_addr32[0] = ip4->ip_src;
      ip_dst.s6_addr32[0] = ip4->ip_dst;

      if ( ip4->ip_p == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE TCP:\n"); */

         s_check = cx_track(ip_src, tcph->src_port, ip_dst, tcph->dst_port,
                            ip4->ip_p, p_bytes, tcph->t_flags, tstamp, AF_INET);

         if ( TCP_ISFLAGSET(tcph,(TF_SYN)) && !TCP_ISFLAGSET(tcph,(TF_ACK)) ) {
            /* fp_tcp(ip, ttl, ipopts, len, id, ipflags, df); */
            //printf("[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(tcph->dst_port));
         } else if ( TCP_ISFLAGSET(tcph,(TF_SYN)) && TCP_ISFLAGSET(tcph,(TF_ACK)) ){
            //printf("[*] Got a SYNACK from a SERVER: src_port:%d\n",ntohs(tcph->src_port));
         }
         if (s_check == 0) { 
            //printf("[*] - CHECKING TCP PACKAGE\n");
         char *payload;
         payload = (char *)(packet + eth_header_len + (IP_HL(ip4)*4) + TCP_HEADER_LEN);
         service_tcp4(ip4,tcph,payload,(pheader->caplen - (TCP_OFFSET(tcph))*4 - eth_header_len));
         client_tcp4(ip4,tcph,payload,(pheader->caplen - (TCP_OFFSET(tcph))*4 - eth_header_len));
         }else{
            //printf("[*] - NOT CHECKING TCP PACKAGE\n");
         } 
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); */

         s_check = cx_track(ip_src, udph->src_port, ip_dst, udph->dst_port, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         if (s_check == 0) {
            //printf("[*] - CHECKING UDP PACKAGE\n");
         char *payload;
         payload = (char *)(packet + eth_header_len + (IP_HL(ip4)*4) + UDP_HEADER_LEN);
         service_udp4(ip4,udph,payload,(pheader->caplen - UDP_HEADER_LEN - (IP_HL(ip4)*4) - eth_header_len));
         /* fp_udp(ip, ttl, ipopts, len, id, ipflags, df); */
         }else{
            //printf("[*] - NOT CHECKING UDP PACKAGE\n");
         }
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_ICMP) {
         icmp_header *icmph;
         icmph = (icmp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IP PROTOCOL TYPE ICMP\n"); */

         s_check = cx_track(ip_src, icmph->s_icmp_id, ip_dst, icmph->s_icmp_id, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         if (s_check == 0) {
            printf("[*] - CHECKING ICMP PACKAGE\n");
         /* service_icmp(*ip4,*tcph) */
         /* fp_icmp(ip, ttl, ipopts, len, id, ipflags, df); */
         }else{
            printf("[*] - NOT CHECKING ICMP PACKAGE\n");
         }
         inpacket = 0;
         return;
      }
      else {
         printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n",ip4->ip_p); 

         s_check  = cx_track(ip_src, 0, ip_dst, 0, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         if (s_check == 0) {
            printf("[*] - CHECKING OTHER PACKAGE\n");
         /* service_other(*ip4,*tcph) */
         /* fp_other(ip, ttl, ipopts, len, id, ipflags, df); */
         }else{
            printf("[*] - NOT CHECKING OTHER PACKAGE\n");
         }
         inpacket = 0;
         return;
      }
   }

   else if ( eth_type == ETHERNET_TYPE_IPV6) {
      printf("[*] Got IPv6 Packet...\n"); 
      ip6_header *ip6;
      ip6 = (ip6_header *) (packet + eth_header_len);
      if ( ip6->next == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE TCP:\n"); */

         s_check = cx_track(ip6->ip_src, tcph->src_port, ip6->ip_dst, tcph->dst_port,
                            ip6->next, ip6->len, tcph->t_flags, tstamp, AF_INET6);
         if ( TCP_ISFLAGSET(tcph,(TF_SYN)) && !TCP_ISFLAGSET(tcph,(TF_ACK)) ) {
            /* fp_tcp(ip6, ttl, ipopts, len, id, ipflags, df); */
            printf("[*] - Got a SYN from a CLIENT: dst_port:%d\n",ntohs(tcph->dst_port));
         } else if ( TCP_ISFLAGSET(tcph,(TF_SYN)) && TCP_ISFLAGSET(tcph,(TF_ACK)) ){
            printf("[*] - Got a SYNACK from a SERVER: src_port:%d\n",ntohs(tcph->src_port));
         }
         if (s_check == 0) {
            printf("[*] - CHECKING TCP PACKAGE\n");
            char *payload;
            payload = (char *) (packet + eth_header_len + sizeof(ip6_header) );
            service_tcp6(ip6,tcph,payload,(pheader->caplen - (TCP_OFFSET(tcph))*4 - eth_header_len));
         }else{
            printf("[*] - NOT CHECKING TCP PACKAGE\n");
         }
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE UDP:\n"); */

         s_check = cx_track(ip6->ip_src, udph->src_port, ip6->ip_dst, udph->dst_port,
                            ip6->next, ip6->len, 0, tstamp, AF_INET6);
         if (s_check == 0) {
            printf("[*] - CHECKING UDP PACKAGE\n");
         /* fp_udp(ip6, ttl, ipopts, len, id, ipflags, df); */
            char *payload;
            payload = (char *) (packet + eth_header_len + sizeof(ip6_header) );
            service_udp6(ip6,udph,payload,(pheader->caplen - sizeof(udp_header) - eth_header_len));
         }else{
            printf("[*] - NOT CHECKING UDP PACKAGE\n");
         }
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP6_PROTO_ICMP) {
         icmp6_header *icmph;
         icmph = (icmp6_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE ICMP\n"); */

         s_check = cx_track(ip6->ip_src, ip6->hop_lmt, ip6->ip_dst,
                            ip6->hop_lmt, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         if (s_check == 0) {
            printf("[*] - CHECKING ICMP PACKAGE\n");
         /* service_icmp(*ip6,*tcph) */
         /* fp_icmp(ip6, ttl, ipopts, len, id, ipflags, df); */
         }else{
            printf("[*] - NOT CHECKING ICMP PACKAGE\n");
         }
         inpacket = 0;
         return;
      }
      else {
         printf("[*] IPv6 PROTOCOL TYPE OTHER: %d\n",ip6->next); 

         s_check = cx_track(ip6->ip_src, 0, ip6->ip_dst, 0,
                            ip6->next, ip6->len, 0, tstamp, AF_INET6);
         if (s_check == 0) {
         /* printf("[*] - CHECKING OTHER PACKAGE\n"); */
         /* service_other(*ip4,*tcph) */
         /* fp_other(ip, ttl, ipopts, len, id, ipflags, df); */
         }else{
         /*  printf("[*] - NOT CHECKING OTHER PACKAGE\n"); */
         }
         inpacket = 0;
         return;
      }
   }
   if ( ntohs(eth_type) == ETHERNET_TYPE_ARP ) {
      printf("[*] Got ARP Packet...\n"); 
      /* arp_check(eth_hdr,tstamp); */
      return;
   }

   inpacket = 0;
   return;
   /* else { */
      /* printf("[*] ETHERNET TYPE : %x\n", eth_hdr->eth_ip_type); */
   /*   return; */
   /* } */
}

static void check_interupt() {
   return;
}

static void usage() {
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
    printf(" -v             : verbose\n\n");
}

int main(int argc, char *argv[]) {

   int ch, fromfile, setfilter, version, drop_privs_flag, daemon_flag;
   int use_syslog = 0;
   struct in_addr addr;
   struct bpf_program cfilter;
   char *bpff, errbuf[PCAP_ERRBUF_SIZE], *user_filter;
   char *net_ip_string;
   bpf_u_int32 net_mask;
   ch = fromfile = setfilter = version = drop_privs_flag = daemon_flag = 0;
   dev = "eth0";
   bpff = "";
   dpath = "/tmp";
   cxtbuffer = NULL;
   cxtrackerid  = 0;
   inpacket = gameover = intr_flag = 0;
   timecnt = time(NULL);

   //signal(SIGTERM, game_over);
   //signal(SIGINT,  game_over);
   //signal(SIGQUIT, game_over);
   signal(SIGALRM, end_sessions);

   while ((ch = getopt(argc, argv, "b:d:Dg:hi:p:P:u:v")) != -1)
   switch (ch) {
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

   printf("[*] Running prads %s\n",VERSION);
   load_servicefp_file(1,"../etc/tcp-service.sig");
   load_servicefp_file(2,"../etc/udp-service.sig");
   load_servicefp_file(3,"../etc/tcp-clients.sig");
   //load_servicefp_file(4,"../etc/udp-client.sig");

   errbuf[0] = '\0';
   /* look up an availible device if non specified */
   if (dev == 0x0) dev = pcap_lookupdev(errbuf);
   printf("[*] Device: %s\n", dev);

   if ((handle = pcap_open_live(dev, 65535, 1, 500, errbuf)) == NULL) {
      printf("[*] Error pcap_open_live: %s \n", errbuf);
      exit(1);
   }
   else if ((pcap_compile(handle, &cfilter, bpff, 1 ,net_mask)) == -1) {
      printf("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(handle));
      exit(1);
   }

   pcap_setfilter(handle, &cfilter);

   /* B0rk if we see an error... */
   if (strlen(errbuf) > 0) {
      printf("[*] Error errbuf: %s \n", errbuf);
      exit(1);
   }

   if(daemon_flag) {
      if(!is_valid_path(pidpath))
         printf("[*] PID path \"%s\" is bad, check privilege.",pidpath);
         openlog("prads", LOG_PID | LOG_CONS, LOG_DAEMON);
         printf("[*] Daemonizing...\n\n");
         go_daemon();
   }

   if(drop_privs_flag) {
      printf("[*] Dropping privs...\n\n");
      drop_privs();
   } 
   bucket_keys_NULL();

   printf("[*] Sniffing...\n\n");
   pcap_loop(handle,-1,got_packet,NULL);

   pcap_close(handle);
   return(0);
}
