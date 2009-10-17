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

/*  G L O B A L E S  **********************************************************/
u_int64_t    cxtrackerid;
time_t       timecnt,tstamp;
pcap_t       *handle;
connection   *bucket[BUCKET_SIZE];
connection   *cxtbuffer = NULL;
static char  src_s[INET6_ADDRSTRLEN], dst_s[INET6_ADDRSTRLEN];
static char  *dev,*dpath;
static char  *group_name, *user_name, *true_pid_name;
static char  *pidfile = "prads.pid";
static char  *pidpath = "/var/run";
static int   verbose, inpacket, gameover, use_syslog;

/*  I N T E R N A L   P R O T O T Y P E S  ************************************/
void move_connection (connection*, connection**);
void cx_track4(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void cx_track6(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet);
void end_sessions();
void cxtbuffer_write();
void game_over();

void got_packet (u_char *useless,const struct pcap_pkthdr *pheader, const u_char *packet) {
   if ( gameover == 1 ) { game_over(); }
   inpacket = 1;
   tstamp = time(NULL);
   u_short p_bytes;

   /* printf("[*] Got network packet...\n"); */
   ether_header *eth_hdr;
   eth_hdr = (ether_header *) (packet);
   u_short eth_type;
   eth_type = ntohs(eth_hdr->eth_ip_type);
   int eth_header_len;
   eth_header_len = ETHERNET_HEADER_LEN;

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
      /* printf("[*] Got IPv4 Packet...\n"); */
      ip4_header *ip4;
      ip4 = (ip4_header *) (packet + eth_header_len);
      p_bytes = (ip4->ip_len - (IP_HL(ip4)*4));

      if ( ip4->ip_p == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE TCP:\n"); */
         cx_track4(ip4->ip_src, tcph->src_port, ip4->ip_dst, tcph->dst_port, ip4->ip_p, p_bytes, tcph->t_flags, tstamp, AF_INET);
         /*packet_tcp(ip, ttl, ipopts, len, id, ipflags, df);*/
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IPv4 PROTOCOL TYPE UDP:\n"); */
         cx_track4(ip4->ip_src, udph->src_port, ip4->ip_dst, udph->dst_port, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         /*packet_udp(ip, ttl, ipopts, len, id, ipflags, df);*/
         inpacket = 0;
         return;
      }
      else if (ip4->ip_p == IP_PROTO_ICMP) {
         icmp_header *icmph;
         icmph = (icmp_header *) (packet + eth_header_len + (IP_HL(ip4)*4));
         /* printf("[*] IP PROTOCOL TYPE ICMP\n"); */
         cx_track4(ip4->ip_src, icmph->s_icmp_id, ip4->ip_dst, icmph->s_icmp_id, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         /*packet_icmp(ip, ttl, ipopts, len, id, ipflags, df);*/
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv4 PROTOCOL TYPE OTHER: %d\n",ip4->ip_p); */
         cx_track4(ip4->ip_src, ip4->ip_p, ip4->ip_dst, ip4->ip_p, ip4->ip_p, p_bytes, 0, tstamp, AF_INET);
         inpacket = 0;
         return;
      }
   }

   else if ( eth_type == ETHERNET_TYPE_IPV6) {
      /* printf("[*] Got IPv6 Packet...\n"); */
      ip6_header *ip6;
      ip6 = (ip6_header *) (packet + eth_header_len);
      if ( ip6->next == IP_PROTO_TCP ) {
         tcp_header *tcph;
         tcph = (tcp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE TCP:\n"); */
         cx_track6(ip6->ip_src, tcph->src_port, ip6->ip_dst, tcph->dst_port, ip6->next, ip6->len, tcph->t_flags, tstamp, AF_INET6);
         /*packet_tcp(ip, ttl, ipopts, len, id, ipflags, df);*/
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP_PROTO_UDP) {
         udp_header *udph;
         udph = (udp_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE UDP:\n"); */
         cx_track6(ip6->ip_src, udph->src_port, ip6->ip_dst, udph->dst_port, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         /*packet_udp(ip, ttl, ipopts, len, id, ipflags, df);*/
         inpacket = 0;
         return;
      }
      else if (ip6->next == IP6_PROTO_ICMP) {
         icmp6_header *icmph;
         icmph = (icmp6_header *) (packet + eth_header_len + ip6->len);
         /* printf("[*] IPv6 PROTOCOL TYPE ICMP\n"); */
         cx_track6(ip6->ip_src, ip6->hop_lmt, ip6->ip_dst, ip6->hop_lmt, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         /*packet_icmp(ip, ttl, ipopts, len, id, ipflags, df);*/
         inpacket = 0;
         return;
      }
      else {
         /* printf("[*] IPv6 PROTOCOL TYPE OTHER: %d\n",ip6->next); */
         cx_track6(ip6->ip_src, ip6->next, ip6->ip_dst, ip6->next, ip6->next, ip6->len, 0, tstamp, AF_INET6);
         inpacket = 0;
         return;
      }
   }
   if ( ntohs(eth_type) == ETHERNET_TYPE_ARP ) {
      /* printf("[*] Got ARP Packet...\n"); */
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

/* For prads, I guess cx_track needs to return a value, which can
 * be used for evaluating if we should do some fingerprinting
 */
void cx_track4(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *cxt = NULL;
   connection *head = NULL;
   uint64_t hash;

   hash = (( ip_src + ip_dst )) % BUCKET_SIZE;

   cxt = bucket[hash];
   head = cxt;

   while ( cxt != NULL ) {
      if ( cxt->s_ip4 == ip_src && cxt->d_ip4 == ip_dst && cxt->s_port == src_port && cxt->d_port == dst_port ) {
         cxt->s_tcpFlags    |= tcpflags;
         cxt->s_total_bytes += p_bytes;
         cxt->s_total_pkts  += 1;
         cxt->last_pkt_time  = tstamp;
         /* Check if :
          * cxt->s_total_bytes > MAX_BYTE_CHECK
          *  or
          * cxt->s_total_pkts > MAX_PACKET_CHECK
          * If so, return value should indicate not to do fingerprinting.
          */
         return;
      }
      else if ( cxt->s_ip4 == ip_dst && cxt->d_ip4 == ip_src && cxt->d_port == src_port && cxt->s_port == dst_port ) {
         cxt->d_tcpFlags    |= tcpflags;
         cxt->d_total_bytes += p_bytes;
         cxt->d_total_pkts  += 1;
         cxt->last_pkt_time  = tstamp;
         /* Check if :
          * cxt->s_total_bytes > MAX_BYTE_CHECK
          *  or
          * cxt->s_total_pkts > MAX_PACKET_CHECK
          * If so, return value should indicate not to do fingerprinting.
          */
         return;
      }
      cxt = cxt->next;
   }

   if ( cxt == NULL ) {
      cxtrackerid += 1;
      cxt = (connection*) calloc(1, sizeof(connection));
      if (head != NULL ) { 
         head->prev = cxt;
      }
      /* printf("[*] New connection...\n"); */
      cxt->cxid           = cxtrackerid;
      cxt->ipversion      = af;
      cxt->s_tcpFlags     = tcpflags;
      cxt->d_tcpFlags     = 0x00;
      cxt->s_total_bytes  = p_bytes;
      cxt->s_total_pkts   = 1;
      cxt->d_total_bytes  = 0;
      cxt->d_total_pkts   = 0;
      cxt->start_time     = tstamp;
      cxt->last_pkt_time  = tstamp;
      cxt->s_ip4          = ip_src;
      cxt->s_ip6.s6_addr32[0]          = 0; 
      /* cxt->s_ip6.s6_addr32[1]          = 0; */
      /* cxt->s_ip6.s6_addr32[2]          = 0; */
      /* cxt->s_ip6.s6_addr32[3]          = 0; */
      cxt->s_port         = src_port;
      cxt->d_ip4          = ip_dst;
      cxt->d_ip6.s6_addr32[0]          = 0; 
      /* cxt->d_ip6.s6_addr32[1]          = 0; */
      /* cxt->d_ip6.s6_addr32[2]          = 0; */
      /* cxt->d_ip6.s6_addr32[3]          = 0; */
      cxt->d_port         = dst_port;
      cxt->proto          = ip_proto;
      cxt->next           = head;
      cxt->prev           = NULL;

      /* New connections are pushed on to the head of bucket[s_hash] */
      bucket[hash] = cxt;

      if ( ((tstamp - timecnt) > TIMEOUT) ) {
         timecnt = time(NULL);
         end_sessions();
      }
      /* Return value should be X, telling to do fingerprinting */
      return;
   }
   /* Should never be here! */
   return;
}

void cx_track6(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) {

   connection *cxt = NULL;
   connection *head = NULL;
   uint32_t hash;

   /* Do we need all fields? */
   hash = ((  ip_src.s6_addr32[0] + ip_src.s6_addr32[1] + ip_src.s6_addr32[2] + ip_src.s6_addr32[3]
              + ip_dst.s6_addr32[0] + ip_dst.s6_addr32[1] + ip_dst.s6_addr32[2] + ip_dst.s6_addr32[3]
              + src_port + dst_port )) % BUCKET_SIZE;

   cxt = bucket[hash];
   head = cxt;

   while ( cxt != NULL ) {
      if ( memcmp(&cxt->s_ip6,&ip_src,16) && memcmp(&cxt->d_ip6,&ip_dst,16) &&
           cxt->s_port == src_port && cxt->d_port == dst_port ) {
         cxt->s_tcpFlags    |= tcpflags;
         cxt->s_total_bytes += p_bytes;
         cxt->s_total_pkts  += 1;
         cxt->last_pkt_time  = tstamp;
         return;
      }else 
      if ( memcmp(&cxt->s_ip6,&ip_dst,16) && memcmp(&cxt->d_ip6,&ip_src,16) &&
           cxt->d_port == src_port && cxt->s_port == dst_port ) {
         cxt->d_tcpFlags    |= tcpflags;
         cxt->d_total_bytes += p_bytes;
         cxt->d_total_pkts  += 1;
         cxt->last_pkt_time  = tstamp;
         return;
      }
      cxt = cxt->next;
   }

   if ( cxt == NULL ) {
      cxtrackerid += 1;
      cxt = (connection*) calloc(1, sizeof(connection));
      if (head) {
         head->prev = cxt;
      }
      /* printf("[*] New connection...\n"); */
      cxt->cxid           = cxtrackerid;
      cxt->ipversion      = af;
      cxt->s_tcpFlags     = tcpflags;
      cxt->d_tcpFlags     = 0x00;
      cxt->s_total_bytes  = p_bytes;
      cxt->s_total_pkts   = 1;
      cxt->d_total_bytes  = 0;
      cxt->d_total_pkts   = 0;
      cxt->start_time     = tstamp;
      cxt->last_pkt_time  = tstamp;
      cxt->s_ip4          = 0;
      cxt->s_ip6          = ip_src;
      cxt->s_port         = src_port;
      cxt->d_ip4          = 0;
      cxt->d_ip6          = ip_dst;
      cxt->d_port         = dst_port;
      cxt->proto          = ip_proto;
      cxt->next           = head;
      cxt->prev           = NULL;

      bucket[hash] = cxt;

      if ( ((tstamp - timecnt) > TIMEOUT) ) {
         timecnt = time(NULL);
         end_sessions();
      }
      return;
   }
   /* Should never be here! */
   return;
}

/*
 This sub marks sessions as ENDED on different criterias:
*/

void end_sessions() {

   connection *cxt;
   time_t check_time;
   check_time = time(NULL);
   int cxkey, xpir;
   uint32_t curcxt  = 0;
   uint32_t expired = 0;
   cxtbuffer = NULL;
   
   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      xpir = 0;
      while ( cxt != NULL ) {
         curcxt++;
         /* TCP */
         if ( cxt->proto == IP_PROTO_TCP ) {
           /* FIN from both sides */
           if ( cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN && (check_time - cxt->last_pkt_time) > 5 ) {
              xpir = 1;
           }
           /* RST from eather side */
           else if ( (cxt->s_tcpFlags & TF_RST || cxt->d_tcpFlags & TF_RST) && (check_time - cxt->last_pkt_time) > 5) {
              xpir = 1;
           }
           /* if not a complete TCP 3-way handshake */
           else if ( !cxt->s_tcpFlags&TF_SYNACK || !cxt->d_tcpFlags&TF_SYNACK && (check_time - cxt->last_pkt_time) > 10) {
              xpir = 1;
           }
           /* Ongoing timout */
           else if ( (cxt->s_tcpFlags&TF_SYNACK || cxt->d_tcpFlags&TF_SYNACK) && ((check_time - cxt->last_pkt_time) > 120)) {
              xpir = 1;
           }
           else if ( (check_time - cxt->last_pkt_time) > 600 ) {
              xpir = 1;
           }
         }
         else if ( cxt->proto == IP_PROTO_UDP && (check_time - cxt->last_pkt_time) > 60 ) {
            xpir = 1;
         }
         else if ( cxt->proto == IP_PROTO_ICMP || cxt->proto == IP6_PROTO_ICMP ) {
            if ( (check_time - cxt->last_pkt_time) > 60 ) {
               xpir = 1;
            }
         }
         else if ( (check_time - cxt->last_pkt_time) > 300 ) {
            xpir = 1;
         }

         if ( xpir == 1 ) {
            expired++;
            xpir = 0;
            connection *tmp = cxt;
            if (cxt == cxt->next) {
               cxt->next == NULL;
            }
            cxt = cxt->next;
            del_connection(tmp, &bucket[cxkey]);
         }else{
            cxt = cxt->next;
         }
      }
   }
   /* printf("Expired: %u of %u total connections:\n",expired,curcxt); */
   
   /* Not needed here */
   /* cxtbuffer_write();  */
}

void del_connection (connection* cxt, connection **bucket_ptr ){
   /* remove cxt from bucket */
   connection *prev = cxt->prev; /* OLDER connections */
   connection *next = cxt->next; /* NEWER connections */
   if(prev == NULL){
      // beginning of list
      *bucket_ptr = next;
      // not only entry
      if(next)
         next->prev = NULL;
   } else if(next == NULL){
      // at end of list!
      prev->next = NULL;
   } else {
      // a node.
      prev->next = next;
      next->prev = prev;
   }

   /* Free and set to NULL */
   free(cxt);
   cxt=NULL;
}

void end_all_sessions() {
   connection *cxt;
   int cxkey;
   int expired = 0;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      cxt = bucket[cxkey];
      while ( cxt != NULL ) {
         expired++;
         connection *tmp = cxt;
         cxt = cxt->next;           
         move_connection(tmp, &bucket[cxkey]);
         if ( cxt == NULL ) {
            bucket[cxkey] = NULL;
         }
      }
   }
   /* printf("Expired: %d.\n",expired); */
}

void bucket_keys_NULL() {
   int cxkey;

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      bucket[cxkey] = NULL;
   }
}

void game_over() {
   gameover = 1;
   if (inpacket == 0) {
      end_all_sessions();
      cxtbuffer_write();
      pcap_close(handle);
      exit (0);
   }
}

static int drop_privs(void) {
   struct group *gr;
   struct passwd *pw;
   char *endptr;
   int i;
   int do_setuid = 0;
   int do_setgid = 0;
   unsigned long groupid = 0;
   unsigned long userid = 0;

   if ( group_name != NULL ) {
      do_setgid = 1;
      if( isdigit(group_name[0]) == 0 ) {
         gr = getgrnam(group_name);
         groupid = gr->gr_gid;
      }
      else {
         groupid = strtoul(group_name, &endptr, 10);
      }        
   }
    
   if ( user_name != NULL ) {
      do_setuid = 1;
      do_setgid = 1;
      if ( isdigit(user_name[0]) == 0 ) {
         pw = getpwnam(user_name);
         userid = pw->pw_uid;
      } else {
         userid = strtoul(user_name, &endptr, 10);
         pw = getpwuid(userid);
      }
        
      if ( group_name == NULL ) {
         groupid = pw->pw_gid;
      }
   }

   if ( do_setgid ) {
      if ( (i = setgid(groupid)) < 0 ) {
         printf("Unable to set group ID: %s", strerror(i));
      }
   }
    
   endgrent();
   endpwent();
    
   if ( do_setuid ) {
      if (getuid() == 0 && initgroups(user_name, groupid) < 0 ) {
         printf("Unable to init group names (%s/%lu)", user_name, groupid);
      }
      if ( (i = setuid(userid)) < 0 ) {
         printf("Unable to set user ID: %s\n", strerror(i));
      }
   }
   return 0;
}

static int is_valid_path(char *path) {
   struct stat st;

   if ( path == NULL ) {
      return 0;
   }
   if ( stat(path, &st) != 0 ) {
      return 0;
   }
   if ( !S_ISDIR(st.st_mode) || access(path, W_OK) == -1 ) {
      return 0;
   }
   return 1;
}

static int create_pid_file(char *path, char *filename) {
   char filepath[STDBUF];
   char *fp = NULL;
   char *fn = NULL;
   char pid_buffer[12];
   struct flock lock;
   int rval;
   int fd;

   memset(filepath, 0, STDBUF);

   if ( !filename ) {
      fn = pidfile;
   }
   else {
      fn = filename;
   }

   if ( !path ) {
      fp = pidpath;
   }
   else {
      fp = path;
   }

   if ( is_valid_path(fp) ) {
      snprintf(filepath, STDBUF-1, "%s/%s", fp, fn);
   }
   else {
      printf("PID path \"%s\" isn't a writeable directory!", fp);
   }
   
   true_pid_name = strdup(filename);
   
   if ( (fd = open(filepath, O_CREAT | O_WRONLY,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1 ) {
      return ERROR;
   }

   /* pid file locking */
   lock.l_type = F_WRLCK;
   lock.l_start = 0;
   lock.l_whence = SEEK_SET;
   lock.l_len = 0;

   if ( fcntl(fd, F_SETLK, &lock) == -1 ) {
      if ( errno == EACCES || errno == EAGAIN ) {
         rval = ERROR;
      }
      else {
         rval = ERROR;
      }
      close(fd);
      return rval;
   }

   snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int) getpid());
   if ( ftruncate(fd, 0) != 0 ) { return ERROR; }
   if ( write(fd, pid_buffer, strlen(pid_buffer)) != 0 ) { return ERROR; }
   return SUCCESS;
}

int daemonize() {
   pid_t pid;
   int fd;

   pid = fork();

   if ( pid > 0 ) {
      exit(0); /* parent */
   }

   use_syslog = 1;
   if ( pid < 0 ) {
      return ERROR;
   }

   /* new process group */
   setsid();

   /* close file handles */
   if ( (fd = open("/dev/null", O_RDWR)) >= 0 ) {
      dup2(fd, 0);
      dup2(fd, 1);
      dup2(fd, 2);
      if ( fd > 2 ) {
         close(fd);
      }
   }

   if ( pidfile ) {
      return create_pid_file(pidpath, pidfile);
   }

   return SUCCESS;
}

static int go_daemon() {
    return daemonize(NULL);
}

static void usage() {
    printf("USAGE:\n");
    printf(" $ prads [options]\n");
    printf("\n");
    printf(" OPTIONS:\n");
    printf("\n");
    printf(" -i             : network device (default: eth0)\n");
    printf(" -b             : berkeley packet filter\n");
    printf(" -d             : xxx\n");
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
   inpacket = gameover = 0;
   timecnt = time(NULL);

   signal(SIGTERM, game_over);
   signal(SIGINT,  game_over);
   signal(SIGQUIT, game_over);
   signal(SIGALRM, end_sessions);
   /* alarm(TIMEOUT); */

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
