/* author: Kacper Wysocki <kwy@redpill-linpro.com> */
#include "../prads.h"
#include "../sys_func.h"
#include "../sig.h"
#include "../config.h"
#include "../cxt.h"
#include "log.h"
#include "log_stdout.h"

output_plugin p_stdout = {
    .init = &init_output_stdout,
    .arp = &stdout_arp,
    .os = &stdout_os,
    .service = &stdout_service,
    .connection = NULL,
    .denit = &end_log_stdout,
    .data = NULL,
};

output_plugin *init_log_stdout()
{
    return &p_stdout;
}

int init_output_stdout(output_plugin *p, const char *f, int flags)
{
    if(flags & (CONFIG_CXWRITE | CONFIG_CONNECT)){
        p->connection = &stdout_connection;
        if(!(flags & CONFIG_VERBOSE)){
            p->arp = NULL;
            p->os = NULL;
            p->service = NULL;
        }
    }
    return 0;
}

int end_log_stdout (output_plugin *log)
{
    return 0;
}


void stdout_arp (output_plugin *unused, asset *main)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];

    if (memcmp(main->mac_addr, "\0\0\0\0\0\0", 6)) {
        u_ntop(main->ip_addr, main->af, ip_addr_s);
        printf("%s", ip_addr_s);
        if (main->vlan != 0) printf(",[vlan:%u]", ntohs(main->vlan));
        printf(",[arp:%s]",
        hex2mac(main->mac_addr));
        if(main->macentry) printf(",%s", main->macentry->vendor);
        printf("\n");
    }
    fflush(0);
}

void stdout_os (output_plugin *unused, asset *main, os_asset *os, connection* c)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    uint8_t tmp_ttl;

    u_ntop(main->ip_addr, main->af, ip_addr_s);
    printf("%s", ip_addr_s);
    if (main->vlan != 0) printf(",[vlan:%u]", ntohs(main->vlan));
    
    printf(",[");
    if (os->detection == CO_SYN) printf("syn");
    if (os->detection == CO_SYNACK) printf("synack");
    if (os->detection == CO_ACK) printf("ack");
    if (os->detection == CO_RST) printf("rst");
    if (os->detection == CO_FIN) printf("fin");
    if (os->detection == CO_UDP) printf("udp");
    if (os->detection == CO_ICMP) printf("icmp");

    printf(":");
    if (os->raw_fp != NULL) {
        printf("%s]", (char *)bdata(os->raw_fp));
    } else {
        bstring b = gen_fp_tcp(&os->fp, os->uptime, os->detection);
        os->raw_fp = b;
        printf("%s]", (char *)bdata(os->raw_fp));

        if (os->fp.os != NULL) printf(",[%s", os->fp.os);
            else printf(",[unknown");
        if (os->fp.desc != NULL) printf(":%s]", os->fp.desc);
            else printf(":unknown]");
        
        if (os->fp.mss) printf(",[link:%s]",lookup_link(os->fp.mss,1));
    }

    if (os->uptime) printf(",[uptime:%dhrs]",os->uptime/360000);
    if (os->ttl) {
        tmp_ttl = normalize_ttl(os->ttl);
        printf(",[distance:%d]",tmp_ttl - os->ttl);
    }
    printf("\n");
    fflush(0);
}

void stdout_service (output_plugin* unused, asset *main, serv_asset *service, connection *c)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    uint8_t tmp_ttl;

    u_ntop(main->ip_addr, main->af, ip_addr_s);
    printf("%s", ip_addr_s);
    if (main->vlan != 0) printf(",[vlan:%u]", ntohs(main->vlan));

    if (service->role == SC_SERVER) {
        printf(",[service:%s:%u:%u]",
        (char *)bdata(service->application),
        ntohs(service->port),service->proto);
    } else {
        printf(",[client:%s:%u:%u]",
        (char*)bdata(service->application),
        ntohs(service->port),service->proto);
    }
    if (service->ttl) {
        tmp_ttl = normalize_ttl(service->ttl);
        printf(",[distance:%d]",tmp_ttl - service->ttl);
    }
    printf("\n");
    fflush(0);
}

void stdout_excessive(connection *cxt)
{
   static char src_s[INET6_ADDRSTRLEN];
   static char dst_s[INET6_ADDRSTRLEN];
   if(!inet_ntop(cxt->af, (cxt->af == AF_INET6? (void*) &cxt->s_ip : (void*) cxt->s_ip.s6_addr32), src_s, INET6_ADDRSTRLEN))
      perror("inet_ntop");
   if(!inet_ntop(cxt->af, (cxt->af == AF_INET6? (void*) &cxt->d_ip : (void*) cxt->d_ip.s6_addr32), dst_s, INET6_ADDRSTRLEN))
      perror("inet_ntop");
   printf("conn[%4lu] %s:%u -> %s:%u\n", cxt->cxid, 
          src_s, ntohs(cxt->s_port),
          dst_s, ntohs(cxt->d_port));
}

void stdout_connection (output_plugin *plugin, connection *cxt, int outputmode)
{
    char stime[80], ltime[80];
    time_t tot_time;
   static char src_s[INET6_ADDRSTRLEN];
   static char dst_s[INET6_ADDRSTRLEN];
    if(outputmode == CX_EXCESSIVE){
       stdout_excessive(cxt);
       return;
    }
    FILE *fd = stdout;
    strftime(stime, 80, "%F %H:%M:%S", gmtime(&cxt->start_time));
    strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cxt->last_pkt_time));
    tot_time = cxt->last_pkt_time - cxt->start_time;

    fprintf(fd, "%ld%09ju|%s|%s|%ld|%hhu|",
            cxt->start_time, cxt->cxid, stime, ltime, tot_time,
            cxt->proto);
    if(!inet_ntop(cxt->af, (cxt->af == AF_INET6? (void*) &cxt->s_ip : (void*) cxt->s_ip.s6_addr32), src_s, INET6_ADDRSTRLEN))
        perror("inet_ntop");
    if(!inet_ntop(cxt->af, (cxt->af == AF_INET6? (void*) &cxt->d_ip : (void*) cxt->d_ip.s6_addr32), dst_s, INET6_ADDRSTRLEN))
        perror("inet_ntop");
    fprintf(fd, "%s|%u|%s|%u|",
            src_s, ntohs(cxt->s_port),
            dst_s, ntohs(cxt->d_port));
    fprintf(fd, "%ju|%ju|", 
            cxt->s_total_pkts, cxt->s_total_bytes);
    fprintf(fd, "%ju|%ju|%u|%u",
            cxt->d_total_pkts, cxt->d_total_bytes,
            cxt->s_tcpFlags, cxt->d_tcpFlags);
    // hack to distinguish output paths
    char *o = NULL;
    switch (outputmode) {
        case CX_EXPIRE:
            o="[expired]";
            break;
        case CX_ENDED:
            o="[ended]";
            break;
        case CX_NEW:
            o="[New]";
            break;
    }
    if(o) fprintf(fd, "|%s", o);
    fprintf(fd, "\n");
}


