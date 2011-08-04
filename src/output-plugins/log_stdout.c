#include "../prads.h"
#include "../sys_func.h"
#include "../sig.h"
#include "log.h"
#include "log_stdout.h"

output_plugin p_stdout = {
    .init = NULL,
    .arp = &stdout_arp,
    .os = &stdout_os,
    .service = &stdout_service,
    .denit = &end_log_stdout,
    .data = NULL,
};

output_plugin *init_log_stdout()
{
    return &p_stdout;
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
        //bstring b = gen_fp_tcp(&os->fp, os->fp.zero_stamp, os->detection);
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

