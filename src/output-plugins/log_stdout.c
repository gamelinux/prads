
#include "../prads.h"
#include "log_stdout.h"
#include "../sys_func.h"
#include "../sig.h"

void stdout_arp (asset *main)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];

    if (memcmp(main->mac_addr, "\0\0\0\0\0\0", 6)) {
        u_ntop(main->ip_addr, main->af, ip_addr_s);
        printf("\n%s", ip_addr_s);
        printf(",[arp:%s]",
        hex2mac((const char *)main->mac_addr));
    }
}

void stdout_os (asset *main, os_asset *os)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    printf("\n%s,[", ip_addr_s);
    
    if (os->detection == CO_SYN) printf("syn");
    if (os->detection == CO_SYNACK) printf("synack");
    if (os->detection == CO_ACK) printf("ack");
    if (os->detection == CO_RST) printf("rst");
    if (os->detection == CO_FIN) printf("fin");
    if (os->detection == CO_UDP) printf("udp");
    if (os->detection == CO_ICMP) printf("icmp");

    printf(":");
    if (os->raw_fp != NULL) printf("%s", (char *)bdata(os->raw_fp));
    if (os->match != NULL) {
        print_sig(os->match);
    }
    printf("]");
    // if vendor and os is != NULL
    //printf(",[%s - %s]", (char *)bdata(os->vendor),(char *)bdata(os->os));
    if (os->uptime) printf(",[uptime:%dhrs]",os->uptime/360000);
}

void stdout_service (asset *main, serv_asset *service)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    printf("\n%s", ip_addr_s);

    if (service->role == 1) {
        printf(",[service:%s:%u:%u]",
        (char *)bdata(service->application),
        ntohs(service->port),service->proto);
    } else {
        printf(",[client:%s:%u:%u]",
        (char*)bdata(service->application),
        ntohs(service->port),service->proto);
    }
}

char *hex2mac(const char *mac)
{

    static char buf[32];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             (mac[0] & 0xFF), (mac[1] & 0xFF), (mac[2] & 0xFF),
             (mac[3] & 0xFF), (mac[4] & 0xFF), (mac[5] & 0xFF));

    return buf;
}


