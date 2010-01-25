/**
 * \file
 * \author Edward FjellskÃ¥l <edward.fjellskaal@redpill-linpro.com>
 */

#include "../prads.h"
#include "log_dispatch.h"
#include "log_stdout.h"
#include "../sys_func.h"

extern globalconfig config;

void log_asset_arp (asset *main)
{
    if (config.verbose) {
        stdout_arp (main);
    }
}

void log_asset_os (asset *main, os_asset *os)
{
#ifdef DEBUG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    //dlog("[%lu] Incoming asset, %s: %s:%u [%s]\n",
    //os->last_seen, (char*)bdata(os->detection),ip_addr_s,ntohs(os->port),(char*)bdata(os->raw_fp));
#endif
    if (config.verbose) {
        stdout_os (main,os);
    }
}

void log_asset_service (asset *main, serv_asset *service)
{
#ifdef DEBUG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    if (service->role == 1) {
        dlog("[*] new service: %s:%d %s\n",ip_addr_s,ntohs(service->port),(char *)bdata(service->application));
    } else {
        dlog("[*] new client: %s:%d %s\n",ip_addr_s,ntohs(service->port),(char *)bdata(service->application));
    }
#endif
    if (config.verbose) {
        stdout_service (main,service);
    }
}

