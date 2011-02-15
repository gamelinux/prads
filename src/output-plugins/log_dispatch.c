/**
 * \author Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
 * \author Kacper Wysocki <comotion@krutt.org>
 */

//#include "../common.h"
//#include "../sys_func.h"
//#include "log_sguil.h"

#include "../prads.h"
#include "log.h"
#include "log_stdout.h"
#include "log_file.h"

output_plugin log_fun;

/* set up function pointers for logging */
void init_logging(int logtype, const char *file, int flags)
{
   log_fun.flags = flags;
   switch (logtype)
   {
      case LOG_FILE:
         if(0 == init_log_file(&log_fun) && log_fun.init){
            log_fun.init(&log_fun, file, flags);
         }
         break;
      case LOG_SGUIL:
         //init_output_sguil(&log_fun, file, flags);
         break;
      /* these types are coming !*/
      case LOG_STDOUT:
         break;
      case LOG_ASCII:
         break;
      case LOG_UNIFIED:
         break;
      default:
         fprintf(stderr,"whoops! init_logging\n");
   }
}

void end_logging()
{
    if(log_fun.denit){
       log_fun.denit(&log_fun);
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



void log_asset_arp (asset *masset)
{
#ifdef DEBUG
    //static char ip_addr_s[INET6_ADDRSTRLEN];
    //inet_ntop(AF_INET, &masset->ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
    //dlog("[*] added mac address to asset: %s\n",ip_addr_s);
#endif
    if (log_fun.flags & VERBOSE) {
        stdout_arp(masset);
    }
    log_fun.arp(&log_fun, masset);
}

void log_asset_os (asset *main, os_asset *os)
{
#ifdef DEBUG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    //dlog("[%lu] Incoming asset, %s: %s:%u [%s]\n",
    //os->last_seen, (char*)bdata(os->detection),ip_addr_s,ntohs(os->port),(char*)bdata(os->raw_fp));
#endif
    if (log_fun.flags & VERBOSE) {
        stdout_os(main,os);
    }
    log_fun.os(&log_fun, main,os);
}

void log_asset_service (asset *main, serv_asset *service)
{
#ifdef DEBUG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    if (service->role == 1) {
        fprintf(stderr, "[*] new service: %s:%d %s\n",ip_addr_s,ntohs(service->port),(char *)bdata(service->application));
    } else {
        fprintf(stderr, "[*] new client: %s:%d %s\n",ip_addr_s,ntohs(service->port),(char *)bdata(service->application));
    }
#endif
    if (log_fun.flags & VERBOSE) {
        stdout_service(main,service);
    }
    log_fun.service(&log_fun,main,service);
}

