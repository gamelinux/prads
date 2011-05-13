/**
 * \author Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
 * \author Kacper Wysocki <comotion@krutt.org>
 */

//#include "../common.h"

#include "../prads.h"
#include "../sys_func.h" // u_ntop
#include "../cxt.h"
#include "log.h"
#include "log_stdout.h"
#include "log_file.h"
#include "log_fifo.h"

int n_outputs = 0;
output_plugin *log_output[LOG_MAX];

/* set up function pointers for logging */
int init_logging(int logtype, const char *file, int flags)
{
   int rc;
   output_plugin *log_fun;
   switch (logtype)
   {
      case LOG_FILE:
         log_fun = init_log_file();
         break;
      case LOG_STDOUT:
         log_fun = init_log_stdout();
         break;
      case LOG_FIFO:
         log_fun = init_log_fifo();
         break;
      /* these types are coming !*/
      case LOG_ASCII:
         break;
      case LOG_UNIFIED:
         break;
      default:
         fprintf(stderr,"whoops! init_logging\n");
   }
   if(log_fun){
       log_output[n_outputs++] = log_fun;
       if(log_fun->init) {
           rc = log_fun->init(log_fun, file, flags);
           if(rc)
               n_outputs--;
           return rc;
       } else 
           return 0;
   }
   return 0xFABE;
}

/* magic logging function - iterate over all loggers */
// note... this breaks anywhere non-GNU!
#define log_foo(func, all, count, ...) \
    do { \
        int _i; \
        for(_i = 0; _i < (count) ; _i++) { \
            output_plugin* _p = (all)[_i]; \
            if(_p && _p -> func) \
                _p -> func(_p, ##__VA_ARGS__); \
        } \
    }while(0)


void end_logging()
{
    log_foo(denit, log_output, n_outputs);
}

void log_asset_arp (asset *masset)
{
#ifdef DEBUG_LOG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &masset->ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
    dlog("[*] added mac address to asset: %s\n",ip_addr_s);
#endif
    log_foo(arp, log_output, n_outputs, masset);
}

void log_asset_os (asset *main, os_asset *os, connection *cxt)
{
#ifdef DEBUG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
#ifdef DEBUG_LOG
    dlog("[%lu] Incoming asset, %s: %s:%u [%s]\n",
    os->last_seen, (char*)bdata(os->detection),ip_addr_s,ntohs(os->port),(char*)bdata(os->raw_fp));
#endif
#endif
    log_foo(os, log_output, n_outputs, main, os, cxt);
}

void log_asset_service (asset *main, serv_asset *service, connection *cxt)
{
#ifdef DEBUG
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    if (service->role == SC_SERVER ) {
        fprintf(stderr, "[*] new service: %s:%d %s\n",ip_addr_s,ntohs(service->port),(char *)bdata(service->application));
    } else {
        fprintf(stderr, "[*] new client: %s:%d %s\n",ip_addr_s,ntohs(service->port),(char *)bdata(service->application));
    }
#endif
    log_foo(service, log_output, n_outputs, main, service, cxt);
}


/* log_connection(cxt, fd): write cxt to fd, with the following format:
 ** startsec|id|start time|end time|total time|proto|src|sport|dst|dport|s_packets|s_bytes|d_packets|d_bytes|s_flags|d_flags
 *
 * TODO: call plugins
 *
 * question is only whether to dump ip address as int or human readable

//asprintf(&cxtfname, "%s/stats.%s.%ld", dpath, dev, tstamp);
//cxtFile = fopen(cxtfname, "w");
 */
void log_connection(connection *cxt, FILE* fd, int outputmode)
{
    char stime[80], ltime[80];
    time_t tot_time;
    uint32_t s_ip_t, d_ip_t;
    static char src_s[INET6_ADDRSTRLEN];
    static char dst_s[INET6_ADDRSTRLEN];
    strftime(stime, 80, "%F %H:%M:%S", gmtime(&cxt->start_time));
    strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cxt->last_pkt_time));

    tot_time = cxt->last_pkt_time - cxt->start_time;
    if ( cxt->af == AF_INET ) {
        s_ip_t = ntohl(cxt->s_ip.s6_addr32[0]);
        d_ip_t = ntohl(cxt->d_ip.s6_addr32[0]);
    }

    fprintf(fd, "%ld%09ju|%s|%s|%ld|%u|",
            cxt->start_time, cxt->cxid, stime, ltime, tot_time,
            cxt->proto);
    if(outputmode || cxt->af == AF_INET6) {
        if(!inet_ntop(cxt->af, (cxt->af == AF_INET6? (void*) &cxt->s_ip : (void*) cxt->s_ip.s6_addr32), src_s, INET6_ADDRSTRLEN))
            perror("inet_ntop");
        if(!inet_ntop(cxt->af, (cxt->af == AF_INET6? (void*) &cxt->d_ip : (void*) cxt->d_ip.s6_addr32), dst_s, INET6_ADDRSTRLEN))
            perror("inet_ntop");
        fprintf(fd, "%s|%u|%s|%u|",
                src_s, ntohs(cxt->s_port),
                dst_s, ntohs(cxt->d_port));
    } else {
        fprintf(fd, "%u|%u|%u|%u|",
                s_ip_t, ntohs(cxt->s_port),
                d_ip_t, ntohs(cxt->d_port));
    }
    fprintf(fd, "%ju|%ju|", 
            cxt->s_total_pkts, cxt->s_total_bytes);
    fprintf(fd, "%ju|%ju|%u|%u",
            cxt->d_total_pkts, cxt->d_total_bytes,
            cxt->s_tcpFlags, cxt->d_tcpFlags);
    // hack to distinguish output paths
    char *o = NULL;
    switch (outputmode) {
        case CX_EXPIRE:
            o="[expired.]";
            break;
        case CX_ENDED:
            o="[ended.]";
            break;
        case CX_NEW:
            o="[New]";
            break;
    }
    if(o) fprintf(fd, "|%s", o);
    fprintf(fd, "\n");
}

