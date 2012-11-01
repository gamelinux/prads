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
#include "log_ringbuffer.h"
#include "log_sguil.h"

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
      case LOG_RINGBUFFER:
         log_fun = init_log_ringbuffer();
         break;
      case LOG_SGUIL:
         log_fun = init_log_sguil();
         break;
      /* these types might be coming */
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
# format stats sancp_id,start_time_gmt,stop_time_gmt,duration,ip_proto,src_ip_decimal,src_port,dst_ip_decimal,dst_port,src_pkts,src_bytes,dst_pkts,dst_bytes,sflags,dflags

 *
 * we support 18 out of the 50 sancp fields here.
 * 
 * question is only whether to dump ip address as int or human readable
 */
void log_connection(connection *cxt, int cxstatus)
{
    log_foo(connection, log_output, n_outputs, cxt, cxstatus);
}

/* rotate the logs, whatever that means for your particular output */
void log_rotate(time_t t)
{
   log_foo(rotate, log_output, n_outputs, t);
}


