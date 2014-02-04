/* author: Kacper Wysocki <kwy@redpill-linpro.com> */

#include "../prads.h"
#include "../cxt.h"
#include "../sys_func.h"
#include "log.h"
#include "log_sguil.h"
output_plugin p_sguil = {
        .init = &init_output_sguil,
        .arp = NULL,
        .os = NULL,
        .service = NULL,
        .connection = &sguil_connection,
        .denit = &sguil_end,
        .rotate = &sguil_rotate,
        .data = NULL,
};

output_plugin *init_log_sguil(){
    return &p_sguil;
}

int init_output_sguil(output_plugin *p, const char* log_prefix, int check_time)
{
    FILE *cxtfile;
    static char filename[PATH_MAX];
    struct log_sguil *sguil_data;
    if (!log_prefix){
       elog("sguil plugin on but no output directory!");
       return 1;
    }
    if(!check_time)
        check_time = time(NULL);
    snprintf(filename, PATH_MAX, "%s.%ld", log_prefix, check_time);
    cxtfile = fopen(filename, "w");
    if (cxtfile == NULL) {
       elog("[*] ERROR: Cant open file %s\n", filename);
       return 2;
    }
    dlog("Opened file: %s\n", filename);
    sguil_data = calloc(1, sizeof(*sguil_data));
    sguil_data->prefix = log_prefix;
    sguil_data->filename = filename;
    sguil_data->file = cxtfile;
    p->data = sguil_data;

    return 0;
}

int sguil_end(output_plugin *p)
{
    struct log_sguil *d = (struct log_sguil*) p->data;
    fclose(d->file);
    free(p->data);
    p->data = NULL;
}

/* reopen logfiles */
void sguil_rotate(output_plugin *plugin, time_t check_time)
{
    struct log_sguil *d = (struct log_sguil*) plugin->data;
    const char* prefix = d->prefix;
    /* end_(all)_sessions - make a new logfile 
     * check_time is some time(NULL) */
    sguil_end(plugin);
    init_output_sguil(plugin, prefix, check_time);
}


void sguil_connection (output_plugin *plugin, connection *cxt, int outputmode)
{
    
    /* log_connection */
    char stime[80], ltime[80];
    time_t tot_time;
    uint32_t s_ip_t, d_ip_t;
    static char src_s[INET6_ADDRSTRLEN];
    static char dst_s[INET6_ADDRSTRLEN];

    switch(outputmode){
        case CX_NEW:
        case CX_HUMAN:
        case CX_EXCESSIVE:
          return;
    }
    struct log_sguil *d = (struct log_sguil*) plugin->data;
    FILE *fd = d->file;
    strftime(stime, 80, "%F %H:%M:%S", gmtime(&cxt->start_time));
    strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cxt->last_pkt_time));
    tot_time = cxt->last_pkt_time - cxt->start_time;

    if ( cxt->af == AF_INET ) {
        s_ip_t = ntohl(cxt->s_ip.s6_addr32[0]);
        d_ip_t = ntohl(cxt->d_ip.s6_addr32[0]);
    }

    fprintf(fd, "%ld%09ju|%s|%s|%ld|%hhu|",
            cxt->start_time, cxt->cxid, stime, ltime, tot_time,
            cxt->proto);
    if(cxt->af == AF_INET6) {
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
    fprintf(fd, "\n");
}
