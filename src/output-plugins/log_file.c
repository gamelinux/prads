/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2011, Kacper Wysocki <kacper.wysocki@redpill-linpro.com>
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

/* ip,vlan,port,proto,(ASSET DETECTION),FP/MAC,distance,uptime,timstamp */


/*  I N C L U D E S  *********************************************************/
#include "../prads.h"
#include "../config.h"
#include "../sys_func.h"
#include "../sig.h"

#include <stdio.h>

#include "log.h"
#include "log_file.h"

output_plugin p_file = {
   .init = &init_output_log_file,
   .arp = &file_arp,
   .os = &file_os,
   .service = &file_service,
   .denit = &end_output_log_file,
};

output_plugin *init_log_file ()
{
   return &p_file;
}

/* ----------------------------------------------------------
 * FUNCTION : init_output_log_file
 * DESC     : This function initialize the output file.
 *          : If the file already exists, it will read in the
 *          : file and add each asset to the asset data structure.
 * INPUT    : 0 - CSV filename
 * RETURN   : None!
 * --------------------------------------------------------- */
int init_output_log_file (output_plugin *log, const char *file, int flags)
{
    FILE *fp;
    const char *mode = MODE_READ;
    int retry = 0;
    /* Make sure filename isn't NULL. */
    if (!file)
        return -1;

    log->path = file;
    log->flags = flags;

    /* Check to see if *filename exists. */
reopen:
    if ((fp = fopen(log->path, mode)) == NULL) {
        int e = errno;
        switch(e) {
            case EISDIR:
            case EFAULT:
            case EACCES:
                /* retry in current working directory */
                if(retry){
                    if(flags & CONFIG_VERBOSE )
                       elog("%s denied opening asset log '%s'", strerror(e), log->path);
                    return e;
                }
                log->path = PRADS_ASSETLOG;
                retry++;
                goto reopen;
            case ENOENT:
                mode = MODE_WRITE;
                goto reopen;
            default:
                if(flags & CONFIG_VERBOSE)
                   elog("Cannot open file %s: %s!", log->path, strerror(errno));
                return e;
        }

    } else {
        log->data = (void *) fp;

        if (*mode == 'w'){
            /* File did not exist, create new.. */
            fprintf(fp, "asset,vlan,port,proto,service,[service-info],distance,discovered\n");
        }
        /* File does exist, read it into data structure. */
        fclose(fp);
//       read_report_file();

        /* Open file and assign it to the global FILE pointer.  */
        if ((log->data = (void *) fopen(log->path, "a")) == NULL) {
            int e = errno;
            printf("Cannot open log file %s for append!\n", log->path); 
            return e;
        }
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION : read_report_file
 * DESC     : This function will read in a specified
 *          : report CSV file. It will then break a part
 *          : the line and add the assets to the
 *          : specified asset data structure.
 * INPUT    : None
 * RETURN   : None
 * ---------------------------------------------------------- */
void
read_report_file (output_plugin *log)
{
    FILE *fp;
    bstring filedata;
    struct bstrList *lines;
    int i;

    printf("[*] Processing Assets from persistent file %s\n", log->path);

    /* Open Signature File */
    if ((fp = fopen(log->path, "r")) == NULL) {
        printf("Unable to open CSV file - %s", log->path);
    }

    /* Read file into 'filedata' and process it accordingly. */
    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_raw_report(lines->entry[i]);
        }
    }

    /* Clean Up */
    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);
}

/* ----------------------------------------------------------
 * FUNCTION : parse_raw_report
 * DESC     : This function will parse through a single
 *          : line of the CSV file.
 * INPUT    : 0 - Raw Line
 * RETURN   : 0 - Sucess
 *          :-1 - Error
 * ---------------------------------------------------------- */
int parse_raw_report (bstring line)
{
    struct bstrList *list;
    int ret = 0;

    /* Temporary Storage */
    struct in_addr ip_addr;
    //char mac_addr[MAC_ADDR_LEN];
    int port;
    int proto;
    bstring service;
    bstring application;
    time_t discovered;

    /* Check to see if this line has something to read. */
    if (line->data[0] == '\0' || line->data[0] == '#')
        return 0;

    /* Break line apart. */
    if ((list = bsplit(line, ',')) == NULL)
        return -1;

    /* Check to see if this line contains the header. */
    if ((biseqcstr(list->entry[0], "asset")) == 1) {
        if (list != NULL)
            bstrListDestroy(list);
            return -1;
    }

    /* Place data from 'list' into temporary data storage. */
    if ((inet_aton(bdata(list->entry[0]), &ip_addr)) == -1)
        ret = -1;

    if ((port = htons(atoi(bdata(list->entry[1])))) == -1)
        ret = -1;

    if ((proto = atoi(bdata(list->entry[2]))) == -1)
        ret = -1;

    if ((service = bstrcpy(list->entry[3])) == NULL)
        ret = -1;

    if ((application = bstrcpy(list->entry[4])) == NULL)
        ret = -1;

    if ((discovered = atol(bdata(list->entry[5]))) == -1)
        ret = -1;

    /* Make sure that this line contains 'good' data. */
    if (service->slen == 0 || application->slen == 0 || discovered <= 0)
        ret = -1;

    /* Add Asset to Data Structure */
    if (proto == 0 && ret != -1) {
        /* ARP */
        //mac2hex(bdata(application), mac_addr, MAC_ADDR_LEN);
        //add_arp_asset(ip_addr, mac_addr, discovered);
    } else {
        /* Everything Else */
        //add_asset(ip_addr, port, proto, service, application, discovered);
    }

     // Clean Up
    if (list != NULL)
        bstrListDestroy(list);
    if (service != NULL)
        bdestroy(service);
    if (application != NULL)
        bdestroy(application);

    return ret;
}

/* ----------------------------------------------------------
 * FUNCTION : file_arp
 * DESC     : This function prints an ARP asset to the log file
 * INPUT    : 0 - Main asset
 * RETURN   : VOID
 * ---------------------------------------------------------- */
void file_arp (output_plugin *log, asset *main)
{
    /* ip,vlan,port,proto,ARP (mac-resolved),mac-address,timstamp*/
    static char ip_addr_s[INET6_ADDRSTRLEN];
    if ((FILE*)log->data == NULL) {
        if(log->flags & CONFIG_VERBOSE )
           elog("[!] ERROR:  File handle not open!\n");
        return;
    }
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    if (main->macentry != NULL) {
        /* ip,0,0,ARP (mac-resolved),mac-address,timstamp */
        /* XXX: vendor info breaks csv niceness */
        fprintf((FILE*)log->data, "%s,%u,0,0,ARP,[%s,(%s)],0,%lu\n", ip_addr_s,
            main->vlan ? ntohs(main->vlan) : 0, hex2mac(main->mac_addr), 
            main->macentry->vendor, main->last_seen);
    } else {
        /* ip,0,0,ARP,mac-address,timstamp */
        fprintf((FILE*)log->data, "%s,%u,0,0,ARP,[%s],0,%lu\n", ip_addr_s,
            main->vlan ? ntohs(main->vlan) : 0,hex2mac(main->mac_addr), main->last_seen);
    }
    fflush((FILE*)log->data);
}

/* ----------------------------------------------------------
 * FUNCTION : file_service
 * DESC     : Prints a service asset to the log file.
 * INPUT    : 0 - Main asset
 *          : 1 - Serice asset
 * ---------------------------------------------------------- */
void
file_service (output_plugin* log,asset *main, serv_asset *service, connection *cxt)
{
    if ((FILE*)log->data != NULL) {
        uint8_t tmp_ttl;
        static char ip_addr_s[INET6_ADDRSTRLEN];
        u_ntop(main->ip_addr, main->af, ip_addr_s);
        /* ip,vlan,port,proto,SERVICE,application,timstamp*/
        fprintf((FILE*)log->data, "%s,%u,%d,%d,",
            ip_addr_s, main->vlan ? ntohs(main->vlan) : 0,
            ntohs(service->port),service->proto);
        if (service->role == SC_SERVER) {
            fprintf((FILE*)log->data, "SERVER,[%s:%s]",
                (char*)bdata(service->service),
                (char *)bdata(service->application));
        } else {
            fprintf((FILE*)log->data, "CLIENT,[%s:%s]",
                (char*)bdata(service->service),
                (char*)bdata(service->application));
        }

        tmp_ttl = normalize_ttl(service->ttl);
        fprintf((FILE*)log->data, ",%d,%lu\n",tmp_ttl - service->ttl,service->last_seen);
        fflush((FILE*)log->data);
    } else {
        if(log->flags & CONFIG_VERBOSE )
           elog("[!] ERROR:  File handle not open!\n");
    }
}

/* ----------------------------------------------------------
 * FUNCTION : file_os
 * DESC     : Prints a os asset to the log file.
 * INPUT    : 0 - Main asset
 *          : 1 - OS asset
 * RETURN   : VOID
 * ---------------------------------------------------------- */
void
file_os (output_plugin *log, asset *main, os_asset *os, connection *cxt)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    uint8_t tmp_ttl;

    if (!log) {
       return; // nah..
    }
    if(log->data == NULL){
        if(log->flags & CONFIG_VERBOSE)
           elog("[!] ERROR:  File handle not open: %s!\n", log->path);
        return;
    }

    u_ntop(main->ip_addr, main->af, ip_addr_s);

    /* ip,vlan,port,proto,OS-FP,FP,timstamp*/
    fprintf((FILE*)log->data, "%s,%u,%d,", ip_addr_s,
            main->vlan ? ntohs(main->vlan) : 0, os->port);
            //ntohs(main->port),service->proto);

    switch (os->detection) {
        case CO_SYN:
            fprintf((FILE*)log->data, "6,SYN");
            break;
        case CO_SYNACK:
            fprintf((FILE*)log->data, "6,SYNACK");
            break;
        case CO_ACK:
            fprintf((FILE*)log->data, "6,ACK");
            break;
        case CO_RST:
            fprintf((FILE*)log->data, "6,RST");
            break;
        case CO_FIN:
            fprintf((FILE*)log->data, "6,FIN");
            break;
        case CO_UDP:
            fprintf((FILE*)log->data, "17,UDP");
            break;
        case CO_ICMP:
            // 58 is ICMPv6
            fprintf((FILE*)log->data, "1,ICMP");
            break;
        case CO_DHCP:
            fprintf((FILE*)log->data, "17,DHCP");

        default:
        fprintf(stderr,
            "[!] error in detection type %d (isn't implemented!)\n", os->detection);
    }

    if (os->raw_fp != NULL) {
        fprintf((FILE*)log->data, ",[%s:", (char *)bdata(os->raw_fp));
    } else {
        //bstring b = gen_fp_tcp(&os->fp, os->fp.zero_stamp, 0);
        bstring b = gen_fp_tcp(&os->fp, os->uptime, 0);
        os->raw_fp = b;
        fprintf((FILE*)log->data, ",[%s:", (char *)bdata(os->raw_fp));
    }
    if (os->fp.os != NULL) fprintf((FILE*)log->data,"%s", os->fp.os);
        else fprintf((FILE*)log->data, "unknown");
    if (os->fp.desc != NULL) fprintf((FILE*)log->data, ":%s", os->fp.desc);
        else fprintf((FILE*)log->data, ":unknown");

    if (os->fp.mss) fprintf((FILE*)log->data, ":link:%s",lookup_link(os->fp.mss,1));
    if (os->uptime) fprintf((FILE*)log->data, ":uptime:%dhrs",os->uptime/360000);

    tmp_ttl = normalize_ttl(os->ttl);
    fprintf((FILE*)log->data, "],%d,%lu\n",tmp_ttl - os->ttl, os->last_seen);   
    fflush((FILE*)log->data);
}

/* ----------------------------------------------------------
 * FUNCTION : end_output_log_file
 * DESC     : This function will free the memory declared
 *          : for the log_file output.
 * INPUT    : output plugin
 * OUTPUT   : None!
 * ---------------------------------------------------------- */
int end_output_log_file (output_plugin* log)
{
    dlog("[*] Closing asset log.\n");

    if (log->data != NULL)
    fclose((FILE*)log->data);
    return 0;
}

