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

/* ip,vlan,port,proto,(ASSET DETECTION),FP/MAC,distance,uptime,timstamp */

#include "log_file.h"

log_file_conf output_log_file_conf;

/* ----------------------------------------------------------
 * FUNCTION : init_output_log_file
 * DESC     : This function initialize the output file.
 *          : If the file already exists, it will read in the
 *          : file and add each asset to the asset data structure.
 * INPUT    : 0 - CSV filename
 * RETURN   : None!
 * --------------------------------------------------------- */
int init_output_log_file (bstring filename)
{
    FILE *fp;

    /* Make sure filename isn't NULL. */
    if (filename != NULL)
        output_log_file_conf.filename = bstrcpy(filename);
    else
        output_log_file_conf.filename = bstrcpy(bfromcstr("prads-assets.log"));

    /* Check to see if *filename exists. */
    if ((fp = fopen(bdata(output_log_file_conf.filename), "r")) == NULL) {
        /* File does not exist, create new.. */
        if ((output_log_file_conf.file = fopen(bdata(output_log_file_conf.filename), "w")) != NULL) {
            fprintf(output_log_file_conf.file, "asset,vlan,port,proto,service,[application-info],discovered\n");

        } else {
            printf("Cannot open file %s!", bdata(output_log_file_conf.filename));
        }
    } else {
        /* File does exist, read it into data structure. */
        fclose(fp);
//       read_report_file();

        /* Open file and assign it to the global FILE pointer.  */
        if ((output_log_file_conf.file = fopen(bdata(output_log_file_conf.filename), "a")) == NULL) {
            printf("Cannot open log file %s for append!", bdata(output_log_file_conf.filename));
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
read_report_file (void)
{
    FILE *fp;
    bstring filedata;
    struct bstrList *lines;
    int i;

    printf("[*] Processing Assets from persistent file %s\n", bdata(output_log_file_conf.filename));

    /* Open Signature File */
    if ((fp = fopen(bdata(output_log_file_conf.filename), "r")) == NULL) {
        printf("Unable to open CSV file - %s", bdata(output_log_file_conf.filename));
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
void file_arp (asset *main)
{
    /* ip,vlan,port,proto,ARP (mac-resolved),mac-address,timstamp*/
    static char ip_addr_s[INET6_ADDRSTRLEN];
    if (output_log_file_conf.file != NULL) {
        u_ntop(main->ip_addr, main->af, ip_addr_s);
        if (main->mac_resolved != NULL) {
            /* ip,0,0,ARP (mac-resolved),mac-address,timstamp */
            fprintf(output_log_file_conf.file, "%s,%u,0,0,ARP (%s),%s,%lu\n", ip_addr_s,
                main->vlan ? ntohs(main->vlan) : 0,bdata(main->mac_resolved),
                hex2mac((const char *)main->mac_addr), main->last_seen);
        } else {
            /* ip,0,0,ARP,mac-address,timstamp */
            fprintf(output_log_file_conf.file, "%s,%u,0,0,ARP,[%s],%lu\n", ip_addr_s,
                main->vlan ? ntohs(main->vlan) : 0,hex2mac((const char *)main->mac_addr), main->last_seen);
        }
        fflush(output_log_file_conf.file);
    } else {
        fprintf(stderr, "[!] ERROR:  File handle not open!\n");
    }
}

/* ----------------------------------------------------------
 * FUNCTION : file_service
 * DESC     : Prints a service asset to the log file.
 * INPUT    : 0 - Main asset
 *          : 1 - Serice asset
 * ---------------------------------------------------------- */
void
file_service (asset *main, serv_asset *service)
{
    if (output_log_file_conf.file != NULL) {
        static char ip_addr_s[INET6_ADDRSTRLEN];
        u_ntop(main->ip_addr, main->af, ip_addr_s);
        /* ip,vlan,port,proto,SERVICE,application,timstamp*/
        fprintf(output_log_file_conf.file, "%s,%u,%d,%d,",
            ip_addr_s, main->vlan ? ntohs(main->vlan) : 0,
            ntohs(service->port),service->proto);
        if (service->role == 1) {
            fprintf(output_log_file_conf.file, "SERVER,[%s]",
                (char *)bdata(service->application));
        } else {
            fprintf(output_log_file_conf.file, "CLIENT,[%s]",
                (char*)bdata(service->application));
        }
        fprintf(output_log_file_conf.file, ",%lu\n",service->last_seen);
        fflush(output_log_file_conf.file);
    } else {
        fprintf(stderr, "[!] ERROR:  File handle not open!\n");
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
file_os (asset *main, os_asset *os)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    //uint8_t tmp_ttl;

    if (output_log_file_conf.file == NULL) {
        fprintf(stderr, "[!] ERROR:  File handle not open!\n");
        return;
    }

    u_ntop(main->ip_addr, main->af, ip_addr_s);

    /* ip,vlan,port,proto,OS-FP,FP,timstamp*/
    fprintf(output_log_file_conf.file, "%s,%u,0,0,",
            ip_addr_s, main->vlan ? ntohs(main->vlan) : 0);
            //ntohs(main->port),service->proto);

    switch (os->detection) {
        case CO_SYN:
            fprintf(output_log_file_conf.file, "SYN");
            break;
        case CO_SYNACK:
            fprintf(output_log_file_conf.file, "SYNACK");
            break;
        case CO_ACK:
            fprintf(output_log_file_conf.file, "ACK");
            break;
        case CO_RST:
            fprintf(output_log_file_conf.file, "RST");
            break;
        case CO_FIN:
            fprintf(output_log_file_conf.file, "FIN");
            break;
        case CO_UDP:
            fprintf(output_log_file_conf.file, "UDP");
            break;
        case CO_ICMP:
            fprintf(output_log_file_conf.file, "ICMP");
            break;

        default:
        fprintf(stderr,
            "[!] error in detection type %d (isn't implemented!)\n", os->detection);
    }

    if (os->raw_fp != NULL) {
        fprintf(output_log_file_conf.file, ",[%s:", (char *)bdata(os->raw_fp));
    } else {
        bstring b = gen_fp_tcp(&os->fp, os->fp.zero_stamp, 0);
        os->raw_fp = b;
        fprintf(output_log_file_conf.file, ",[%s:", (char *)bdata(os->raw_fp));
    }
    if (os->fp.os != NULL) fprintf(output_log_file_conf.file,"%s", os->fp.os);
        else fprintf(output_log_file_conf.file, "unknown");
    if (os->fp.desc != NULL) fprintf(output_log_file_conf.file, ":%s", os->fp.desc);
        else fprintf(output_log_file_conf.file, ":unknown");

    //if (os->fp.mss) fprintf(output_log_file_conf.file, ",[link:%s]",lookup_link(os->fp.mss,1));
    //if (os->uptime) fprintf(output_log_file_conf.file, ",[uptime:%dhrs]",os->uptime/360000);
    //if (os->ttl) {
    //    tmp_ttl = normalize_ttl(os->ttl);
    //    fprintf(output_log_file_conf.file, ",[distance:%d]",tmp_ttl - os->ttl);
    //}

    fprintf(output_log_file_conf.file, "],%lu\n",os->last_seen);   
    fflush(output_log_file_conf.file);
}

/* ----------------------------------------------------------
 * FUNCTION : end_output_log_file
 * DESC     : This function will free the memory declared
 *          : for the log_file output.
* INPUT    : None!
 * OUTPUT   : None!
 * ---------------------------------------------------------- */
int end_output_log_file ()
{
    printf("[*] Closing log file.");

    if (output_log_file_conf.file != NULL)
    fclose(output_log_file_conf.file);

    if (output_log_file_conf.filename != NULL)
    bdestroy(output_log_file_conf.filename);

    return 0;
}

