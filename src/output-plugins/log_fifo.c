/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2011, Kacper Wysocki   <kwy@redpill-linpro.com>
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

** Props go out to Matt Sheldon <matt@mattsheldon.com>
** author of pads and the basis of this code.

** NOTE: fifo output does not reach its full potential as sguil
** only supports so much data..
*/


/*  I N C L U D E S  *********************************************************/
#include "../prads.h"
#include "../config.h"
#include "../sys_func.h"

#include <stdio.h>
#include <sys/stat.h>

#include "log.h"
#include "log_fifo.h"

output_plugin p_fifo = {
    .init = &init_output_fifo,
    .arp = &fifo_arp,
    .os = &fifo_stat,
    .service = &fifo_service,
    .denit = &fifo_end,
};

output_plugin *init_log_fifo()
{
    return &p_fifo;
}

/*
 * NOTES:
 *
 * This module will write asset data to a FIFO special file.  This will
 * separate the detection engine from the IO module and increase the
 * overall speed of the system.
 *
 * Output written to the FIFO will be in comma separated format and will
 * begin with an action_id field.  This field will allow different types
 * of output to be written to the FIFO.
 *
 * action_id        action
 * 01           TCP / ICMP Asset Discovered
 * 02           ARP Asset Discovered
 * 03           TCP / ICMP Statistic Information
 *
 * The following lines contains an example of the data written to the
 * FIFO:
 *
 * Sguil patch adds ntohl ip addrs in output
 * 01,10.10.10.83,168430163,22,6,ssh,OpenSSH 3.8.1 (Protocol 2.0),1100846817
 * 02,10.10.10.81,168430161,3Com 3CRWE73796B,00:50:da:5a:2d:ae,1100846817
 * 03,10.10.10.83,168430163,22,6,1100847309
 *

 01
 87.238.42.2
 1475226114
 94.139.80.5
 1586188293
 34029
 80
 6
 www
 Apache
 1267455148
 0101080A3131A869006707800101080A3131A86900670780485454502F312E3120323030204F4B0D0A5365727665723A204170616368650D0A4C6173742D4D6F6469666965643A205468752C203139204D617220323030392030383A33353A323020474D540D0A455461673A2022343030652D3265382D34363537346165333238323030220D0A436F6E74656E742D547970653A20746578742F68746D6C3B20636861727365743D49534F2D383835392D310D0A436F6E74656E742D4C656E6774683A203734340D0A446174653A204D6F6E2C203031204D617220323031302031343A35323A323820474D540D0A582D5661726E6973683A20343337333930313335203433373339303133340D0A4167653A2033310D0A5669613A20312E31207661726E6973680D0A436F6E6E656374696F6E3A20636C6F73650D0A0D0A

 */

/* ----------------------------------------------------------
 * FUNCTION : init_output_fifo
 * DESC     : This function will initialize the FIFO file.
 * INPUT    : 0 - FIFO filename
 * RETURN   : None!
 * --------------------------------------------------------- */
int init_output_fifo (output_plugin *p, const char* fifo_file, int flags)
{
    FILE *fp;
    int e;

    /* Make sure report_file isn't NULL. */
    if (fifo_file == NULL)
        fifo_file = "prads.fifo";

    p->path = fifo_file;

    if(0 != mkfifo (fifo_file, S_IFIFO | 0755)){
        e = errno;
        perror("creating fifo"); // not fatal
    }
    fp = fopen(fifo_file, "w+");
    if(fp == NULL) {
        e = errno;
        perror("opening fifo");
        return e;
    }
    p->data = (void *) fp;
   return 0;
}

/* ----------------------------------------------------------
 * FUNCTION : fifo_arp
 * DESC     : This function prints an ARP asset to the FIFO file.
 * INPUT    : 0 - IP Address
 *          : 1 - MAC Address
 * ---------------------------------------------------------- */
void fifo_arp (output_plugin *p, asset *main)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    FILE *fd;
    /* Print to FIFO */
    if (p->data == NULL) {
        elog("[!] ERROR:  File handle not open!\n");
        return;
    }
    fd = (FILE *)p->data;
    u_ntop(main->ip_addr, main->af, ip_addr_s);
    if (main->macentry != NULL) {
        /* prads_agent.tcl process each line until it receivs a dot by itself */
        fprintf(fd, "02\n%s\n%u\n%s\n%s\n%lu\n.\n", ip_addr_s,
                htonl(IP4ADDR(&main->ip_addr)), main->macentry->vendor,
                hex2mac(main->mac_addr), main->last_seen);
    } else {
        /* prads_agent.tcl process each line until it receivs a dot by itself */
        fprintf(fd, "02\n%s\n%u\nunknown\n%s\n%lu\n.\n", ip_addr_s,
                htonl(IP4ADDR(&main->ip_addr)), hex2mac(main->mac_addr), main->last_seen);
    }
    fflush(fd);
}

/* ----------------------------------------------------------
 * FUNCTION : fifo_service
 * DESC     : Prints a service asset to the FIFO file.
 * INPUT    : 0 - Port
 *          : 1 - IP  Address
 *          : 2 - Protocol
 *          : 3 - Service
 *          : 4 - Application
 *          : 5 - Discovered
 * ---------------------------------------------------------- */
// base64-encoded payloads for squil happiness
#define B64_PRADS_CLIENT "505241445320434C49454E54"
#define B64_PRADS_SERVER "505241445320534552564552"
static connection NULL_CXT;
void fifo_service (output_plugin *p, asset *main, serv_asset *service, connection *cxt)
{
    FILE *fd;
    static char sip[INET6_ADDRSTRLEN];
    static char dip[INET6_ADDRSTRLEN];
    char *role = B64_PRADS_CLIENT;
    if(!cxt)
        cxt = &NULL_CXT;

    /* Print to FIFO */
    if (p->data == NULL) {
        elog("[!] ERROR:  File handle not open!\n");
        return;
    }
    fd = (FILE *)p->data;
    /* prads_agent.tcl process each line until it receivs a dot by itself */
    u_ntop(main->ip_addr, main->af, sip);
    u_ntop(cxt->d_ip, cxt->af, dip);
    
    if ( service->role == SC_SERVER ) { /* SERVER ASSET */
        role = B64_PRADS_SERVER;
    }
    fprintf(fd, "01\n%s\n%u\n%s\n%u\n%d\n%d\n%d\n%s\n%s\n%lu\n%s\n.\n",
            sip, htonl(IP4ADDR(&cxt->s_ip)),
            dip, htonl(IP4ADDR(&cxt->d_ip)), 
            ntohs(cxt->s_port), ntohs(cxt->d_port), service->proto, 
            bdata(service->service), bdata(service->application), 
            main->last_seen, role);
    fflush(fd);
}

/* ----------------------------------------------------------
 * FUNCTION : print_stat_sguil
 * DESC     : This function prints stats info to the FIFO file
 * INPUT    : 0 - IP Address
 *          : 1 - Port
 *          : 2 - Protocol
 * Example  : ID \n IP \n NumIP \n PORT \n PROTO \n timestamp \n . \n
 *            03\n10.10.10.83\n168430163\n22\n6\n1100847309\n.\n
 * ---------------------------------------------------------- */
void fifo_stat (output_plugin *p, asset *rec, os_asset *os, /*UNUSED*/ connection *cxt)
{
    (void)(cxt); /* UNUSED */
    static char ip_addr_s[INET6_ADDRSTRLEN];
    if (p->data == NULL) {
        elog("[!] ERROR:  File handle not open!\n");
        return;
    }
    /* pads_agent.tcl process each line until it receivs a dot by itself */
    u_ntop(rec->ip_addr, rec->af, ip_addr_s);
    fprintf((FILE*)p->data, "03\n%s\n%u\n%d\n%d\n%ld\n.\n",
              ip_addr_s, htonl(IP4ADDR(&rec->ip_addr)), ntohs(os->port), 6 /*just for now*/, rec->last_seen);
    fflush((FILE*) p->data);
}

/* ----------------------------------------------------------
 * FUNCTION : fifo_end
 * DESC     : This function frees the memory declared by fifo
 * INPUT    : None
 * OUTPUT   : 0 - Success
 *          :-1 - Error
 * ---------------------------------------------------------- */
int fifo_end (output_plugin *p)
{
    if(p->flags & CONFIG_VERBOSE)
       plog("Closing FIFO file\n");
    fclose((FILE *)p->data);

    p->data = NULL;
    p->path = NULL;
    return 0;
}
