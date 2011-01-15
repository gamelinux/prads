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

#include "log_sguil.h"

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

sguil_conf output_fifo_conf;

/* ----------------------------------------------------------
 * FUNCTION : init_output_sguil
 * DESC     : This function will initialize the FIFO file.
 * INPUT    : 0 - FIFO filename
 * RETURN   : None!
 * --------------------------------------------------------- */
int init_output_sguil (bstring fifo_file)
{
    FILE *fp;
    register u_int len = 0;
    char *filename;

    /* Make sure report_file isn't NULL. */
    if (fifo_file == NULL)
    fifo_file = bstrcpy(bfromcstr("prads.fifo"));

    output_fifo_conf.filename = bstrcpy(fifo_file);

    mkfifo (bdata(fifo_file), S_IFIFO | 0755);

    if ((output_fifo_conf.file = fopen(bdata(fifo_file), "w+")) == NULL)
    printf("Unable to open FIFO file (%s)!\n", bdata(fifo_file));

    return;
}

/* ----------------------------------------------------------
 * FUNCTION : sguil_arp
 * DESC     : This function prints an ARP asset to the FIFO file.
 * INPUT    : 0 - IP Address
 *          : 1 - MAC Address
 * RETURN   : 0 - Success
 *          :-1 - Error
 * ---------------------------------------------------------- */
void
sguil_arp (asset *main)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    /* Print to FIFO */
    if (output_fifo_conf.file != NULL) {
        u_ntop(main->ip_addr, main->af, ip_addr_s);
        if (main->mac_resolved != NULL) {
            /* prads_agent.tcl process each line until it receivs a dot by itself */
            fprintf(output_fifo_conf.file, "02\n%s\n%u\n%s\n%s\n%d\n.\n", ip_addr_s,
                    ntohl(main->ip_addr.s_addr), main->mac_resolved,
                    hex2mac(&main->mac_addr), main->last_seen);
        } else {
            /* prads_agent.tcl process each line until it receivs a dot by itself */
            fprintf(output_fifo_conf.file, "02\n%s\n%u\nunknown\n%s\n%d\n.\n", ip_addr_s,
                    ntohl(main->ip_addr.s_addr), hex2mac(&main->mac_addr), main->last_seen);
        }
        fflush(output_fifo_conf.file);
    } else {
        fprintf(stderr, "[!] ERROR:  File handle not open!\n");
    }
}

/* ----------------------------------------------------------
 * FUNCTION : sguil_service
 * DESC     : Prints a service asset to the FIFO file.
 * INPUT    : 0 - Port
 *          : 1 - IP  Address
 *          : 2 - Protocol
 *          : 3 - Service
 *          : 4 - Application
 *          : 5 - Discovered
 * RETURN   : 0 - Success
 *          : -1 - Error
 * ---------------------------------------------------------- */
void
sguil_service (asset *main, serv_asset *service)
{
    if (output_fifo_conf.file != NULL) {
        /* prads_agent.tcl process each line until it receivs a dot by itself */
        fprintf(output_fifo_conf.file, "01\n%s\n%u\n%s\n%u\n%d\n%d\n%d\n%s\n%s\n%d\n%s\n.\n",
                sip, ntohl(main->c_ip_addr.s_addr), 
                dip, ntohl(main->ip_addr.s_addr), 
                ntohs(main->c_port), ntohs(main->port), main->proto, 
                bdata(main->service), bdata(main->application), 
                main->discovered, bdata(main->hex_payload));

        fflush(output_fifo_conf.file);
    }
    }
    } else {
        fprintf(stderr, "[!] ERROR:  File handle not open!\n");
    }
}

/* ----------------------------------------------------------
 * FUNCTION : print_stat_sguil
 * DESC     : This function prints stats info to the FIFO file
 * INPUT    : 0 - IP Address
 *          : 1 - Port
 *          : 2 - Protocol
 * RETURN   : 0 - Success
 *          :-1 - Error
 * ---------------------------------------------------------- */
int print_stat_sguil (Asset *rec)
{
    if (output_fifo_conf.file != NULL) {
        /* pads_agent.tcl process each line until it receivs a dot by itself */
        fprintf(output_fifo_conf.file, "03\n%s\n%d\n%d\n%d\n.\n",
                inet_ntoa(rec->ip_addr), ntohs(rec->port), rec->proto, time(NULL));
        fflush(output_fifo_conf.file);
    } else {
        fprintf(stderr, "[!] ERROR:  File handle not open!\n");
        return -1;
    }
    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION : end_output_sguil
 * DESC     : This function frees the memory declared by fifo
 * INPUT    : None
 * OUTPUT   : 0 - Success
 *          :-1 - Error
 * ---------------------------------------------------------- */
int end_output_sguil ()
{
    printf("Closing FIFO File used for Sguil\n");
    fclose(output_fifo_conf.file);

    /* Clean Up */
    if (output_fifo_conf.filename)
        bdestroy(output_fifo_conf.filename);

    return 0;
}
