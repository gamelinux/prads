/*
** This file is a part of PRADS.
**
** Copyright (C) 2010, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2010, Kacper Wysocki   <kacper.wysocki@redpill-linpro.com>
** Adopted from PADS by Matt Shelton
** Copyright (C) 2004 Matt Shelton <matt@mattshelton.com>
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

/*  I N C L U D E S  *********************************************************/
#include "common.h"
#include "prads.h"
#include "sys_func.h"
#include "config.h"
#include "mac.h"
#include "sig.h"

/*  G L O B A L E S  *********************************************************/
extern globalconfig config;

/* F U N C T I O N S  ********************************************************/
void display_config()
{
    olog("[*] OS checks enabled:");
    if (IS_COSET(&config,CO_SYN))    olog (" SYN");
    if (IS_COSET(&config,CO_SYNACK)) olog (" SYNACK");
    if (IS_COSET(&config,CO_RST))    olog (" RST");
    if (IS_COSET(&config,CO_FIN))    olog (" FIN");
    if (IS_COSET(&config,CO_ACK))    olog (" ACK");
    olog("\n");
    
    olog("[*] Service checks enabled:");
    if (IS_CSSET(&config,CS_TCP_SERVER))    olog (" TCP-SERVER");
    if (IS_CSSET(&config,CS_TCP_CLIENT))    olog (" TCP-CLIENT");
    if (IS_CSSET(&config,CS_UDP_SERVICES))  olog (" UDP-SERVICES");
    if (IS_CSSET(&config,CS_ICMP))          olog (" ICMP");
    if (IS_CSSET(&config,CS_ARP))           olog (" ARP");
    if (IS_CSSET(&config,CS_MAC))           olog (" MAC");
    olog("\n");

    return;
}

void free_config()
{
    if (config.dev != NULL) free (config.dev);
    if (config.cfilter.bf_insns != NULL) free (config.cfilter.bf_insns);
// Grr - no nice way to tell if the settings comes from configfile or not :/
    if (config.pidfile != NULL) free(config.pidfile);
    if (config.user_name != NULL) free(config.user_name);
    if (config.group_name != NULL) free(config.group_name);
    if (config.bpff != NULL) free(config.bpff);
}

void set_default_config_options()
{
    config.ctf    |= CO_SYN;
    config.ctf    |= CO_RST;
    config.ctf    |= CO_FIN;
    config.ctf    |= CO_ACK;
    config.ctf    |= CO_SYNACK;
    //config.ctf    |= CO_ICMP;
    //config.ctf    |= CO_UDP;
    //config.ctf    |= CO_OTHER;
    config.cof    |= CS_TCP_SERVER;
    config.cof    |= CS_TCP_CLIENT;
    config.cof    |= CS_UDP_SERVICES;
    config.cof    |= CS_MAC;
    config.dev     = strdup("eth0");
    config.bpff    = strdup("");
    config.dpath   = "/tmp";
    config.pidfile = strdup("/var/run/prads.pid");
    config.assetlog= strdup(LOGDIR PRADS_ASSETLOG);
    config.fifo    = NULL;
    // default source net owns everything
    config.s_net   = DEFAULT_NETS ;
    config.errbuf[0] = '\0';
    config.configpath = CONFDIR "";
    // files should be relative to configpath somehow
    config.sig_file_syn = CONFDIR "tcp-syn.fp";
    config.sig_file_synack = CONFDIR "tcp-synack.fp";
    config.sig_file_ack = CONFDIR "tcp-stray-ack.fp";
    config.sig_file_fin = CONFDIR "tcp-fin.fp";
    config.sig_file_rst = CONFDIR "tcp-rst.fp";
    config.sig_file_mac = CONFDIR "mac.sig";
    config.sig_file_serv_tcp = CONFDIR "tcp-service.sig";
    config.sig_file_serv_udp = CONFDIR "udp-service.sig";
    config.sig_file_cli_tcp = CONFDIR "tcp-clients.sig";
    config.sig_syn = NULL;
    config.sig_synack = NULL;
    config.sig_ack = NULL;
    config.sig_fin = NULL;
    config.sig_rst = NULL;
    config.sig_mac = NULL;
    config.sig_hashsize = SIG_HASHSIZE;
    config.mac_hashsize = MAC_HASHSIZE;
    // don't chroot by default
    config.chroot_dir = NULL;
}

void parse_config_file(bstring fname)
{
    FILE *fp;
    bstring filedata;
    struct bstrList *lines;
    int i;
    vlog(0x3, "config - Processing '%s'.", bdata(fname));

    if ((fp = fopen((char *)bdata(fname), "r")) == NULL) {
        elog("Unable to open configuration file - %s\n", bdata(fname));
        return;
    }

    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_line(lines->entry[i]);
        }
    }

    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);
}

void parse_line (bstring line)
{
    bstring param, value;
    struct bstrList *list;
    int i;
    /* Check to see if this line has something to read. */
    if (line->data[0] == '\0' || line->data[0] == '#')
       return;

    /* Check to see if this line has a comment in it. */
    if ((list = bsplit(line, '#')) != NULL) {
        if ((bassign(line, list->entry[0])) == -1) {
            elog("warning:  'bassign' in function 'parse_line' failed.\n");
        }
        if (list != NULL)
            bstrListDestroy(list);
    }

    /* Separate line into a parameter and a value. */
    if ((i = bstrchr(line, '=')) == BSTR_ERR)
        return;
    if ((param = bmidstr(line, 0, i)) == NULL)
        return;
    if ((value = bmidstr(line, i + 1, line->slen - i)) == NULL)
        return;

    /* Normalize Strings */
    if ((btolower(param)) != 0)
        elog("warning:  'btolower' in function 'parse_line' failed.\n");
    if ((bltrim(value)) != 0)
        elog("warning:  'bltrim' in function 'parse_line' failed.\n");
    if ((brtrim(value)) != 0)
        elog("warning:  'brtrim' in function 'parse_line' failed.\n");

    /* Do something based upon value. */
    if ((biseqcstr(param, "daemon")) == 1) {
        /* DAEMON */
        if (!config.daemon_flag) {
            if (value->data[0] == '1')
                config.daemon_flag = 1;
            else
                config.daemon_flag = 0;
        }
    } else if ((biseqcstr(param, "mac")) == 1) {
        /* MAC CHECK */
        if (value->data[0] == '1')
            config.cof |= CS_MAC;
        else 
            config.cof &= ~CS_MAC;
    } else if ((biseqcstr(param, "arp")) == 1) {
        /* ARP CHECK */
        if (value->data[0] == '1')
            config.cof |= CS_ARP;
        else 
            config.cof &= ~CS_ARP;
    } else if ((biseqcstr(param, "service_tcp")) == 1) {
        /* TCP Service check */
        if (value->data[0] == '1')
            config.cof |= CS_TCP_SERVER;
        else
            config.cof &= ~CS_TCP_SERVER;
    } else if ((biseqcstr(param, "client_tcp")) == 1) {
        /* TCP Client check */
        if (value->data[0] == '1')
            config.cof |= CS_TCP_CLIENT;
        else
            config.cof &= ~CS_TCP_CLIENT;
    } else if ((biseqcstr(param, "service_udp")) == 1) {
        /* UPD service and client checks */
        if (value->data[0] == '1')
            config.cof |= CS_UDP_SERVICES;
        else
            config.cof &= ~CS_UDP_SERVICES;
    } else if ((biseqcstr(param, "os_icmp")) == 1) {
        /* ICMP OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_ICMP;
        else
            config.ctf &= ~CO_ICMP;
   } else if ((biseqcstr(param, "os_udp")) == 1) {
        /* UDP OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_UDP;
        else
            config.ctf &= ~CO_UDP;
    } else if ((biseqcstr(param, "service_udp")) == 1) {
        /* UPD service and client checks */
        if (value->data[0] == '1')
            config.cof |= CS_UDP_SERVICES;
        else
            config.cof &= ~CS_UDP_SERVICES;
   } else if ((biseqcstr(param, "os_syn_fingerprint")) == 1) {
        /* TCP SYN OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_SYN;
        else
            config.ctf &= ~CO_SYN;
   } else if ((biseqcstr(param, "os_synack_fingerprint")) == 1) {
        /* TCP SYNACK OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_SYNACK;
        else
            config.ctf &= ~CO_SYNACK;
   } else if ((biseqcstr(param, "os_ack_fingerprint")) == 1) {
        /* TCP Stray ACK OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_ACK;
        else
            config.ctf &= ~CO_ACK;
   } else if ((biseqcstr(param, "os_rst_fingerprint")) == 1) {
        /* TCP RST OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_RST;
        else
            config.ctf &= ~CO_RST;
   } else if ((biseqcstr(param, "os_fin_fingerprint")) == 1) {
        /* TCP FIN OS Fingerprinting */
        if (value->data[0] == '1')
            config.ctf |= CO_FIN;
        else
            config.ctf &= ~CO_FIN;

    } else if ((biseqcstr(param, "pid_file")) == 1) {
        /* PID FILE */
        free(config.pidfile);
        config.pidfile = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "asset_log")) == 1) {
        /* PRADS ASSET LOG */
        if(config.assetlog) free(config.assetlog);
        config.assetlog = bstr2cstr(value,'-');
    } else if ((biseqcstr(param, "fifo")) == 1) {
        /* FIFO path */
        config.fifo = bstr2cstr (value, '-');
    } else if ((biseqcstr(param, "sig_file_serv_tcp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_serv_tcp = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_cli_tcp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_cli_tcp =  bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_serv_udp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_serv_udp = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_cli_udp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_cli_udp =  bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "mac_file")) == 1) {
        /* MAC / VENDOR RESOLUTION FILE */
        config.sig_file_mac = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "output")) == 1) {
        /* OUTPUT */
        //conf_module_plugin(value, &activate_output_plugin);
    } else if ((biseqcstr(param, "user")) == 1) {
        /* USER */
        config.user_name = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "group")) == 1) {
        /* GROUP */
        config.group_name = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "interface")) == 1) {
        /* INTERFACE */
        free(config.dev);
        config.dev = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "bpfilter")) == 1) {
        /* FILTER */
        free(config.bpff);
        config.bpff = bstr2cstr(value, '-');

//    } else if ((biseqcstr(param, "network")) == 1) {
//        /* NETWORK */
//        parse_networks((unsigned char *)bdata(value));
//    } else if ((biseqcstr(param, "hide_unknowns")) == 1) {
//        /* UNKNOWN */
//        if (!config.hide_unknowns) {
//            if (value->data[0] == '1')
//                config.hide_unknowns = 1;
//            else
//                config.hide_unknowns = 0;
//        }
    }

    vlog(0x3,"config - PARAM:  |%s| / VALUE:  |%s|\n", bdata(param), bdata(value));

    /* Clean Up */
    if (param != NULL)
        bdestroy(param);
    if (value != NULL)
        bdestroy(value);
}

/* ----------------------------------------------------------
 * FUNCTION : bltrim
 * DESCRIPTION  : This function will trim the whitespace from
 *      : the left side of a string.
 * INPUT    : 0 - String
 * ---------------------------------------------------------- */
int bltrim (bstring string)
{
    int i;
    int len = 0;

    /* Find Whitespace */
    for (i = 0; i < string->slen; i++) {
    if (string->data[i] == ' ' || string->data[i] == '\t')
        len++;
    else
        break;
    }

    /* Remove Whitespace */
    if (len > 0)
    bdelete(string, 0, len);

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION : brtrim
 * DESCRIPTION  : This function will trim the whitespace from
 *      : the right side of a string.
 * INPUT    : 0 - String
 * ---------------------------------------------------------- */
int brtrim (bstring string)
{
    int i;
    int len = 0;

    /* Find Whitespace */
    for (i = (string->slen - 1); i > 0; i--) {
    if (string->data[i] == ' ' || string->data[i] == '\t')
        len++;
    else
        break;
    }

    /* Remove Whitespace */
    if (len > 0)
    bdelete(string, i + 1, len);

    return 0;
}

