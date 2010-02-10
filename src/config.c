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

/*  G L O B A L E S  *********************************************************/
extern globalconfig config;

/* F U N C T I O N S  ********************************************************/
void display_config()
{
    printf("[*] OS checks enabled:");
    if (IS_COSET(&config,CO_SYN))    printf (" SYN");
    if (IS_COSET(&config,CO_SYNACK)) printf (" SYNACK");
    if (IS_COSET(&config,CO_RST))    printf (" RST");
    if (IS_COSET(&config,CO_SYN))    printf (" FIN");
    if (IS_COSET(&config,CO_ACK))    printf (" ACK");
    printf("\n");
    
    printf("[*] Service checks enabled:");
    if (IS_CSSET(&config,CS_TCP_SERVER))    printf (" TCP-SERVER");
    if (IS_CSSET(&config,CS_TCP_CLIENT))    printf (" TCP-CLIENT");
    if (IS_CSSET(&config,CS_UDP_SERVICES))  printf (" UDP-SERVICES");
    if (IS_CSSET(&config,CS_ICMP))          printf (" ICMP");
    if (IS_CSSET(&config,CS_ARP))           printf (" ARP");
    printf("\n");

    return;
}

void free_config()
{
    if (config.dev != NULL) free (config.dev);
    if (config.cfilter.bf_insns != NULL) free (config.cfilter.bf_insns);
// Grr - no nice way to tell if the settings comes from configfile or not :/
//    if (config.pidfile != NULL) bcstrfree(config.pidfile);
//    if (config.user_name != NULL) bcstrfree(config.user_name);
//    if (config.group_name != NULL) bcstrfree(config.group_name);
//    if (config.dev != NULL) bcstrfree(config.dev);
//    if (config.bpff != NULL) bcstrfree(config.bpff);
}

void set_default_config_options()
{
    config.ctf    |= CO_SYN;
    //config.ctf  |= CO_RST;
    //config.ctf  |= CO_FIN;
    //config.ctf  |= CO_ACK;
    config.ctf    |= CO_SYNACK;
    config.ctf    |= CO_ICMP;
    config.ctf    |= CO_UDP;
    //config.ctf  |= CO_OTHER;
    config.cof    |= CS_TCP_SERVER;
    config.cof    |= CS_TCP_CLIENT;
    config.cof    |= CS_UDP_SERVICES;
    config.dev     = "eth0";
    config.bpff    = "";
    config.dpath   = "/tmp";
    config.pidfile = "prads.pid";
    config.pidpath = "/var/run";
    // default source net owns everything
    config.s_net   = "0.0.0.0/0,::/0";
    config.errbuf[0] = '\0';
    config.configpath = "../etc/";
    // files should be relative to configpath somehow
    config.sig_file_syn = "../etc/os.fp";
    config.sig_file_synack = "../etc/osa.fp";
    config.sig_syn = NULL;
    config.sig_synack = NULL;
    config.sig_hashsize = 241;
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
        config.pidfile = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_serv_tcp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_serv_tcp = bstrcpy(value);
    } else if ((biseqcstr(param, "sig_file_cli_tcp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_cli_tcp = bstrcpy(value);
    } else if ((biseqcstr(param, "sig_file_serv_udp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_serv_udp = bstrcpy(value);
    } else if ((biseqcstr(param, "sig_file_cli_udp")) == 1) {
        /* SIGNATURE FILE */
        config.sig_file_cli_udp = bstrcpy(value);
    } else if ((biseqcstr(param, "mac_file")) == 1) {
        /* MAC / VENDOR RESOLUTION FILE */
        config.sig_file_mac = bstrcpy(value);
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
        config.dev = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "bpfilter")) == 1) {
        /* FILTER */
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


/*
int conf_module_plugin (bstring value, int (*ptrFunc)(bstring, bstring))
{
    struct bstrList *list;

    if (*ptrFunc == NULL)
        return -1;

    // Split line in half.  There should only be one ':'. 
    if ((list = bsplit(value, ':')) != NULL) {
        if (list->qty > 1) {
            // Input processor contains an argument.
            if ((btrim(list->entry[1])) == -1)
                elog("warning:  'btrim' in function 'conf_module_processor' faild.");
            if (((*ptrFunc)(list->entry[0], list->entry[1])) == -1)
                elog("warning:  'ptrFunc' in function 'conf_module_processor' failed.");
        } else {
            // Input processor does not contain an argument.
            bstring empty = bfromcstr("");
            if (((*ptrFunc)(list->entry[0], empty)) == -1)
                elog("warning:  'ptrFunc' in function 'conf_module_processor' failed.");
            bdestroy(empty);
        }
        if (list != NULL)
            bstrListDestroy(list);

    } else {
        elog("warning:  'split' in function 'conf_module_processor' failed.");
    }

    return 0;
}
*/
