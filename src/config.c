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
#include "dhcp.h"
#include "config.h"
#include "mac.h"
#include "sig.h"

/*  G L O B A L E S  *********************************************************/
extern globalconfig config;

/* F U N C T I O N S  ********************************************************/
void display_config(globalconfig *conf)
{
    olog("[*] OS checks enabled:");
    if (IS_COSET(conf,CO_SYN))    olog (" SYN");
    if (IS_COSET(conf,CO_SYNACK)) olog (" SYNACK");
    if (IS_COSET(conf,CO_RST))    olog (" RST");
    if (IS_COSET(conf,CO_FIN))    olog (" FIN");
    if (IS_COSET(conf,CO_ACK))    olog (" ACK");
    olog("\n");
    
    olog("[*] Service checks enabled:");
    if (IS_CSSET(conf,CS_TCP_SERVER))    olog (" TCP-SERVER");
    if (IS_CSSET(conf,CS_TCP_CLIENT))    olog (" TCP-CLIENT");
    if (IS_CSSET(conf,CS_UDP_SERVICES))  olog (" UDP-SERVICES");
    if (IS_CSSET(conf,CS_ICMP))          olog (" ICMP");
    if (IS_CSSET(conf,CS_ARP))           olog (" ARP");
    if (IS_CSSET(conf,CS_MAC))           olog (" MAC");
    olog("\n");

    return;
}

void free_config()
{
// Grr - no nice way to tell if the settings comes from configfile or not :/
    if (config.pidfile != NULL) free(config.pidfile);
    if (config.user_name != NULL) free(config.user_name);
    if (config.group_name != NULL) free(config.group_name);
    if (config.bpff != NULL) free(config.bpff);
    if (config.bpf_file != NULL) free(config.bpf_file);
    if (config.assetlog != NULL) free(config.assetlog);
    if (config.pcap_file != NULL) free(config.pcap_file);
}

void set_default_config_options(globalconfig *conf)
{
    conf->file    = CONFDIR "prads.conf";
    conf->ctf    |= CO_SYN;
    conf->ctf    |= CO_RST;
    conf->ctf    |= CO_FIN;
    //conf->ctf    |= CO_ACK;
    conf->ctf    |= CO_SYNACK;
    //conf->ctf    |= CO_ICMP;
    //conf->ctf    |= CO_UDP;
    //conf->ctf    |= CO_DHCP;
    conf->cof    |= CS_TCP_SERVER;
    conf->cof    |= CS_TCP_CLIENT;
    conf->cof    |= CS_UDP_SERVICES;
    conf->cof    |= CS_MAC;
    conf->dev     = 0x0; // default is to lookup device
    conf->bpff    = strdup("");
    //conf->pidfile = strdup("/var/run/prads.pid");
    conf->assetlog= strdup(LOGDIR PRADS_ASSETLOG);
    conf->fifo    = NULL;
    conf->ringbuffer = 0;
    // default source net owns everything
    conf->s_net   = DEFAULT_NETS ;
    conf->errbuf[0] = '\0';
    conf->configpath = CONFDIR "";
    // files should be relative to confpath somehow
    conf->sig_file_syn = CONFDIR "tcp-syn.fp";
    conf->sig_file_synack = CONFDIR "tcp-synack.fp";
    conf->sig_file_ack = CONFDIR "tcp-stray-ack.fp";
    conf->sig_file_fin = CONFDIR "tcp-fin.fp";
    conf->sig_file_rst = CONFDIR "tcp-rst.fp";
    conf->sig_file_mac = CONFDIR "mac.sig";
    conf->sig_file_dhcp = CONFDIR "dhcp.fp";
    conf->sig_file_serv_tcp = CONFDIR "tcp-service.sig";
    conf->sig_file_serv_udp = CONFDIR "udp-service.sig";
    conf->sig_file_cli_tcp = CONFDIR "tcp-clients.sig";
    conf->sig_syn = NULL;
    conf->sig_synack = NULL;
    conf->sig_ack = NULL;
    conf->sig_fin = NULL;
    conf->sig_rst = NULL;
    conf->sig_mac = NULL;
    conf->sig_dhcp = NULL;
    conf->sig_hashsize = SIG_HASHSIZE;
    conf->mac_hashsize = MAC_HASHSIZE;
    // drop privileges by default
    conf->user_name = strdup("1");
    conf->group_name = strdup("1");

    conf->drop_privs_flag = 1;
    // don't chroot or daemonize by default
    conf->chroot_dir = NULL;
    conf->daemon_flag = 0;
    conf->cxtlogdir[0] = '\0';
    conf->cxtfname[0] = '\0';
    conf->tcpopt_parsable = 1;
}

void parse_config_file(const char* fname)
{
    FILE *fp;
    bstring filedata;
    struct bstrList *lines;
    int i;
    vlog(0x3, "config - Processing '%s'.", fname);

    if ((fp = fopen(fname, "r")) == NULL) {
        elog("Unable to open configuration file - %s\n", fname);
        return;
    }

    filedata = bread ((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_line(&config, lines->entry[i]);
        }
    }

    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);
}

void parse_line (globalconfig * conf, bstring line)
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
        if (!conf->daemon_flag) {
            if (value->data[0] == '1')
                conf->daemon_flag = 1;
            else
                conf->daemon_flag = 0;
        }
    } else if ((biseqcstr(param, "mac")) == 1) {
        /* MAC CHECK */
        if (value->data[0] == '1')
            conf->cof |= CS_MAC;
        else 
            conf->cof &= ~CS_MAC;
    } else if ((biseqcstr(param, "arp")) == 1) {
        /* ARP CHECK */
        if (value->data[0] == '1')
            conf->cof |= CS_ARP;
        else 
            conf->cof &= ~CS_ARP;
    } else if ((biseqcstr(param, "service_tcp")) == 1) {
        /* TCP Service check */
        if (value->data[0] == '1')
            conf->cof |= CS_TCP_SERVER;
        else
            conf->cof &= ~CS_TCP_SERVER;
    } else if ((biseqcstr(param, "client_tcp")) == 1) {
        /* TCP Client check */
        if (value->data[0] == '1')
            conf->cof |= CS_TCP_CLIENT;
        else
            conf->cof &= ~CS_TCP_CLIENT;
    } else if ((biseqcstr(param, "service_udp")) == 1) {
        /* UPD service and client checks */
        if (value->data[0] == '1')
            conf->cof |= CS_UDP_SERVICES;
        else
            conf->cof &= ~CS_UDP_SERVICES;
    } else if ((biseqcstr(param, "os_icmp")) == 1) {
        /* ICMP OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_ICMP;
        else
            conf->ctf &= ~CO_ICMP;
   } else if ((biseqcstr(param, "os_udp")) == 1) {
        /* UDP OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_UDP;
        else
            conf->ctf &= ~CO_UDP;
    } else if ((biseqcstr(param, "service_udp")) == 1) {
        /* UPD service and client checks */
        if (value->data[0] == '1')
            conf->cof |= CS_UDP_SERVICES;
        else
            conf->cof &= ~CS_UDP_SERVICES;
   } else if ((biseqcstr(param, "os_syn_fingerprint")) == 1) {
        /* TCP SYN OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_SYN;
        else
            conf->ctf &= ~CO_SYN;
   } else if ((biseqcstr(param, "os_synack_fingerprint")) == 1) {
        /* TCP SYNACK OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_SYNACK;
        else
            conf->ctf &= ~CO_SYNACK;
   } else if ((biseqcstr(param, "os_ack_fingerprint")) == 1) {
        /* TCP Stray ACK OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_ACK;
        else
            conf->ctf &= ~CO_ACK;
   } else if ((biseqcstr(param, "os_rst_fingerprint")) == 1) {
        /* TCP RST OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_RST;
        else
            conf->ctf &= ~CO_RST;
   } else if ((biseqcstr(param, "os_fin_fingerprint")) == 1) {
        /* TCP FIN OS Fingerprinting */
        if (value->data[0] == '1')
            conf->ctf |= CO_FIN;
        else
            conf->ctf &= ~CO_FIN;
   } else if ((biseqcstr(param, "chroot_dir")) == 1) {
        /* CHROOT DIRECTORY */
        if(conf->chroot_dir) free(conf->chroot_dir);
        conf->chroot_dir = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "pid_file")) == 1) {
        /* PID FILE */
        if(conf->pidfile) free(conf->pidfile);
        conf->pidfile = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "asset_log")) == 1) {
        /* PRADS ASSET LOG */
        if(conf->assetlog) free(conf->assetlog);
        conf->assetlog = bstr2cstr(value,'-');
    } else if ((biseqcstr(param, "fifo")) == 1) {
        /* FIFO path */
        conf->fifo = bstr2cstr (value, '-');
    } else if ((biseqcstr(param, "ringbuffer")) == 1) {
        /* Ringbuffer */
        if (!conf->ringbuffer)
            conf->ringbuffer = value->data[0] == '1' ? 1 : 0;
    } else if ((biseqcstr(param, "sig_file_serv_tcp")) == 1) {
        /* SIGNATURE FILE */
        conf->sig_file_serv_tcp = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_cli_tcp")) == 1) {
        /* SIGNATURE FILE */
        conf->sig_file_cli_tcp =  bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_serv_udp")) == 1) {
        /* SIGNATURE FILE */
        conf->sig_file_serv_udp = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "sig_file_cli_udp")) == 1) {
        /* SIGNATURE FILE */
        conf->sig_file_cli_udp =  bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "mac_file")) == 1) {
        /* MAC / VENDOR RESOLUTION FILE */
        conf->sig_file_mac = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "output")) == 1) {
        /* OUTPUT */
        //conf_module_plugin(value, &activate_output_plugin);
    } else if ((biseqcstr(param, "user")) == 1) {
        /* USER */
        conf->user_name = bstr2cstr(value, '-');
        conf->drop_privs_flag = 1;
    } else if ((biseqcstr(param, "group")) == 1) {
        /* GROUP */
        conf->group_name = bstr2cstr(value, '-');
        conf->drop_privs_flag = 1;
    } else if ((biseqcstr(param, "interface")) == 1) {
        /* INTERFACE */
        conf->dev = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "bpfilter")) == 1) {
        /* FILTER */
        free(conf->bpff);
        conf->bpff = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "bpf_file")) == 1) {
        /* FILTER FILE */
        if(conf->bpf_file) free(conf->bpf_file);
        conf->bpf_file = bstr2cstr(value, '-');
    } else if ((biseqcstr(param, "home_nets")) == 1) {
        /* HOME NETS FILTER */
        //free(conf->s_net);
        conf->s_net = bstr2cstr(value, '-');

    }

cleanup:
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

/* Parse commandline and make conf reflect this */
int parse_args(globalconfig *conf, int argc, char *argv[], char *args)
{
    int ch = 0;
    while ((ch = getopt(argc, argv, args)) != -1) {
        switch (ch) {
        case 'a':
            if(strlen(optarg) == 0)
                conf->s_net = DEFAULT_NETS;
            else
                conf->s_net = strdup(optarg);
            break;
        case 'c':
            // too late at this point
            conf->file = optarg; 
            break;
        case 'C':
            conf->chroot_dir = strdup(optarg);
            break;
        case 'i':
            conf->dev = optarg;
            break;
        case 'r':
            conf->pcap_file = strdup(optarg);
            break;
        case 'b':
            conf->bpff = strdup(optarg);
            break;
        case 'v':
            conf->verbose++;
            conf->cflags |= CONFIG_VERBOSE;
            break;
        case 'h':
            return 1; // usage
            break;
        case 'D':
            conf->daemon_flag = 1;
            conf->cflags |= CONFIG_SYSLOG;
            break;
        case 'u':
            conf->user_name = strdup(optarg);
            conf->drop_privs_flag = 1;
            break;
        case 'g':
            conf->group_name = strdup(optarg);
            conf->drop_privs_flag = 1;
            break;
        case 'd':
            conf->drop_privs_flag = 0;
            break;
        case 'p':
            conf->pidfile = strdup(optarg);
            break;
        case 'l':
            conf->assetlog = strdup(optarg);
            break;
        case 'f':
            conf->fifo = strdup(optarg);
            break;
        case 'B':
            conf->ringbuffer = 1;
            break;
        case 's':
            conf->payload = strtol(optarg, NULL, 0);
            break;
        case 'q':
            conf->cflags |= CONFIG_QUIET;
            break;
        case 'O':
            conf->cflags |= CONFIG_CONNECT;
            break;
        case 'Z':
            conf->cflags |= CONFIG_PDNS;
            break;
        case 'x':
            conf->cflags |= CONFIG_CXWRITE;
            break;
        case 'X':
            conf->ctf = 0;
            conf->cof = 0;
            break;
        case 'F':
            conf->ctf |= CO_FIN;
            break;
        case 'R':
            conf->ctf |= CO_RST;
            break;
        case 'M':
            conf->cof |= CS_MAC;
            conf->cof |= CS_ARP;
            break;
        case 'S':
            conf->ctf |= CO_SYN;
            break;
        case 'A':
            conf->ctf |= CO_ACK;
            break;
        case 'K':
            conf->ctf |= CO_SYNACK;
            break;
        case 'U':
            conf->cof |= CS_UDP_SERVICES;
            break;
        case 'T':
            conf->cof |= CS_TCP_SERVER;
            break;
        case 'I':
            conf->cof |= CS_ICMP;
            break;
        case 't':
            conf->cof |= CS_TCP_CLIENT;
            break;
        case 'P':
        case 'H':
            conf->ctf |= CO_DHCP;
            break;
        case 'L':
            strcpy(conf->cxtlogdir, optarg);
            break;
        case '?':
            elog("unrecognized argument: '%c'\n", optopt);
            break;
        default:
            elog("Did not recognize argument '%c'\n", ch);
        }
    }
    return 0;
}

