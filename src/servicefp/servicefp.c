/*
** Copyright (C) 2009 Redpill Linpro, AS.
** Copyright (C) 2009 Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */

/* servicefp
 *
 * Purpose:
 *
 * This file holds essential functions for the service fingerprinting
 *
 * Arguments:
 *
 * *NONE
 *
 * Effect:
 *
 * HOLDS all the stuff that needs to be initialized.
 *
 * Comments:
 *
 * Old school...
 */

#include "../common.h"
#include "../sys_func.h"
#include "../prads.h"
#include "../config.h"
#include "servicefp.h"

extern globalconfig config;

servicelist *services[MAX_PORTS];

/* ----------------------------------------------------------
 * FUNCTION     : init_identification
 * DESCRIPTION  : This function will read the signature file
 *              : into the signature data structure.
 * INPUT        : 0 - Data Structure
 * RETURN       : -1 - Error
 *              : 0 - Normal Return
 * ---------------------------------------------------------- */
int load_servicefp_file(char *sigfile, signature **db, int len)
{

    FILE *fp;
    bstring filename;
    bstring filedata;
    struct bstrList *lines;
    int i;
    (void)(len); // doesn't matter

    /*
     * Check for a PADS_SIGNATURE_LIST file within the current directory.  
     */
    if ((fp = fopen(TCP_SIGNATURE_LIST, "r")) != NULL) {
        filename = bformat("%s", sigfile);
        fclose(fp);
    } else {
        filename = bformat(sigfile);
    }

    /*
     * Open Signature File 
     */
    if ((fp = fopen(bdata(filename), "r")) == NULL) {
        printf("Unable to open signature file - %s\n", bdata(filename));
        return 1;
    }

    /*
     * Read file into 'filedata' and process it accordingly. 
     */
    filedata = bread((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_raw_signature(lines->entry[i], i + 1, db);
        }
    }

    /*
     * Clean Up 
     */
    bdestroy(filename);
    bdestroy(filedata);
    bstrListDestroy(lines);
    fclose(fp);

    return 0;
}

void dump_sig_service(signature *sig, int len)
{
    (void)(len); // it's a linked list, not important.
    while(sig) {
        // the actual regex is compiled and not available here.
        printf("%s,v/%s/%s/%s/\n", bdata(sig->service),
            bdata(sig->title.app), bdata(sig->title.ver), bdata(sig->title.misc));
        sig = sig->next;
    }
}


/* ----------------------------------------------------------
 * FUNCTION     : parse_raw_signature
 * DESCRIPTION  : This function will take a line from the
 *              : signature file and parse it into it's data
 *              : structure.
 * INPUT        : 0 - Raw Signature (bstring)
 *              : 1 - The line number this signature is on.
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int parse_raw_signature(bstring line, int lineno, signature **db)
{
    struct bstrList *raw_sig = NULL;
    struct bstrList *title = NULL;
    signature *sig, *head;
    sig = head = NULL;
    bstring pcre_string = NULL;
    const char *err = NULL;     /* PCRE */
    int erroffset;              /* PCRE */
    int ret = 0;
    int i;

    /*
     * Check to see if this line has something to read. 
     */
    if (line->data[0] == '\0' || line->data[0] == '#')
        return -1;

    /*
     * Split Line 
     */
    //if ((raw_sig = bsplitstr(line, bformat("||") )) == NULL)
    if ((raw_sig = bsplit(line, ',')) == NULL)
        return -1;

    /*
     * Reconstruct the PCRE string.  This is needed in case there are PCRE
     * * strings containing commas within them. 
     */
    if (raw_sig->qty < 3) {
        ret = -1;
    } else if (raw_sig->qty > 3) {
        pcre_string = bstrcpy(raw_sig->entry[2]);
        for (i = 3; i < raw_sig->qty; i++) {
            //bstring tmp = bfromcstr("||");
            bstring tmp = bfromcstr(",");
            if ((bconcat(pcre_string, tmp)) == BSTR_ERR)
                ret = -1;
            if ((bconcat(pcre_string, raw_sig->entry[i])) == BSTR_ERR)
                ret = -1;
            bdestroy(tmp);
        }
    } else {
        pcre_string = bstrcpy(raw_sig->entry[2]);
    }

    /*
     * Split Title 
     */
    if (raw_sig->entry[1] != NULL && ret != -1)
        title = bsplit(raw_sig->entry[1], '/');
    if (title == NULL) {
        bdestroy(pcre_string);
        return -1;
    }
    if (title->qty < 3)
        ret = -1;

    /*
     * Create signature data structure for this record. 
     */
    if (ret != -1) {
        sig = (signature *) calloc(1, sizeof(signature));
        sig->next = NULL;
        sig->prev = NULL;
        if (raw_sig->entry[0] != NULL)
            sig->service = bstrcpy(raw_sig->entry[0]);
        if (title->entry[1] != NULL)
            sig->title.app = bstrcpy(title->entry[1]);
        if (title->entry[2] != NULL)
            sig->title.ver = bstrcpy(title->entry[2]);
        if (title->entry[3] != NULL)
            sig->title.misc = bstrcpy(title->entry[3]);

        /*
         * PCRE 
         */
        if (pcre_string != NULL) {
            if ((sig->regex =
                 pcre_compile((char *)bdata(pcre_string), 0, &err,
                              &erroffset, NULL)) == NULL) {
                printf("Unable to compile signature:  %s at line %d (%s)",
                       err, lineno, bdata(line));
                ret = -1;
            }
        }
        if (ret != -1) {
            sig->study = pcre_study(sig->regex, 0, &err);
            if (err != NULL)
                printf("Unable to study signature:  %s", err);
        }

        /*
         * Add signature to 'signature_list' data structure. 
         */
        if (ret != -1) {
            if(add_service_sig(sig, db)) {
             //dlog("SIG ADDED:%s to %d\n",(char *)bdata(sig->service),storage); 
            }
        }
    }

    /*
     * Garbage Collection 
     */
    if (raw_sig != NULL)
        bstrListDestroy(raw_sig);
    if (title != NULL)
        bstrListDestroy(title);
    if (pcre_string != NULL)
        bdestroy(pcre_string);

    return ret;
}

int add_service_sig(signature *sig, signature **db)
{
    signature *tail;
    tail = *db;
    if(tail == NULL) {
       *db = sig;
    }else{
       while(tail->next != NULL) {
          tail = tail->next;
       }
       tail->next = sig;
    }
    return 1;
}

void free_signature_list (signature *head)
{
    signature *tmp;
    while (head != NULL) {
            bdestroy(head->service);
            bdestroy(head->title.app);
            bdestroy(head->title.ver);
            bdestroy(head->title.misc);
            if (head->regex != NULL) free(head->regex);
            if (head->study != NULL) free(head->study);
            tmp = head->next;
            free(head);
            head = NULL;
            head = tmp;
    }
}

void del_signature_lists()
{
    /* server tcp */
    free_signature_list(config.sig_serv_tcp);
    /* server udp */
    free_signature_list(config.sig_serv_udp);
    /* client tcp */
    free_signature_list(config.sig_client_tcp);
    /* client udp */
    free_signature_list(config.sig_client_udp);

    dlog("signature list memory has been cleared\n");
}

/* ----------------------------------------------------------
 * FUNCTION     : get_app_name
 * DESCRIPTION  : This function will take the results of a
 *              : pcre match and compile the application name
 *              : based off of the signature.
 * INPUT        : 0 - Signature Pointer
 *              : 1 - payload
 *              : 2 - ovector
 *              : 3 - rc (return from pcre_exec)
 * RETURN       : processed app name
 * ---------------------------------------------------------- */
bstring get_app_name(signature * sig,
                     const uint8_t *payload, int *ovector, int rc)
{
    char sub[512];
    char app[5000];
    const char *expr;
    bstring retval;
    int i = 0;
    int n = 0;
    int x = 0;
    int z = 0;

    /*
     * Create Application string using the values in signature[i].title.  
     */
    if (sig->title.app != NULL) {
        strncpy(app, bdata(sig->title.app), MAX_APP);
    }
    if (sig->title.ver != NULL) {
        if (sig->title.ver->slen > 0) {
            strcat(app, " ");
            strncat(app, (char *)bdata(sig->title.ver), MAX_VER);
        }
    }
    if (sig->title.misc != NULL) {
        if (sig->title.misc->slen > 0) {
            strcat(app, " (");
            strncat(app, (char *)bdata(sig->title.misc), MAX_MISC);
            strcat(app, ")");
        }
    }

    /*
     * Replace $1, $2, etc. with the appropriate substring.  
     */
    while (app[i] != '\0' && z < (sizeof(sub) - 1)) {
        /*
         * Check to see if the string contains a $? mark variable. 
         */
        if (app[i] == '$') {
            /*
             * Yes it does, replace it with the appropriate match string. 
             */
            i++;
            n = atoi(&app[i]);

            pcre_get_substring((const char *)payload, ovector, rc, n, &expr);
            x = 0;
            while (expr[x] != '\0' && z < (sizeof(sub) - 1)) {
                sub[z] = expr[x];
                z++;
                x++;
            }
            expr = NULL;
            i++;
        } else {
            /*
             * No it doesn't, copy to new string. 
             */
            sub[z] = app[i];
            i++;
            z++;
        }
    }
    sub[z] = '\0';

    retval = bfromcstr(sub);
    return retval;

}

void load_known_ports_file(char *filename, port_t *lports)
{
    /* parse file with "service,port" */
    /* for each line of "service,port" : add_known_port() */
    return;
}

void add_known_services(uint8_t proto, uint16_t port, bstring service_name)
{
    if (services[port] == NULL) {
        services[port] = (servicelist *) calloc(1, sizeof(servicelist));
        services[port]->service_name = service_name;
    }

    if (proto == IP_PROTO_TCP) {
        services[port]->proto |= 0x01; // TCP
    } else if (proto == IP_PROTO_UDP) {
        services[port]->proto |= 0x02; // UDP
    }
}

void del_known_services()
{
    int kport;

    for (kport=0; kport < MAX_PORTS; kport++) {
        if (services[kport] != NULL) {
            bdestroy(services[kport]->service_name);
            free(services[kport]);
        }
    }
    dlog("known services memory has been cleared\n");
}


bstring check_known_port(uint8_t proto, uint16_t port)
{
    if (services[port] == NULL) return NULL;

    if (proto == IP_PROTO_TCP && services[port]->proto & 0x01) 
        return bstrcpy(services[port]->service_name);
    if (proto == IP_PROTO_UDP && services[port]->proto & 0x02) 
        return bstrcpy(services[port]->service_name);

    return NULL;
}

void init_services()
{
    //bformat
    //bfromcstr
    add_known_services( 6,   20,bformat("@ftp-data"));
    add_known_services( 6,   21,bformat("@ftp"));
    add_known_services( 6,   22,bformat("@ssh"));
    add_known_services( 6,   25,bformat("@smtp"));
    add_known_services(17,   53,bformat("@domain"));
    add_known_services( 6,   80,bformat("@www"));
    add_known_services( 6,  110,bformat("@pop3"));
    add_known_services( 6,  111,bformat("@sunrpc"));
    add_known_services(17,  111,bformat("@sunrpc"));
    add_known_services( 6,  113,bformat("@auth"));
    add_known_services( 6,  115,bformat("@sftp"));
    add_known_services( 6,  119,bformat("@nntp"));
    add_known_services(17,  123,bformat("@ntp"));
    add_known_services( 6,  143,bformat("@imap2"));
    add_known_services( 6,  161,bformat("@snmp"));
    add_known_services(17,  161,bformat("@snmp"));
    add_known_services( 6,  162,bformat("@snmp-trap"));
    add_known_services(17,  162,bformat("@snmp-trap"));
    add_known_services( 6,  389,bformat("@ldap"));
    add_known_services( 6,  443,bformat("@https"));
    add_known_services( 6,  445,bformat("@microsoft-ds"));
    add_known_services(17,  514,bformat("@syslog"));
    add_known_services( 6,  554,bformat("@rtsp"));
    add_known_services(17,  554,bformat("@rtsp"));
    add_known_services( 6,  631,bformat("@ipp"));
    add_known_services( 6,  990,bformat("@ftps"));
    add_known_services( 6,  992,bformat("@telnets"));
    add_known_services( 6,  993,bformat("@imaps"));
    add_known_services( 6,  995,bformat("@pop3s"));
    add_known_services(17, 1194,bformat("@openvpn"));
    add_known_services( 6, 2049,bformat("@nfs"));
    add_known_services(17, 2049,bformat("@nfs"));
    add_known_services( 6, 3306,bformat("@mysql"));
    add_known_services( 6, 6667,bformat("@irc"));
}
