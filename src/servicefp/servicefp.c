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
#include "servicefp.h"

/* ----------------------------------------------------------
 * FUNCTION     : init_identification
 * DESCRIPTION  : This function will read the signature file
 *              : into the signature data structure.
 * INPUT        : 0 - Data Structure
 * RETURN       : -1 - Error
 *              : 0 - Normal Return
 * ---------------------------------------------------------- */
int load_servicefp_file(int storage, char *sigfile)
{

    FILE *fp;
    bstring filename;
    bstring filedata;
    struct bstrList *lines;
    int i;

    /*
     * Check for a PADS_SIGNATURE_LIST file within the current directory.  
     */
    if ((fp = fopen(TCP_SIGNATURE_LIST, "r")) != NULL) {
        filename = bformat("./%s", sigfile);
        fclose(fp);
    } else {
        filename = bformat(sigfile);
    }

    /*
     * Open Signature File 
     */
    if ((fp = fopen((char *)bdata(filename), "r")) == NULL) {
        printf("Unable to open signature file - %s", bdata(filename));
        return 1;
    }

    /*
     * Read file into 'filedata' and process it accordingly. 
     */
    filedata = bread((bNread) fread, fp);
    if ((lines = bsplit(filedata, '\n')) != NULL) {
        for (i = 0; i < lines->qty; i++) {
            parse_raw_signature(lines->entry[i], i + 1, storage);
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
int parse_raw_signature(bstring line, int lineno, int storage)
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
            if(add_service_sig(sig, storage)) {
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

int add_service_sig(signature *sig, int storage)
{
    signature *tail;
    if (storage == 1) {
        extern signature *sig_serv_tcp;
        tail = sig_serv_tcp;
        if (sig_serv_tcp == NULL) {
            sig_serv_tcp = sig;
            return 1;
        }
        while (tail->next != NULL) {
            tail = tail->next;
        }
        if (tail->next == NULL ) {
            tail->next = sig;
            return 1;
        }
    } else if (storage == 2) {
        extern signature *sig_serv_udp;
        tail = sig_serv_udp;
        if (sig_serv_udp == NULL) {
            sig_serv_udp = sig;
            return 1;
        }
        while (tail->next != NULL) {
            tail = tail->next;
        }
        if (tail->next == NULL ) {
            tail->next = sig;
            return 1;
        }
    } else if (storage == 3) {
        extern signature *sig_client_tcp;
        tail = sig_client_tcp;
        if (sig_client_tcp == NULL) {
            sig_client_tcp = sig;
            return 1;
        }
        while (tail->next != NULL) {
            tail = tail->next;
        }
        if (tail->next == NULL ) {
            tail->next = sig;
            return 1;
        }
    } else if (storage == 4) {
        extern signature *sig_client_udp;
        tail = sig_client_udp;
        if (sig_client_udp == NULL) {
            sig_client_udp = sig;
            return 1;
        }
        while (tail->next != NULL) {
            tail = tail->next;
        }
        if (tail->next == NULL ) {
            tail->next = sig;
            return 1;
        }
    }
    return 0;
}

void del_signature_lists()
{
    extern signature *sig_serv_tcp;
    extern signature *sig_serv_udp;
    extern signature *sig_client_tcp;
    extern signature *sig_client_udp;

    /* server tcp */
    free_signature_list(sig_serv_tcp);
    /* server udp */
    free_signature_list(sig_serv_udp);
    /* client tcp */
    free_signature_list(sig_client_tcp);
    /* client udp */
    free_signature_list(sig_client_udp);

    printf("\nsignature list memory has been cleared");
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
                     const char *payload, int *ovector, int rc)
{
    char sub[100];
    char app[5000];
    char expr[100];
    bstring retval;
    int i = 0;
    int n = 0;
    int x = 0;
    int z = 0;

    /*
     * Create Application string using the values in signature[i].title.  
     */
    if (sig->title.app != NULL) {
        strncpy(app, (char *)bdata(sig->title.app), MAX_APP);
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

            pcre_copy_substring(payload, ovector, rc, n, expr,
                                sizeof(expr));
            x = 0;
            while (expr[x] != '\0' && z < (sizeof(sub) - 1)) {
                sub[z] = expr[x];
                z++;
                x++;
            }
            for (x = 0; x < sizeof(expr); x++)
                expr[x] = '\0';
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

void add_known_port(uint8_t proto, uint16_t port, bstring service_name)
{
    extern port_t *lports[255];
    port_t *tmp_lports;
    tmp_lports = lports[proto];
    port_t *new_port=NULL;

    while (tmp_lports != NULL) {
        tmp_lports = tmp_lports->next;
    }

    if (tmp_lports == NULL) {
        new_port = (port_t *) calloc(1, sizeof(port_t));
        new_port->h_port = port;
        new_port->service_name = service_name;
        new_port->next = lports[proto];
        lports[proto] = new_port;
    }

    return;
}

void add_known_services(uint8_t proto, uint16_t port, bstring service_name)
{
    extern servicelist *services[65535];

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
    extern servicelist *services[65535];
    int kport;

    for (kport=0; kport < 65535; kport++) {
        if (services[kport] != NULL) {
            bdestroy(services[kport]->service_name);
            free(services[kport]);
        }
    }
}

void del_known_port(uint8_t proto)
{
    extern port_t *lports[255];
    port_t *tmp_lports;
    port_t *port_list;
    port_list = lports[proto];

    while (port_list != NULL) {
        bdestroy(port_list->service_name);
        tmp_lports = port_list->next;
        free(port_list);
        port_list = tmp_lports;
    }
    printf("\nport list %u memory has been cleared",proto);
    return;
}

bstring check_known_port(uint8_t proto, uint16_t port)
{
    extern servicelist *services[65535];

    if (services[port] == NULL) return NULL;

    if (proto == IP_PROTO_TCP && services[port]->proto & 0x01) 
        return bstrcpy(services[port]->service_name);
    if (proto == IP_PROTO_UDP && services[port]->proto & 0x02) 
        return bstrcpy(services[port]->service_name);

    return NULL;
}

bstring check_port(uint8_t proto, uint16_t port)
{
    extern port_t *lports[255];
    port_t *ports_head;
    port_t *tmp_lports;
    ports_head = lports[proto];

    while(ports_head!=NULL){
        //if(port >= ports_head->l_port && port <= ports_head->h_port) {
        if(port == ports_head->h_port) {
            return bstrcpy(ports_head->service_name);
        }
        tmp_lports=ports_head;
        ports_head=tmp_lports->next;
    }

    return NULL;
}

void init_services()
{
    add_known_services( 6,   20,bfromcstr("@ftp-data"));
    add_known_services( 6,   21,bfromcstr("@ftp"));
    add_known_services( 6,   22,bfromcstr("@ssh"));
    add_known_services( 6,   25,bfromcstr("@smtp"));
    add_known_services(17,   53,bfromcstr("@domain"));
    add_known_services( 6,   80,bfromcstr("@www"));
    add_known_services( 6,  110,bfromcstr("@pop3"));
    add_known_services( 6,  111,bfromcstr("@sunrpc"));
    add_known_services(17,  111,bfromcstr("@sunrpc"));
    add_known_services( 6,  113,bfromcstr("@auth"));
    add_known_services( 6,  115,bfromcstr("@sftp"));
    add_known_services( 6,  119,bfromcstr("@nntp"));
    add_known_services(17,  123,bfromcstr("@ntp"));
    add_known_services( 6,  143,bfromcstr("@imap2"));
    add_known_services( 6,  161,bfromcstr("@snmp"));
    add_known_services(17,  161,bfromcstr("@snmp"));
    add_known_services( 6,  162,bfromcstr("@snmp-trap"));
    add_known_services(17,  162,bfromcstr("@snmp-trap"));
    add_known_services( 6,  389,bfromcstr("@ldap"));
    add_known_services( 6,  443,bfromcstr("@https"));
    add_known_services( 6,  445,bfromcstr("@microsoft-ds"));
    add_known_services(17,  514,bfromcstr("@syslog"));
    add_known_services( 6,  554,bfromcstr("@rtsp"));
    add_known_services(17,  554,bfromcstr("@rtsp"));
    add_known_services( 6,  631,bfromcstr("@ipp"));
    add_known_services( 6,  990,bfromcstr("@ftps"));
    add_known_services( 6,  992,bfromcstr("@telnets"));
    add_known_services( 6,  993,bfromcstr("@imaps"));
    add_known_services( 6,  995,bfromcstr("@pop3s"));
    add_known_services(17, 1194,bfromcstr("@openvpn"));
    add_known_services( 6, 2049,bfromcstr("@nfs"));
    add_known_services(17, 2049,bfromcstr("@nfs"));
    add_known_services( 6, 3306,bfromcstr("@mysql"));
    add_known_services( 6, 6667,bfromcstr("@irc"));
}
