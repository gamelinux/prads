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

/* client_tcp
 *
 * Purpose:
 *
 * This file eats .... and adds/enter
 * a service to asset if any match is made, and the fingerprint.
 *
 * Arguments:
 *
 * (ip4_header *ip4, tcp_header *tcph, char *payload, int plen)
 *
 * Effect:
 *
 * Adds a fingerprint match and the fingerprint it matched
 * to the asset
 *
 * Comments:
 *
 * Old school...
 */

#include "../prads.h"
#include "../sys_func.h"
#include "../assets.h"
#include "servicefp.h"

extern bstring UNKNOWN;

void client_tcp4(ip4_header * ip4, tcp_header * tcph, const char *payload, int plen)
{
    int rc;                     /* PCRE */
    int ovector[15];
    extern signature *sig_client_tcp;
    signature *tmpsig;
    bstring app, service_name;

    struct in6_addr ip_addr;
    ip_addr.s6_addr32[0] = ip4->ip_src;
    ip_addr.s6_addr32[1] = 0;
    ip_addr.s6_addr32[2] = 0;
    ip_addr.s6_addr32[3] = 0;

    tmpsig = sig_client_tcp;
    while (tmpsig != NULL) {
        rc = pcre_exec(tmpsig->regex, tmpsig->study, payload, plen, 0, 0,
                       ovector, 15);
        if (rc != -1) {
            app = get_app_name(tmpsig, payload, ovector, rc);
            //printf("[*] - MATCH CLIENT IPv4/TCP: %s\n",(char *)bdata(app));
            update_asset_service(ip_addr, tcph->dst_port, ip4->ip_p,
                                 tmpsig->service, app, AF_INET, CLIENT);
            bdestroy(app);
            return;
        }
        tmpsig = tmpsig->next;
    }
    // Should have a flag set to resolve unknowns to default service
    if ( (service_name = check_port(IP_PROTO_TCP,ntohs(tcph->dst_port))) !=NULL ) {
        update_asset_service(ip_addr, tcph->dst_port, ip4->ip_p,
                             UNKNOWN, service_name, AF_INET, CLIENT);
        bdestroy(service_name);
    }
}

void client_tcp6(ip6_header * ip6, tcp_header * tcph, const char *payload, int plen)
{
    int rc;                     /* PCRE */
    int ovector[15];
    extern signature *sig_client_tcp;
    signature *tmpsig;
    bstring app, service_name;

    tmpsig = sig_client_tcp;
    while (tmpsig != NULL) {
        rc = pcre_exec(tmpsig->regex, tmpsig->study, payload, plen, 0, 0,
                       ovector, 15);
        if (rc != -1) {
            app = get_app_name(tmpsig, payload, ovector, rc);
            //printf("[*] - MATCH CLIENT IPv6/TCP: %s\n",(char *)bdata(app));
            update_asset_service(ip6->ip_src, tcph->dst_port, ip6->next,
                                 tmpsig->service, app, AF_INET6, CLIENT);
            bdestroy(app);
            return;
        }
        tmpsig = tmpsig->next;
    }
    if ( (service_name = check_port(IP_PROTO_TCP,ntohs(tcph->dst_port))) !=NULL ) {
        update_asset_service(ip6->ip_src, tcph->dst_port, ip6->next,
                             UNKNOWN, service_name, AF_INET6, CLIENT);
        bdestroy(service_name);
    }
}
