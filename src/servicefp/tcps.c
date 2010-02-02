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

#include "../prads.h"
#include "../sys_func.h"
#include "../assets.h"
#include "servicefp.h"

void service_tcp4(packetinfo *pi)
{
    int rc;                     /* PCRE */
    int ovector[15];
    int tmplen;
    extern signature *sig_serv_tcp;
    signature *tmpsig;
    bstring app;

    if (pi->plen < 10) return; // if almost no payload - skip
    /* should make a config.tcp_server_flowdept etc
     * a range between 500-1000 should be good?
     */
    if (pi->plen > 600) tmplen = 600;
        else tmplen = pi->plen;

    tmpsig = sig_serv_tcp;
    while (tmpsig != NULL) {
        rc = pcre_exec(tmpsig->regex, tmpsig->study, pi->payload, tmplen, 0, 0,
                       ovector, 15);
        if (rc >= 0) {
            app = get_app_name(tmpsig, pi->payload, ovector, rc);
            //printf("[*] - MATCH SERVICE IPv4/TCP: %s\n",(char *)bdata(app));
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        //} else if (rc == PCRE_ERROR_NOMATCH) {
            //printf("pcre nomatch \n");
        //} else {
            //printf("pcre error: %d \n", rc);
        }
        tmpsig = tmpsig->next;
    }
}

void service_tcp6(packetinfo *pi)
{
    int rc;                     /* PCRE */
    int ovector[15];
    int tmplen;
    extern signature *sig_serv_tcp;
    signature *tmpsig;
    bstring app;

    if (pi->plen < 10) return; // if almost no payload - skip
    /* should make a config.tcp_client_flowdept etc
     * a range between 500-1000 should be good!
     */
    if (pi->plen > 600) tmplen = 600;
        else tmplen = pi->plen;

    tmpsig = sig_serv_tcp;
    while (tmpsig != NULL) {
        rc = pcre_exec(tmpsig->regex, tmpsig->study, pi->payload, tmplen, 0, 0,
                       ovector, 15);
        if (rc >= 0) {
            app = get_app_name(tmpsig, pi->payload, ovector, rc);
            //printf("[*] - MATCH SERVICE IPv6/TCP: %s\n",(char *)bdata(app));
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
        tmpsig = tmpsig->next;
    }
}
