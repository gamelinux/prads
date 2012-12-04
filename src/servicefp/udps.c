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
#include "../assets.h"
#include "../cxt.h"
#include "servicefp.h"

extern bstring UNKNOWN;

void service_udp4(packetinfo *pi, signature* sig_serv_udp)
{
    int rc;                     /* PCRE */
    int ovector[15];
    signature *tmpsig;
    bstring app, service_name;
    app = service_name = NULL;

    if (pi->plen < 5 ) return;
    /* should make a config.tcp_client_flowdept etc
     * a range between 500-1000 should be good!
     */
    tmpsig = sig_serv_udp;
    while (tmpsig != NULL) {
        rc = pcre_exec(tmpsig->regex, tmpsig->study, (const char*) pi->payload, pi->plen, 0, 0,
                       ovector, 15);
        if (rc != -1) {
            app = get_app_name(tmpsig, pi->payload, ovector, rc);
            //printf("[*] - MATCH SERVICE IPv4/UDP: %s\n",(char *)bdata(app));
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
        tmpsig = tmpsig->next;
    }

    /* 
     * If no sig is found/mached, use default port to determin.
     */
    if (pi->sc == SC_CLIENT && !ISSET_CLIENT_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            pi->d_port = pi->udph->src_port;
            update_asset_service(pi, UNKNOWN, service_name);
            pi->d_port = pi->udph->dst_port;
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        }
    } else if (pi->sc == SC_SERVER && !ISSET_SERVICE_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        }
    }
}

void service_udp6(packetinfo *pi, signature* sig_serv_udp)
{
    int rc;                     /* PCRE */
    int ovector[15];
    int tmplen;
    signature *tmpsig;
    bstring app,service_name;
    
    if (pi->plen < 5) return; 
    /* should make a config.tcp_client_flowdept etc
     * a range between 500-1000 should be good!
     */
    if (pi->plen > 600) tmplen = 600;
        else tmplen = pi->plen;
 
    tmpsig = sig_serv_udp;
    while (tmpsig != NULL) {
        rc = pcre_exec(tmpsig->regex, tmpsig->study, (const char *) pi->payload, tmplen, 0, 0,
                       ovector, 15);
        if (rc != -1) {
            app = get_app_name(tmpsig, pi->payload, ovector, rc);
            //printf("[*] - MATCH SERVICE IPv6/UDP: %s\n",(char *)bdata(app));
            update_asset_service(pi, tmpsig->service, app);
            pi->cxt->check |= CXT_SERVICE_DONT_CHECK;
            bdestroy(app);
            return;
        }
        tmpsig = tmpsig->next;
    }
    if (pi->sc == SC_CLIENT && !ISSET_CLIENT_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            pi->d_port = pi->udph->src_port;
            update_asset_service(pi, UNKNOWN, service_name);
            pi->d_port = pi->udph->dst_port;
            pi->cxt->check |= CXT_CLIENT_UNKNOWN_SET;
            bdestroy(service_name);
        }
    } else if (pi->sc == SC_SERVER && !ISSET_SERVICE_UNKNOWN(pi)) {
        if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->s_port))) !=NULL ) {
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        } else if ((service_name = (bstring) check_known_port(IP_PROTO_UDP,ntohs(pi->d_port))) !=NULL ) {
            reverse_pi_cxt(pi);
            update_asset_service(pi, UNKNOWN, service_name);
            pi->cxt->check |= CXT_SERVICE_UNKNOWN_SET;
            bdestroy(service_name);
        }
    }
}
