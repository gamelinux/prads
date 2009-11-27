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

/* service_tcp
 * 
 * Purpose:
 *
 * This file eats an *IP-packet and tcp-header and adds/enter
 * a service to asset if any match is made, and the fingerprint.
 *
 * Arguments:
 *   
 * *IP-packet, tcp-header
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

#include <pcre.h>

void service_tcp4 (ip4_header *ip4, tcp_header *tcph, char *payload, int plen) {

   const char        *err = NULL;    /* PCRE */
   int               erroffset,rc;   /* PCRE */
   int               ovector[15];
   extern signature  *sig_serv_tcp;
   signature         *tmpsig;
   bstring           app;

   tmpsig = sig_serv_tcp;
   while ( tmpsig != NULL ) {
      rc = pcre_exec(tmpsig->regex, tmpsig->study, payload, plen, 0, 0, ovector, 15);
      if (rc >= 0) {
         app = get_app_name(tmpsig, payload, ovector, rc);
         //printf("[*] - MATCH SERVICE IPv4/TCP: %s\n",(char *)bdata(app));
         struct in6_addr ip_addr;
         ip_addr.s6_addr32[0] = ip4->ip_src;
         ip_addr.s6_addr32[1] = 0;
         ip_addr.s6_addr32[2] = 0;
         ip_addr.s6_addr32[3] = 0;
         update_asset_service(ip_addr, tcph->src_port, ip4->ip_p, tmpsig->service, app, AF_INET);
         bdestroy(app);
         return;
      }
      else if ( rc == PCRE_ERROR_NOMATCH) {
         //printf("pcre nomatch \n");
      }
      else {
         printf("pcre error: %d \n",rc);
      }
      tmpsig = tmpsig->next;
   }
}

void service_tcp6 (ip6_header *ip6, tcp_header *tcph, char *payload, int plen) {
   const char        *err = NULL;        /* PCRE */
   int               erroffset,rc;   /* PCRE */
   int               ovector[15];
   extern signature  *sig_serv_tcp;
   signature         *tmpsig;
   bstring           app;

   tmpsig = sig_serv_tcp;
   while ( tmpsig != NULL ) {
      rc = pcre_exec(tmpsig->regex, tmpsig->study, payload, plen, 0, 0, ovector, 15);
      if (rc >= 0) {
         app = get_app_name(tmpsig, payload, ovector, rc);
         //printf("[*] - MATCH SERVICE IPv6/TCP: %s\n",(char *)bdata(app));
         update_asset_service(ip6->ip_src, tcph->src_port, ip6->next, tmpsig->service, app, AF_INET6);
         bdestroy(app);
         return;
      }
      tmpsig = tmpsig->next;
   }
}

