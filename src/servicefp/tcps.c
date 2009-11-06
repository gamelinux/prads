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

   const char        *err = NULL;        /* PCRE */
   int               erroffset,ret,rc;   /* PCRE */
   int               ovector[15];
   extern signature  *sig_serv_tcp;
   signature         *tmpsig;

   ret = 0;
   tmpsig = sig_serv_tcp;
   while ( tmpsig != NULL ) {
      rc = pcre_exec(tmpsig->regex, tmpsig->study, payload, plen, 0, 0, ovector, 15);
      ret ++;
      if (rc != -1) {
         char expr [100];
         pcre_copy_substring(payload, ovector, rc, 0, expr, sizeof(expr));
         printf("[*] MATCH SERVICE IPv4/TCP: %s - %s",(char *)bdata(tmpsig->service),expr);
         //printf("[*] checked %d sig_serv_tcp.\n",ret);
         return;
      }
      tmpsig = tmpsig->next;
   }
}

void service_tcp6 (ip6_header *ip6, tcp_header *tcph, char *payload, int plen) {
   const char        *err = NULL;        /* PCRE */
   int               erroffset,ret,rc;   /* PCRE */
   int               ovector[15];
   extern signature  *sig_serv_tcp;
   signature         *tmpsig;

   ret = 0;
   tmpsig = sig_serv_tcp;
   while ( tmpsig != NULL ) {
      rc = pcre_exec(tmpsig->regex, tmpsig->study, payload, plen, 0, 0, ovector, 15);
      ret ++;
      if (rc != -1) {
         char expr [100];
         pcre_copy_substring(payload, ovector, rc, 0, expr, sizeof(expr));
         printf("[*] MATCH SERVICE IPv6/TCP: %s - %s\n",(char *)bdata(tmpsig->service),expr);
         //printf("[*] checked %d sig_serv_tcp.\n",ret);
         return;
      }
      tmpsig = tmpsig->next;
   }
}

