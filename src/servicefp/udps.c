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

/* service_udp
 * 
 * Purpose:
 *
 * This file eats an *IP-packet and udp-header and adds/enter
 * a service to asset if any match is made, and the fingerprint.
 *
 * Arguments:
 *   
 * *IP-packet, udp-header
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

// include

/* service_udp(*ip6,*udph)*/
void service_udp4 (ip4_header *ip4, udp_header *udph) {
   printf("KABOOM!\n");
   return;
}

void service_udp6 (ip6_header *ip6, udp_header *udph) {
   return;
}

