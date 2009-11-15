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

/* ipfp 
 * 
 * Purpose:
 *
 * This file eats an IPv4 or an IPv6 packet/fingerprint, and returns a 
 * fingerprint match.
 *
 * Arguments:
 *   
 * IP-version, args to eat...
 *
 * Effect:
 *
 * Returns a fingerprint match and the fingerprint
 *
 * Comments:
 *
 * Old school...
 */


void display_signature( uint8_t  ttl,
                        uint16_t tot,
                        uint8_t  df,
                        uint8_t  *op,
                        uint8_t  ocnt,
                        uint16_t mss,
                        uint16_t wss,
                        uint8_t  wsc,
                        uint32_t tstamp,
                        uint32_t quirks,
                        uint8_t  ftype) {

   uint32_t j;
   uint8_t  d=0,open_mode=0;

   if ( ftype == TF_SYN ) printf("[*] ASSET IP/TCP/SYN FINGERPRINT: ["); else
   if ( ftype == TF_SYNACK ) printf("[*] ASSET IP/TCP/SYNACK FINGERPRINT: ["); else
   if ( ftype == TF_ACK ) {
      printf("[*] ASSET IP/TCP/STRAY-ACK FINGERPRINT: [");
      open_mode=1;
   }

   if (mss && wss && !(wss % mss)) printf("S%d",wss/mss); else
   if (wss && !(wss % 1460)) printf("S%d",wss/1460); else
   if (mss && wss && !(wss % (mss+40))) printf("T%d",wss/(mss+40)); else
   if (wss && !(wss % 1500)) printf("T%d",wss/1500); else
   if (wss == 12345) printf("*(12345)"); else printf("%d",wss);

   if (!open_mode) {
      if (tot < PACKET_BIG) printf(":%d:%d:%d:",ttl,df,tot);
      else printf(":%d:%d:*(%d):",ttl,df,tot);
   } else printf(":%d:%d:*:",ttl,df);
 
   for (j=0;j<ocnt;j++) {
      switch (op[j]) {
         case TCPOPT_NOP: putchar('N'); d=1; break;
         case TCPOPT_WSCALE: printf("W%d",wsc); d=1; break;
         case TCPOPT_MAXSEG: printf("M%d",mss); d=1; break;
         case TCPOPT_TIMESTAMP: putchar('T');
            if (!tstamp) putchar('0'); d=1; break;
         case TCPOPT_SACKOK: putchar('S'); d=1; break;
         case TCPOPT_EOL: putchar('E'); d=1; break;
         default: printf("?%d",op[j]); d=1; break;
      }
      if (j != ocnt-1) putchar(',');
   }

   if (!d) putchar('.');

   putchar(':');

   if (!quirks) putchar('.'); else {
      if (quirks & QUIRK_RSTACK) putchar('K');
      if (quirks & QUIRK_SEQEQ) putchar('Q');
      if (quirks & QUIRK_SEQ0) putchar('0');
      if (quirks & QUIRK_PAST) putchar('P');
      if (quirks & QUIRK_ZEROID) putchar('Z');
      if (quirks & QUIRK_IPOPT) putchar('I');
      if (quirks & QUIRK_URG) putchar('U');
      if (quirks & QUIRK_X2) putchar('X');
      if (quirks & QUIRK_ACK) putchar('A');
      if (quirks & QUIRK_T2) putchar('T');
      if (quirks & QUIRK_FLAGS) putchar('F');
      if (quirks & QUIRK_DATA) putchar('D');
      if (quirks & QUIRK_BROKEN) putchar('!');
   }
  printf("]\n");
}
