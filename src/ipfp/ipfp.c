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
                        uint8_t  ftype,
                        struct in6_addr ip_src,
                        uint16_t port,
                        int      af) {

   uint32_t j;
   uint8_t  d=0,open_mode=0;
   bstring fp, de;
   fp = de = bfromcstr("");
   //de = bfromcstr("");

   //if ( ftype == TF_SYN ) printf("[*] ASSET IP/TCP/SYN FINGERPRINT: ["); else
   if ( ftype == TF_SYN ) de=bformat("SYN"); else
   //if ( ftype == TF_SYNACK ) printf("[*] ASSET IP/TCP/SYNACK FINGERPRINT: ["); else
   if ( ftype == TF_SYNACK ) de=bformat("SYNACK"); else
   if ( ftype == TF_ACK ) {
      //printf("[*] ASSET IP/TCP/STRAY-ACK FINGERPRINT: [");
      de=bformat("ACK");
      open_mode=1;
   }

//bfromcstr ("A");
   //if (mss && wss && !(wss % mss)) printf("S%d",wss/mss); else
   if (mss && wss && !(wss % mss)) fp=bformat("S%d",(wss/mss)); else
   //if (wss && !(wss % 1460)) printf("S%d",wss/1460); else
   if (wss && !(wss % 1460)) bformata(fp,"S%d",(wss/1460)); else
   //if (mss && wss && !(wss % (mss+40))) printf("T%d",wss/(mss+40)); else
   if (mss && wss && !(wss % (mss+40))) bformata(fp,"T%d",(wss/(mss+40))); else
   //if (wss && !(wss % 1500)) printf("T%d",wss/1500); else
   if (wss && !(wss % 1500)) bformata(fp,"T%d",(wss/1500)); else
   //if (wss == 12345) printf("*(12345)"); else printf("%d",wss);
   if (wss == 12345) bformata(fp,"*(12345)"); else bformata(fp,"%d",wss);

   if (!open_mode) {
      //if (tot < PACKET_BIG) printf(":%d:%d:%d:",ttl,df,tot);
      if (tot < PACKET_BIG) bformata(fp,":%d:%d:%d:",ttl,df,tot);
      //else printf(":%d:%d:*(%d):",ttl,df,tot);
      else bformata(fp,":%d:%d:*(%d):",ttl,df,tot);
   //} else printf(":%d:%d:*:",ttl,df);
   } else bformata(fp,":%d:%d:*:",ttl,df);
 
   for (j=0;j<ocnt;j++) {
      switch (op[j]) {
         //case TCPOPT_NOP: putchar('N'); d=1; break;
         case TCPOPT_NOP: bformata(fp,"N"); d=1; break;
         //case TCPOPT_WSCALE: printf("W%d",wsc); d=1; break;
         case TCPOPT_WSCALE: bformata(fp,"W%d",wsc); d=1; break;
         //case TCPOPT_MAXSEG: printf("M%d",mss); d=1; break;
         case TCPOPT_MAXSEG: bformata(fp,"M%d",mss); d=1; break;
         //case TCPOPT_TIMESTAMP: putchar('T');
         case TCPOPT_TIMESTAMP: bformata(fp,"T");
            //if (!tstamp) putchar('0'); d=1; break;
            if (!tstamp) bformata(fp,"0"); d=1; break;
         //case TCPOPT_SACKOK: putchar('S'); d=1; break;
         case TCPOPT_SACKOK: bformata(fp,"S"); d=1; break;
         //case TCPOPT_EOL: putchar('E'); d=1; break;
         case TCPOPT_EOL: bformata(fp,"E"); d=1; break;
         //default: printf("?%d",op[j]); d=1; break;
         default: bformata(fp,"?%d",op[j]); d=1; break;
      }
      //if (j != ocnt-1) putchar(',');
      if (j != ocnt-1) bformata(fp,",");
   }

   //if (!d) putchar('.');
   if (!d) bformata(fp,".");

   //putchar(':');
   bformata(fp,":");

   //if (!quirks) putchar('.'); else {
   if (!quirks) bformata(fp,"."); else {
      //if (quirks & QUIRK_RSTACK) putchar('K');
      if (quirks & QUIRK_RSTACK) bformata(fp,"K");
      //if (quirks & QUIRK_SEQEQ) putchar('Q');
      if (quirks & QUIRK_SEQEQ) bformata(fp,"Q");
      //if (quirks & QUIRK_SEQ0) putchar('0');
      if (quirks & QUIRK_SEQ0) bformata(fp,"0");
      //if (quirks & QUIRK_PAST) putchar('P');
      if (quirks & QUIRK_PAST) bformata(fp,"P");
      //if (quirks & QUIRK_ZEROID) putchar('Z');
      if (quirks & QUIRK_ZEROID) bformata(fp,"Z");
      //if (quirks & QUIRK_IPOPT) putchar('I');
      if (quirks & QUIRK_IPOPT) bformata(fp,"I");
      //if (quirks & QUIRK_URG) putchar('U');
      if (quirks & QUIRK_URG) bformata(fp,"U");
      //if (quirks & QUIRK_X2) putchar('X');
      if (quirks & QUIRK_X2) bformata(fp,"X");
      //if (quirks & QUIRK_ACK) putchar('A');
      if (quirks & QUIRK_ACK) bformata(fp,"A");
      //if (quirks & QUIRK_T2) putchar('T');
      if (quirks & QUIRK_T2) bformata(fp,"T");
      //if (quirks & QUIRK_FLAGS) putchar('F');
      if (quirks & QUIRK_FLAGS) bformata(fp,"F");
      //if (quirks & QUIRK_DATA) putchar('D');
      if (quirks & QUIRK_DATA) bformata(fp,"D");
      //if (quirks & QUIRK_BROKEN) putchar('!');
      if (quirks & QUIRK_BROKEN) bformata(fp,"!");
   }

   //printf("[%s]\n",(char *)bdata(fp));
   update_asset_os(ip_src, port, de, fp, af);
   //bdestroy(de);
   //bdestroy(fp);

}

void display_signature_icmp ( uint8_t  type,
                              uint8_t  code,
                              uint8_t  ttl,
                              uint8_t  df,
                              int32_t  olen,
                              uint16_t totlen,
                              uint16_t ip_off,
                              uint8_t  ip_tos) {
   bstring fingerprint;
   printf("[*] ASSET IP/ICMP FINGERPRINT: ");
   fingerprint = bformat("%u:%u:%u:%u:%d:%u:%u:%u",type,code,ttl,df,olen,totlen,df,ip_off,ip_tos);
   printf("[%s]\n",(char*)bdata(fingerprint));
   //update_asset_os(ip_addr, port, detection, raw_fp, af);
   bdestroy(fingerprint);
}

void display_signature_udp (  uint16_t  totlen,
                              uint8_t   ttl,
                              uint8_t   df,
                              int32_t   olen,
                              uint16_t  ip_len,
                              uint16_t ip_off,
                              uint8_t  ip_tos) {

   bstring fingerprint;
   printf("[*] ASSET IP/UDP FINGERPRINT: ");
   fingerprint = bformat("%u:%u:%u:%d:%u:%u",totlen,ttl,df,olen,ip_off,ip_tos);
   printf("[%s]\n",(char*)bdata(fingerprint));
   //update_asset_os(ip_addr, port, detection, raw_fp, af);
   bdestroy(fingerprint);
}
