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

#include "../common.h"
#include "../prads.h"
#include "../assets.h"
#include "ipfp.h"

void gen_fp_tcp(uint8_t ttl,
                uint16_t tot,
                uint8_t df,
                uint8_t * op,
                uint8_t ocnt,
                uint16_t mss,
                uint16_t wss,
                uint8_t wsc,
                uint32_t tstamp,
                uint32_t quirks,
                uint8_t ftype,
                struct in6_addr ip_src, uint16_t port, int af)
{

    uint32_t j;
    uint8_t d = 0;
    //uint8_t q = 0;
    bstring fp, de;

    if (ftype == TF_SYN) {
        de = bformat("syn");
    } else if (ftype == TF_SYNACK) {
        de = bformat("synack");
    } else if (ftype == TF_ACK) {
        de = bformat("ack");
        ocnt = 3;
    } else if (ftype == TF_RST) {
        de = bformat("rst");
    } else if (ftype == TF_FIN) {
        de = bformat("fin");
    } else {
        de = bformat("error");
    }

    fp = bformat("");

    if (mss && wss && !(wss % mss))
        bformata(fp, "S%d", (wss / mss));
    else if (wss && !(wss % 1460))
        bformata(fp, "S%d", (wss / 1460));
    else if (mss && wss && !(wss % (mss + 40)))
        bformata(fp, "T%d", (wss / (mss + 40)));
    else if (wss && !(wss % 1500))
        bformata(fp, "T%d", (wss / 1500));
    else if (wss == 12345)
        bformata(fp, "*(12345)");
    else if (wss == 65535)
        bformata(fp, "*(65535)");
    //else if (ftype==TF_ACK || ftype==TF_FIN || ftype==TF_RST) {
    //    bformata(fp, "*");
    //} 
    else {
        bformata(fp, "%d", wss);
    }

    if ( ftype == TF_ACK || ftype == TF_RST ) {
        bformata(fp, ":%d:%d:*:",ttl,df);
    } else {
        if (tot < PACKET_BIG)
            bformata(fp, ":%d:%d:%d:", ttl, df, tot);
        else
            bformata(fp, ":%d:%d:*(%d):", ttl, df, tot);
    }

    for (j = 0; j < ocnt; j++) {
        switch (op[j]) {
        case TCPOPT_NOP:
            bformata(fp, "N");
            d = 1;
            break;
        case TCPOPT_WSCALE:
            bformata(fp, "W%d", wsc);
            d = 1;
            break;
        case TCPOPT_MAXSEG:
            bformata(fp, "M%d", mss);
            d = 1;
            break;
        case TCPOPT_TIMESTAMP:
            bformata(fp, "T");
            if (!tstamp)
                bformata(fp, "0");
            d = 1;
            break;
        case TCPOPT_SACKOK:
            bformata(fp, "S");
            d = 1;
            break;
        case TCPOPT_EOL:
            bformata(fp, "E");
            d = 1;
            break;
        default:
            bformata(fp, "?%d", op[j]);
            d = 1;
            break;
        }
        if (j != ocnt - 1)
            bformata(fp, ",");
    }

    if (!d)
        bformata(fp, ".");

    bformata(fp, ":");

    if (!quirks)
        bformata(fp, ".");
    else {
        if (quirks & QUIRK_RSTACK)
            bformata(fp, "K");
        if (quirks & QUIRK_SEQEQ)
            bformata(fp, "Q");
        if (quirks & QUIRK_SEQ0)
            bformata(fp, "0");
        if (quirks & QUIRK_PAST)
            bformata(fp, "P");
        if (quirks & QUIRK_ZEROID)
            bformata(fp, "Z");
        if (quirks & QUIRK_IPOPT)
            bformata(fp, "I");
        if (quirks & QUIRK_URG)
            bformata(fp, "U");
        if (quirks & QUIRK_X2)
            bformata(fp, "X");
        if (quirks & QUIRK_ACK)
            bformata(fp, "A");
        if (quirks & QUIRK_T2)
            bformata(fp, "T");
        if (quirks & QUIRK_FLAGS)
            bformata(fp, "F");
        if (quirks & QUIRK_DATA)
            bformata(fp, "D");

        /*
         * edward 
         */
        if (quirks & QUIRK_FINACK)
            bformata(fp, "N");
        if (quirks & QUIRK_FLOWL)
            bformata(fp, "L");

        if (quirks & QUIRK_BROKEN)
            bformata(fp, "!");
    }

    // This should get into the asset somehow: tstamp
    //if (tstamp) printf("(* uptime: %d hrs)\n",tstamp/360000);
    update_asset_os(ip_src, port, de, fp, af, tstamp?tstamp:0);
    // cleanup
    bdestroy(fp);
    bdestroy(de);
}

void gen_fp_icmp(uint8_t type,
                 uint8_t code,
                 uint8_t ttl,
                 uint8_t df,
                 int32_t olen,
                 uint16_t totlen,
                 uint8_t idata,
                 uint16_t ip_off,
                 uint8_t ip_tos,
                 uint32_t quirks, struct in6_addr ip_src, int af)
{
    bstring fp;
    //printf("[*] ASSET IP/ICMP FINGERPRINT: ");

    fp = bformat("%u:%u:%u:%u:%u:%d:%u:%u:", idata, type, code, ttl, df,
                 olen, totlen, ip_off, ip_tos);
    if (!quirks)
        bformata(fp, ".");
    else {
        if (quirks & QUIRK_ZEROID)
            bformata(fp, "Z");
        if (quirks & QUIRK_IPOPT)
            bformata(fp, "I");
    }

    //printf("[%s]\n",(char*)bdata(fp));
    bstring t = bformat("icmp");
    //icmp might have uptime?
    update_asset_os(ip_src, htons(type), t, fp, af,0);
    bdestroy(t);
    bdestroy(fp);
    // add mss ? for MTU detection ?
}

void gen_fp_udp(uint16_t totlen,
                uint16_t udata,
                uint8_t ttl,
                uint8_t df,
                int32_t olen,
                uint16_t ip_len,
                uint16_t ip_off,
                uint8_t ip_tos,
                uint32_t quirks,
                struct in6_addr ip_src, uint16_t port, int af)
{

    bstring fp;
    //printf("[*] ASSET IP/UDP FINGERPRINT: ");

    //fp = bformat("%u:%u:%u:%u:%d:%u:%u:",udata,totlen,ttl,df,olen,ip_off,ip_tos);
    fp = bformat("%u,%u:%u:%d:%u:%u:", totlen, ttl, df, olen, ip_off,
                 ip_tos);
    if (!quirks)
        bformata(fp, ".");
    else {
        if (quirks & QUIRK_ZEROID)
            bformata(fp, "Z");
        if (quirks & QUIRK_IPOPT)
            bformata(fp, "I");
    }
    bstring t = bformat("udp");

    //printf("[%s]\n",(char*)bdata(fp));
    update_asset_os(ip_src, port, t, fp, af,0);
    bdestroy(fp);
    bdestroy(t);
}
