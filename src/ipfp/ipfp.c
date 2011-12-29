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

#include "../common.h"
#include "../prads.h"
#include "../assets.h"
#include "../config.h"
#include "ipfp.h"

/* ripped out gen_fp_tcp, sorry */
void gen_fp_icmp(uint8_t type,
                 uint8_t code,
                 uint8_t ttl,
                 uint8_t df,
                 int32_t olen,
                 uint16_t totlen,
                 uint8_t idata,
                 uint16_t ip_off,
                 uint8_t ip_tos,
                 uint32_t quirks,
                packetinfo *pi)
{
    bstring fp;
    //printf("[*] ASSET IP/ICMP FINGERPRINT: ");
    ttl = normalize_ttl(ttl);
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

    //icmp might have uptime?
    update_asset_os(pi, CO_ICMP, fp, NULL, 0);
    bdestroy(fp);
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
                packetinfo *pi)
{

    bstring fp;
    
    //printf("[*] ASSET IP/UDP FINGERPRINT: ");

    //fp = bformat("%u:%u:%u:%u:%d:%u:%u:",udata,totlen,ttl,df,olen,ip_off,ip_tos);
    //fp = bformat("%u,%u:%u:%d:%u:%u:", totlen, ttl, df, olen, ip_off,
    // add "20" to be prads.pl compatible :)
    ttl = normalize_ttl(ttl);
    fp = bformat("20:%u:%u:%d:%u:%u:", ttl, df, olen, ip_off,ip_tos);
    if (!quirks)
        bformata(fp, ".");
    else {
        if (quirks & QUIRK_ZEROID)
            bformata(fp, "Z");
        if (quirks & QUIRK_IPOPT)
            bformata(fp, "I");
    }

    update_asset_os(pi, CO_UDP, fp, NULL, 0);
    bdestroy(fp);
}

/*
uint8_t normalize_ttl (uint8_t ttl)
{
    if ( ttl > 128 ) return 255;
    if ( ttl >  64 ) return 128;
    if ( ttl >  32 ) return  64;
    else  return  32;
}
*/
