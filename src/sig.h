/*
** This file is a part of PRADS.
**
** Copyright (C) 2009, Redpill Linpro
** Copyright (C) 2009, Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
** Copyright (C) 2009, Kacper Wysocki   <kacper.wysocki@redpill-linpro.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/* signature interface */
#define SIG_HASHSIZE 241

// the print_ and display_ functions need to be refactored
// and folded into gen_fp - to return a string for printing / storing
void print_sig(fp_entry * e);
void print_sigs(fp_entry * e);
void display_signature(uint8_t ttl, uint16_t tot, uint8_t df,
                                     uint8_t * op, uint8_t ocnt,
                                     uint16_t mss, uint16_t wss,
                                     uint8_t wsc, uint32_t tstamp,
                                     uint32_t quirks);
int load_sigs(const char *file, fp_entry **sigp[], int hashsize);
void dump_sigs(fp_entry *mysig[], int max);
void unload_sigs(fp_entry **sigp, int size);
// a starting point - the p0f find_match()
fp_entry *find_match(fp_entry *sig[],uint32_t hashsize,
                      fp_entry *fingerprint, packetinfo *pi,
                      uint32_t tstamp,
                      uint8_t plen,
                      uint8_t *pay);
fp_entry *find_matche(fp_entry *sig[], uint32_t hashsize,
                       uint16_t tot,uint8_t df,uint8_t ttl,uint16_t wss,uint32_t src,
                       uint32_t dst,uint16_t sp,uint16_t dp,uint8_t ocnt,uint8_t* op,uint16_t mss,
                       uint8_t wsc,uint32_t tstamp,uint8_t tos,uint32_t quirks,uint8_t ecn,
                       uint8_t* pkt,uint8_t plen,uint8_t* pay);

bstring gen_fp_tcp(fp_entry *e, uint32_t tstamp, uint8_t tf);
uint8_t* lookup_link(uint16_t mss,uint8_t txt);
