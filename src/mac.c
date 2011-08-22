/*
** Copyright (C) 2010 Kacper Wysocki <kacper.wysocki@redpill-linpro.com>
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

#include "common.h"
#include "prads.h"
#include "sys_func.h"
#include "mac.h"
/* macfp
 *
 * Purpose:
 *
 * This file eats a MAC-address and returns a MAC-vendor match.
 *
 * File format:
 *  primary file format in use is Wireshark format:
 * MA:CC:AD:RE:SS[/36] manufacturer # optional comment
 *
 * MAC-address
 *
 * Effect:
 *
 * Returns a fingerprint match and the fingerprint it matched
 *
 * Comments:
 *
 * Old school...
 */
/* alloc_mac return a newly allocated copy of *e */
static mac_entry *alloc_mac(mac_entry *e)
{
    mac_entry *n = calloc(1, sizeof(mac_entry));
    *n = *e; // copy
    return n;
}

void print_mac(const uint8_t *mac){
   int i;
   for(i = 0; i < 6; i++){
      printf("%02hhx:", mac[i]);
   }
}

void print_mac_entry(mac_entry *e){
   if(!e) return;

   print_mac(e->o);

   if(e->mask)
      printf("/%d", e->mask);

   printf(" %s ", e->vendor);
   if(e->comment)
      printf("# %s", e->comment);

   printf("\n");

   return;
}

void print_mac_entries(mac_entry *e) {
   print_mac_entry(e);

   if(e->next)
      print_mac_entries(e->next);
}

void dump_macs(mac_entry **sig, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if(sig[i]){
            printf("%d: ", i);
            print_mac_entries(sig[i]);
        }
    }
}

/* match mac with vendor list
 * most specific match first.
 * 
 * how does this grab ya:
 * aa:bb:cc:dd:ee:ff matches
 * aa:bb:cc:d0/26
 * .. by searching upward from
 * aa:bb:cc:00
 */
mac_entry *match_mac(mac_entry **db, const uint8_t mac[], uint8_t mask)
{
   uint32_t index = hash_mac(mac, mask / 8);
   uint8_t r,i,ditch = 0;
   /* debug
   if(mask == 48) {
      print_mac(mac);
      printf("/%d match\n", mask);
   } */
   if(db == NULL) return NULL; // database not loaded!


   if(mask == 0)
      return NULL; // oopsy we run out of matches.

   // hash will only get us so far, we must search the rest of the way
   mac_entry *match = db[index];
   if(match) {

check_match:
      do {
         //print_mac_entry(match);
        
         /* XXX: we could definitely take advantage of
          * 64bit or SIMD instructions to speed this up, here and in the hash func
          */
         for(i = 0; i < match->mask / 8; i++){
            if (mac[i] != match->o[i])
               i = 6; // 7!? flag and break
         }
         if(i == 7){
            continue; // we flagged and broke
         }
         // do we have a winner?           
         r = match->mask % 8;
         if(r) {
            // there is more to match, maybe less than a nibble
            //dlog("nibble match! /%d :%d, %02x=?%02x\n", match->mask, r, mac[i] >> match->mask, match->o[i] >> match->mask);
            if(! ((mac[i] ^ match->o[i]) & (0xFF << (8 - r))) )
               return match; // if the bits match, expression is 0
         } else {
            // easy case: we have a winner..
            return match;
         }
      } while (NULL != (match = match->next));
   }
   // tail recurse, defer to the wisdom of our elders
   if(! ditch ) {
      match = match_mac(db, mac, mask - 8);
   }

   // real tough case.. we didn't find anything down the road
   // and must search upwards :-P. This is the DITCH, we scan
   // 255 hashpoints per octet to find out if there is anything around..

   if(!match) {
      while(ditch++ < 0xFF) {
         match = db[index +ditch %MAC_HASHSIZE];
         if(match)
            goto check_match;
      }
   }
   return match;
}


/* load_mac: fill **macp with mac_entry
 *
 * sigp is a pointer to either 
 ** a pointer to a preallocated buffer of size max_sigs * fp_entry OR
 ** a NULL pointer indicating that we should allocate max_sigs for you
 * max_sigs is the maximal size of the buffer, or 0 in which case we decide
 *
 * Theory:   snarf sigs in serially, easypeasy
 * 
 * returns errno
 */
int load_mac(const char *file, mac_entry **sigp[], int hashsize)
{
    mac_entry **sig; // output
    uint32_t ln = 0;
    uint32_t sigcnt = 0; 
    //debug("opening %s\n", file);
    FILE *f = fopen(file, "r");
    char buf[MAXLINE];
    char *p;
    if (!f) {
        perror("failed to open file");
        return errno;
    }
    if(!sigp){
        perror("need a pointer to fill");
        return -1;
    }
    if(!hashsize)
        hashsize = MAC_HASHSIZE;
    if(*sigp == NULL){
        *sigp = calloc(hashsize, sizeof(mac_entry *));
        sig = *sigp;
    }

    // read a line at a time and load it into the hash.
    while ((p = fgets(buf, sizeof(buf), f))) {
        mac_entry entry = {{0}}; //guarantee it's empty
        uint32_t l, lp;
        uint8_t octet = 0;
        char vendor[128] = {0}; 
        char *comment = 0;

        mac_entry *e;

        ln++;

        /* Remove leading and trailing blanks */
        SKIP_SPACES(p);
        l = strlen(p);
        while (l && isspace(*(p + l - 1)))
            *(p + (l--) - 1) = 0;

        /* Skip empty lines and comments */
        if (!l)
            continue;
        if (*p == '#')
            continue;

        /* first part: mac address */
        while (*p && !isspace(*p))
        {
           if (isxdigit(*p) && isxdigit(*(p+1))) {
              //mac.o[octet++] = strtol(p,&(p+1), 16);
              sscanf(p, "%2hhx", &entry.o[octet]);
              octet++;
              p += 2;
              continue;
           } else if (*p == '-' || *p == ':') {
              p++;
              continue;
           } else if (*p == '/') {
              // mac mask
              entry.mask = strtol(p+1, NULL, 10);
              p += 2;
              continue;
           } // else
           p++; // skip unknown chars...
        }
        SKIP_SPACES(p);
        /* second part: vendor */
        sscanf(p, "%127s", vendor);
        // scan forward..
        while (*p && !isspace(*p))
           p++;
        SKIP_SPACES(p);

        /* third part, #comment (optional) */
        if(*p == '#') {
           /* chomp it first */
           p++;
           SKIP_SPACES(p);
           lp = strlen(p);

           while (lp && isspace(*(p + lp - 1)))
              *(p + (lp--) - 1) = 0;

           /* then copy the comment */
           comment = calloc(1, lp + 1);
           strncpy(comment, p, lp);
        }
        
        /* roll hash */
        entry.vendor = strdup(vendor);
        entry.comment = comment;

        // if there is no mask, all octets count
        if(!entry.mask)
           entry.mask = octet * 8; //48 - octet * 8;

        int index = hash_mac(entry.o, octet);
        e = sig[index];

        if (!e) {
            sig[index] = alloc_mac(&entry);
        } else {
            int cc = 0;
            // collision!
            while (e->next){
                e = e->next;
                cc++;
            }
            /*
            printf("hash collision %d: at index %d\n", cc, index);
            print_mac(&entry);
            */
            e->next = alloc_mac(&entry);
        }
        sigcnt++;
    }

    fclose(f);
#ifdef DEBUG_HASH
    {
        int i,max;
        mac_entry *p;
        printf("Hash table layout: ");
        max = 0;
        for (i = 0; i < MAC_HASHSIZE; i++) {
            int z = 0;
            p = sig[i];
            while (p) {
                p = p->next;
                z++;
            }
            max = (max > z)? max : z;
            printf("%d ", z);

        }
        putchar('\n');
        printf ("max : %d\n", max);
    }
#endif                          /* DEBUG_HASH */
    
    if (!sigcnt)
        debug("[!] WARNING: no signatures loaded from config file.\n");
    else
       dlog("%d sigs from %d lines\n", sigcnt, ln);

    return 0;
}

/* eats an ARP packet and adds/enters the asset */
void arp_check(eth_hdr, tstamp)
{
    return;
}
