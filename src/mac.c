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

void print_mac(mac_entry *e){
   int i;
   if(!e) return;

   for(i = 0; i < 6; i++){
      printf("%02hhx:", e->o[i]);
   }
   if(e->mask)
      printf("/%d", e->mask);

   printf(" %s ", e->vendor);
   if(e->comment)
      printf("# %s", e->comment);

   printf("\n");

   if(e->next)
      print_mac(e->next);
   return;
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
    debug("opening %s\n", file);
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
           lp = strnlen(p, MAXLINE - (p - buf) - 1);

           while (lp && isspace(*(p + lp - 1)))
              *(p + (lp--) - 1) = 0;

           /* then copy the comment */
           comment = calloc(1, lp + 1);
           strncpy(comment, p, lp);
        }
        
        /* assemble & hash */
        entry.vendor = strdup(vendor);
        entry.comment = comment;
        if(!entry.mask)
           entry.mask = 48 - octet * 8;

        int index = MAC_HASH((entry.o));
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
#ifdef DUMP_HASH
    {
        int i;
        for (i = 0; i < MAC_HASHSIZE; i++) {
            if(sig[i]){
               printf("%d: ", i);
               print_mac(sig[i]);
            }
        }
    }
#endif
#ifdef DEBUG_HASH
    {
        int i;
        mac_entry *p;
        printf("Hash table layout: ");
        for (i = 0; i < MAC_HASHSIZE; i++) {
            int z = 0;
            p = sig[i];
            while (p) {
                p = p->next;
                z++;
            }
            printf("%d ", z);
        }
        putchar('\n');
    }
#endif                          /* DEBUG_HASH */
    
    if (!sigcnt)
        debug("[!] WARNING: no signatures loaded from config file.\n");

    return 0;
}

/* eats an ARP packet and adds/enters the asset */
void arp_check(eth_hdr, tstamp)
{
    return;
}
