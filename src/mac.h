/*
*/

#ifndef _HAVE_MAC_H
#define _HAVE_MAC_H

#define MAXLINE 1024
#define MAC_HASHSIZE 19963 //28001 //19963 //18899

typedef struct _mac_entry {
  uint8_t o[MAC_ADDR_LEN];
  uint8_t mask; // optional
  char *vendor;
  char *comment;
  struct _mac_entry *next;
} mac_entry;

/* GRR... on 64 bits there is no problem. on 32 bits, not so...
 * #define MAC_HASH(mac) (( (((uint32_t)mac[0]) ^ ((uint32_t)mac[1]) << 24) ^ ( ((uint32_t)mac[2]) << 16) ^ (mac[3]<<8) ^ (mac[4] ^ mac[5]) ) % MAC_HASHSIZE)

 * we need a monotonic rising hash for lookups to be just right.
 * otherwise, we can't search "near" the hash for a match.
 */
static inline uint32_t hash_mac(const uint8_t mac[], const uint8_t octets)
{
   int i;
   uint32_t hash;
   for(i = 0; i < octets; i++){
      //hash ^= mac[i] << ( (i*8) % 24); // reverse
      hash ^= mac[i] << (24 - ((i*8) % 24) );
   }
   return hash % MAC_HASHSIZE;
}

#define SKIP_SPACES(s) do { while(isspace(*s)) s++; } while (0)

int load_mac(const char *file, mac_entry **sigp[], int hashsize);
mac_entry *match_mac(mac_entry **db, const uint8_t mac[], uint8_t mask);
#endif /* ! _HAVE_MAC_H */
