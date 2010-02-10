/* Load and match signatures
 *
 * (c) Kacper Wysocki <kacperw@gmail.com> for PRADS, 2009
 *
 * straight port of p0f load,match_sigs and support functions - nothing new here
 *
 * p0f loads sigs as struct fp_entry into the sig[] array 
 * ... and uses a static hash lookup to jump into this array
 * - based on size, option count, quirks and don't fragment
 *
 * thoughts to improve:
  - decouple fingerprints from signatures,
  provide consistent interface for matching assets
  across services (arp,ip,tcp,udp,link,dhcp,...)

  *** The interface (should be) ***

    *** sigs ***
    load_sigs() <- create hashtable from file
    usage: 
    sigs* = load_sigs(file)
    load_sigs_{syn,ack,synack,..}()

    match_fp(char *fp, struct *fp) <- take a fingerprint string/struct
      and lookup into hash. return unique, fuzzy, best match.

    match_fp(packetinfo) - guess OS based on packet info

    find_match(foo)


 TODO:
  - fp_entry* = find_match(sigs, pi, e)
  - unload_sigs(sigs);
  - ipv6 fix
  - collide
  - merge gen_fp and display_signature


 */

#include "common.h"
#include "prads.h"
#include "mtu.h"
#include "tos.h"

#define MAXLINE 1024
#define SIG_HASHSIZE 1024
#define MAXDIST 512
#define PKT_DLEN 16
#define PKT_MAXPAY 45

/* SIGHASH needs some tweaking
 * the addition of wsize has reduced collisions
 * but similar signatures still collide.
 *
 * best case (and least efficient) would be to hash on
 * full options and quirks
 */
#define SIGHASH(wsize, tsize,optcnt,q,df) \
	( ((wsize << 3) ^ ((tsize) << 2) ^ ((optcnt) << 1) ^ (df) ^ (q) ))
#define debug(x...)	fprintf(stderr,x)
#define fatal(x...)	do { debug("[-] ERROR: " x); exit(1); } while (0)

uint32_t packet_count;
uint8_t operating_mode;
uint32_t st_time;
static uint8_t no_extra,
    no_osdesc,
    no_known,
    no_unknown,
    rst_mode,
    mode_oneline,
    always_sig,
    do_resolve,
    check_collide,
    full_dump, use_fuzzy, payload_dump;

static uint8_t problems;

void display_signature(uint8_t ttl, uint16_t tot, uint8_t df,
                                     uint8_t * op, uint8_t ocnt,
                                     uint16_t mss, uint16_t wss,
                                     uint8_t wsc, uint32_t tstamp,
                                     uint32_t quirks)
{

    uint32_t j;
    uint8_t d = 0;

    if (mss && wss && !(wss % mss))
        printf("S%d", wss / mss);
    else if (wss && !(wss % 1460))
        printf("S%d", wss / 1460);
    else if (mss && wss && !(wss % (mss + 40)))
        printf("T%d", wss / (mss + 40));
    else if (wss && !(wss % 1500))
        printf("T%d", wss / 1500);
    else if (wss == 12345)
        printf("*(12345)");
    else
        printf("%d", wss);

    if (tot < PACKET_BIG)
        printf(":%d:%d:%d:", ttl, df, tot);
    else
        printf(":%d:%d:*(%d):", ttl, df, tot);

    for (j = 0; j < ocnt; j++) {
        switch (op[j]) {
        case TCPOPT_NOP:
            putchar('N');
            d = 1;
            break;
        case TCPOPT_WSCALE:
            printf("W%d", wsc);
            d = 1;
            break;
        case TCPOPT_MAXSEG:
            printf("M%d", mss);
            d = 1;
            break;
        case TCPOPT_TIMESTAMP:
            putchar('T');
            if (!tstamp)
                putchar('0');
            d = 1;
            break;
        case TCPOPT_SACKOK:
            putchar('S');
            d = 1;
            break;
        case TCPOPT_EOL:
            putchar('E');
            d = 1;
            break;
        default:
            printf("?%d", op[j]);
            d = 1;
            break;
        }
        if (j != ocnt - 1)
            putchar(',');
    }

    if (!d)
        putchar('.');

    putchar(':');

    if (!quirks)
        putchar('.');
    else {
        if (quirks & QUIRK_RSTACK)
            putchar('K');
        if (quirks & QUIRK_SEQEQ)
            putchar('Q');
        if (quirks & QUIRK_SEQ0)
            putchar('0');
        if (quirks & QUIRK_PAST)
            putchar('P');
        if (quirks & QUIRK_ZEROID)
            putchar('Z');
        if (quirks & QUIRK_IPOPT)
            putchar('I');
        if (quirks & QUIRK_URG)
            putchar('U');
        if (quirks & QUIRK_X2)
            putchar('X');
        if (quirks & QUIRK_ACK)
            putchar('A');
        if (quirks & QUIRK_T2)
            putchar('T');
        if (quirks & QUIRK_FLAGS)
            putchar('F');
        if (quirks & QUIRK_DATA)
            putchar('D');
        if (quirks & QUIRK_BROKEN)
            putchar('!');
    }

}

void print_sig(fp_entry * e)
{
    display_signature(e->ttl,
                      e->size,
                      e->df,
                      e->opt,
                      e->optcnt,
                      e->mss, e->wsize, e->wsc, e->zero_stamp, e->quirks);

    printf(" :  %s : %s \n", e->os, e->desc);
    if (e->next)
        print_sig(e->next);
}

/* collide: check 
static void collide(uint32_t id)
{
    uint32_t i, j;
    uint32_t cur;

    if (sig[id].ttl % 32 && sig[id].ttl != 255 && sig[id].ttl % 30) {
        problems = 1;
        debug("[!] Unusual TTL (%d) for signature '%s %s' (line %d).\n",
              sig[id].ttl, sig[id].os, sig[id].desc, sig[id].line);
    }

    for (i = 0; i < id; i++) {

        if (!strcmp(sig[i].os, sig[id].os) &&
            !strcmp(sig[i].desc, sig[id].desc)) {
            problems = 1;
            debug
                ("[!] Duplicate signature name: '%s %s' (line %d and %d).\n",
                 sig[i].os, sig[i].desc, sig[i].line, sig[id].line);
        }

        //If TTLs are sufficiently away from each other, the risk of
        // a collision is lower. 
        if (abs((int32_t) sig[id].ttl - (int32_t) sig[i].ttl) > 25)
            continue;

        if (sig[id].df ^ sig[i].df)
            continue;
        if (sig[id].zero_stamp ^ sig[i].zero_stamp)
            continue;

        // * Zero means >= PACKET_BIG 
        if (sig[id].size) {
            if (sig[id].size ^ sig[i].size)
                continue;
        } else if (sig[i].size < PACKET_BIG)
            continue;

        if (sig[id].optcnt ^ sig[i].optcnt)
            continue;
        if (sig[id].quirks ^ sig[i].quirks)
            continue;

        switch (sig[id].wsize_mod) {

        case 0:                // Current: const

            cur = sig[id].wsize;

          do_const:

            switch (sig[i].wsize_mod) {

            case 0:            // Previous is also const

                 // * A problem if values match 
                if (cur ^ sig[i].wsize)
                    continue;
                break;

            case MOD_CONST:    // Current: const, prev: modulo (or *) 

                 // A problem if current value is a multiple of that modulo 
                if (cur % sig[i].wsize)
                    continue;
                break;

            case MOD_MSS:      // Current: const, prev: mod MSS 

                if (sig[i].mss_mod || sig[i].wsize *
                    (sig[i].mss ? sig[i].mss : 1460) != cur)
                    continue;

                break;

            case MOD_MTU:      // Current: const, prev: mod MTU

                if (sig[i].mss_mod
                    || sig[i].wsize * ((sig[i].mss ? sig[i].mss : 1460) +
                                       40) != cur)
                    continue;

                break;

            }

            break;

        case 1:                // Current signature is modulo something

             // A problem only if this modulo is a multiple of the 
             // previous modulo 

            if (sig[i].wsize_mod != MOD_CONST)
                continue;
            if (sig[id].wsize % sig[i].wsize)
                continue;

            break;

        case MOD_MSS:          // Current is modulo MSS

             // There's likely a problem only if the previous one is close
             // to '*'; we do not check known MTUs, because this particular
             // signature can be made with some uncommon MTUs in mind. The
             // problem would also appear if current signature has a fixed
             // MSS. 

            if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize >= 8) {
                if (!sig[id].mss_mod) {
                    cur =
                        (sig[id].mss ? sig[id].mss : 1460) * sig[id].wsize;
                    goto do_const;
                }
                continue;
            }

            break;

        case MOD_MTU:          // Current is modulo MTU

            if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize <= 8) {
                if (!sig[id].mss_mod) {
                    cur =
                        ((sig[id].mss ? sig[id].mss : 1460) +
                         40) * sig[id].wsize;
                    goto do_const;
                }
                continue;
            }

            break;

        }

         // Same for wsc 
        switch (sig[id].wsc_mod) {

        case 0:                // Current: const

            cur = sig[id].wsc;

            switch (sig[i].wsc_mod) {

            case 0:            // Previous is also const

                // A problem if values match 
                if (cur ^ sig[i].wsc)
                    continue;
                break;

            case 1:            // Current: const, prev: modulo (or *) 

                // A problem if current value is a multiple of that modulo 
                if (cur % sig[i].wsc)
                    continue;
                break;

            }

            break;

        case MOD_CONST:        // Current signature is modulo something

             // A problem only if this modulo is a multiple of the 
             // previous modulo 

            if (!sig[i].wsc_mod)
                continue;
            if (sig[id].wsc % sig[i].wsc)
                continue;

            break;

        }

        // Same for mss 
        switch (sig[id].mss_mod) {

        case 0:                // Current: const 

            cur = sig[id].mss;

            switch (sig[i].mss_mod) {

            case 0:            // Previous is also const

                // A problem if values match 
                if (cur ^ sig[i].mss)
                    continue;
                break;

            case 1:            // Current: const, prev: modulo (or *) 

                // A problem if current value is a multiple of that modulo 
                if (cur % sig[i].mss)
                    continue;
                break;

            }

            break;

        case MOD_CONST:        // Current signature is modulo something

            // A problem only if this modulo is a multiple of the 
            // previous modulo 
            if (!sig[i].mss_mod)
                continue;
            if ((sig[id].mss ? sig[id].mss : 1460) %
                (sig[i].mss ? sig[i].mss : 1460))
                continue;

            break;

        }

        // Now check option sequence 
        for (j = 0; j < sig[id].optcnt; j++)
            if (sig[id].opt[j] ^ sig[i].opt[j])
                goto reloop;

        problems = 1;
        debug("[!] Signature '%s %s' (line %d)\n"
              "    is already covered by '%s %s' (line %d).\n",
              sig[id].os, sig[id].desc, sig[id].line, sig[i].os,
              sig[i].desc, sig[i].line);

      reloop:
        ;
    }
}
//collide () */
/* recursively free signatures */
static void free_sigs(fp_entry *e){
    if(e->next)
        free_sigs(e->next);
    free(e);
}

/* alloc_sig return a newly allocated copy of *e */
static fp_entry *alloc_sig(fp_entry *e)
{
    fp_entry *n = calloc(1, sizeof(fp_entry));
    *n = *e; // copy
    return n;
}

/* parse the wss field of the signature line */
static int parse_sig_wsize(fp_entry *sig, char* w)
{
    if (w[0] == '*') {
        sig->wsize = 1;
        sig->wsize_mod = MOD_CONST;
    } else if (tolower(w[0]) == 's') {
        sig->wsize_mod = MOD_MSS;
        if (!isdigit(*(w + 1)))
            fatal("Bad Snn value in WSS in line %d.\n", sig->line);
        sig->wsize = atoi(w + 1);
    } else if (tolower(w[0]) == 't') {
        sig->wsize_mod = MOD_MTU;
        if (!isdigit(*(w + 1)))
            fatal("Bad Tnn value in WSS in line %d.\n", sig->line);
        sig->wsize = atoi(w + 1);
    } else if (w[0] == '%') {
        if (!(sig->wsize = atoi(w + 1)))
            fatal("Null modulo for window size in config line %d.\n",
                  sig->line);
        sig->wsize_mod = MOD_CONST;
    } else
        sig->wsize = atoi(w);

    return 0;
}

/* parse the option field of the signature line */
static int parse_sig_options(fp_entry *sig, char* p)
{
    sig->zero_stamp = 1;

    if (*p == '.')
        p++;

    while (*p) {
        uint8_t optcnt = sig->optcnt;
        switch (tolower(*p)) {

            case 'n':
                sig->opt[optcnt] = TCPOPT_NOP;
                break;

            case 'e':
                sig->opt[optcnt] = TCPOPT_EOL;
                if (*(p + 1))
                    fatal("EOL not the last option (line %d).\n", sig->line);
                break;

            case 's':
                sig->opt[optcnt] = TCPOPT_SACKOK;
                break;

            case 't':
                sig->opt[optcnt] = TCPOPT_TIMESTAMP;
                if (*(p + 1) != '0') {
                    sig->zero_stamp = 0;
                    if (isdigit(*(p + 1)))
                        fatal("Bogus Tstamp specification in line %d.\n",
                              sig->line);
                }
                break;

            case 'w':
                sig->opt[optcnt] = TCPOPT_WSCALE;
                if (p[1] == '*') {
                    sig->wsc = 1;
                    sig->wsc_mod = MOD_CONST;
                } else if (p[1] == '%') {
                    if (!(sig->wsc = atoi(p + 2)))
                        fatal
                            ("Null modulo for wscale in config line %d.\n",
                             sig->line);
                    sig->wsc_mod = MOD_CONST;
                } else if (!isdigit(*(p + 1)))
                    fatal("Incorrect W value in line %d.\n", sig->line);
                else
                    sig->wsc = atoi(p + 1);
                break;

            case 'm':
                sig->opt[optcnt] = TCPOPT_MAXSEG;
                if (p[1] == '*') {
                    sig->mss = 1;
                    sig->mss_mod = MOD_CONST;
                } else if (p[1] == '%') {
                    if (!(sig->mss = atoi(p + 2)))
                        fatal("Null modulo for MSS in config line %d.\n",
                              sig->line);
                    sig->mss_mod = MOD_CONST;
                } else if (!isdigit(*(p + 1)))
                    fatal("Incorrect M value in line %d.\n", sig->line);
                else
                    sig->mss = atoi(p + 1);
                break;

                /*
                 * Yuck! 
                 */
            case '?':
                if (!isdigit(*(p + 1)))
                    fatal("Bogus ?nn value in line %d.\n", sig->line);
                else
                    sig->opt[optcnt] = atoi(p + 1);
                break;

            default:
                fatal("Unknown TCP option '%c' in config line %d.\n", *p,
                      sig->line);
        }

        if (++sig->optcnt >= MAXOPT)
            fatal
                ("Too many TCP options specified in config line %d.\n",
                 sig->line);

        /*
         * Skip separators 
         */
        do {
            p++;
        } while (*p && !isalpha(*p) && *p != '?');
    }
    return 0;
}

/* parse the quirks field of the signature line */
static int parse_sig_quirks(fp_entry *sig, uint8_t *p)
{
    while (*p){
        switch (toupper(*(p++))) {
            case 'E':
                fatal
                    ("Quirk 'E' (line %d) is obsolete. Remove it, append E to the "
                     "options.\n", sig->line);

            case 'K':
                if (!rst_mode)
                    fatal("Quirk 'K' (line %d) is valid only in RST+ (-R)"
                          " mode (wrong config file?).\n", sig->line);
                sig->quirks |= QUIRK_RSTACK;
                break;

            case 'D':
                sig->quirks |= QUIRK_DATA;
                break;

            case 'Q':
                sig->quirks |= QUIRK_SEQEQ;
                break;
            case '0':
                sig->quirks |= QUIRK_SEQ0;
                break;
            case 'P':
                sig->quirks |= QUIRK_PAST;
                break;
            case 'Z':
                sig->quirks |= QUIRK_ZEROID;
                break;
            case 'I':
                sig->quirks |= QUIRK_IPOPT;
                break;
            case 'U':
                sig->quirks |= QUIRK_URG;
                break;
            case 'X':
                sig->quirks |= QUIRK_X2;
                break;
            case 'A':
                sig->quirks |= QUIRK_ACK;
                break;
            case 'T':
                sig->quirks |= QUIRK_T2;
                break;
            case 'F':
                sig->quirks |= QUIRK_FLAGS;
                break;
            case '!':
                sig->quirks |= QUIRK_BROKEN;
                break;
            case '.':
                break;
            default:
                fatal("Bad quirk '%c' in line %d.\n", *(p - 1), sig->line);
        }
    }
    return 0;
}


/* load_sigs: fill **sig with fp_entry signatures from *file
 *
 * sigp is a pointer to either 
 ** a pointer to a preallocated buffer of size max_sigs * fp_entry OR
 ** a NULL pointer indicating that we should allocate max_sigs for you
 * max_sigs is the maximal size of the buffer, or 0 in which case we decide
 *
 * Theory:   snarf sigs in serially, easypeasy
 * Practice: lookups are a bitch and require a buckethash.
 ** -> store sigs directly into hash.
 * 
 * returns errno
 */
int load_sigs(const char *file, fp_entry **sigp[], int hashsize)
{
    fp_entry **sig; // output
    uint32_t ln = 0;
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
        hashsize = SIG_HASHSIZE;
    if(*sigp == NULL){
        *sigp = calloc(hashsize, sizeof(fp_entry*));
        sig = *sigp;
    }

    while ((p = fgets(buf, sizeof(buf), f))) {
        uint32_t l;

        char obuf[MAXLINE], genre[MAXLINE], desc[MAXLINE],
            quirks[MAXLINE];
        char w[MAXLINE], sb[MAXLINE];
        char *gptr = genre;
        uint32_t t, d, s;
        fp_entry asig = {0}; //guarantee it's empty this sig
        fp_entry *e;

        ln++;

        /* Remove leading and trailing blanks */
        while (isspace(*p))
            p++;
        l = strlen(p);
        while (l && isspace(*(p + l - 1)))
            *(p + (l--) - 1) = 0;

        /* Skip empty lines and comments */
        if (!l)
            continue;
        if (*p == '#')
            continue;

        if (sscanf
            (p, "%[0-9%*()ST]:%d:%d:%[0-9()*]:%[^:]:%[^ :]:%[^:]:%[^:]", 
            w, &t, &d, sb, obuf, quirks, genre, desc) != 8)
            fatal("Syntax error in config line %d.\n", ln);

        gptr = genre;

        if (*sb != '*') {
            s = atoi(sb);
        } else
            s = 0;

      reparse_ptr:

        switch (*gptr) {
        case '-':
            asig.userland = 1;
            gptr++;
            goto reparse_ptr;
        case '*':
            asig.no_detail = 1;
            gptr++;
            goto reparse_ptr;
        case '@':
            asig.generic = 1;
            gptr++;
            //gencnt++;
            goto reparse_ptr;
        case 0:
            fatal("Empty OS genre in line %d.\n", ln);
        }

        asig.os = strdup(gptr);
        asig.desc = strdup(desc);
        asig.ttl = t;
        asig.size = s;
        asig.df = d;

        parse_sig_wsize(&asig, w);
        asig.line = ln;
        parse_sig_options(&asig, obuf);
        parse_sig_quirks(&asig, quirks);
        uint32_t index = SIGHASH(asig.wsize, s, asig.optcnt, asig.quirks, d) % hashsize;
        e = sig[index];

        if (!e) {
            sig[index] = alloc_sig(&asig);
        } else {
            int cc = 0;
            // collision!
            while (e->next){
                e = e->next;
                cc++;
            }
            /*
            fprintf(stderr, "hash collision %d: \n%d: %s - %s\n%d: %s - %s\n",
            cc, asig.line, asig.os, asig.desc, e->line, e->os, e->desc);
            */
            e->next = alloc_sig(&asig);
        }

        /*
        if (check_collide)
            collide(sigcnt);
            */

        /* 
        if (++sigcnt >= hashsize)
            fatal("Maximum signature count exceeded.\n");
            */

    }

    fclose(f);
#ifdef DUMP_HASH
    {
        int i;
        for (i = 0; i < sigcnt; i++) {
            print_sig(&sig[i]);
        }
    }
#endif
#ifdef DEBUG_HASH
    {
        int i;
        fp_entry *p;
        printf("Hash table layout: ");
        for (i = 0; i < hashsize; i++) {
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

    if (check_collide && !problems)
        debug("[+] Signature collision check successful.\n");

    /*
    if (!sigcnt)
        debug("[!] WARNING: no signatures loaded from config file.\n");
        */

    return 0;
}

/* run through the hash, free entries, then free hash */
void unload_sigs(fp_entry **sigp, int size)
{
    int i = size;
    fp_entry *e;
    while(i--){
        e = sigp[i];
        if (e)
            free_sigs(e);
        sigp[i] = NULL; // clear
    }
    free(*sigp);
    *sigp = NULL;
}



#define MY_MAXDNS 32

#include <netdb.h>
static inline char* grab_name(char* a) {
  struct hostent* r;
  static char rbuf[MY_MAXDNS+6] = "/";
  uint32_t j;
  char *s,*d = rbuf+1;

  if (!do_resolve) return "";
  r = gethostbyaddr(a,4,AF_INET);
  if (!r || !(s = r->h_name) || !(j = strlen(s))) return "";
  if (j > MY_MAXDNS) return "";

  while (j--) {
    if (isalnum(*s) || *s == '-' || *s == '.') *d = *s;
      else *d = '?';
    d++; s++;
  }

  *d=0;

  return rbuf;

}



static uint8_t* lookup_link(uint16_t mss,uint8_t txt) {
  uint32_t i;
  static char tmp[32];

  if (!mss) return txt ? "unspecified" : 0;
  mss += 40;
  
  for (i=0;i<MTU_CNT;i++) {
   if (mss == mtu[i].mtu) return mtu[i].dev;
   if (mss < mtu[i].mtu)  goto unknown;
  }

unknown:

  if (!txt) return 0;
  sprintf(tmp,"unknown-%d",mss);
  return tmp;

}


static uint8_t* lookup_tos(uint8_t t) {
  uint32_t i;

  if (!t) return 0;

  for (i=0;i<TOS_CNT;i++) {
   if (t == tos[i].tos) return tos[i].desc;
   if (t < tos[i].tos) break;
  }

  return 0;

}


static void dump_packet(uint8_t* pkt,uint16_t plen) {
  uint32_t i;
  uint8_t  tbuf[PKT_DLEN+1];
  uint8_t* t = tbuf;
 
  for (i=0;i<plen;i++) {
    uint8_t c = *(pkt++);
    if (!(i % PKT_DLEN)) printf("  [%02x] ",i);
    printf("%02x ",c);
    *(t++) = isprint(c) ? c : '.';
    if (!((i+1) % PKT_DLEN)) {
      *t=0;
      printf(" | %s\n",(t=tbuf));
    }
  }
  
  if (plen % PKT_DLEN) {
    *t=0;
    while (plen++ % PKT_DLEN) printf("   ");
    printf(" | %s\n",tbuf);
  }

}


static void dump_payload(uint8_t* data,uint16_t dlen) {
  uint8_t  tbuf[PKT_MAXPAY+2];
  uint8_t* t = tbuf;
  uint8_t  i;
  uint8_t  max = dlen > PKT_MAXPAY ? PKT_MAXPAY : dlen;

  if (!dlen) return;

  for (i=0;i<max;i++) {
    if (isprint(*data)) *(t++) = *data; 
      else if (!*data)  *(t++) = '?';
      else *(t++) = '.';
    data++;
  }

  *t = 0;

  if (!mode_oneline) putchar('\n');
  printf("  # Payload: \"%s\"%s",tbuf,dlen > PKT_MAXPAY ? "..." : "");
}





uint32_t matched_packets;


fp_entry *find_match(fp_entry *sig[], uint32_t hashsize, 
                       uint16_t tot,uint8_t df,uint8_t ttl,uint16_t wss,uint32_t src,
                       uint32_t dst,uint16_t sp,uint16_t dp,uint8_t ocnt,uint8_t* op,uint16_t mss,
                       uint8_t wsc,uint32_t tstamp,uint8_t tos,uint32_t quirks,uint8_t ecn,
                       uint8_t* pkt,uint8_t plen,uint8_t* pay, struct timeval pts) {

  uint32_t j;
  uint8_t* a;
  uint8_t  nat=0;
  fp_entry* p;
  uint8_t  orig_df  = df;
  uint8_t* tos_desc = 0;

  fp_entry* fuzzy = 0;
  uint8_t fuzzy_now = 0;

re_lookup:

  p = sig[SIGHASH(wss,tot,ocnt,quirks,df) % hashsize];

  if (tos) tos_desc = lookup_tos(tos);

  printf("\nmatch:  ");
  display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);
  printf("\n");
  while (p) {
  
    printf("check:  ");
    print_sig(p);
    printf("\n");
    /* Cheap and specific checks first... */

      /* psize set to zero means >= PACKET_BIG */
    if (p->size) { if (tot ^ p->size) { p = p->next; continue; } }
    else if (tot < PACKET_BIG) { p = p->next; continue; }

    if (ocnt ^ p->optcnt) { p = p->next; continue; }

    if (p->zero_stamp ^ (!tstamp)) { p = p->next; continue; }
    if (p->df ^ df) { p = p->next; continue; }
    if (p->quirks ^ quirks) { p = p->next; continue; }

    /* Check MSS and WSCALE... */
    if (!p->mss_mod) {
      if (mss ^ p->mss) { p = p->next; continue; }
    } else if (mss % p->mss) { p = p->next; continue; }

    if (!p->wsc_mod) {
      if (wsc ^ p->wsc) { p = p->next; continue; }
    } else if (wsc % p->wsc) { p = p->next; continue; }

    /* Then proceed with the most complex WSS check... */
    switch (p->wsize_mod) {
      case 0:
        if (wss ^ p->wsize) { p = p->next; continue; }
        break;
      case MOD_CONST:
        if (wss % p->wsize) { p = p->next; continue; }
        break;
      case MOD_MSS:
        if (mss && !(wss % mss)) {
          if ((wss / mss) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1460)) {
          if ((wss / 1460) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
      case MOD_MTU:
        if (mss && !(wss % (mss+40))) {
          if ((wss / (mss+40)) ^ p->wsize) { p = p->next; continue; }
        } else if (!(wss % 1500)) {
          if ((wss / 1500) ^ p->wsize) { p = p->next; continue; }
        } else { p = p->next; continue; }
        break;
     }

    /* Numbers agree. Let's check options */

    for (j=0;j<ocnt;j++)
      if (p->opt[j] ^ op[j]) goto continue_search;

    /* Check TTLs last because we might want to go fuzzy. */
    if (p->ttl < ttl) {
      if (use_fuzzy) fuzzy = p;
      p = p->next;
      continue;
    }

    /* Naah... can't happen ;-) */
    if (!p->no_detail)
      if (p->ttl - ttl > MAXDIST) { 
        if (use_fuzzy) fuzzy = p;
        p = p->next; 
        continue; 
      }

continue_fuzzy:    
    
    /* Match! */
    
    matched_packets++;

    if (mss & wss) {
      if (p->wsize_mod == MOD_MSS) {
        if ((wss % mss) && !(wss % 1460)) nat=1;
      } else if (p->wsize_mod == MOD_MTU) {
        if ((wss % (mss+40)) && !(wss % 1500)) nat=2;
      }
    }

    if (!no_known) {

      a=(uint8_t*)&src;

      printf("\n"); //edward
      printf("%d.%d.%d.%d%s:%d - %s ",a[0],a[1],a[2],a[3],grab_name(a),
             sp,p->os);

      if (!no_osdesc) printf("%s ",p->desc);

      if (nat == 1) printf("(NAT!) "); else
        if (nat == 2) printf("(NAT2!) ");

      if (ecn) printf("(ECN) ");
      if (orig_df ^ df) printf("(firewall!) ");

      if (tos) {
        if (tos_desc) printf("[%s] ",tos_desc); else printf("[tos %d] ",tos);
      }

      if (p->generic) printf("[GENERIC] ");
      if (fuzzy_now) printf("[FUZZY] ");

      if (p->no_detail) printf("* "); else
        if (tstamp) printf("(up: %d hrs) ",tstamp/360000);

      if (always_sig || (p->generic && !no_unknown)) {

        if (!mode_oneline) printf("\n  ");
        printf("Signature: [");

        display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

        if (p->generic)
          printf(":%s:?] ",p->os);
        else
          printf("] ");

      }

      if (!no_extra && !p->no_detail) {
	a=(uint8_t*)&dst;
        if (!mode_oneline) printf("\n  ");

        if (fuzzy_now) 
          printf("-> %d.%d.%d.%d%s:%d (link: %s)",
               a[0],a[1],a[2],a[3],grab_name(a),dp,
               lookup_link(mss,1));
        else
          printf("-> %d.%d.%d.%d%s:%d (distance %d, link: %s)",
                 a[0],a[1],a[2],a[3],grab_name(a),dp,p->ttl - ttl,
                 lookup_link(mss,1));
      }

      if (pay && payload_dump) dump_payload(pay,plen - (pay - pkt));

      //putchar('\n'); //edward
      if (full_dump) dump_packet(pkt,plen);

    }

/*
   if (find_masq && !p->userland) {
     int16_t sc = p0f_findmasq(src,p->os,(p->no_detail || fuzzy_now) ? -1 : 
                            (p->ttl - ttl), mss, nat, orig_df ^ df,p-sig,
                            tstamp ? tstamp / 360000 : -1);
     a=(uint8_t*)&src;
     if (sc > masq_thres) {
       printf(">> Masquerade at %u.%u.%u.%u%s: indicators at %d%%.",
              a[0],a[1],a[2],a[3],grab_name(a),sc);
       if (!mode_oneline) putchar('\n'); else printf(" -- ");
       if (masq_flags) {
         printf("   Flags: ");
         p0f_descmasq();
         putchar('\n');
       }
     }
   }

   if (use_cache || find_masq)
     p0f_addcache(src,dst,sp,dp,p->os,p->desc,(p->no_detail || fuzzy_now) ? 
                  -1 : (p->ttl - ttl),p->no_detail ? 0 : lookup_link(mss,0),
                  tos_desc, orig_df ^ df, nat, !p->userland, mss, p-sig,
                  tstamp ? tstamp / 360000 : -1);
   */

    fflush(0);

    return p; // XXX: nothing useful yet!

continue_search:

    p = p->next;

  }

  if (!df) { df = 1; goto re_lookup; }

  if (use_fuzzy && fuzzy) {
    df = orig_df;
    fuzzy_now = 1;
    p = fuzzy;
    fuzzy = 0;
    goto continue_fuzzy;
  }

  if (mss & wss) {
    if ((wss % mss) && !(wss % 1460)) nat=1;
    else if ((wss % (mss+40)) && !(wss % 1500)) nat=2;
  }

  if (!no_unknown) { 
    a=(uint8_t*)&src;
    printf("\n%d.%d.%d.%d%s:%d - UNKNOWN [",a[0],a[1],a[2],a[3],grab_name(a),sp);

    display_signature(ttl,tot,orig_df,op,ocnt,mss,wss,wsc,tstamp,quirks);

    printf(":?:?] ");

    if (rst_mode) {

      /* Display a reasonable diagnosis of the RST+ACK madness! */
 
      switch (quirks & (QUIRK_RSTACK | QUIRK_SEQ0 | QUIRK_ACK)) {

        /* RST+ACK, SEQ=0, ACK=0 */
        case QUIRK_RSTACK | QUIRK_SEQ0:
          printf("(invalid-K0) "); break;

        /* RST+ACK, SEQ=0, ACK=n */
        case QUIRK_RSTACK | QUIRK_ACK | QUIRK_SEQ0: 
          printf("(refused) "); break;
 
        /* RST+ACK, SEQ=n, ACK=0 */
        case QUIRK_RSTACK: 
          printf("(invalid-K) "); break;

        /* RST+ACK, SEQ=n, ACK=n */
        case QUIRK_RSTACK | QUIRK_ACK: 
          printf("(invalid-KA) "); break; 

        /* RST, SEQ=n, ACK=0 */
        case 0:
          printf("(dropped) "); break;

        /* RST, SEQ=m, ACK=n */
        case QUIRK_ACK: 
          printf("(dropped 2) "); break;
 
        /* RST, SEQ=0, ACK=0 */
        case QUIRK_SEQ0: 
          printf("(invalid-0) "); break;

        /* RST, SEQ=0, ACK=n */
        case QUIRK_ACK | QUIRK_SEQ0: 
          printf("(invalid-0A) "); break; 

      }

    }

    if (nat == 1) printf("(NAT!) ");
      else if (nat == 2) printf("(NAT2!) ");

    if (ecn) printf("(ECN) ");

    if (tos) {
      if (tos_desc) printf("[%s] ",tos_desc); else printf("[tos %d] ",tos);
    }

    if (tstamp) printf("(up: %d hrs) ",tstamp/360000);

    if (!no_extra) {
      a=(uint8_t*)&dst;
      if (!mode_oneline) printf("\n  ");
      printf("-> %d.%d.%d.%d%s:%d (link: %s)",a[0],a[1],a[2],a[3],
	       grab_name(a),dp,lookup_link(mss,1));
    }

    /*
    if (use_cache)
      p0f_addcache(src,dst,sp,dp,0,0,-1,lookup_link(mss,0),tos_desc,
                   0,nat,0 // not real, we're not sure
                   ,mss,(uint32_t)-1,
                   tstamp ? tstamp / 360000 : -1);
      */

    if (pay && payload_dump) dump_payload(pay,plen - (pay - pkt));
    //putchar('\n'); //edward
    if (full_dump) dump_packet(pkt,plen);
    fflush(0);

  }
  return p; // XXX does not return anything useful yet

}

// pass the pointers
// unresolved: pass the packet?
/*
static inline void find_match_e(fp_entry *e, uint32_t tstamp, void *packet)
{
    return find_match(e->size, e->df, e->ttl, e->wsize, e->optcnt, e->opt, e->mss, e->wsc, tstamp, e->tos, e->quirks, e->ecn, packet, 0, 0, 0);
}
*/


/* my ideal interface
fp_entry *lookup_sig(fp_entry sig[], packetinfo *pi)
{
    fp_entry *e = bh[SIGHASH(s, sig[sigcnt].optcnt, sig[sigcnt].quirks, d)];

        if (!e) {
            bh[SIGHASH(s, sig[sigcnt].optcnt, sig[sigcnt].quirks, d)] =
                sig + sigcnt;
        } else {
            while (e->next)
                e = e->next;
            e->next = sig + sigcnt;
        }
}
*/

void dump_sigs(fp_entry *mysig[], int max)
{
    int i;
    for (i = 0; i < max; i++){
        if (!mysig[i] || !mysig[i]->os)
            continue;
        print_sig(mysig[i]);
    }
}


#ifdef SIG_STANDALONE
#define HSIZE 241
int main(int argc, char **argv)
{

    fp_entry **siga[16] = {0};
    int i = 0;
    if (argc < 2) {
        fprintf(stderr, "Where are my sigs?\n");
        exit(1);
    }
    while (--argc) {
        argv++;
        load_sigs(*argv, &siga[i], HSIZE);
        dump_sigs(siga[i], HSIZE);
        unload_sigs(siga[i], HSIZE);
    }

}

#endif
