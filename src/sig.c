/* Load and match signatures
 *
 * (c) Kacper Wysocki <kacperw@gmail.com> for PRADS, 2009
 *
 * straight port of p0f load_config and support functions
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
    load_sigs_{syn,ack,synack,..}()

    match_fp(char *fp, struct *fp) <- take a fingerprint string/struct
      and lookup into hash. return unique, fuzzy, best match.

    match_fp(packetinfo) - guess OS based on packet info

    matcher - might have to import find_match from p0f too

 */

#include "common.h"
#include "prads.h"

#define MAXLINE 1024
#define MAXSIGS 1024

// what the dillio? bh is 16 pointers?
#define SIGHASH(tsize,optcnt,q,df) \
	(( (uint8_t) (((tsize) << 1) ^ ((optcnt) << 1) ^ (df) ^ (q) )) & 0x0f)
#define debug(x...)	fprintf(stderr,x)
#define fatal(x...)	do { debug("[-] ERROR: " x); exit(1); } while (0)

static fp_entry sig[MAXSIGS];
static uint32_t sigcnt, gencnt;
static fp_entry *bh[1024];

uint32_t packet_count;
uint8_t operating_mode;
uint32_t st_time;
static uint8_t no_extra,
    find_masq,
    masq_flags,
    no_osdesc,
    no_known,
    no_unknown,
    no_banner,
    use_promisc,
    add_timestamp,
    header_len,
    ack_mode,
    rst_mode,
    go_daemon,
    use_logfile,
    mode_oneline,
    always_sig,
    do_resolve,
    check_collide,
    full_dump, use_fuzzy, use_vlan, payload_dump, port0_wild;

static uint8_t problems;

static inline void display_signature(uint8_t ttl, uint16_t tot, uint8_t df,
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

static void print_sig(fp_entry * e)
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

        /*
         * If TTLs are sufficiently away from each other, the risk of
         * a collision is lower. 
         */
        if (abs((int32_t) sig[id].ttl - (int32_t) sig[i].ttl) > 25)
            continue;

        if (sig[id].df ^ sig[i].df)
            continue;
        if (sig[id].zero_stamp ^ sig[i].zero_stamp)
            continue;

        /*
         * Zero means >= PACKET_BIG 
         */
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

        case 0:                /* Current: const */

            cur = sig[id].wsize;

          do_const:

            switch (sig[i].wsize_mod) {

            case 0:            /* Previous is also const */

                /*
                 * A problem if values match 
                 */
                if (cur ^ sig[i].wsize)
                    continue;
                break;

            case MOD_CONST:    /* Current: const, prev: modulo (or *) */

                /*
                 * A problem if current value is a multiple of that modulo 
                 */
                if (cur % sig[i].wsize)
                    continue;
                break;

            case MOD_MSS:      /* Current: const, prev: mod MSS */

                if (sig[i].mss_mod || sig[i].wsize *
                    (sig[i].mss ? sig[i].mss : 1460) != cur)
                    continue;

                break;

            case MOD_MTU:      /* Current: const, prev: mod MTU */

                if (sig[i].mss_mod
                    || sig[i].wsize * ((sig[i].mss ? sig[i].mss : 1460) +
                                       40) != cur)
                    continue;

                break;

            }

            break;

        case 1:                /* Current signature is modulo something */

            /*
             * A problem only if this modulo is a multiple of the 
             * previous modulo 
             */

            if (sig[i].wsize_mod != MOD_CONST)
                continue;
            if (sig[id].wsize % sig[i].wsize)
                continue;

            break;

        case MOD_MSS:          /* Current is modulo MSS */

            /*
             * There's likely a problem only if the previous one is close
             * to '*'; we do not check known MTUs, because this particular
             * signature can be made with some uncommon MTUs in mind. The
             * problem would also appear if current signature has a fixed
             * MSS. 
             */

            if (sig[i].wsize_mod != MOD_CONST || sig[i].wsize >= 8) {
                if (!sig[id].mss_mod) {
                    cur =
                        (sig[id].mss ? sig[id].mss : 1460) * sig[id].wsize;
                    goto do_const;
                }
                continue;
            }

            break;

        case MOD_MTU:          /* Current is modulo MTU */

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

        /*
         * Same for wsc 
         */
        switch (sig[id].wsc_mod) {

        case 0:                /* Current: const */

            cur = sig[id].wsc;

            switch (sig[i].wsc_mod) {

            case 0:            /* Previous is also const */

                /*
                 * A problem if values match 
                 */
                if (cur ^ sig[i].wsc)
                    continue;
                break;

            case 1:            /* Current: const, prev: modulo (or *) */

                /*
                 * A problem if current value is a multiple of that modulo 
                 */
                if (cur % sig[i].wsc)
                    continue;
                break;

            }

            break;

        case MOD_CONST:        /* Current signature is modulo something */

            /*
             * A problem only if this modulo is a multiple of the 
             * previous modulo 
             */

            if (!sig[i].wsc_mod)
                continue;
            if (sig[id].wsc % sig[i].wsc)
                continue;

            break;

        }

        /*
         * Same for mss 
         */
        switch (sig[id].mss_mod) {

        case 0:                /* Current: const */

            cur = sig[id].mss;

            switch (sig[i].mss_mod) {

            case 0:            /* Previous is also const */

                /*
                 * A problem if values match 
                 */
                if (cur ^ sig[i].mss)
                    continue;
                break;

            case 1:            /* Current: const, prev: modulo (or *) */

                /*
                 * A problem if current value is a multiple of that modulo 
                 */
                if (cur % sig[i].mss)
                    continue;
                break;

            }

            break;

        case MOD_CONST:        /* Current signature is modulo something */

            /*
             * A problem only if this modulo is a multiple of the 
             * previous modulo 
             */

            if (!sig[i].mss_mod)
                continue;
            if ((sig[id].mss ? sig[id].mss : 1460) %
                (sig[i].mss ? sig[i].mss : 1460))
                continue;

            break;

        }

        /*
         * Now check option sequence 
         */

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

/* load_sigs: fill **sig with fp_entry signatures from *file
 * returns errno
 */
int load_sigs(const char *file, fp_entry sig[], int max)
{
    uint32_t ln = 0;
    debug("opening %s\n", file);
    FILE *f = fopen(file, "r");
    unsigned char buf[MAXLINE];
    unsigned char *p;
    if (!f) {
        perror("failed to open file");
        return errno;
    }
    while ((p = fgets(buf, sizeof(buf), f))) {
        uint32_t l;

        uint8_t obuf[MAXLINE], genre[MAXLINE], desc[MAXLINE],
            quirks[MAXLINE];
        uint8_t w[MAXLINE], sb[MAXLINE];
        uint8_t *gptr = genre;
        uint32_t t, d, s;
        fp_entry *e;

        ln++;

        /*
         * Remove leading and trailing blanks 
         */
        while (isspace(*p))
            p++;
        l = strlen(p);
        while (l && isspace(*(p + l - 1)))
            *(p + (l--) - 1) = 0;

        /*
         * Skip empty lines and comments 
         */
        if (!l)
            continue;
        if (*p == '#')
            continue;

        if (sscanf
            (p, "%[0-9%*()ST]:%d:%d:%[0-9()*]:%[^:]:%[^ :]:%[^:]:%[^:]", w,
             &t, &d, sb, obuf, quirks, genre, desc) != 8)
            fatal("Syntax error in config line %d.\n", ln);

        gptr = genre;

        if (*sb != '*') {
            s = atoi(sb);
        } else
            s = 0;

      reparse_ptr:

        switch (*gptr) {
        case '-':
            sig[sigcnt].userland = 1;
            gptr++;
            goto reparse_ptr;
        case '*':
            sig[sigcnt].no_detail = 1;
            gptr++;
            goto reparse_ptr;
        case '@':
            sig[sigcnt].generic = 1;
            gptr++;
            gencnt++;
            goto reparse_ptr;
        case 0:
            fatal("Empty OS genre in line %d.\n", ln);
        }

        sig[sigcnt].os = strdup(gptr);
        sig[sigcnt].desc = strdup(desc);
        sig[sigcnt].ttl = t;
        sig[sigcnt].size = s;
        sig[sigcnt].df = d;

        if (w[0] == '*') {
            sig[sigcnt].wsize = 1;
            sig[sigcnt].wsize_mod = MOD_CONST;
        } else if (tolower(w[0]) == 's') {
            sig[sigcnt].wsize_mod = MOD_MSS;
            if (!isdigit(*(w + 1)))
                fatal("Bad Snn value in WSS in line %d.\n", ln);
            sig[sigcnt].wsize = atoi(w + 1);
        } else if (tolower(w[0]) == 't') {
            sig[sigcnt].wsize_mod = MOD_MTU;
            if (!isdigit(*(w + 1)))
                fatal("Bad Tnn value in WSS in line %d.\n", ln);
            sig[sigcnt].wsize = atoi(w + 1);
        } else if (w[0] == '%') {
            if (!(sig[sigcnt].wsize = atoi(w + 1)))
                fatal("Null modulo for window size in config line %d.\n",
                      ln);
            sig[sigcnt].wsize_mod = MOD_CONST;
        } else
            sig[sigcnt].wsize = atoi(w);

        /*
         * Now let's parse options 
         */

        p = obuf;

        sig[sigcnt].zero_stamp = 1;

        if (*p == '.')
            p++;

        while (*p) {
            uint8_t optcnt = sig[sigcnt].optcnt;
            switch (tolower(*p)) {

            case 'n':
                sig[sigcnt].opt[optcnt] = TCPOPT_NOP;
                break;

            case 'e':
                sig[sigcnt].opt[optcnt] = TCPOPT_EOL;
                if (*(p + 1))
                    fatal("EOL not the last option (line %d).\n", ln);
                break;

            case 's':
                sig[sigcnt].opt[optcnt] = TCPOPT_SACKOK;
                break;

            case 't':
                sig[sigcnt].opt[optcnt] = TCPOPT_TIMESTAMP;
                if (*(p + 1) != '0') {
                    sig[sigcnt].zero_stamp = 0;
                    if (isdigit(*(p + 1)))
                        fatal("Bogus Tstamp specification in line %d.\n",
                              ln);
                }
                break;

            case 'w':
                sig[sigcnt].opt[optcnt] = TCPOPT_WSCALE;
                if (p[1] == '*') {
                    sig[sigcnt].wsc = 1;
                    sig[sigcnt].wsc_mod = MOD_CONST;
                } else if (p[1] == '%') {
                    if (!(sig[sigcnt].wsc = atoi(p + 2)))
                        fatal
                            ("Null modulo for wscale in config line %d.\n",
                             ln);
                    sig[sigcnt].wsc_mod = MOD_CONST;
                } else if (!isdigit(*(p + 1)))
                    fatal("Incorrect W value in line %d.\n", ln);
                else
                    sig[sigcnt].wsc = atoi(p + 1);
                break;

            case 'm':
                sig[sigcnt].opt[optcnt] = TCPOPT_MAXSEG;
                if (p[1] == '*') {
                    sig[sigcnt].mss = 1;
                    sig[sigcnt].mss_mod = MOD_CONST;
                } else if (p[1] == '%') {
                    if (!(sig[sigcnt].mss = atoi(p + 2)))
                        fatal("Null modulo for MSS in config line %d.\n",
                              ln);
                    sig[sigcnt].mss_mod = MOD_CONST;
                } else if (!isdigit(*(p + 1)))
                    fatal("Incorrect M value in line %d.\n", ln);
                else
                    sig[sigcnt].mss = atoi(p + 1);
                break;

                /*
                 * Yuck! 
                 */
            case '?':
                if (!isdigit(*(p + 1)))
                    fatal("Bogus ?nn value in line %d.\n", ln);
                else
                    sig[sigcnt].opt[optcnt] = atoi(p + 1);
                break;

            default:
                fatal("Unknown TCP option '%c' in config line %d.\n", *p,
                      ln);
            }

            if (++sig[sigcnt].optcnt >= MAXOPT)
                fatal
                    ("Too many TCP options specified in config line %d.\n",
                     ln);

            /*
             * Skip separators 
             */
            do {
                p++;
            } while (*p && !isalpha(*p) && *p != '?');

        }

        sig[sigcnt].line = ln;

        p = quirks;

        while (*p)
            switch (toupper(*(p++))) {
            case 'E':
                fatal
                    ("Quirk 'E' (line %d) is obsolete. Remove it, append E to the "
                     "options.\n", ln);

            case 'K':
                if (!rst_mode)
                    fatal("Quirk 'K' (line %d) is valid only in RST+ (-R)"
                          " mode (wrong config file?).\n", ln);
                sig[sigcnt].quirks |= QUIRK_RSTACK;
                break;

            case 'D':
                sig[sigcnt].quirks |= QUIRK_DATA;
                break;

            case 'Q':
                sig[sigcnt].quirks |= QUIRK_SEQEQ;
                break;
            case '0':
                sig[sigcnt].quirks |= QUIRK_SEQ0;
                break;
            case 'P':
                sig[sigcnt].quirks |= QUIRK_PAST;
                break;
            case 'Z':
                sig[sigcnt].quirks |= QUIRK_ZEROID;
                break;
            case 'I':
                sig[sigcnt].quirks |= QUIRK_IPOPT;
                break;
            case 'U':
                sig[sigcnt].quirks |= QUIRK_URG;
                break;
            case 'X':
                sig[sigcnt].quirks |= QUIRK_X2;
                break;
            case 'A':
                sig[sigcnt].quirks |= QUIRK_ACK;
                break;
            case 'T':
                sig[sigcnt].quirks |= QUIRK_T2;
                break;
            case 'F':
                sig[sigcnt].quirks |= QUIRK_FLAGS;
                break;
            case '!':
                sig[sigcnt].quirks |= QUIRK_BROKEN;
                break;
            case '.':
                break;
            default:
                fatal("Bad quirk '%c' in line %d.\n", *(p - 1), ln);
            }

        e = bh[SIGHASH(s, sig[sigcnt].optcnt, sig[sigcnt].quirks, d)];

        if (!e) {
            bh[SIGHASH(s, sig[sigcnt].optcnt, sig[sigcnt].quirks, d)] =
                sig + sigcnt;
        } else {
            while (e->next)
                e = e->next;
            e->next = sig + sigcnt;
        }

        if (check_collide)
            collide(sigcnt);

        if (++sigcnt >= MAXSIGS)
            fatal("Maximum signature count exceeded.\n");

    }

    fclose(f);
//#ifdef DUMP_HASH
    {
        int i;
        for (i = 0; i < sigcnt; i++) {
            print_sig(&sig[i]);
        }
    }
//#endif
#ifdef DEBUG_HASH
    {
        int i;
        struct fp_entry *p;
        printf("Hash table layout: ");
        for (i = 0; i < 16; i++) {
            int z = 0;
            p = bh[i];
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

    if (!sigcnt)
        debug("[!] WARNING: no signatures loaded from config file.\n");

}

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

void dump_sigs(fp_entry sig[], int sigcnt)
{
    int i;
    for (i = 0; i < sigcnt; i++){
        print_sig(&sig[i]);
    }
}


#ifdef SIG_STANDALONE
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Where are my sigs?\n");
        exit(1);
    }
    while (--argc) {
        argv++;
        load_sigs(*argv, sig, MAXSIGS);
    }

    dump_sigs(sig, sigcnt);
}

#endif
