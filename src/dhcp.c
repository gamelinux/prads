#include "prads.h"
#include "config.h"
#include "sys_func.h"
#include "dhcp.h"

extern globalconfig config;

static int parse_dhcp_sig_opts(dhcp_fp_entry *sig, char* p);
static int parse_dhcp_sig_optreq(dhcp_fp_entry *sig, char* p);
static dhcp_fp_entry *alloc_dhcp_sig(dhcp_fp_entry *e);
static void free_dhcp_sigs(dhcp_fp_entry *e);

static const unsigned char vendcookie[] = { 99, 130, 83, 99 };
#define BOOTP_COOKIE_SIZE 4
#define PKT_MAXPAY 16

void print_dhcp_header(dhcp_header *dhcph)
{
    plog("OP:%d\n",dhcph->op);
    plog("HTYPE:%d\n",dhcph->htype);
    plog("HLEN:%d\n",dhcph->hlen);
    plog("HOPS:%d\n",dhcph->hops);
    plog("XID:%d\n",dhcph->xid);
    plog("SECS:%d\n",dhcph->secs);
    plog("FLAGS:%d\n",dhcph->flags);

    char dest[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(dhcph->ciaddr),dest,INET_ADDRSTRLEN + 1);
    plog("CIP:%s\n",dest);
    inet_ntop(AF_INET,&(dhcph->yiaddr),dest,INET_ADDRSTRLEN + 1);
    plog("YIP:%s\n",dest);
    inet_ntop(AF_INET,&(dhcph->siaddr),dest,INET_ADDRSTRLEN + 1);
    plog("SIP:%s\n",dest);
    inet_ntop(AF_INET,&(dhcph->giaddr),dest,INET_ADDRSTRLEN + 1);
    plog("GIP:%s\n",dest);
    plog("CHADDR:");
    uint8_t i;
    for(i = 0; i < 6; i++){
        printf("%02hhx", dhcph->chaddr[i]);
        if (i != dhcph->hlen-1)
            printf(":");
    }
    plog("\n");
    plog("SNAME:%s\n",dhcph->sname);
    plog("FILE:%s\n",dhcph->file);
}


dhcp_fp_entry *dhcp_fingerprint(packetinfo *pi)
{
    plog("Got DHCP packet:\n");
    config.pr_s.dhcp_os_assets++;

    uint8_t dhcp_header_length;
    uint8_t *dhcp_mc;
    uint8_t *dhcp_options;
    uint8_t optlen = 0;
    uint8_t dhcp_opt_type = 0;
    uint8_t end_opt_parsing = 0;

    /*
    dhcp_header *dhcph;
    dhcph = (dhcp_header *) (pi->payload);
    print_dhcp_header(dhcph);
    */
    dhcp_header_length = sizeof(dhcp_header);
    dhcp_mc = (uint8_t *) (pi->payload + dhcp_header_length);

    /* TODO: check and bail if not there */  
//plog("Magic Cookie: %d%d%d%d\n", *dhcp_mc, *(dhcp_mc+1), *(dhcp_mc+2), *(dhcp_mc+3)); // 99 130 83 99

    dhcp_options = (uint8_t *) dhcp_mc + BOOTP_COOKIE_SIZE;
    uint8_t *optptr = dhcp_options;
    uint8_t max_len = (pi->plen - dhcp_header_length - BOOTP_COOKIE_SIZE);

    dhcp_fp_entry dhcpfp = {0}; //guarantee it's empty this sig
    dhcpfp.ttl = pi->ip4->ip_ttl;


    uint8_t optcnt = 0;
    
    while (optlen < max_len) {
        uint8_t i;

        uint8_t opt      = *(optptr);
        uint8_t optsize  = *(optptr+1);
        uint8_t *optdata =   optptr+2;

        dhcpfp.opt[optcnt] = opt;

        switch(opt) {
            case DHCP_OPTION_TYPE: /* 53 */
                if (optsize == 1) {
                    dhcp_opt_type = *optdata;
                    dhcpfp.type = dhcp_opt_type;
                }
                break;
            case DHCP_OPTION_OPTIONREQ: /* 55 */
                if (optsize > 0) {
                    uint8_t optreqcnt = 0;
                    for (i=2; i < optsize+2; i++) {
                        dhcpfp.optreq[optreqcnt] = *(optptr+i);
                        optreqcnt++;
                    }
                    dhcpfp.optreqcnt = optreqcnt;
                }
                break;
            case DHCP_OPTION_CLASS_IDENTIFIER: /* 60 */
                if (optsize > 0) {
                    dhcpfp.vc = calloc(1, optsize + 1);
                    strncpy(dhcpfp.vc, (char*) optdata, optsize);
                }
                break;
            case DHCP_OPTION_PAD: /* 0 */
                break;
            case DHCP_OPTION_END: /* 255 */
                end_opt_parsing = 1;
                optcnt++;
                break;
            default:
                break;
        }

        optptr = optptr + optsize + 2;        

        optlen = optlen + optsize + 2;

        if (end_opt_parsing == 1) break;

        /* Just to be sure */
        if (*(optptr) != DHCP_OPTION_END) {
            if (optptr + *(optptr+1) + 2 > pi->payload + pi->plen) break;
        }
        optcnt++;
    }
    dhcpfp.optcnt = optcnt;

    print_dhcp_sig(&dhcpfp);
    plog("\n");

    dhcp_fp_entry *match = find_dhcp_match(&dhcpfp, pi);

#define OS_DHCP = 0x01
    //update_asset_os(pi, OS_DHCP, NULL, &dhcpfp, tstamp);
    return match;
}

dhcp_fp_entry *find_dhcp_match(dhcp_fp_entry *dhcpfp, packetinfo *pi)
{
    dhcp_fp_entry* p;
    uint32_t j;
    
    //uint32_t hashsize; // = config.sig_hashsize;

    //if(!hashsize)
    //    hashsize = DHCP_SIG_HASHSIZE;

    uint32_t index;
    
    index = (DHCP_SIGHASH(dhcpfp->type, dhcpfp->optcnt) % 331);

    p = config.sig_dhcp[index];
    while (p) {
        /* Cheap and specific checks first... */
        if (dhcpfp->type ^ p->type) { p = p->next; continue; }
        if (dhcpfp->optcnt ^ p->optcnt) { p = p->next; continue; }
        if (dhcpfp->optreqcnt ^ p->optreqcnt) { p = p->next; continue; }

        /* Numbers agree. Let's check options 53 first */
        if (dhcpfp->optreqcnt != 0) {
            for (j=0;j<dhcpfp->optreqcnt;j++){
                if (p->optreq[j] ^ dhcpfp->optreq[j]) goto continue_search;
            }
        }

        /* Let's check options */
        if (dhcpfp->optcnt != 0) {
            for (j=0;j<dhcpfp->optcnt;j++){
                if (p->opt[j] ^ dhcpfp->opt[j]) goto continue_search;
            }
        }

        /* Numbers agree. Lets match Vendor Code */
        if (p->vc != NULL && dhcpfp->vc != NULL) {
            if (strcmp(p->vc, dhcpfp->vc) == 0) {
                /* Huston - we have a match */
                plog("[*] We have a match (");
                print_dhcp_sig(p);
                plog(")\n");
                //plog("OS: %s\n",p->os);
                //plog("DESC: %s\n",p->desc);
                break;
            }
        } else {
            /* Huston - we have a match */
            plog("[*] We have a match (");
            print_dhcp_sig(p);
            plog(")\n");
            //plog("OS: %s, ",p->os);
            //plog("DESC: %s)\n",p->desc);
            break;
        }

continue_search:
        p = p->next;
    }
    return dhcpfp;
}

void print_data(const uint8_t* data, uint16_t dlen) {
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

  plog("%s",tbuf);
}

int load_dhcp_sigs(const char *file, dhcp_fp_entry **dhcpsp[], int hashsize)
{
    // sigp == dhcpsp
    dhcp_fp_entry **sig; // output
    uint32_t ln = 0;
    FILE *f = fopen(file, "r");
    char buf[MAXLINE];
    char *p;
    if (!f) {
        perror("failed to open file");
        return errno;
    }
    if(!dhcpsp){
        perror("need a pointer to fill");
        return -1;
    }
    if(!hashsize)
        hashsize = DHCP_SIG_HASHSIZE;
    if(*dhcpsp == NULL){
        *dhcpsp = calloc(hashsize, sizeof(dhcp_fp_entry*));
        sig = *dhcpsp;
    }

    while ((p = fgets(buf, sizeof(buf), f))) {
        uint32_t l;

        char opts[MAXLINE], optreq[MAXLINE], genre[MAXLINE], desc[MAXLINE];
        char vc[MAXLINE];
        char *gptr = genre;
        uint32_t t, type;
        dhcp_fp_entry asig = {0}; //guarantee it's empty this sig
        dhcp_fp_entry *e;

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

        /* T4:64:1:60:M*,S,T,N,W7:.:Linux:2.6 (newer, 7) */
        /* 53-OPTION:TTL:ALL-OPTIONS:55-OPTIONS:60-OPTIONS:OS:OS Details */
        /* 1:128:53,116,61,12,60,55,43:1,15,3,6,44,46,47,31,33,121,249,43:MSFT 5.0:Windows:Windows XP SP3 */
        if (sscanf
            (p, "%d:%d:%[^:]:%[^:]:%[^:]:%[^:]:%[^:]",
            &type, &t, opts, optreq, vc, genre, desc) != 7)
            fatal("Syntax error in config line %d.\n", ln);

        gptr = genre;

        asig.type = type;
        asig.ttl = t;
        asig.os = strdup(gptr);
        asig.desc = strdup(desc);
        asig.vc = strdup(vc);
        asig.line = ln;

        parse_dhcp_sig_opts(&asig, opts);
        parse_dhcp_sig_optreq(&asig, optreq);

        uint32_t index = (DHCP_SIGHASH(asig.type, asig.optcnt) % 331);
        e = sig[index];
 
        if (!e) {
            sig[index] = alloc_dhcp_sig(&asig);
        } else {
            int cc = 0;
            // collision!
            while (e->next){
                e = e->next;
                cc++;
            }
            /*
            fprintf(stderr, "hash collision: %s\n", p);
            */
            e->next = alloc_dhcp_sig(&asig);
        }
    }

    fclose(f);
#ifdef DUMP_SIG_HASH
    {
        int i;
        for (i = 0; i < sigcnt; i++) {
            print_dhcp_sig(&sig[i]);
        }
    }
#endif
#ifdef DEBUG_HASH
    {
        int i;
        dhcp_fp_entry *p;
        printf("DHCP hash table layout: ");
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

//    if (check_collide)
//        debug("[+] DHCP signature collision check successful.\n");

    return 0;
}

/* run through the hash, free entries, then free hash */
void unload_dhcp_sigs(dhcp_fp_entry **sigp, int size)
{
    int i = size;
    dhcp_fp_entry *e;
    while(i--){
        e = sigp[i];
        if (e)
            free_dhcp_sigs(e);
        sigp[i] = NULL; // clear
    }
    free(*sigp);
    *sigp = NULL;
}

/* alloc_sig return a newly allocated copy of *e */
static dhcp_fp_entry *alloc_dhcp_sig(dhcp_fp_entry *e)
{
    dhcp_fp_entry *n = calloc(1, sizeof(dhcp_fp_entry));
    *n = *e; // copy
    return n;
}

/* recursively free signatures */
static void free_dhcp_sigs(dhcp_fp_entry *e){
    if(e->next)
        free_dhcp_sigs(e->next);
    free(e);
}

void dump_dhcp_sigs(dhcp_fp_entry *mysig[], int max)
{
    int i;
    for (i = 0; i < max; i++){
        if (!mysig[i] || !mysig[i]->os)
            continue;
        print_dhcp_sig(mysig[i]);
    }
}

void print_dhcp_sig(dhcp_fp_entry * e)
{
    int32_t j;

    plog("[%d:%d:",e->type,e->ttl);
    for (j=0;j<e->optcnt;j++){
        plog("%d",e->opt[j]);
        if ((j+1) < (e->optcnt)) plog(",");
    }
    plog(":");
    for (j=0;j<e->optreqcnt;j++){
        plog("%d",e->optreq[j]);
        if ((j+1) < (e->optreqcnt)) plog(",");
    }
    if (e->optreqcnt==0) plog(".");
    plog(":");
    if (e->vc == NULL) {
        plog(".");
    } else {
        plog("%s",e->vc);
    }
    plog(":");
    if (e->os == NULL) {
        plog("unknown");
    } else {
       plog("%s",e->os);
    }
    plog(":");
    if (e->desc == NULL) {
        plog("unknown");
    } else {
       plog("%s",e->desc);
    }
    plog("]");
}
void print_dhcp_sigs(dhcp_fp_entry * e)
{
    print_dhcp_sig(e);
    if (e->next)
        print_dhcp_sigs(e->next);
}


/* parse the option field of the signature line */
static int parse_dhcp_sig_opts(dhcp_fp_entry *sig, char* p)
{
   uint8_t optcnt = 0;
   if (*p == '.')
        p++;

    while (*p) {

        if (!isdigit(*(p))) {
            fatal("Bogus DHCP value in line %d.\n", sig->line);
        } else {
            if (!isdigit(*(p+1))) {
               sig->opt[optcnt] = atoi(p);
            } else if (!isdigit(*(p+2))) {
               sig->opt[optcnt] = atoi(p);
               p++;
            } else if (!isdigit(*(p+3))) {
               sig->opt[optcnt] = atoi(p);
               p++;
               p++;
            }
        }

        if (++optcnt >= MAXDHCPOPTS)
            fatal
                ("Too many DHCP options specified in config line %d.\n",
                 sig->line);
        /*
         * Skip separators 
         */
        do {
            p++;
        } while (*p && !isdigit(*p));
    }
    sig->optcnt = optcnt;
    return 0;
}

/* parse the option field of the signature line */
static int parse_dhcp_sig_optreq(dhcp_fp_entry *sig, char* p)
{
   uint8_t optreqcnt = 0;

   if (*p == '.')
        p++;

    while (*p) {
        if (!isdigit(*(p))) {
            fatal("Bogus DHCP value in line %d.\n", sig->line);
        } else {
            if (!isdigit(*(p + 1))) {
               sig->optreq[optreqcnt] = atoi(p);
            } else if (!isdigit(*(p + 2))) {
               sig->optreq[optreqcnt] = atoi(p);
               p++;
            } else if (!isdigit(*(p + 3))) {
               sig->optreq[optreqcnt] = atoi(p);
               p++;
               p++;
            }
        }

        if (++optreqcnt >= MAXDHCPOPTS)
            fatal
                ("Too many DHCP request options specified in config line %d.\n",
                 sig->line);
        /*
         * Skip separators 
         */
        do {
            p++;
        } while (*p && !isdigit(*p));
    }
    sig->optreqcnt = optreqcnt;
    return 0;
}

