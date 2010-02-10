#include "../common.h"
#include "../prads.h"
#include "../sig.h"
#include "ipfp.h"

inline void parse_quirks_flag(uint8_t ftype, tcp_header *tcph, uint32_t *quirks, uint8_t open_mode)
{
    if (ftype == TF_RST && (tcph->t_flags & TF_ACK))
        *quirks |= QUIRK_RSTACK;
    if (ftype == TF_FIN && (tcph->t_flags & TF_ACK))
        *quirks |= QUIRK_FINACK;

    if (tcph->t_seq == tcph->t_ack)
        *quirks |= QUIRK_SEQEQ;
    if (!tcph->t_seq)
        *quirks |= QUIRK_SEQ0;
    if (tcph->t_flags & ~(TF_SYN | TF_ACK | TF_RST | TF_ECE | TF_CWR
                          | (open_mode ? TF_PUSH : 0)))
        *quirks |= QUIRK_FLAGS;
    if (tcph->t_ack)
        *quirks |= QUIRK_ACK;
    if (tcph->t_urgp)
        *quirks |= QUIRK_URG;
    if (TCP_X2(tcph))
        *quirks |= QUIRK_X2;
}


/* parse TCP option header field
 * yes, this function returns the timestamp for now */ 
inline uint32_t parse_tcpopt(const uint8_t *opt_ptr, int32_t ilen, const uint8_t *end_ptr, fp_entry *e)
{
    uint8_t ocnt = 0, olen;
    // mnemonics
    uint32_t *quirks = &e->quirks;
    uint8_t *op = e->opt;
    // timestamp is 64bit, but see if I care
    uint32_t tstamp = 0;

    while (ilen > 0) {
        ilen--;

        // * let the phun begin... 
        switch (*(opt_ptr++)) {
        case TCPOPT_EOL:
            // * EOL 
            op[ocnt] = TCPOPT_EOL;

            if (ilen) {
                *quirks |= QUIRK_PAST;
            }
            break;

        case TCPOPT_NOP:
            // * NOP 
            op[ocnt] = TCPOPT_NOP;
            break;

        case TCPOPT_SACKOK:
            // * SACKOK LEN 
            op[ocnt] = TCPOPT_SACKOK;
            ilen--;
            opt_ptr++;
            break;

        case TCPOPT_MAXSEG:
            // * MSS LEN D0 D1 
            if (opt_ptr + 3 > end_ptr) {
borken:
                *quirks |= QUIRK_BROKEN;
                goto end_parsing;
            }
            op[ocnt] = TCPOPT_MAXSEG;
            e->mss = GET16(opt_ptr + 1);
            ilen -= 3;
            opt_ptr += 3;
            break;

        case TCPOPT_WSCALE:
            // * WSCALE LEN D0 
            if (opt_ptr + 2 > end_ptr)
                goto borken;
            op[ocnt] = TCPOPT_WSCALE;
            e->wsc = *(uint8_t *) (opt_ptr + 1);
            ilen -= 2;
            opt_ptr += 2;
            break;

        case TCPOPT_TIMESTAMP:
            // * TSTAMP LEN T0 T1 T2 T3 A0 A1 A2 A3 
            // ugly handling of a beautiful 64bit field
            if (opt_ptr + 9 > end_ptr)
                goto borken;
            op[ocnt] = TCPOPT_TIMESTAMP;

            memcpy(&tstamp, opt_ptr + 5, 4);
            if (tstamp)
                *quirks |= QUIRK_T2;

            memcpy(&tstamp, opt_ptr + 1, 4);
            tstamp = ntohl(tstamp);

            ilen -= 9;
            opt_ptr += 9;
            break;

        default:
            // * Hrmpf... 
            if (opt_ptr + 1 > end_ptr)
                goto borken;

            op[ocnt] = *(opt_ptr - 1);
            olen = *(uint8_t *) (opt_ptr) - 1;
            if (olen > 32 || (olen < 0))
                goto borken;

            ilen -= olen;
            opt_ptr += olen;
            break;

        }
        ocnt++;
        if (ocnt >= MAXOPT - 1)
            goto borken;

        // * Whoops, we're past end_ptr 
        if (ilen > 0)
            if (opt_ptr >= end_ptr)
                goto borken;
    }

end_parsing:
    e->optcnt = ocnt;
    return tstamp;
}

void fp_tcp(packetinfo *pi, uint8_t ftype)
{

    uint8_t *opt_ptr;
    const uint8_t * end_ptr;
    uint8_t *payload = 0;
    uint8_t op[MAXOPT];
    fp_entry e = { 0 };
    uint8_t open_mode = 0;    /* open_mode=stray ack */
    int32_t ilen;
    uint32_t tstamp = 0;

    // convenience
    //ip4_header *ip4 = (ip4_header *)ip46;
    //ip6_header *ip6 = (ip6_header *)ip46;
    
    if (ftype == TF_ACK)
        open_mode = 1;

    /*
     * If the declared length is shorter than the snapshot (etherleak
     * or such), truncate the package. 
     */
    switch(pi->af){
        case AF_INET6:
            opt_ptr = (uint8_t *) pi->ip6 + IP6_HEADER_LEN + ntohs(pi->ip6->len); //*
            break;
        case AF_INET:
            opt_ptr = (uint8_t *) pi->ip4 + ntohs(pi->ip4->ip_len); // fixed from htons
            break;
        default:
            fprintf(stderr, "tcp_fp: something very unsafe happened!\n");
            return;
    }
    end_ptr = pi->end_ptr;
    if (end_ptr > opt_ptr)
        end_ptr = opt_ptr;

    switch(pi->af){
        case AF_INET6:
            // If IP header ends past end_ptr
            if ((uint8_t *) (pi->ip6 + 1) > end_ptr)
                return;
            if (IP6_FL(pi->ip6) > 0) { //*
                e.quirks |= QUIRK_FLOWL;
            }
            e.ttl = pi->ip6->hop_lmt;
            e.size = open_mode ? 0 : ntohs(pi->ip6->len);
            e.df = 1; // for now
            if (!IP6_FL(pi->ip6)) //*
                e.quirks |= QUIRK_ZEROID;
            break;
        case AF_INET:
            if ((uint8_t *) (pi->ip4 + 1) > end_ptr)
                return;
            ilen = pi->ip4->ip_vhl & 15;

            /* * B0rked packet */
            if (ilen < 5)
                return;

            if (ilen > 5) {
                e.quirks |= QUIRK_IPOPT;
            }
            e.ttl = pi->ip4->ip_ttl;
            e.size = open_mode ? 0 : ntohs(pi->ip4->ip_len);
            e.df = (ntohs(pi->ip4->ip_off) & IP_DF) != 0;
            if (!pi->ip4->ip_id)
                e.quirks |= QUIRK_ZEROID;
            break;
            // default: there is no default
    }
    //printf("\nend_ptr:%u  opt_ptr:%u",end_ptr,opt_ptr);

    parse_quirks_flag(ftype,pi->tcph,&e.quirks, open_mode);
    ilen = (TCP_OFFSET(pi->tcph) << 2) - TCP_HEADER_LEN;

    opt_ptr = (uint8_t *) (pi->tcph + 1);
    if ((uint8_t *) opt_ptr + ilen < end_ptr) {
        if (!open_mode)
            e.quirks |= QUIRK_DATA;
        payload = opt_ptr + ilen;
    }
    tstamp = parse_tcpopt(opt_ptr, ilen, pi->end_ptr, &e);

    e.wsize = ntohs(pi->tcph->t_win);

    gen_fp_tcp(e.ttl, 
               e.size,
               e.df,
               e.opt,
               e.optcnt,
               e.mss,
               e.wsize,
               e.wsc,
               tstamp, e.quirks, ftype, pi);
    // find_match(pi, e);
    // return this into asset engine
    if (pi->ip6 != NULL) return; // Fix this when find_match() is IPv6 aware
return;
    find_match(e.size,
               e.df,
               e.ttl,
               e.wsize,
               pi->ip_src.s6_addr32[0],
               0, //ip_dst,
               ntohs(pi->tcph->src_port),
               ntohs(pi->tcph->dst_port),
               e.optcnt,
               e.opt,
               e.mss,
               e.wsc,
               tstamp,
               pi->ip4->ip_tos,
               e.quirks,
               pi->tcph->t_flags & (TF_ECE|TF_CWR), //ECN
               (uint8_t*) pi->ip4,
               end_ptr - (uint8_t *) pi->ip4,
               payload
               // pts, // *not used
               );
/*
printf("hop:%u, len:%u, ver:%u, class:%u, label:%u|mss:%u, win:%u\n",ip6->hop_lmt,open_mode ? 0 : ntohs(ip6->len),
                                                     IP6_V(ip6),ntohs(IP6_TC(ip6)),
                                                     ntohs(IP6_FL(ip6)),
                                                     mss_val, ntohs(tcph->t_win));
*/


//     /* sp */    ntohs(tcph->sport),
//     /* dp */    ntohs(tcph->dport),
//     /* ocnt */  ocnt,
//     /* op */    op,
//     /* mss */   mss_val,
//     /* wsc */   wsc_val,
//     /* tst */   tstamp,
//     /* TOS */   iph->tos,
//     /* Q? */    quirks,
//     /* ECN */   tcph->flags & (TH_ECE|TH_CWR),
//     /* pkt */   (_u8*)iph,
//     /* len */   end_ptr - (_u8*)iph,
//     /* pay */   pay,
//     /* ts */    pts
//  );

}


// deprecate these guys soon
/*
void fp_tcp4(ip4_header * ip4, tcp_header * tcph, const uint8_t * end_ptr,
             uint8_t ftype, struct in6_addr ip_src)
{
    fp_tcp(AF_INET, ip4, tcph, end_ptr, ftype, ip_src);
}

void fp_tcp6(ip6_header * ip6, tcp_header * tcph, const uint8_t * end_ptr,
             uint8_t ftype, struct in6_addr ip_src)
{
    fp_tcp(AF_INET6, ip6, tcph, end_ptr, ftype, ip_src);
}
*/
