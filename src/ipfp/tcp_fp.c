#include "../common.h"
#include "../prads.h"
#include "ipfp.h"

void fp_tcp4(ip4_header * ip4, tcp_header * tcph, const uint8_t * end_ptr,
             uint8_t ftype, struct in6_addr ip_src)
{

    uint8_t *opt_ptr;
    uint8_t *payload = 0;
    uint8_t op[MAXOPT];
    uint8_t ocnt = 0, open_mode = 0;    /* open_mode=stray ack */
    uint16_t mss_val = 0, wsc_val = 0;
    int32_t ilen, olen;
    uint32_t quirks = 0, tstamp = 0;

    /*
     * If the declared length is shorter than the snapshot (etherleak
     * or such), truncate the package. 
     */
    opt_ptr = (uint8_t *) ip4 + htons(ip4->ip_len);
    if (end_ptr > opt_ptr)
        end_ptr = opt_ptr;

    opt_ptr = (uint8_t *) (tcph + 1);
    ilen = ip4->ip_vhl & 15;
    /*
     * B0rked packet 
     */
    if (ilen < 5)
        return;

    if (ilen > 5) {
        quirks |= QUIRK_IPOPT;
    }

    /*
     * If IP header ends past end_ptr 
     */
    if ((uint8_t *) (ip4 + 1) > end_ptr)
        return;

    if (ftype == TF_ACK)
        open_mode = 1;
    if (ftype == TF_RST && (tcph->t_flags & TF_ACK))
        quirks |= QUIRK_RSTACK;
    if (ftype == TF_FIN && (tcph->t_flags & TF_ACK))
        quirks |= QUIRK_FINACK;

    if (tcph->t_seq == tcph->t_ack)
        quirks |= QUIRK_SEQEQ;
    if (!tcph->t_seq)
        quirks |= QUIRK_SEQ0;
    if (tcph->t_flags & ~(TF_SYN | TF_ACK | TF_RST | TF_ECE | TF_CWR
                          | (open_mode ? TF_PUSH : 0)))
        quirks |= QUIRK_FLAGS;

    ilen = ((tcph->t_offx2) << 2) - TCP_HEADER_LEN;

    if ((uint8_t *) opt_ptr + ilen < end_ptr) {
        if (!open_mode)
            quirks |= QUIRK_DATA;
        payload = opt_ptr + ilen;
    }
    while (ilen > 0) {

        ilen--;

        /*
         * let the phun begin... 
         */
        switch (*(opt_ptr++)) {
        case TCPOPT_EOL:
            /*
             * EOL 
             */
            op[ocnt] = TCPOPT_EOL;
            ocnt++;

            if (ilen) {
                quirks |= QUIRK_PAST;
            }
        case TCPOPT_NOP:
            /*
             * NOP 
             */
            op[ocnt] = TCPOPT_NOP;
            ocnt++;
            break;

        case TCPOPT_SACKOK:
            /*
             * SACKOK LEN 
             */
            op[ocnt] = TCPOPT_SACKOK;
            ocnt++;
            ilen--;
            opt_ptr++;
            break;

        case TCPOPT_MAXSEG:
            /*
             * MSS LEN D0 D1 
             */
            if (opt_ptr + 3 > end_ptr) {
              borken:
                quirks |= QUIRK_BROKEN;
                goto end_parsing;
            }
            op[ocnt] = TCPOPT_MAXSEG;
            mss_val = GET16(opt_ptr + 1);
            ocnt++;
            ilen -= 3;
            opt_ptr += 3;
            break;

        case TCPOPT_WSCALE:
            /*
             * WSCALE LEN D0 
             */
            if (opt_ptr + 2 > end_ptr)
                goto borken;
            op[ocnt] = TCPOPT_WSCALE;
            wsc_val = *(uint8_t *) (opt_ptr + 1);
            ocnt++;
            ilen -= 2;
            opt_ptr += 2;
            break;

        case TCPOPT_TIMESTAMP:
            /*
             * TSTAMP LEN T0 T1 T2 T3 A0 A1 A2 A3 
             */
            if (opt_ptr + 9 > end_ptr)
                goto borken;
            op[ocnt] = TCPOPT_TIMESTAMP;

            memcpy(&tstamp, opt_ptr + 5, 4);
            if (tstamp)
                quirks |= QUIRK_T2;

            memcpy(&tstamp, opt_ptr + 1, 4);
            tstamp = ntohl(tstamp);

            ocnt++;
            ilen -= 9;
            opt_ptr += 9;
            break;

        default:

            /*
             * Hrmpf... 
             */
            if (opt_ptr + 1 > end_ptr)
                goto borken;

            op[ocnt] = *(opt_ptr - 1);
            olen = *(uint8_t *) (opt_ptr) - 1;
            if (olen > 32 || (olen < 0))
                goto borken;

            ocnt++;
            ilen -= olen;
            opt_ptr += olen;
            break;

        }
        if (ocnt >= MAXOPT - 1)
            goto borken;

        /*
         * Whoops, we're past end_ptr 
         */
        if (ilen > 0)
            if (opt_ptr >= end_ptr)
                goto borken;

    }

  end_parsing:

    if (tcph->t_ack)
        quirks |= QUIRK_ACK;
    if (tcph->t_urgp)
        quirks |= QUIRK_URG;
    if (TCP_X2(tcph))
        quirks |= QUIRK_X2;
    if (!ip4->ip_id)
        quirks |= QUIRK_ZEROID;

    gen_fp_tcp(ip4->ip_ttl, open_mode ? 0 : ntohs(ip4->ip_len),
               (ntohs(ip4->ip_off) & IP_DF) != 0,
               op,
               ocnt,
               mss_val,
               ntohs(tcph->t_win),
               wsc_val,
               tstamp, quirks, ftype, ip_src, tcph->src_port, AF_INET);

//   find_match(
//     /* total */ open_mode ? 0 : ntohs(iph->tot_len),
//     /* DF */    (ntohs(iph->off) & IP_DF) != 0,
//     /* TTL */   iph->ttl,
//     /* WSS */   ntohs(tcph->win),
//     /* src */   iph->saddr,
//     /* dst */   iph->daddr,
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

void fp_tcp6(ip6_header * ip6, tcp_header * tcph, const uint8_t * end_ptr,
             uint8_t ftype, struct in6_addr ip_src)
{
//   return;
    uint8_t *opt_ptr;
    uint8_t *payload = 0;
    uint8_t op[MAXOPT];
    uint8_t ocnt = 0, open_mode = 0;    /* open_mode=stray ack */
    uint16_t mss_val = 0, wsc_val = 0;
    int32_t ilen, olen;
    uint32_t quirks = 0, tstamp = 0;

    /*
     * If the declared length is shorter than the snapshot (etherleak
     * or such), truncate the package. 
     */
    opt_ptr = (uint8_t *) ip6 + IP6_HEADER_LEN + ntohs(ip6->len);
    if (end_ptr > opt_ptr)
        end_ptr = opt_ptr;

    opt_ptr = (uint8_t *) (tcph + 1);

    if (IP6_FL(ip6) > 0) {
        quirks |= QUIRK_FLOWL;
    }

    /*
     * If IP header ends past end_ptr 
     */
    if ((uint8_t *) (ip6 + 1) > end_ptr)
        return;

    if (ftype == TF_ACK)
        open_mode = 1;
    if (ftype == TF_RST && (tcph->t_flags & TF_ACK))
        quirks |= QUIRK_RSTACK;
    if (ftype == TF_FIN && (tcph->t_flags & TF_ACK))
        quirks |= QUIRK_FINACK;

    if (tcph->t_seq == tcph->t_ack)
        quirks |= QUIRK_SEQEQ;
    if (!tcph->t_seq)
        quirks |= QUIRK_SEQ0;
    if (tcph->t_flags & ~(TF_SYN | TF_ACK | TF_RST | TF_ECE | TF_CWR
                          | (open_mode ? TF_PUSH : 0)))
        quirks |= QUIRK_FLAGS;

    ilen = ((tcph->t_offx2) << 2) - TCP_HEADER_LEN;

    if ((uint8_t *) opt_ptr + ilen < end_ptr) {
        if (!open_mode)
            quirks |= QUIRK_DATA;
        payload = opt_ptr + ilen;
    }
    while (ilen > 0) {

        ilen--;

        /*
         * let the phun begin... 
         */
        switch (*(opt_ptr++)) {
        case TCPOPT_EOL:
            /*
             * EOL 
             */
            op[ocnt] = TCPOPT_EOL;
            ocnt++;

            if (ilen) {
                quirks |= QUIRK_PAST;
            }
        case TCPOPT_NOP:
            /*
             * NOP 
             */
            op[ocnt] = TCPOPT_NOP;
            ocnt++;
            break;

        case TCPOPT_SACKOK:
            /*
             * SACKOK LEN 
             */
            op[ocnt] = TCPOPT_SACKOK;
            ocnt++;
            ilen--;
            opt_ptr++;
            break;

        case TCPOPT_MAXSEG:
            /*
             * MSS LEN D0 D1 
             */
            if (opt_ptr + 3 > end_ptr) {
              borken:
                quirks |= QUIRK_BROKEN;
                goto end_parsing;
            }
            op[ocnt] = TCPOPT_MAXSEG;
            mss_val = GET16(opt_ptr + 1);
            ocnt++;
            ilen -= 3;
            opt_ptr += 3;
            break;
        case TCPOPT_WSCALE:
            /*
             * WSCALE LEN D0 
             */
            if (opt_ptr + 2 > end_ptr)
                goto borken;
            op[ocnt] = TCPOPT_WSCALE;
            wsc_val = *(uint8_t *) (opt_ptr + 1);
            ocnt++;
            ilen -= 2;
            opt_ptr += 2;
            break;

        case TCPOPT_TIMESTAMP:
            /*
             * TSTAMP LEN T0 T1 T2 T3 A0 A1 A2 A3 
             */
            if (opt_ptr + 9 > end_ptr)
                goto borken;
            op[ocnt] = TCPOPT_TIMESTAMP;

            memcpy(&tstamp, opt_ptr + 5, 4);
            if (tstamp)
                quirks |= QUIRK_T2;

            memcpy(&tstamp, opt_ptr + 1, 4);
            tstamp = ntohl(tstamp);

            ocnt++;
            ilen -= 9;
            opt_ptr += 9;
            break;

        default:

            /*
             * Hrmpf... 
             */
            if (opt_ptr + 1 > end_ptr)
                goto borken;

            op[ocnt] = *(opt_ptr - 1);
            olen = *(uint8_t *) (opt_ptr) - 1;
            if (olen > 32 || (olen < 0))
                goto borken;

            ocnt++;
            ilen -= olen;
            opt_ptr += olen;
            break;

        }
        if (ocnt >= MAXOPT - 1)
            goto borken;

        /*
         * Whoops, we're past end_ptr 
         */
        if (ilen > 0)
            if (opt_ptr >= end_ptr)
                goto borken;

    }

  end_parsing:

    if (tcph->t_ack)
        quirks |= QUIRK_ACK;
    if (tcph->t_urgp)
        quirks |= QUIRK_URG;
    if (TCP_X2(tcph))
        quirks |= QUIRK_X2;
    if (!IP6_FL(ip6))
        quirks |= QUIRK_ZEROID;

/*
printf("hop:%u, len:%u, ver:%u, class:%u, label:%u|mss:%u, win:%u\n",ip6->hop_lmt,open_mode ? 0 : ntohs(ip6->len),
                                                     IP6_V(ip6),ntohs(IP6_TC(ip6)),
                                                     ntohs(IP6_FL(ip6)),
                                                     mss_val, ntohs(tcph->t_win));
*/
    gen_fp_tcp(ip6->hop_lmt, open_mode ? 0 : ntohs(ip6->len), 1,        // simulate df bit for now
               op,
               ocnt,
               mss_val,
               ntohs(tcph->t_win),
               wsc_val,
               tstamp, quirks, ftype, ip_src, tcph->src_port, AF_INET6);

}
