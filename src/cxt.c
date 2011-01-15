#include "common.h"
#include "prads.h"
#include "cxt.h"
#include "sys_func.h"
#include "util-cxt.h"
#include "util-cxt-queue.h"

// vector fill: srcprt,dstprt,srcip,dstip = 96 bytes. rest is 0
#define VEC_FILL(vec, _ipsrc,_ipdst,_portsrc,_portdst) do {\
    vec.s[0] = (_portsrc); \
    vec.s[1] = (_portdst); \
    vec.w[1] = (_ipsrc); \
    vec.w[2] = (_ipdst); \
    vec.w[3] = 0; \
} while (0)

void cxt_init()
{
    /* alloc hash memory */
    uint32_t i = 0;

    /* pre allocate conection trackers */
    for (i = 0; i < CXT_DEFAULT_PREALLOC; i++) {
        connection *cxt = connection_alloc();
        if (cxt == NULL) {
            printf("ERROR: connection_alloc failed: %s\n", strerror(errno));
            exit(1);
        }
        cxt_enqueue(&cxt_spare_q,cxt);
     }
}

int cx_track(struct in6_addr *ip_src, uint16_t src_port,
             struct in6_addr *ip_dst, uint16_t dst_port, uint8_t ip_proto,
             uint16_t p_bytes, uint8_t tcpflags, time_t tstamp, int af)
{

    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;

    if (af == AF_INET) {
        hash = CXT_HASH4(IP4ADDR(ip_src),IP4ADDR(ip_dst));
    } else if (af == AF_INET6) {
        hash = CXT_HASH6(ip_src,ip_dst);
    }
    cxt = bucket[hash];
    head = cxt;

    while (cxt != NULL) {
        // Two-way compare of given connection against connection table
        if (af == AF_INET) {
            if (CMP_CXT4(cxt,IP4ADDR(ip_src),src_port,IP4ADDR(ip_dst),dst_port)){
                cxt->s_tcpFlags |= tcpflags;
                cxt->s_total_bytes += p_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont check!
                }
                return 1;       // Client should send the first packet (TCP/SYN - UDP?), hence this is a client
            } else if (CMP_CXT4(cxt,IP4ADDR(ip_dst),dst_port,IP4ADDR(ip_src),src_port)) {
                cxt->d_tcpFlags |= tcpflags;
                cxt->d_total_bytes += p_bytes;
                cxt->d_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont check!
                }
                return 2;       // This should be a server (Maybe not when we start up but in the long run)
            }
        } else if (af == AF_INET6) {
            if (CMP_CXT6(cxt,ip_src,src_port,ip_dst,dst_port)){

                cxt->s_tcpFlags |= tcpflags;
                cxt->s_total_bytes += p_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont Check!
                }
                return 1;       // Client
            } else if (CMP_CXT6(cxt,ip_dst,dst_port,ip_src,src_port)){

                cxt->d_tcpFlags |= tcpflags;
                cxt->d_total_bytes += p_bytes;
                cxt->d_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont Check!
                }
                return 2;       // Server
            }
        }
        cxt = cxt->next;
    }

    if (cxt == NULL) {
        //TODO: refactor into cxt_new()
        extern u_int64_t cxtrackerid;
        cxtrackerid += 1;
        cxt = (connection *) calloc(1, sizeof(connection));
        if (head != NULL) {
            head->prev = cxt;
        }
        /*
         * printf("[*] New connection...\n"); 
         * calloc initiates with 0, so just  set the things we need.
         */
        cxt->cxid = cxtrackerid;
        cxt->af = af;
        cxt->s_tcpFlags = tcpflags;
        //cxt->d_tcpFlags = 0x00;
        cxt->s_total_bytes = p_bytes;
        cxt->s_total_pkts = 1;
        //cxt->d_total_bytes = 0;
        //cxt->d_total_pkts = 0;
        cxt->start_time = tstamp;
        cxt->last_pkt_time = tstamp;

        cxt->s_ip = *ip_src;
        cxt->d_ip = *ip_dst;

        cxt->s_port = src_port;
        cxt->d_port = dst_port;
        cxt->proto = ip_proto;
        cxt->next = head;
        //cxt->prev = NULL;
        /*
         * New connections are pushed on to the head of bucket[s_hash] 
         */
        bucket[hash] = cxt;

        /*
         * Return value should be 1, telling to do client service fingerprinting 
         */
        return 1;
    }
    /*
     * Should never be here! 
     */
   return -1;
}

/* vector comparisons to speed up cx tracking.
 * meaning, compare source:port and dest:port at the same time.
 *
 * about vectors and potential improvements:
 *
 * all 64bit machines have at least SSE2 instructions
 * *BUT* there is no guarantee we won't loose time on
 * copying the vectors around.
 * ... indeed, a quick objdump shows us that
 * there is a shitton of mov instructions to align the addresses.
 *
 * Needs support to give improvements: 
 * the addresses should already be aligned as a 128-bit word
 * in the connection tracking bucket.
 *
 * note, we can employ the same technique for ipv6 addresses, but
 * one address at a time.
 */
#ifdef VECTOR_CXTRACKER
inline void cx_track_simd_ipv4(packetinfo *pi)
{
    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;

    // add to packetinfo ? dont through int32 around :)
    hash = make_hash(pi);
    extern connection *bucket[BUCKET_SIZE];
    cxt = bucket[hash];
    head = cxt;

    ip6v incoming;
    ip6v compare;
    VEC_FILL(incoming,
        pi->ip_src.__u6_addr.__u6_addr32[0],
        pi->ip_dst.__u6_addr.__u6_addr32[0],
        pi->s_port,
        pi->d_port);
    while (cxt != NULL) {
        VEC_FILL(compare,
        cxt->s_ip.__u6_addr.__u6_addr32[0],
        cxt->d_ip.__u6_addr.__u6_addr32[0],
        cxt->s_port,
        cxt->d_port);

        // single-instruction compare -msse2
        compare.v = __builtin_ia32_pcmpeqd128(incoming.v,compare.v);
        // same thing, really. c == v iff c ^ v == 0
        //compare.v = compare.v ^ incoming.v;

        // 64-bit compare reduce
        if(!(compare.i[0] & compare.i[1])){
            //ok
            dlog("[*] Updating src connection: %lu\n",cxt->cxid);
            cxt_update_src(cxt,pi);
            return;
        }

        // compare the other direction
        VEC_FILL(compare,
        cxt->d_ip.__u6_addr.__u6_addr32[0],
        cxt->s_ip.__u6_addr.__u6_addr32[0],
        cxt->d_port,
        cxt->s_port);

        compare.v = __builtin_ia32_pcmpeqd128(incoming.v,compare.v);
        if(!(compare.i[0] & compare.i[1])){
            dlog("[*] Updating dst connection: %lu\n",cxt->cxid);
            cxt_update_dst(cxt,pi);
            return;
        }
        cxt = cxt->next;
    }
    if (cxt == NULL) {
        cxt = (connection *) connection_alloc();
        //cxt = (connection *) calloc(1, sizeof(connection));
        if (head != NULL) {
            head->prev = cxt;
        }
        cxt_new(cxt,pi);
        dlog("[*] New connection: %lu\n",cxt->cxid);
        cxt->next = head;
        bucket[hash] = cxt;
        return;
    }
    printf("[*] Error in session tracking...\n");
    exit (1);
}

#endif
inline
void connection_tracking(packetinfo *pi) {

    // add to packetinfo ? dont through int32 around :)
    cxt_update(pi);
    return;
}

/*
 This sub marks sessions as ENDED on different criterias:
*/

void end_sessions()
{

    connection *cxt;
    time_t check_time;
    check_time = time(NULL);
    int xpir;
    uint32_t curcxt = 0;
    uint32_t expired = 0;
    
    for (cxt = cxt_est_q.bot; cxt != NULL;) {
        xpir = 0;
        curcxt++;
        /** TCP */
        if (cxt->proto == IP_PROTO_TCP) {
            /* * FIN from both sides */
            if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                    && (check_time - cxt->last_pkt_time) > 5) {
                xpir = 1;
            } /* * RST from either side */
            else if ((cxt->s_tcpFlags & TF_RST
                    || cxt->d_tcpFlags & TF_RST)
                    && (check_time - cxt->last_pkt_time) > 5) {
                xpir = 1;
            }
            // Commented out, since &TF_SYNACK is wrong!
                /*
                 * if not a complete TCP 3-way handshake 
                 */
                //else if ( !cxt->s_tcpFlags&TF_SYNACK || !cxt->d_tcpFlags&TF_SYNACK && (check_time - cxt->last_pkt_time) > 10) {
                //   xpir = 1;
                //}
                /*
                 * Ongoing timout 
                 */
                //else if ( (cxt->s_tcpFlags&TF_SYNACK || cxt->d_tcpFlags&TF_SYNACK) && ((check_time - cxt->last_pkt_time) > 120)) {
                //   xpir = 1;
                //}
            else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                xpir = 1;
            }
        }            /*
             * UDP 
             */
        else if (cxt->proto == IP_PROTO_UDP
                && (check_time - cxt->last_pkt_time) > 60) {
            xpir = 1;
        }            /*
             * ICMP 
             */
        else if (cxt->proto == IP_PROTO_ICMP
                || cxt->proto == IP6_PROTO_ICMP) {
            if ((check_time - cxt->last_pkt_time) > 60) {
                xpir = 1;
            }
        }            /*
             * All Other protocols 
             */
        else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
            xpir = 1;
        }

        if (xpir == 1) {
            expired++;
            xpir = 0;
            /* remove from the hash */
            if (cxt->hprev)
                cxt->hprev->hnext = cxt->hnext;
            if (cxt->hnext)
                cxt->hnext->hprev = cxt->hprev;
            // cb is deprecated (we believe)
            if (cxt->cb && cxt->cb->cxt == cxt)
                cxt->cb->cxt = cxt->hnext;

            connection *tmp = cxt;
            cxt = cxt->prev;

            /* cxt_requeue(tmp, &cxt_est_q, &cxt_log_q); */
            cxt_requeue(tmp, &cxt_est_q, &cxt_spare_q);
            CLEAR_CXT(tmp);
            //printf("[*] connection deleted!!!\n");
        } else {
            cxt = cxt->prev;
        }
    }
}

void del_connection(connection * cxt, connection ** bucket_ptr)
{
    connection *prev = cxt->prev;       /* OLDER connections */
    connection *next = cxt->next;       /* NEWER connections */

    if (prev == NULL) {
        // beginning of list
        *bucket_ptr = next;
        // not only entry
        if (next)
            next->prev = NULL;
    } else if (next == NULL) {
        // at end of list!
        prev->next = NULL;
    } else {
        // a node.
        prev->next = next;
        next->prev = prev;
    }

    /*
     * Free and set to NULL 
     */
    free(cxt);
    cxt = NULL;
}

void end_all_sessions()
{
    connection *cxt;
    int cxkey;
    int expired = 0;

    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++) {
        cxt = bucket[cxkey];
        while (cxt != NULL) {
            expired++;
            connection *tmp = cxt;
            cxt = cxt->next;
            del_connection(tmp, &bucket[cxkey]);
            if (cxt == NULL) {
                bucket[cxkey] = NULL;
            }
        }
    }
}
