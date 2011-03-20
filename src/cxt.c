#include <assert.h>
#include "common.h"
#include "prads.h"
#include "cxt.h"
#include "sys_func.h"

uint64_t cxtrackerid;
connection *bucket[BUCKET_SIZE];
connection *cxtbuffer = NULL;

void cxt_init()
{
    cxtbuffer = NULL;
    cxtrackerid = 0;
}

/* freshly smelling connection :d */
connection *cxt_new()
{
    connection *cxt;
    cxtrackerid++;
    cxt = (connection *) calloc(1, sizeof(connection));
    assert(cxt);
    cxt->cxid = cxtrackerid;
    return cxt;
}

int connection_tracking(packetinfo *pi)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_d[INET6_ADDRSTRLEN];
    struct in_addr *ipa; 
    cx_track(pi);

    if(pi->af == AF_INET6) {
      u_ntop(pi->ip6->ip_src, pi->af, ip_addr_s);
      u_ntop(pi->ip6->ip_dst, pi->af, ip_addr_d);
    } else {
      ipa = pi->ip4->ip_src;
      inet_ntop(pi->af, &ipa, ip_addr_s, INET6_ADDRSTRLEN);
      ipa = pi->ip4->ip_dst;
      inet_ntop(pi->af, &ipa, ip_addr_d, INET6_ADDRSTRLEN);
    }
    printf("conn[%4llu] %s:%u -> %s:%u [%s]\n", pi->cxt->cxid, 
	ip_addr_s, pi->s_port,
        ip_addr_d, pi->d_port,
	pi->sc?pi->sc==SC_SERVER? "server":"client":"NONE"); 
    return 0;
}

/* return value: client or server?
 *** USED TO BE: 0 = dont check, 1 = client, 2 = server
 * now returns 0, SC_CLIENT(=1), SC_SERVER(=2)
 */

int cx_track(packetinfo *pi) {
    struct in6_addr *ip_src;
    struct in6_addr *ip_dst;
    struct in6_addr ips;
    struct in6_addr ipd;
    uint16_t src_port = pi->s_port;
    uint16_t dst_port = pi->d_port;
    uint8_t ip_proto = pi->proto;
    uint16_t p_bytes = pi->packet_bytes;
    uint8_t tcpflags;
    time_t tstamp = pi->pheader->ts.tv_sec;
    int af = pi->af;

    if(af== AF_INET6){
        ip_src = &PI_IP6SRC(pi);
        ip_dst = &PI_IP6DST(pi);
    }else {
        // ugly hack :(
        // the way we do ip4/6 is DIRTY
        ips.s6_addr32[0] = pi->ip4->ip_src;
        ipd.s6_addr32[0] = pi->ip4->ip_dst;
        ip_src = &ips;
        ip_dst = &ipd;
    }
    if(pi->tcph) tcpflags = pi->tcph->t_flags;

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
                pi->cxt = cxt;
                pi->sc = SC_CLIENT;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont check!
                }
                return SC_CLIENT; // Client should send the first packet (TCP/SYN - UDP?), hence this is a client
            } else if (CMP_CXT4(cxt,IP4ADDR(ip_dst),dst_port,IP4ADDR(ip_src),src_port)) {
                cxt->d_tcpFlags |= tcpflags;
                cxt->d_total_bytes += p_bytes;
                cxt->d_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                pi->cxt = cxt;
                pi->sc = SC_SERVER;
                if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont check!
                }
                return SC_SERVER;       // This should be a server (Maybe not when we start up but in the long run)
            }
        } else if (af == AF_INET6) {
            if (CMP_CXT6(cxt,ip_src,src_port,ip_dst,dst_port)){

                cxt->s_tcpFlags |= tcpflags;
                cxt->s_total_bytes += p_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                pi->cxt = cxt;
                pi->sc = SC_CLIENT;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont Check!
                }
                return SC_CLIENT;       // Client
            } else if (CMP_CXT6(cxt,ip_dst,dst_port,ip_src,src_port)){

                cxt->d_tcpFlags |= tcpflags;
                cxt->d_total_bytes += p_bytes;
                cxt->d_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                pi->cxt = cxt;
                pi->sc = SC_SERVER;
                if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont Check!
                }
                return SC_SERVER;       // Server
            }
        }
        cxt = cxt->next;
    }

    if (cxt == NULL) {

        cxt = cxt_new();
        cxt->af = af;
        cxt->s_tcpFlags = tcpflags;
        //cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);//why??
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

        cxt->check = 0x00;
        cxt->c_asset = NULL;
        cxt->s_asset = NULL;
        cxt->reversed = 0;

        //cxt->prev = NULL;
        /*
         * New connections are pushed on to the head of bucket[s_hash] 
         */
        cxt->next = head;
        if (head != NULL) {
            head->prev = cxt;
        }
        bucket[hash] = cxt;
        pi->cxt = cxt;

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

void reverse_pi_cxt(packetinfo *pi)
{
    uint8_t tmpFlags;
    uint64_t tmp_pkts;
    uint64_t tmp_bytes;
    struct in6_addr tmp_ip;
    uint16_t tmp_port;
    connection *cxt;

    cxt = pi->cxt;

    /* First we chang the cxt */
    /* cp src to tmp */
    tmpFlags = cxt->s_tcpFlags;
    tmp_pkts = cxt->s_total_pkts;
    tmp_bytes = cxt->s_total_bytes;
    tmp_ip = cxt->s_ip;
    tmp_port = cxt->s_port;

    /* cp dst to src */
    cxt->s_tcpFlags = cxt->d_tcpFlags;
    cxt->s_total_pkts = cxt->d_total_pkts;
    cxt->s_total_bytes = cxt->d_total_bytes;
    cxt->s_ip = cxt->d_ip;
    cxt->s_port = cxt->d_port;

    /* cp tmp to dst */
    cxt->d_tcpFlags = tmpFlags; 
    cxt->d_total_pkts = tmp_pkts;
    cxt->d_total_bytes = tmp_bytes;
    cxt->d_ip = tmp_ip;
    cxt->d_port = tmp_port;

    /* Not taking any chances :P */
    cxt->c_asset = cxt->s_asset = NULL;
    cxt->check = 0x00;

    /* Then we change pi */
    if (pi->sc == SC_CLIENT) pi->sc = SC_SERVER;
        else pi->sc = SC_CLIENT;
}



/*
 This sub marks sessions as ENDED on different criterias:

 XXX: May be the fugliest code in PRADS :-(
*/

void end_sessions()
{

    connection *cxt;
    time_t check_time;
    check_time = time(NULL);
    int ended;
    uint32_t curcxt = 0;
    uint32_t expired = 0;
    
    int iter = 0;
    for(cxt = bucket[iter++]; iter < BUCKET_SIZE; iter++) while (cxt) {
        ended = 0;
        curcxt++;
        /** TCP */
        if (cxt->proto == IP_PROTO_TCP) {
            /* * FIN from both sides */
            if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                    && (check_time - cxt->last_pkt_time) > 5) {
                ended = 1;
            } /* * RST from either side */
            else if ((cxt->s_tcpFlags & TF_RST
                    || cxt->d_tcpFlags & TF_RST)
                    && (check_time - cxt->last_pkt_time) > 5) {
                ended = 1;
            }
            // Commented out, since &TF_SYNACK is wrong!
                /*
                 * if not a complete TCP 3-way handshake 
                 */
                //else if ( !cxt->s_tcpFlags&TF_SYNACK || !cxt->d_tcpFlags&TF_SYNACK && (check_time - cxt->last_pkt_time) > 10) {
                //   ended = 1;
                //}
                /*
                 * Ongoing timout 
                 */
                //else if ( (cxt->s_tcpFlags&TF_SYNACK || cxt->d_tcpFlags&TF_SYNACK) && ((check_time - cxt->last_pkt_time) > 120)) {
                //   ended = 1;
                //}
            else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                ended = 1;
            }
        }            /*
             * UDP 
             */
        else if (cxt->proto == IP_PROTO_UDP
                && (check_time - cxt->last_pkt_time) > 60) {
            ended = 1;
        }            /*
             * ICMP 
             */
        else if (cxt->proto == IP_PROTO_ICMP
                || cxt->proto == IP6_PROTO_ICMP) {
            if ((check_time - cxt->last_pkt_time) > 60) {
                ended = 1;
            }
        }            /*
             * All Other protocols 
             */
        else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
            ended = 1;
        }

        if (ended == 1) {
            expired++;
            ended = 0;
            /* remove from the hash */
            if (cxt->prev)
                cxt->prev->next = cxt->next;
            if (cxt->next)
                cxt->next->prev = cxt->prev;
            connection *tmp = cxt;
            cxt = cxt->prev;

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
// vector fill: srcprt,dstprt,srcip,dstip = 96 bytes. rest is 0
#define VEC_FILL(vec, _ipsrc,_ipdst,_portsrc,_portdst) do {\
    vec.s[0] = (_portsrc); \
    vec.s[1] = (_portdst); \
    vec.w[1] = (_ipsrc); \
    vec.w[2] = (_ipdst); \
    vec.w[3] = 0; \
} while (0)

inline void cx_track_simd_ipv4(packetinfo *pi)
{
    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;

    // add to packetinfo ? dont through int32 around :)
    hash = make_hash(pi);
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
