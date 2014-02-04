#include <assert.h>
#include "common.h"
#include "prads.h"
#include "cxt.h"
#include "sys_func.h"
#include "config.h"
#include "output-plugins/log.h"

extern globalconfig config;

uint64_t cxtrackerid;
connection *bucket[BUCKET_SIZE];

void cxt_init()
{
    cxtrackerid = 0;
}

/* freshly smelling connection :d */
connection *cxt_new(packetinfo *pi)
{
    struct in6_addr ips;
    struct in6_addr ipd;
    connection *cxt;
    cxtrackerid++;
    cxt = (connection *) calloc(1, sizeof(connection));
    assert(cxt);
    cxt->cxid = cxtrackerid;

    cxt->af = pi->af;
    if(pi->tcph) cxt->s_tcpFlags = pi->tcph->t_flags;
    //cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);//why??
    //cxt->d_tcpFlags = 0x00;
    cxt->s_total_bytes = pi->packet_bytes;
    cxt->s_total_pkts = 1;
    cxt->start_time = pi->pheader->ts.tv_sec;
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if(pi-> af== AF_INET6){
        cxt->s_ip = PI_IP6SRC(pi);
        cxt->d_ip = PI_IP6DST(pi);
    }else {
        ips.s6_addr32[0] = pi->ip4->ip_src;
        ipd.s6_addr32[0] = pi->ip4->ip_dst;
        cxt->s_ip = ips;
        cxt->d_ip = ipd;
    }

    cxt->s_port = pi->s_port;
    cxt->d_port = pi->d_port;
    cxt->proto = pi->proto;
    cxt->hw_proto = ntohs(pi->eth_type);

    cxt->check = 0x00;
    cxt->c_asset = NULL;
    cxt->s_asset = NULL;
    cxt->reversed = 0;

    return cxt;
}

int connection_tracking(packetinfo *pi)
{
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_d[INET6_ADDRSTRLEN];
    cx_track(pi);

    if(config.cflags & CONFIG_CONNECT){
        log_connection(pi->cxt, CX_EXCESSIVE);
    }
    return 0;
}

int cxt_update_client(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if(pi->tcph) cxt->s_tcpFlags |= pi->tcph->t_flags;
    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_CLIENT;
    if(!cxt->c_asset)
        cxt->c_asset = pi->asset; // connection client asset
    if (cxt->s_total_bytes > MAX_BYTE_CHECK
        || cxt->s_total_pkts > MAX_PKT_CHECK) {
        return 0;   // Dont Check!
    }
    return SC_CLIENT;
}

int cxt_update_server(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if(pi->tcph) cxt->d_tcpFlags |= pi->tcph->t_flags;
    cxt->d_total_bytes += pi->packet_bytes;
    cxt->d_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_SERVER;
    if(!cxt->s_asset)
        cxt->s_asset = pi->asset; // server asset
    if (cxt->d_total_bytes > MAX_BYTE_CHECK
        || cxt->d_total_pkts > MAX_PKT_CHECK) {
        return 0;   // Dont check!
    }
    return SC_SERVER;

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
    int af = pi->af;
    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;


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

    // find the right connection bucket
    if (af == AF_INET) {
        hash = CXT_HASH4(IP4ADDR(ip_src),IP4ADDR(ip_dst),src_port,dst_port,pi->proto);
    } else if (af == AF_INET6) {
        hash = CXT_HASH6(ip_src,ip_dst,src_port,dst_port,pi->proto);
    }
    head = bucket[hash];

    // search through the bucket
    for (cxt = head; cxt != NULL; cxt = cxt->next) {
        if (af != cxt->af)
          continue;

        // Two-way compare of given connection against connection table
        if (af == AF_INET) {
            if (CMP_CXT4(cxt,IP4ADDR(ip_src),src_port,IP4ADDR(ip_dst),dst_port)){
                // Client sends first packet (TCP/SYN - UDP?) hence this is a client
                return cxt_update_client(cxt, pi);
            } else if (CMP_CXT4(cxt,IP4ADDR(ip_dst),dst_port,IP4ADDR(ip_src),src_port)) {
                // This is a server (Maybe not when we start up but in the long run)
                return cxt_update_server(cxt, pi);
            }
        } else if (af == AF_INET6) {
            if (CMP_CXT6(cxt,ip_src,src_port,ip_dst,dst_port)){
                return cxt_update_client(cxt, pi);
            } else if (CMP_CXT6(cxt,ip_dst,dst_port,ip_src,src_port)){
                return cxt_update_server(cxt, pi);
            }
        }
    }
    // bucket turned upside down didn't yeild anything. new connection
    cxt = cxt_new(pi);
    log_connection(cxt, CX_NEW);

    /* * New connections are pushed on to the head of bucket[s_hash] */
    cxt->next = head;
    if (head != NULL) {
        // are we doubly linked?
        head->prev = cxt;
    }
    bucket[hash] = cxt;
    pi->cxt = cxt;

    /* * Return value should be 1, telling to do client service fingerprinting */
    return 1;
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
    if (pi->sc == SC_CLIENT)
       pi->sc = SC_SERVER;
    else
       pi->sc = SC_CLIENT;
}

/*
 This sub marks sessions as ENDED on different criterias:

 XXX: May be the fugliest code in PRADS :-(
*/

void end_sessions()
{

    connection *cxt;
    int iter;
    int cxstatus = CX_NONE;
    time_t check_time = time(NULL);

    log_rotate(check_time);
    for (iter = 0; iter < BUCKET_SIZE; iter++) {
        cxt = bucket[iter];
        while (cxt != NULL) {
            /* TCP */
            if (cxt->proto == IP_PROTO_TCP) {
                /* * FIN from both sides */
                if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                    && (check_time - cxt->last_pkt_time) > 5) {
                    cxstatus = CX_ENDED;
                } /* * RST from either side */
                else if ((cxt->s_tcpFlags & TF_RST
                          || cxt->d_tcpFlags & TF_RST)
                          && (check_time - cxt->last_pkt_time) > 5) {
                    cxstatus = CX_ENDED;
                }
                else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                    cxstatus = CX_EXPIRE;
                }
            }
            /* UDP */
            else if (cxt->proto == IP_PROTO_UDP
                     && (check_time - cxt->last_pkt_time) > 60) {
                cxstatus = CX_EXPIRE;
            }
            /* ICMP */
            else if (cxt->proto == IP_PROTO_ICMP
                     || cxt->proto == IP6_PROTO_ICMP) {
                if ((check_time - cxt->last_pkt_time) > 60) {
                    cxstatus = CX_EXPIRE;
                }
            }
            /* All Other protocols */
            else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                cxstatus = CX_EXPIRE;
            }

            if (cxstatus == CX_ENDED || cxstatus == CX_EXPIRE) {
                /* remove from the hash */
                if (cxt->prev)
                    cxt->prev->next = cxt->next;
                if (cxt->next)
                    cxt->next->prev = cxt->prev;
                connection *tmp = cxt;

                log_connection(cxt, cxstatus);
                cxstatus = CX_NONE;

                cxt = cxt->next;

                del_connection(tmp, &bucket[iter]);
                if (cxt == NULL) {
                    bucket[iter] = NULL;
                }
            } else {
                cxt = cxt->next;
            }
        } // end while cxt
    } // end for buckets
}

void log_connection_all()
{
    int i;
    connection *cxt;
    if(! (config.cflags & CONFIG_CXWRITE))
        return;
    for(i = 0; i < BUCKET_SIZE; i++) {
        cxt = bucket[i];
        while(cxt) {
            log_connection(cxt, CX_HUMAN);
            cxt = cxt->next;
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
    FILE *cxtFile = NULL;

    log_rotate(time(NULL));
    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++) {
        cxt = bucket[cxkey];
        while (cxt != NULL) {
            connection *tmp = cxt;

            log_connection(cxt, CX_ENDED);
            cxt = cxt->next;
            del_connection(tmp, &bucket[cxkey]);
            if (cxt == NULL) {
                bucket[cxkey] = NULL;
            }
        }
    }
    if (cxtFile != NULL) {
        fclose(cxtFile);
    }
}

void cxt_log_buckets(int dummy)
{
    connection *cxt = NULL;
    FILE *logfile = NULL;
    int i;
    int len;

    logfile = fopen("/tmp/prads-buckets.log", "w");
    if (!logfile)
        return;

    dlog("Recieved SIGUSR1 - Dumping bucketlist to logfile\n");
    for (i = 0; i < BUCKET_SIZE; i++) {
        len = 0;
        for (cxt = bucket[i]; cxt; cxt = cxt->next)
            len++;
        if (len > 0)
            fprintf(logfile, "%d in bucket[%5d]\n", len, i);
    }

    fflush(logfile);
    fclose(logfile);
}



/* vector comparisons to speed up cx tracking.
 * meaning, compare source:port and dest:port at the same time.
 *
 * about vectors and potential improvements:
 * * all 64bit machines have at least SSE2 instructions * *BUT* there is no guarantee we won't loose time on
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
        cxt = cxt_new(pi);
        dlog("[*] New connection: %lu\n",cxt->cxid);
        cxt->next = head;
        bucket[hash] = cxt;
        return;
    }
    printf("[*] Error in session tracking...\n");
    exit (1);
}

#endif
