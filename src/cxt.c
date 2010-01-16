#include "common.h"
#include "prads.h"
#include "cxt.h"
#include "sys_func.h"

/* For prads, I guess cx_track needs to return a value, which can
 * be used for evaluating if we should do some fingerprinting
 * I suggest:
 * 0 : NEVER CHECK PACKAGE
 * 1 : Check package - (Package commes from Client)
 * 2 : Check package - (Package commes from Server)
 */

/* void cx_track(uint64_t ip_src,uint16_t src_port,uint64_t ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af) { */

/*
void setup_cxt_info(connection *cxt, connection *head, connection ** bucket_ptr, struct in6_addr *ip_src,
                    uint16_t src_port, struct in6_addr *ip_dst, uint16_t dst_port,
                    uint8_t ip_proto, uint16_t p_bytes, uint8_t tcpflags,
                    time_t tstamp, int af)
{
    extern u_int64_t cxtrackerid;
    cxtrackerid += 1;
    if (cxt == NULL) {
        cxt = (connection *) calloc(1, sizeof (connection));
        *
         * printf("[*] New connection...\n");
         *
        if (head != NULL) {
            head->prev = cxt;
        }

        cxt->cxid = cxtrackerid;
        cxt->af = af;
        cxt->s_tcpFlags = tcpflags;
        cxt->d_tcpFlags = 0x00;
        cxt->s_total_bytes = p_bytes;
        cxt->s_total_pkts = 1;
        cxt->d_total_bytes = 0;
        cxt->d_total_pkts = 0;
        cxt->start_time = tstamp;
        cxt->last_pkt_time = tstamp;

        cxt->s_ip = *ip_src;
        cxt->d_ip = *ip_dst;

        cxt->s_port = src_port;
        cxt->d_port = dst_port;
        cxt->proto = ip_proto;
        cxt->next = head;
        cxt->prev = NULL;
        *bucket_ptr = cxt;
        return;
    }
    return;
}
*/

int cx_track(struct in6_addr *ip_src, uint16_t src_port,
             struct in6_addr *ip_dst, uint16_t dst_port, uint8_t ip_proto,
             uint16_t p_bytes, uint8_t tcpflags, time_t tstamp, int af)
{

    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;

    if (af == AF_INET) {
        hash = ((ip_src->s6_addr32[0] + ip_dst->s6_addr32[0])) % BUCKET_SIZE;
    } else if (af == AF_INET6) {
        hash =
            ((ip_src->s6_addr32[0] + ip_src->s6_addr32[1] +
              ip_src->s6_addr32[2] + ip_src->s6_addr32[3] +
              ip_dst->s6_addr32[0] + ip_dst->s6_addr32[1] +
              ip_dst->s6_addr32[2] + ip_dst->s6_addr32[3]
             )) % BUCKET_SIZE;
    }
    extern connection *bucket[BUCKET_SIZE];
    cxt = bucket[hash];
    head = cxt;
/*
    if (cxt == NULL) {
        setup_cxt_info(cxt, head, &bucket[hash], ip_src, src_port, ip_dst, src_port, ip_proto,
                       p_bytes, tcpflags, tstamp, af);
        return 1;
    }
*/
    while (cxt != NULL) {
        if (af == AF_INET) {
            if (cxt->s_port == src_port && cxt->d_port == dst_port
                && cxt->s_ip.s6_addr32[0] == ip_src->s6_addr32[0]
                && cxt->d_ip.s6_addr32[0] == ip_dst->s6_addr32[0]) {
                cxt->s_tcpFlags |= tcpflags;
                cxt->s_total_bytes += p_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont check!
                }
                return 1;       // Client should send the first packet (TCP/SYN - UDP?), hence this is a client
            } else if (cxt->s_port == dst_port && cxt->d_port == src_port
                       && cxt->s_ip.s6_addr32[0] == ip_dst->s6_addr32[0]
                       && cxt->d_ip.s6_addr32[0] == ip_src->s6_addr32[0]) {
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
            if (cxt->s_port == src_port && cxt->d_port == dst_port
                && cxt->s_ip.s6_addr32[3] == ip_src->s6_addr32[3]
                && cxt->s_ip.s6_addr32[2] == ip_src->s6_addr32[2]
                && cxt->s_ip.s6_addr32[1] == ip_src->s6_addr32[1]
                && cxt->s_ip.s6_addr32[0] == ip_src->s6_addr32[0]

                && cxt->d_ip.s6_addr32[3] == ip_dst->s6_addr32[3]
                && cxt->d_ip.s6_addr32[2] == ip_dst->s6_addr32[2]
                && cxt->d_ip.s6_addr32[1] == ip_dst->s6_addr32[1]
                && cxt->d_ip.s6_addr32[0] == ip_dst->s6_addr32[0]) {

                cxt->s_tcpFlags |= tcpflags;
                cxt->s_total_bytes += p_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = tstamp;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    return 0;   // Dont Check!
                }
                return 1;       // Client
            } else if (cxt->d_port == src_port && cxt->s_port == dst_port
                       && cxt->s_ip.s6_addr32[0] == ip_dst->s6_addr32[0]
                       && cxt->s_ip.s6_addr32[1] == ip_dst->s6_addr32[1]
                       && cxt->s_ip.s6_addr32[2] == ip_dst->s6_addr32[2]
                       && cxt->s_ip.s6_addr32[3] == ip_dst->s6_addr32[3]

                       && cxt->d_ip.s6_addr32[0] == ip_src->s6_addr32[0]
                       && cxt->d_ip.s6_addr32[1] == ip_src->s6_addr32[1]
                       && cxt->d_ip.s6_addr32[2] == ip_src->s6_addr32[2]
                       && cxt->d_ip.s6_addr32[3] == ip_src->s6_addr32[3]) {

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

//    setup_cxt_info(cxt, head, &bucket[hash], ip_src, src_port, ip_dst, src_port, ip_proto,
//                       p_bytes, tcpflags, tstamp, af);
//    return 1;
    if (cxt == NULL) {
        printf("hi\n");
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

        /*
         * if (af = AF_INET) { 
         * cxt->s_ip6.s6_addr32[1]          = 0; 
         * cxt->s_ip6.s6_addr32[2]          = 0; 
         * cxt->s_ip6.s6_addr32[3]          = 0; 
         * cxt->d_ip6.s6_addr32[1]          = 0; 
         * cxt->d_ip6.s6_addr32[2]          = 0; 
         * cxt->d_ip6.s6_addr32[3]          = 0; 
         * } 
         */

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

// void connection_tracking (packetinfo *pi)
//pi->s_check =
//cx_track(&pi->ip_src, pi->tcph->src_port, 
// &pi->ip_dst, pi->tcph->dst_port, 
// pi->ip4->ip_p, pi->packet_bytes,
// pi->tcph->t_flags, pi->pheader->ts.tv_sec, pi->af);

uint32_t make_hash(packetinfo *pi)
{
    if (pi->ip4 != NULL) {
        return ((pi->ip_src.s6_addr32[0] + pi->ip_dst.s6_addr32[0])) % BUCKET_SIZE;
    } else {
        return ((pi->ip_src.s6_addr32[0] + pi->ip_src.s6_addr32[1] +
                pi->ip_src.s6_addr32[2] + pi->ip_src.s6_addr32[3] +
                pi->ip_dst.s6_addr32[0] + pi->ip_dst.s6_addr32[1] +
                pi->ip_dst.s6_addr32[2] + pi->ip_dst.s6_addr32[3]
                )) % BUCKET_SIZE;
    }
}

void connection_tracking(packetinfo *pi)
{
    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;

    // add to packetinfo ? dont through int32 around :)
    hash = make_hash(pi);
    extern connection *bucket[BUCKET_SIZE];
    cxt = bucket[hash];
    head = cxt;

    while (cxt != NULL) {
        if (pi->af == AF_INET) {
            if (cxt->s_port == pi->s_port && cxt->d_port == pi->d_port
                && cxt->s_ip.s6_addr32[0] == pi->ip_src.s6_addr32[0]
                && cxt->d_ip.s6_addr32[0] == pi->ip_dst.s6_addr32[0]) {

                cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
                cxt->s_total_bytes += pi->packet_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = pi->pheader->ts.tv_sec;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    pi->s_check = 0; // Don't check!
                    return;
                }
                pi->s_check = 1; // Client & check
                return;
            } else if (cxt->s_port == pi->d_port && cxt->d_port == pi->s_port
                       && cxt->s_ip.s6_addr32[0] == pi->ip_dst.s6_addr32[0]
                       && cxt->d_ip.s6_addr32[0] == pi->ip_src.s6_addr32[0]) {

                cxt->d_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
                cxt->d_total_bytes += pi->packet_bytes;
                cxt->d_total_pkts += 1;
                cxt->last_pkt_time = pi->pheader->ts.tv_sec;
                if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                    pi->s_check = 0; // Don't check!
                    return;
                }
                pi->s_check = 2; // Server & check
                return;
            }
        } else if (pi->af == AF_INET6) {
            if (cxt->s_port == pi->s_port && cxt->d_port == pi->d_port
                && cxt->s_ip.s6_addr32[3] == pi->ip_src.s6_addr32[3]
                && cxt->s_ip.s6_addr32[2] == pi->ip_src.s6_addr32[2]
                && cxt->s_ip.s6_addr32[1] == pi->ip_src.s6_addr32[1]
                && cxt->s_ip.s6_addr32[0] == pi->ip_src.s6_addr32[0]

                && cxt->d_ip.s6_addr32[3] == pi->ip_dst.s6_addr32[3]
                && cxt->d_ip.s6_addr32[2] == pi->ip_dst.s6_addr32[2]
                && cxt->d_ip.s6_addr32[1] == pi->ip_dst.s6_addr32[1]
                && cxt->d_ip.s6_addr32[0] == pi->ip_dst.s6_addr32[0]) {

                cxt->s_tcpFlags |= pi->tcph->t_flags;
                cxt->s_total_bytes += pi->packet_bytes;
                cxt->s_total_pkts += 1;
                cxt->last_pkt_time = pi->pheader->ts.tv_sec;
                if (cxt->s_total_bytes > MAX_BYTE_CHECK
                    || cxt->s_total_pkts > MAX_PKT_CHECK) {
                    pi->s_check = 0; // Don't check
                    return;
                }
                pi->s_check = 1; // Client & check
                return;
            } else if (cxt->d_port == pi->s_port && cxt->s_port == pi->d_port
                       && cxt->s_ip.s6_addr32[0] == pi->ip_dst.s6_addr32[0]
                       && cxt->s_ip.s6_addr32[1] == pi->ip_dst.s6_addr32[1]
                       && cxt->s_ip.s6_addr32[2] == pi->ip_dst.s6_addr32[2]
                       && cxt->s_ip.s6_addr32[3] == pi->ip_dst.s6_addr32[3]

                       && cxt->d_ip.s6_addr32[0] == pi->ip_src.s6_addr32[0]
                       && cxt->d_ip.s6_addr32[1] == pi->ip_src.s6_addr32[1]
                       && cxt->d_ip.s6_addr32[2] == pi->ip_src.s6_addr32[2]
                       && cxt->d_ip.s6_addr32[3] == pi->ip_src.s6_addr32[3]) {

                cxt->d_tcpFlags |= pi->tcph->t_flags;
                cxt->d_total_bytes += pi->packet_bytes;
                cxt->d_total_pkts += 1;
                cxt->last_pkt_time = pi->pheader->ts.tv_sec;
                if (cxt->d_total_bytes > MAX_BYTE_CHECK
                    || cxt->d_total_pkts > MAX_PKT_CHECK) {
                    pi->s_check = 0; // Don't check
                    return;
                }
                pi->s_check = 2; // Server & check
                return;
            }
        }
        cxt = cxt->next;
    }
    if (cxt == NULL) {
        extern u_int64_t cxtrackerid;
        cxtrackerid += 1;

        cxt = (connection *) calloc(1, sizeof(connection));
        vlog(0x3, "[*] New connection: %lu",cxtrackerid);
        if (head != NULL) {
            head->prev = cxt;
        }
        cxt->cxid = cxtrackerid;
        cxt->af = pi->af;
        cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
        cxt->s_total_bytes = pi->packet_bytes;
        cxt->s_total_pkts = 1;
        cxt->start_time = pi->pheader->ts.tv_sec;
        cxt->last_pkt_time = pi->pheader->ts.tv_sec;
        cxt->s_ip = pi->ip_src;
        cxt->d_ip = pi->ip_dst;
        cxt->s_port = pi->s_port;
        cxt->d_port = pi->d_port;
        cxt->proto = (pi->ip4 ? pi->ip4->ip_p : pi->ip6->next);

        cxt->next = head;
        bucket[hash] = cxt;
        pi->s_check = 1;
        return;
    }
    printf("[*] Error in session tracking...\n");
    exit (1);
}

/*
 This sub marks sessions as ENDED on different criterias:
*/

void end_sessions()
{

    connection *cxt;
    time_t check_time;
    check_time = time(NULL);
    int cxkey, xpir;
    uint32_t curcxt = 0;
    uint32_t expired = 0;
    extern connection *cxtbuffer, *bucket[BUCKET_SIZE];
    cxtbuffer = NULL;

    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++) {
        cxt = bucket[cxkey];
        xpir = 0;
        while (cxt != NULL) {
            curcxt++;
            /*
             * TCP 
             */
            if (cxt->proto == IP_PROTO_TCP) {
                /*
                 * FIN from both sides 
                 */
                if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                    && (check_time - cxt->last_pkt_time) > 5) {
                    xpir = 1;
                }
                /*
                 * RST from eather side 
                 */
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
            }
            /*
             * UDP 
             */
            else if (cxt->proto == IP_PROTO_UDP
                     && (check_time - cxt->last_pkt_time) > 60) {
                xpir = 1;
            }
            /*
             * ICMP 
             */
            else if (cxt->proto == IP_PROTO_ICMP
                     || cxt->proto == IP6_PROTO_ICMP) {
                if ((check_time - cxt->last_pkt_time) > 60) {
                    xpir = 1;
                }
            }
            /*
             * All Other protocols 
             */
            else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                xpir = 1;
            }

            if (xpir == 1) {
                expired++;
                xpir = 0;
                connection *tmp = cxt;
                if (cxt == cxt->next) {
                    cxt->next = NULL;
                }
                cxt = cxt->next;
                del_connection(tmp, &bucket[cxkey]);
                //printf("[*] connection deleted!!!\n");
            } else {
                cxt = cxt->next;
            }
        }
    }
    /*
     * printf("Expired: %u of %u total connections:\n",expired,curcxt); 
     */
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
    extern connection *bucket[BUCKET_SIZE];

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
    /*
     * printf("Expired: %d.\n",expired); 
     */
}
