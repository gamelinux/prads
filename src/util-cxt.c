/*
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 */

#include "prads.h"
#include "util-cxt.h"
#include <stddef.h>

/* Allocate a connection */
inline
connection *connection_alloc(void)
{
    connection *cxt;

    cxt = calloc(1, sizeof(connection));
    if(cxt == NULL) {
        printf("calloc failed to allocate connection\n");
        return NULL;
    }
    cxt->next = NULL;
    cxt->prev = NULL;

    return cxt;
}

/* free the memory of a connection tracker */
void connection_free(connection *cxt)
{
    free(cxt);
}

/* initialize the connection from the first packet we see from it. */
void connection_init(connection *cxt, struct in6_addr *ip_src, uint16_t src_port,
             struct in6_addr *ip_dst, uint16_t dst_port, uint8_t ip_proto,
             uint16_t p_bytes, uint8_t tcpflags, time_t tstamp, int af)
{

    extern u_int64_t cxtrackerid;
    cxtrackerid += 1;

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
}

cxtqueue *cxtqueue_new()
{
    cxtqueue *q = (cxtqueue *)calloc(1, sizeof(cxtqueue));
    if (q == NULL) {
        printf("Error allocating connection queue\n");
        exit(EXIT_FAILURE);
    }
    return q;
}

void cxt_enqueue (cxtqueue *q, connection *cxt) {
    /* more connection in the queue */
    if (q->top != NULL) {
        cxt->next = q->top;
        q->top->prev = cxt;
        q->top = cxt;
    /* only one connection */
    } else {
        q->top = cxt;
        q->bot = cxt;
    }
    q->len++;
}

connection *cxt_dequeue (cxtqueue *q) {

    connection *cxt = q->bot;
    if (cxt == NULL)
        return NULL;

    /* more connection trackers in queue */
    if (q->bot->prev != NULL) {
        q->bot = q->bot->prev;
        q->bot->next = NULL;
    /* just the one we remove, so now empty */
    } else {
        q->top = NULL;
        q->bot = NULL;
    }

    q->len--;

    cxt->next = NULL;
    cxt->prev = NULL;

    return cxt;
}

void cxt_requeue(connection *cxt, cxtqueue *srcq, cxtqueue *dstq)
{
    if (srcq != NULL)
    {
        /* remove from old queue */
        if (srcq->top == cxt)
            srcq->top = cxt->next;       /* remove from queue top */
        if (srcq->bot == cxt)
            srcq->bot = cxt->prev;       /* remove from queue bot */
        if (cxt->prev)
            cxt->prev->next = cxt->next; /* remove from flow prev */
        if (cxt->next)
            cxt->next->prev = cxt->prev; /* remove from flow next */

        srcq->len--; /* adjust len */

        cxt->next = NULL;
        cxt->prev = NULL;

    }

    /* now put it in dst, add to new queue (append) */
    cxt->prev = dstq->bot;
    if (cxt->prev)
        cxt->prev->next = cxt;
    cxt->next = NULL;
    dstq->bot = cxt;
    if (dstq->top == NULL)
        dstq->top = cxt;

    dstq->len++;
}

connection *cxt_get_from_hash (struct in6_addr *ip_src, uint16_t src_port,
             struct in6_addr *ip_dst, uint16_t dst_port, uint8_t ip_proto,
             uint16_t p_bytes, uint8_t tcpflags, time_t tstamp, int af, uint32_t hash)
{
    connection *cxt = NULL;
    int ret = 0;
    /* get our hash bucket and lock it */
    cxtbucket *cb = &cxt_hash[hash];

    /* see if the bucket already has a connection */
    if (cb->cxt == NULL) {
        /* no, so get a new one */
        cxt = cb->cxt = cxt_dequeue(&cxt_spare_q);
        if (cxt == NULL) {
            cxt = cb->cxt = connection_alloc();
            if (cxt == NULL) {
                return NULL;
            }
        }
        /* these are protected by the bucket lock */
        cxt->hnext = NULL;
        cxt->hprev = NULL;

        /* got one, initialize and return */
        connection_init(cxt,ip_src, src_port, ip_dst, dst_port, ip_proto,
                        p_bytes, tcpflags, tstamp, af);
        cxt_requeue(cxt, NULL, &cxt_est_q);
        cxt->cb = cb;

        return cxt;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    cxt = cb->cxt;

    /* see if this is the flow we are looking for */
    if (af == AF_INET) {
        ret = CMP_CXT4(cxt, ip_src, src_port, ip_dst, dst_port);
    } else if (af == AF_INET6){
        ret = CMP_CXT6(cxt, ip_src, src_port, ip_dst, dst_port);
    }

    if (ret == 0) {
        connection *pcxt = NULL; /* previous connection */

        while (cxt != NULL) {
            pcxt = cxt; /* pf is not locked at this point */
            cxt = cxt->hnext;

            if (cxt == NULL) {
                /* get us a new one and put it and the list tail */
                cxt = pcxt->hnext = cxt_dequeue(&cxt_spare_q);
                if (cxt == NULL) {

                    cxt = cb->cxt = connection_alloc();
                    if (cxt == NULL) {
                        return NULL;
                    }
                }

                cxt->hnext = NULL;
                cxt->hprev = pcxt;

                /* lock, initialize and return */
                connection_init(cxt,ip_src, src_port, ip_dst, dst_port,
                                ip_proto, p_bytes, tcpflags, tstamp, af);
                cxt_requeue(cxt, NULL, &cxt_est_q);

                cxt->cb = cb;

                return cxt;
            }

            if (af == AF_INET) {
                ret = CMP_CXT4(cxt, ip_src, src_port, ip_dst, dst_port);
            } else if (af == AF_INET6) {
                ret = CMP_CXT6(cxt, ip_src, src_port, ip_dst, dst_port);
            }
            if ( ret != 0) {
                /* we found our flow, lets put it on top of the
                 * hash list -- this rewards active flows */
                if (cxt->hnext) cxt->hnext->hprev = cxt->hprev;
                if (cxt->hprev) cxt->hprev->hnext = cxt->hnext;

                cxt->hnext = cb->cxt;
                cxt->hprev = NULL;
                cb->cxt->hprev = cxt;
                cb->cxt = cxt;

                /* found our connection */
                return cxt;
            }

            /* not found, try the next... */
        }
    }

    /* The 'root' connection was our connection, return it. */
    return cxt;
}

void free_queue()
{
    connection *cxt;

    while((cxt = cxt_dequeue(&cxt_spare_q))) {
        connection_free(cxt);
    }

    while((cxt = cxt_dequeue(&cxt_est_q))) {
        connection_free(cxt);
    }

    if (cxt_hash != NULL) {
        free(cxt_hash);
    }
    printf("queue memory has been cleared\n");
}

inline
void cxt_update_dst (connection *cxt, packetinfo *pi)
{
    cxt->d_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
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

inline
void cxt_update_src (connection *cxt, packetinfo *pi)
{
    cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;
    if (cxt->d_total_bytes > MAX_BYTE_CHECK
        || cxt->d_total_pkts > MAX_PKT_CHECK) {
        pi->s_check = 0; // Don't check
        return;
    }
    pi->s_check = 1; // Client & check
    return;
}

inline
void cxt_new (connection *cxt, packetinfo *pi)
{
        extern u_int64_t cxtrackerid;
        cxtrackerid += 1;

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
        pi->s_check = 1;
}

