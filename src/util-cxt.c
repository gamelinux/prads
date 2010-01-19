/*
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 */

#include "prads.h"
#include "util-cxt.h"
#include "util-cxt-queue.h"
#include <stddef.h>

/* Allocate a connection */
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

inline void cxt_update (packetinfo *pi, uint32_t hash)
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
                return;
            }
        }
        /* these are protected by the bucket lock */
        cxt->hnext = NULL;
        cxt->hprev = NULL;

        /* got one, initialize and return */
        cxt_new(cxt,pi);
        cxt_requeue(cxt, NULL, &cxt_est_q);
        cxt->cb = cb;
        cxt_update_src(cxt, pi);
        pi->cxt = cxt;
        return;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    cxt = cb->cxt;

    /* see if this is the flow we are looking for */
    if (pi->af == AF_INET) {
        if (CMP_CXT4(cxt, &pi->ip_src, pi->s_port, &pi->ip_dst, pi->d_port)) {
            cxt_update_src(cxt, pi);
            ret = 1;
        } else if (CMP_CXT4(cxt, &pi->ip_dst, pi->d_port, &pi->ip_src, pi->s_port)) {
            cxt_update_dst(cxt, pi);
            ret = 1;
        }
    } else if (pi->af == AF_INET6){
        if (CMP_CXT6(cxt, &pi->ip_src, pi->s_port, &pi->ip_dst, pi->d_port)) {
            cxt_update_src(cxt, pi);
            ret = 1;
        } else if (CMP_CXT6(cxt, &pi->ip_dst, pi->d_port, &pi->ip_src, pi->s_port)) {
            cxt_update_dst(cxt, pi);
            ret = 1;
        }
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
                        return;
                    }
                }

                cxt->hnext = NULL;
                cxt->hprev = pcxt;

                /* initialize and return */
                cxt_new(cxt,pi);
                cxt_requeue(cxt, NULL, &cxt_est_q);

                cxt->cb = cb;
                cxt_update_src(cxt, pi);
                pi->cxt = cxt;
                return;
            }

            if (pi->af == AF_INET) {
                if (CMP_CXT4(cxt, &pi->ip_src, pi->s_port, &pi->ip_dst, pi->d_port)) {
                    cxt_update_src(cxt, pi);
                    ret = 1;
                } else if (CMP_CXT4(cxt, &pi->ip_dst, pi->d_port, &pi->ip_src, pi->s_port)) {
                    cxt_update_dst(cxt, pi);
                    ret = 1;
                }
            } else if (pi->af == AF_INET6) {
                if (CMP_CXT6(cxt, &pi->ip_src, pi->s_port, &pi->ip_dst, pi->d_port)) {
                    cxt_update_src(cxt, pi);
                    ret = 1;
                } else if (CMP_CXT6(cxt, &pi->ip_dst, pi->d_port, &pi->ip_src, pi->s_port)) {
                    cxt_update_dst(cxt, pi);
                    ret = 1;
                }
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
                pi->cxt = cxt;
                return;
            }

            /* not found, try the next... */
        }
    }
    pi->cxt = cxt;
    /* The 'root' connection was our connection, return it. */
    return;
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

/* initialize the connection from the first packet we see from it. */

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

