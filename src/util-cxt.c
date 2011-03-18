/*
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * Fikling by Kacper Wyoscki
 *
 * Created on January 16, 2010, 1:18 PM
 */

#include "prads.h"
#include "cxt.h"
#include "util-cxt.h"
#include "util-cxt-queue.h"
#include <stddef.h>

void cxt_queue_init()
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
    cxt->hnext = NULL;
    cxt->hprev = NULL;
    cxt->c_asset = NULL;
    cxt->s_asset = NULL;

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
    pi->sc = SC_SERVER;
    if (!(cxt->check & CXT_DONT_CHECK_SERVER)
            && (cxt->d_total_bytes > MAX_BYTE_CHECK
            || cxt->d_total_pkts > MAX_PKT_CHECK)) {
        cxt->check |= CXT_DONT_CHECK_SERVER; // Don't check
    }
    return;
}

inline
void cxt_update_src (connection *cxt, packetinfo *pi)
{
    cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;
    pi->sc = SC_CLIENT;
    if (!(cxt->check & CXT_DONT_CHECK_CLIENT)
            && (cxt->s_total_bytes > MAX_BYTE_CHECK
            || cxt->s_total_pkts > MAX_PKT_CHECK)) {
        cxt->check |= CXT_DONT_CHECK_CLIENT; // Don't check
    }
    return;
}

inline void cxt_update (packetinfo *pi)
{
    connection *cxt = NULL;
    int ret = 0;
    uint32_t hash;
    /* get our hash bucket and lock it */
    if (pi->ip4 != NULL) {
        hash = CXT_HASH4(PI_IP4SRC(pi),PI_IP4DST(pi));
        hash = hash % BUCKET_SIZE;
    } else {
        hash = CXT_HASH6(&PI_IP6SRC(pi),&PI_IP6DST(pi));
        hash = hash % BUCKET_SIZE;
    }
    cxt = bucket[hash];

    /* see if the bucket already has a connection */
    if (cxt == NULL) {
printf ("bucket[%u] is empty...\n",hash);

        /* no, so get a new one */
        cxt = cxt_dequeue(&cxt_spare_q);
        if (cxt == NULL) {
            cxt = connection_alloc();
            if (cxt == NULL) {
                return;
            }
        }
        /* these are protected by the bucket lock */
        cxt->hnext = NULL;
        cxt->hprev = NULL;

        /* got one, initialize and return */
        cxt_new(cxt,pi);
 bucket[hash] = cxt; /* is this what is missing ???? */
        cxt_requeue(cxt, NULL, &cxt_est_q);
        cxt_update_src(cxt, pi);
        pi->cxt = cxt;
        return;
    }

    /* ok, we have a flow in the bucket. Let's find out if it is our flow */
    /* see if this is the flow we are looking for */
    if (pi->af == AF_INET) {
        if (CMP_CXT4(cxt, PI_IP4SRC(pi), pi->s_port, PI_IP4DST(pi), pi->d_port)) {
            cxt_update_src(cxt, pi);
            ret = 1;
        } else if (CMP_CXT4(cxt, PI_IP4DST(pi), pi->d_port, PI_IP4SRC(pi), pi->s_port)) {
            cxt_update_dst(cxt, pi);
            ret = 1;
        }
    } else if (pi->af == AF_INET6){
        if (CMP_CXT6(cxt, &PI_IP6SRC(pi), pi->s_port, &PI_IP6DST(pi), pi->d_port)) {
            cxt_update_src(cxt, pi);
            ret = 1;
        } else if (CMP_CXT6(cxt, &PI_IP6DST(pi), pi->d_port, &PI_IP6SRC(pi), pi->s_port)) {
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

                    cxt = connection_alloc();
                    if (cxt == NULL) {
                        return;
                    }
                }

                cxt->hnext = NULL;
                cxt->hprev = pcxt;

                /* initialize and return */
                cxt_new(cxt,pi);
                cxt_requeue(cxt, NULL, &cxt_est_q);

                cxt_update_src(cxt, pi);
                pi->cxt = cxt;
                return;
            }

            if (pi->af == AF_INET) {
                if (CMP_CXT4(cxt, PI_IP4SRC(pi), pi->s_port, PI_IP4DST(pi), pi->d_port)) {
                    cxt_update_src(cxt, pi);
                    ret = 1;
                } else if (CMP_CXT4(cxt, PI_IP4DST(pi), pi->d_port, PI_IP4SRC(pi), pi->s_port)) {
                    cxt_update_dst(cxt, pi);
                    ret = 1;
                }
            } else if (pi->af == AF_INET6) {
                if (CMP_CXT6(cxt, &PI_IP6SRC(pi), pi->s_port, &PI_IP6DST(pi), pi->d_port)) {
                    cxt_update_src(cxt, pi);
                    ret = 1;
                } else if (CMP_CXT6(cxt, &PI_IP6DST(pi), pi->d_port, &PI_IP6SRC(pi), pi->s_port)) {
                    cxt_update_dst(cxt, pi);
                    ret = 1;
                }
            }
            if ( ret != 0) {
                /* we found our flow, lets put it on top of the
                 * hash list -- this rewards active flows */
                if (cxt->hnext) cxt->hnext->hprev = cxt->hprev;
                if (cxt->hprev) cxt->hprev->hnext = cxt->hnext;

                cxt->hnext = cxt;
                cxt->hprev = NULL;
                cxt->hprev = cxt;
                cxt = cxt;

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

    printf("\nqueue memory has been cleared");
}

/* initialize the connection from the first packet we see from it. */

void cxt_new (connection *cxt, packetinfo *pi)
{
printf("New connection...\n");
        extern u_int64_t cxtrackerid;
        cxtrackerid += 1;

        cxt->cxid = cxtrackerid;
        cxt->af = pi->af;
        cxt->s_tcpFlags |= (pi->tcph ? pi->tcph->t_flags : 0x00);
        cxt->s_total_bytes = pi->packet_bytes;
        cxt->s_total_pkts = 1;
        cxt->start_time = pi->pheader->ts.tv_sec;
        cxt->last_pkt_time = pi->pheader->ts.tv_sec;
        if(pi->af == AF_INET){
            IP4ADDR(&cxt->s_ip) = PI_IP4SRC(pi);
            IP4ADDR(&cxt->d_ip) = PI_IP4DST(pi);
        }else{
            cxt->s_ip = PI_IP6SRC(pi);
            cxt->d_ip = PI_IP6DST(pi);
        }
        cxt->s_port = pi->s_port;
        cxt->d_port = pi->d_port;
        cxt->proto = (pi->ip4 ? pi->ip4->ip_p : pi->ip6->next);
        cxt->check = 0x00;
        cxt->c_asset = NULL;
        cxt->s_asset = NULL;
        cxt->reversed = 0;
        pi->sc = SC_CLIENT;
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


