/*
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 */

#include <stddef.h>
#include "util-cxt-queue.h"

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
    if (cxt->prev != NULL) {
        q->bot = cxt->prev;
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
