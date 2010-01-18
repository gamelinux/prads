/*
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 */

#ifndef _UTIL_CXT_QUEUE_H
#define    _UTIL_CXT_QUEUE_H

#include "prads.h"

/* Define a queue for storing connection trackers */
typedef struct _cxtqueue
{
    connection *top;
    connection *bot;
    uint32_t len;
} cxtqueue;

/* spare/unused/prealloced connection trackers live here */
cxtqueue cxt_spare_q;

/* All "established" connections live here, the top holds the
 * last recently used (lru) connection */
cxtqueue cxt_est_q;

cxtqueue *cxtqueue_new();
void cxt_enqueue (cxtqueue *, connection *);
connection *cxt_dequeue (cxtqueue *);
void cxt_requeue(connection *, cxtqueue *, cxtqueue *);

#endif /* _UTIL_CXT_QUEUE_H */

