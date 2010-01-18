/* 
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 */

#ifndef _UTIL_CXT_H
#define    _UTIL_CXT_H

#include "prads.h"

/* Define a queue for storing connection trackers */
typedef struct _cxtqueue
{
    connection *top;
    connection *bot;
    uint32_t len;
} cxtqueue;

/* connection hash bucket -- the hash is basically an array of these buckets.
 * Each bucket contains a connection or list of connections. All these have
 * the same hashkey (the hash is a chained hash). */
typedef struct _cxtbucket {
    connection *cxt;
} cxtbucket;

cxtbucket *cxt_hash;

/* spare/unused/prealloced connection trackers live here */
cxtqueue cxt_spare_q;

/* All "established" connections live here, the top holds the
 * last recently used (lru) connection */
cxtqueue cxt_est_q;

#define CMP_ADDR6(a1,a2) \
    (((a1)->s6_addr32[3] == (a2)->s6_addr32[3] && \
      (a1)->s6_addr32[2] == (a2)->s6_addr32[2] && \
      (a1)->s6_addr32[1] == (a2)->s6_addr32[1] && \
      (a1)->s6_addr32[0] == (a2)->s6_addr32[0]))

#define CMP_ADDR4(a1,a2) \
    (((a1)->s6_addr32[0] == (a2)->s6_addr32[0]))
#define CMP_PORT(p1,p2) \
    ((p1 == p2))

/* Since two or more connections can have the same hash key, we need to
 * compare the connections with the current hash key. */
#define CMP_CXT4(cxt1,src, sp, dst, dp) \
    ((CMP_ADDR4(&(cxt1)->s_ip, src) && \
       CMP_ADDR4(&(cxt1)->d_ip, dst) && \
       CMP_PORT((cxt1)->s_port, sp) && CMP_PORT((cxt1)->d_port, dp))) || \
      ((CMP_ADDR4(&(cxt1)->s_ip, dst) && \
       CMP_ADDR4(&(cxt1)->d_ip, src) && \
       CMP_PORT((cxt1)->s_port, dp) && CMP_PORT((cxt1)->d_port, sp)))

#define CMP_CXT6(cxt1,src, sp, dst, dp) \
    ((CMP_ADDR6(&(cxt1)->s_ip, src) && \
       CMP_ADDR6(&(cxt1)->d_ip, dst) && \
       CMP_PORT((cxt1)->s_port, sp) && CMP_PORT((cxt1)->d_port, dp))) || \
      ((CMP_ADDR6(&(cxt1)->s_ip, dst) && \
       CMP_ADDR6(&(cxt1)->d_ip, src) && \
       CMP_PORT((cxt1)->s_port, dp) && CMP_PORT((cxt1)->d_port, sp)))


cxtqueue *cxtqueue_new();
void cxt_enqueue (cxtqueue *, connection *);
connection *cxt_dequeue (cxtqueue *);
void cxt_requeue(connection *, cxtqueue *, cxtqueue *);
connection *cxt_get_from_hash (struct in6_addr *, uint16_t ,struct in6_addr *,
                               uint16_t , uint8_t , uint16_t , uint8_t , time_t,
                               int , uint32_t);
connection *connection_alloc(void);
void cxt_update_dst (connection *cxt, packetinfo *pi);
void cxt_update_src (connection *cxt, packetinfo *pi);
void cxt_new (connection *cxt, packetinfo *pi);
#endif /* _UTIL_CXT_H */
