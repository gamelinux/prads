/* 
 * Author: Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * Created on January 16, 2010, 1:18 PM
 * Fixed a little by comotion, December 11th
 */

#ifndef _UTIL_CXT_H
#define _UTIL_CXT_H

#include "prads.h"


/* connection hash bucket -- the hash is basically an array of these buckets.
 * Each bucket contains a connection or list of connections. All these have
 * the same hashkey (the hash is a chained hash). */
typedef struct _cxtbucket {
    connection *cxt;
} cxtbucket;

extern connection *bucket[];

/* prototypes */
inline void cxt_update (packetinfo *);
connection *connection_alloc(void);
void cxt_update_dst (connection *cxt, packetinfo *pi);
void cxt_update_src (connection *cxt, packetinfo *pi);
inline void cxt_new (connection *cxt, packetinfo *pi);
void free_queue();
void reverse_pi_cxt(packetinfo *pi);
#endif /* _UTIL_CXT_H */
