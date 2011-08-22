#ifndef CXT_H
#define CXT_H

#define CXT_HASH4(src,dst) \
   ((src + dst) % BUCKET_SIZE)

#define CXT_HASH6(src,dst) \
 (( \
  (src)->s6_addr32[0] + (src)->s6_addr32[1] + \
  (src)->s6_addr32[2] + (src)->s6_addr32[3] + \
  (dst)->s6_addr32[0] + (dst)->s6_addr32[1] + \
  (dst)->s6_addr32[2] + (dst)->s6_addr32[3] \
 ) % BUCKET_SIZE)

enum { CX_NONE, CX_HUMAN, CX_NEW, CX_ENDED, CX_EXPIRE };
void end_sessions();
void cxt_init();
int cx_track(packetinfo *pi);
/*struct in6_addr *ip_src, uint16_t src_port,
             struct in6_addr *ip_dst, uint16_t dst_port, uint8_t ip_proto,
             uint16_t p_bytes, uint8_t tcpflags, time_t tstamp, int af);
*/
void del_connection(connection *, connection **);
void cxt_write(connection *, FILE *fd, int human);
void cxt_write_all();

int connection_tracking(packetinfo *pi);
#endif // CXT_H
