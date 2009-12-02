void end_sessions();
int  cx_track(struct in6_addr ip_src,uint16_t src_port,struct in6_addr ip_dst,uint16_t dst_port,
               uint8_t ip_proto,uint16_t p_bytes,uint8_t tcpflags,time_t tstamp, int af);
void del_connection (connection*, connection**);
