void fp_icmp4 (ip4_header *ip4, icmp_header *icpmh, const uint8_t *end_ptr, struct in6_addr ip_src);
void fp_udp4 (ip4_header *ip4, udp_header *udph, const uint8_t *end_ptr, struct in6_addr ip_src);
void fp_tcp4 (ip4_header *ip4, tcp_header *tcph, const uint8_t *end_ptr, uint8_t ftype, struct in6_addr ip_src);
void fp_tcp6 (ip6_header *ip6, tcp_header *tcph, const uint8_t *end_ptr, uint8_t ftype);


