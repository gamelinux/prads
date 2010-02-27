void fp_icmp4(packetinfo *pi, ip4_header * ip4, icmp_header * icpmh,
              const uint8_t * end_ptr);
void fp_icmp6(packetinfo *pi, ip6_header * ip6, icmp6_header * icpmh,
              const uint8_t * end_ptr);
void fp_udp4(packetinfo *pi, ip4_header * ip4, udp_header * udph, const uint8_t * end_ptr);
             //struct in6_addr ip_src);

/* going once, going twice  ... */
//void fp_tcp(packetinfo *pi, uint8_t ftype);

// fix me
fp_entry *fp_tcp(packetinfo *pi, uint8_t ftype);


//void gen_fp_tcp(uint8_t ttl, uint16_t tot, uint8_t df, uint8_t * op,
//                uint8_t ocnt, uint16_t mss, uint16_t wss, uint8_t wsc,
//                uint32_t tstamp, uint32_t quirks, uint8_t ftype,
//                //struct in6_addr ip_src, uint16_t port, int af);
//                packetinfo *pi);

void gen_fp_udp(uint16_t totlen, uint16_t udata, uint8_t ttl, uint8_t df,
                int32_t olen, uint16_t ip_len, uint16_t ip_off, uint8_t ip_tos,
                uint32_t quirks,
                //struct in6_addr ip_src, uint16_t port, int af);
                packetinfo *pi);

void gen_fp_icmp(uint8_t type, uint8_t code, uint8_t ttl, uint8_t df,
                 int32_t olen, uint16_t totlen, uint8_t idata, uint16_t ip_off,
                 uint8_t ip_tos, uint32_t quirks,
                 //struct in6_addr ip_src, int af);
                 packetinfo *pi);

uint8_t normalize_ttl (uint8_t ttl);
