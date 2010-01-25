void arp_check(char *eth_hdr, time_t tstamp);
int load_servicefp_file(int storage, char *sigfile);
int parse_raw_signature(bstring line, int lineno, int storage);
bstring get_app_name(signature * sig, const char *payload, int *ovector,
                     int rc);
bstring check_port(uint8_t proto, uint16_t port);
void service_tcp4(ip4_header *ip4, tcp_header *tcph, const char *payload, int plen);
void service_tcp6(ip6_header *ip6, tcp_header *tcph, const char *payload, int plen);
void service_udp4(ip4_header *ip4, udp_header *udph, const char *payload, int plen);
void service_udp6(ip6_header *ip6, udp_header *udph, const char *payload, int plen);
void client_tcp6 (ip6_header *ip6, tcp_header *tcph, const char *payload, int plen);
void client_tcp4 (ip4_header *ip4, tcp_header *tcph, const char *payload, int plen);
void add_known_port(uint8_t proto, uint16_t port, bstring service_name);
void del_known_port(uint8_t proto);
void del_signature_lists();
