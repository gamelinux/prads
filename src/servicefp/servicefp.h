#ifndef SERVICEFP_H
#define SERVIDEFP_H

void arp_check(char *eth_hdr, time_t tstamp);
int load_servicefp_file(char *sigfile, signature **db, int);
int parse_raw_signature(bstring line, int lineno, signature **dbp);
bstring get_app_name(signature * sig, const uint8_t *payload, int *ovector,
                     int rc);
bstring check_port(uint8_t proto, uint16_t port);
void service_tcp4(packetinfo *pi, signature *db);
void service_tcp6(packetinfo *pi, signature *db);
void service_udp4(packetinfo *pi, signature *db);
void service_udp6(packetinfo *pi, signature *db);
void client_tcp6(packetinfo *pi, signature *db);
void client_tcp4(packetinfo *pi, signature *db);
void del_signature_lists();
int add_service_sig(signature *sig, signature **dbp);
void add_known_services(uint8_t proto, uint16_t port, bstring service_name);
void del_known_services();
bstring check_known_port(uint8_t proto, uint16_t port);
void init_services();
void dump_sig_service(signature *sig, int len);

enum {SRV_NONE, SRV_TCP_SERVER=1, SRV_UDP_SERVER, SRV_TCP_CLIENT, SRV_UDP_CLIENT };

#define PAYLOAD_MIN 10
#endif// SERVICEFP_H
