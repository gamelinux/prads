void arp_check(char *eth_hdr, time_t tstamp);
int load_servicefp_file(int storage, char *sigfile);
int parse_raw_signature(bstring line, int lineno, int storage);
bstring get_app_name(signature * sig, const char *payload, int *ovector,
                     int rc);
