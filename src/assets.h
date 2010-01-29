void add_asset(int af, struct in6_addr ip_addr);
void del_asset(asset * passet, asset ** bucket_ptr);
void del_os_asset(os_asset ** prev_os, os_asset * passet);
void del_serv_asset(serv_asset ** prev_service, serv_asset * passet);
void update_asset(int af, struct in6_addr ip_addr);
short update_asset_os(struct in6_addr ip_addr,
                      u_int16_t port, bstring detection,
                      bstring raw_fp, int af, int uptime);
short update_asset_service(struct in6_addr ip_addr, u_int16_t port,
                           unsigned short proto, bstring service,
                           bstring application, int af, int role);
void update_asset_arp(u_int8_t arp_sha[MAC_ADDR_LEN], struct in6_addr ip_addr);
void clear_asset_list();
void update_asset_list();
void update_service_stats(int role, uint16_t proto);
