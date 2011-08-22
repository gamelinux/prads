#define ASSET_HASH4(ip) ((ip) % BUCKET_SIZE)

#define ASSET_HASH6(ip) ( (ip).s6_addr32[3] % BUCKET_SIZE )

void add_asset(packetinfo *pi);
void del_asset(asset * passet, asset ** bucket_ptr);
void del_os_asset(os_asset ** prev_os, os_asset * passet);
void del_serv_asset(serv_asset ** prev_service, serv_asset * passet);
void update_asset(packetinfo *pi);
short update_asset_os(packetinfo *pi, uint8_t detection, bstring raw_fp, fp_entry *match, int uptime);
short update_asset_service(packetinfo *pi, bstring service, bstring application);
short update_asset_arp(u_int8_t arp_sha[MAC_ADDR_LEN], packetinfo *pi);
void clear_asset_list();
void update_asset_list();
void update_service_stats(int role, uint16_t proto);
uint8_t asset_lookup(packetinfo *pi);
