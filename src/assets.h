void add_asset (int af, struct in6_addr ip_addr, time_t discovered);
void del_asset (asset *passet, asset **bucket_ptr);
void del_os_asset (os_asset *prev_os, os_asset *passet);
void del_serv_asset (serv_asset *prev_service, serv_asset *passet);
