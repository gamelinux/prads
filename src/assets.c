#include "common.h"
#include "prads.h"
#include "assets.h"
#include "sys_func.h"
#include "output-plugins/log_dispatch.h"

extern globalconfig config;
// static strings for comparison
extern bstring UNKNOWN;

/* looks to see if asset exists and update timestamp. If not, create the asset */
void update_asset(int af, struct in6_addr ip_addr)
{
    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;
    hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
    asset *rec = passet[hash];

    while (rec != NULL) {
        if (rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0]
            && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
            && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
            && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3]) {

            /*
             * printf("[*] ASSET Timestamp updated\n"); 
             */
            rec->last_seen = tstamp;
            return;
        }
        rec = rec->next;
    }
    /*
     * If no match, create the asset 
     */
    add_asset(af, ip_addr);
    return;
}

/* ----------------------------------------------------------
 * FUNCTION     : update_asset_os
 * DESCRIPTION  : This function will update the OS
 *              : fields of an asset.
 * INPUT        : 0 - IP Address
 *              : 1 - Port
 *              : 2 - detection method
 *              : 3 - raw_fp
 *              : 4 - AF_INET/6
 * RETURN       : 0 - Success!
 *              : 1 - Failure!
 * ---------------------------------------------------------- */

short update_asset_os(struct in6_addr ip_addr,
                      u_int16_t port,
                      bstring detection, bstring raw_fp, int af, int uptime)
{

    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;
    hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
    asset *rec = passet[hash];
    //asset *rec = passet;

    int asset_match = 0;

    /*
     * Find asset within linked list.  
     */
    while (rec != NULL) {
        //if (memcmp(&ip_addr,&rec->ip_addr,16))
        if (rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0]
            && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
            && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
            && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3]) {
            //printf("[*] FOUND ASSET\n");
            //dlog("[%lu] Incoming asset, %s: %u:%u [%s]\n",
            //     tstamp, (char*)bdata(detection),ip_addr.s6_addr32[0],ntohs(port),(char*)bdata(raw_fp));

            rec->last_seen = tstamp;
            asset_match = 1;
            os_asset *tmp_oa = NULL;
            os_asset *head_oa = NULL;
            tmp_oa = rec->os;
            head_oa = rec->os;

            while (tmp_oa != NULL) {
                // 
                if ((biseq(detection, tmp_oa->detection) == 1)
                    && (biseq(raw_fp, tmp_oa->raw_fp) == 1)) {
                    /*
                     * Found! 
                     */
                    bdestroy(tmp_oa->detection);
                    tmp_oa->detection = bstrcpy(detection);
                    bdestroy(tmp_oa->raw_fp);
                    tmp_oa->raw_fp = bstrcpy(raw_fp);
                    //tmp_sa->i_attempts++;
                    tmp_oa->last_seen = tstamp;
                    if (uptime) tmp_oa->uptime = uptime;
                    //static char ip_addr_s[INET6_ADDRSTRLEN];
                    //u_ntop(ip_addr, af, ip_addr_s);
                    //dlog("[*] asset %s fp update %16s\n", bdata(detection), ip_addr_s);
                    return 0;
                }
                tmp_oa = tmp_oa->next;
            }

            if (tmp_oa == NULL) {
                os_asset *new_oa = NULL;
                new_oa = (os_asset *) calloc(1, sizeof(os_asset));
                new_oa->detection = bstrcpy(detection);
                new_oa->raw_fp = bstrcpy(raw_fp);
                //new_oa->i_attempts = 1;
                new_oa->first_seen = tstamp;
                new_oa->last_seen = tstamp;
                new_oa->port = port;
                if (uptime) new_oa->uptime = uptime;
                //new_oa->next = rec->os;
                new_oa->next = head_oa;
                if (head_oa != NULL)
                    head_oa->prev = new_oa;
                new_oa->prev = NULL;
                rec->os = new_oa;

                /*
                 * verbose info for sanity checking 
                 */
                log_asset_os(rec,new_oa);
                //static char ip_addr_s[INET6_ADDRSTRLEN];
                //u_ntop(rec->ip_addr, af, ip_addr_s);
                //dlog("[%lu] Incoming asset, %s: %s:%u [%s]\n",
                //     tstamp, (char*)bdata(detection),ip_addr_s,ntohs(port),(char*)bdata(raw_fp));
                return 0;
            }
        }
        rec = rec->next;
    }
    /*
     * If no asset: 
     */
    update_asset(af, ip_addr);
    update_asset_os(ip_addr, port, detection, raw_fp, af, uptime);
    // arguments must be destroyed by caller
    //bdestroy(raw_fp);
    //bdestroy(detection);
    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : update_asset
 * DESCRIPTION  : This function will update the service and
 *              : application fields of an asset.
 * INPUT        : 0 - IP Address
 *              : 1 - Port
 *              : 2 - Proto
 *              : 3 - Service
 *              : 4 - Application
 * RETURN       : 0 - Success!
 *              : 1 - Failure!
 * ---------------------------------------------------------- */
short update_asset_service(struct in6_addr ip_addr,
                           u_int16_t port,
                           unsigned short proto,
                           bstring service, bstring application, int af, int role)
{
    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;
    hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
    asset *rec = passet[hash];
    //asset *rec = passet;

    int asset_match = 0;
    //dlog("Incomming Asset: %d:%d:%d\n",ip_addr.s6_addr32[0],port,proto);

    /*
     * Find asset within linked list.  
     */
    while (rec != NULL) {
        //if (memcmp(&ip_addr,&rec->ip_addr,16)) {
        if (rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0]
            && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
            && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
            && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3]) {
            //printf("[*] FOUND ASSET\n");
            rec->last_seen = tstamp;
            asset_match = 1;
            serv_asset *tmp_sa = NULL;
            serv_asset *head_sa = NULL;
            tmp_sa = rec->services;
            head_sa = rec->services;

            if (tmp_sa == NULL) {
                serv_asset *new_sa = NULL;
                new_sa = (serv_asset *) calloc(1, sizeof(serv_asset));
                new_sa->port = port;
                new_sa->proto = proto;
                new_sa->service = bstrcpy(service);
                new_sa->application = bstrcpy(application);
                new_sa->role = role;
                new_sa->i_attempts = 0;
                new_sa->first_seen = tstamp;
                new_sa->last_seen = tstamp;
                new_sa->next = rec->services;
                new_sa->prev = NULL;
                //head_sa->prev = new_sa; <-- head_sa->prev does not exist!
                rec->services = new_sa;

                /*
                 * verbose info for sanity checking 
                 */
                log_asset_service(rec, new_sa);
                //static char ip_addr_s[INET6_ADDRSTRLEN];
                //u_ntop(ip_addr, af, ip_addr_s);
                //if (role == 1) {
                //    dlog("[*] new service: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
                //} else {
                //    dlog("[*] new client: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
                //}
                return 0;
            }
            while (tmp_sa != NULL) {
                if (port == tmp_sa->port && proto == tmp_sa->proto) {
                    /*
                     * Found! 
                     * If we have an id for the service which is != unknown AND the id now is unknown 
                     * - just increment i_attempts untill MAX_PKT_CHECK before replacing with unknown 
                     */
                    if (!(biseq(UNKNOWN, application) == 1)
                        &&
                        (biseq(UNKNOWN, tmp_sa->application))
                        == 1) {
                        tmp_sa->i_attempts = 0;
                        bdestroy(tmp_sa->service);
                        bdestroy(tmp_sa->application);
                        tmp_sa->service = bstrcpy(service);
                        tmp_sa->application = bstrcpy(application);
                        tmp_sa->last_seen = tstamp;

                        log_asset_service(rec,tmp_sa);
                        /*static char ip_addr_s[INET6_ADDRSTRLEN];
                        u_ntop(ip_addr, af, ip_addr_s);
                        if (role == 1) {
                            dlog("[*] service now known: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
                        } else {
                            dlog("[*] client now known: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
                        }*/

                        return 0;
                    } else if (!(biseq(application, tmp_sa->application) == 1)) {
                        if (tmp_sa->i_attempts > MAX_SERVICE_CHECK) {
                            tmp_sa->i_attempts = 0;
                            bdestroy(tmp_sa->service);
                            bdestroy(tmp_sa->application);
                            tmp_sa->service = bstrcpy(service);
                            tmp_sa->application = bstrcpy(application);
                            tmp_sa->last_seen = tstamp;

                            log_asset_service(rec,tmp_sa);
                            //static char ip_addr_s[INET6_ADDRSTRLEN];
                            //u_ntop(ip_addr, af, ip_addr_s);
                            //dlog("[*] changed service: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));

                            return 0;
                        } else {
                            tmp_sa->i_attempts++;
                            tmp_sa->last_seen = tstamp;
                            return 0;
                        }
                    } else {
                        tmp_sa->i_attempts = 0;
                        tmp_sa->last_seen = tstamp;
                        return 0;
                    }
                }
                if (tmp_sa->next == NULL) {
                    serv_asset *new_sa = NULL;
                    new_sa = (serv_asset *) calloc(1, sizeof(serv_asset));
                    new_sa->port = port;
                    new_sa->proto = proto;
                    new_sa->service = bstrcpy(service);
                    new_sa->application = bstrcpy(application);
                    new_sa->role = role;
                    new_sa->i_attempts = 0;
                    new_sa->first_seen = tstamp;
                    new_sa->last_seen = tstamp;
                    new_sa->next = rec->services;
                    new_sa->prev = NULL;
                    head_sa->prev = new_sa;
                    rec->services = new_sa;

                    log_asset_service(rec, new_sa);
                    /*
                     * verbose info for sanity checking 
                     */
                    //if (role == 2) {
                    //   printf("[*] new client asset: %s %s\n",ip_addr_s,(char *)bdata(application));
                    //}
                    //else {
                    //   printf("[*] new service asset: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
                    //}
                    return 0;
                }
                tmp_sa = tmp_sa->next;
            }
        }
        rec = rec->next;
    }

    if (asset_match == 1) {
        printf("[*] NEED TO ADD SERVICE: Should not be here!\n");       // Service should have been added above
        return 1;
    } else if (asset_match == 0) {
        update_asset(af, ip_addr);
        update_asset_service(ip_addr, port, proto, service, application,
                             af, role);
        return 0;
    }
    printf("[*] Im I here ?\n");
    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION     : add_asset
 * DESCRIPTION  : This function will add an asset to the
 *              : specified asset data structure.
 * INPUT        : 0 - AF_INET
 *              : 1 - IP Address
 *              : 2 - Discovered
 * RETURN       : None!
 * ---------------------------------------------------------- */
void add_asset(int af, struct in6_addr ip_addr)
{

    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;
    hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
    //asset *rec = passet[hash];
    asset *rec = NULL;

    /*
     * Assign list to temp structure.  
     */
    rec = (asset *) calloc(1, sizeof(asset));
    rec->ip_addr = ip_addr;
    rec->af = af;
    rec->i_attempts = 0;
    rec->first_seen = rec->last_seen = tstamp;

    /*
     * Insert record at the head of the data structure.  The logic behind
     * this is to insert it at the head for quick access since it is going 
     * through the identification process.
     */
    rec->next = passet[hash];
    if (passet[hash] != NULL)
        passet[hash]->prev = rec;
    rec->prev = NULL;
    rec->os = NULL;
    rec->services = NULL;
    passet[hash] = rec;

    /*
     * verbose info for sanity checking 
     */
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(ip_addr, af, ip_addr_s);
    dlog("[*] asset added: %s\n",ip_addr_s);
    
    return;
}

/* ----------------------------------------------------------
 * FUNCTION     : hex2mac
 * DESCRIPTION  : Converts a hex representation of a MAC
 *              : address into an ASCII string.  This is a
 *              : more portable equivalent of 'ether_ntoa'.
 * INPUT        : 0 - MAC Hex Address
 * RETURN       : 0 - MAC Address String
 * ---------------------------------------------------------- */
/*char *hex2mac(const char *mac)
{

    static char buf[32];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             (mac[0] & 0xFF), (mac[1] & 0xFF), (mac[2] & 0xFF),
             (mac[3] & 0xFF), (mac[4] & 0xFF), (mac[5] & 0xFF));

    return buf;
}*/

void update_asset_arp(u_int8_t arp_sha[MAC_ADDR_LEN],
                      struct in6_addr ip_addr)
{

    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;

    hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
    asset *rec = passet[hash];

    /*
     * Check the ARP data structure for an existing entry. 
     */
    while (rec != NULL) {
        if (rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0]) {
            if (memcmp(rec->mac_addr, arp_sha, MAC_ADDR_LEN) == 0) {
                /*
                 * UPDATE TIME STAMP 
                 */
                //rec->mac_addr = ;
                rec->last_seen = tstamp;
                return;
            } else {
                /*
                 * UPDATE MAC AND TIME STAMP 
                 */
                memcpy(&rec->mac_addr, arp_sha, MAC_ADDR_LEN);
                rec->last_seen = tstamp;
                /*
                 * For verbos sanity checking 
                 */
                static char ip_addr_s[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
                dlog("[*] added mac address to asset: %s\n",ip_addr_s);
                return;
            }
        }
        rec = rec->next;
    }

    /*
     * ELSE add arp asset 
     */
    asset *new = NULL;
    //bstring mac_resolved = NULL;

    new = (asset *) calloc(1, sizeof(asset));

    new->af = AF_INET;
    new->ip_addr.s6_addr32[0] = ip_addr.s6_addr32[0];
    new->ip_addr.s6_addr32[1] = 0;
    new->ip_addr.s6_addr32[2] = 0;
    new->ip_addr.s6_addr32[3] = 0;

    memcpy(&new->mac_addr, arp_sha, MAC_ADDR_LEN);
    //printf("MAC:%s\n",hex2mac((const char *)new->mac_addr));

    /*
     * Attempt to resolve the vendor name of the MAC address. 
     */
    //#ifndef DISABLE_VENDOR
    //mac_resolved = (bstring) get_vendor(mac_addr);
    //rec->mac_resolved = bstrcpy(mac_resolved);
    //#else
    //new->mac_addr = ?;
    new->mac_resolved = NULL;
    //#endif

    new->first_seen = tstamp;
    new->last_seen = tstamp;

    /*
     * Insert ARP record into data structure. 
     */
    new->next = passet[hash];
    new->prev = NULL;
    if (passet[hash] != NULL)
        passet[hash]->prev = new;
    passet[hash] = new;

    static char ip_addr_s[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
    dlog("[*] arp asset added: %s\n",ip_addr_s);

    return;
}

void del_assets(int ctime)
{
    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    //time_t check_time = tstamp;
    //extern asset *bucket[BUCKET_SIZE];
    //for ( int akey = 0; akey < BUCKET_SIZE; akey++ ) {
    //   passet = bucket[akey];
    //   xpir = 0;
//   while ( passet != NULL ) {
//      if ( (passet->last_seen - check_time) >= ctime ) {
//         del_serv_assets(passet);
//         del_os_assets(passet);
    //del_asset(passet, &bucket[akey]);
//      }
//   }
}

void del_os_asset(os_asset ** head_oa, os_asset * os)
{

    if (os == NULL)
        return;
    os_asset *tmp_oa = NULL;
    os_asset *next_oa = NULL;
    os_asset *prev_oa = NULL;

    tmp_oa = os;
    //bdestroy(tmp_oa->vendor);
    //bdestroy(tmp_oa->os);
    bdestroy(tmp_oa->detection);
    bdestroy(tmp_oa->raw_fp);
    //bdestroy(tmp_oa->matched_fp);

    next_oa = tmp_oa->next;
    prev_oa = tmp_oa->prev;

    if (prev_oa == NULL) {
        /*
         * beginning of list 
         */
        *head_oa = next_oa;
        /*
         * not only entry 
         */
        if (next_oa)
            next_oa->prev = NULL;
    } else if (next_oa == NULL) {
        /*
         * at end of list! 
         */
        prev_oa->next = NULL;
    } else {
        /*
         * a node 
         */
        prev_oa->next = next_oa;
        next_oa->prev = prev_oa;
    }

    free(tmp_oa);
    tmp_oa = NULL;
    os = next_oa;
    return;

}

void del_serv_asset(serv_asset ** head_sa, serv_asset * service)
{

    if (service == NULL)
        return;
    serv_asset *tmp_sa = NULL;
    serv_asset *next_sa = NULL;
    serv_asset *prev_sa = NULL;

    tmp_sa = service;
    bdestroy(tmp_sa->service);
    bdestroy(tmp_sa->application);

    next_sa = tmp_sa->next;
    prev_sa = tmp_sa->prev;

    if (prev_sa == NULL) {
        /*
         * beginning of list 
         */
        *head_sa = next_sa;
        /*
         * not only entry 
         */
        if (next_sa)
            next_sa->prev = NULL;
    } else if (next_sa == NULL) {
        /*
         * at end of list! 
         */
        prev_sa->next = NULL;
    } else {
        /*
         * a node 
         */
        prev_sa->next = next_sa;
        next_sa->prev = prev_sa;
    }

    free(service);
    service = NULL;
    service = next_sa;
    return;
}

void del_asset(asset * passet, asset ** bucket_ptr)
{
    /*
     * remove passet from bucket 
     */
    asset *prev = passet->prev; /* OLDER connections */
    asset *next = passet->next; /* NEWER connections */
    serv_asset *tmp_sa = passet->services;
    os_asset *tmp_oa = passet->os;
    serv_asset *stmp = tmp_sa;
    os_asset *otmp = tmp_oa;

    /*
     * delete all service assets 
     */
    while (tmp_sa != NULL) {
        stmp = tmp_sa;
        tmp_sa = tmp_sa->next;
        del_serv_asset(&passet->services, stmp);
    }
    /*
     * delete all os assets 
     */
    while (tmp_oa != NULL) {
        otmp = tmp_oa;
        tmp_oa = tmp_oa->next;
        del_os_asset(&passet->os, otmp);
    }

    /*
     * now delete the asset 
     */
    if (prev == NULL) {
        // beginning of list
        *bucket_ptr = next;
        // not only entry
        if (next)
            next->prev = NULL;
    } else if (next == NULL) {
        // at end of list!
        prev->next = NULL;
    } else {
        // a node.
        prev->next = next;
        next->prev = prev;
    }

    /*
     * Free and set to NULL 
     */
    bdestroy(passet->mac_resolved);
    free(passet);
    passet = NULL;
}

void clear_asset_list()
{
    extern asset *passet[BUCKET_SIZE];
    asset *rec = NULL;
    int akey;

    for (akey = 0; akey < BUCKET_SIZE; akey++) {
        rec = passet[akey];
        while (rec != NULL) {
            serv_asset *tmp_sa = NULL;
            os_asset   *tmp_oa = NULL;
            tmp_sa = rec->services;
            tmp_oa = rec->os;

            while (tmp_sa != NULL) {
                /* Delete service asset */
                serv_asset *stmp = tmp_sa;
                tmp_sa = tmp_sa->next;
                del_serv_asset(&rec->services, stmp);
            }

            while (tmp_oa != NULL) {
                /* Delete os asset */
                os_asset *otmp = tmp_oa;
                tmp_oa = tmp_oa->next;
                del_os_asset(&rec->os, otmp);
            }
                
            /* Delete the main asset */
            asset *tmp = rec;
            rec = rec->next;
            del_asset(tmp, &passet[akey]);
        }
    }
    printf("\nasset memory has been cleared");
}

void update_asset_list()
{
    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;
    asset *rec = NULL;
    int akey;

    for (akey = 0; akey < BUCKET_SIZE; akey++) {
        rec = passet[akey];
        while (rec != NULL) {
            /* Checks if something has been updated in the asset since last time */
            if (tstamp - rec->last_seen <= CHECK_TIMEOUT) {
                serv_asset *tmp_sa = NULL;
                os_asset *tmp_oa = NULL;
                tmp_sa = rec->services;
                tmp_oa = rec->os;
                if (config.print_updates) log_asset_arp(rec);

                while (tmp_sa != NULL) {
                    /* Just print out the asset if it is updated since lasttime */
                    if (config.print_updates && tstamp - tmp_sa->last_seen <= CHECK_TIMEOUT) {
                        log_asset_service(rec,tmp_sa);
                    }
                    /* If the asset is getting too old - delete it */
                    if (config.print_updates && tstamp - tmp_sa->last_seen >= ASSET_TIMEOUT) {
                        serv_asset *stmp = tmp_sa;
                        tmp_sa = tmp_sa->next;
                        del_serv_asset(&rec->services, stmp);
                    } else {
                        tmp_sa = tmp_sa->next;
                    }
                }

                while (tmp_oa != NULL) {
                    /* Just print out the asset if it is updated since lasttime */
                    if (config.print_updates && tstamp - tmp_oa->last_seen <= CHECK_TIMEOUT) {
                        log_asset_os(rec, tmp_oa);
                    }
                    /* If the asset is getting too old - delete it */
                    if (tstamp - tmp_oa->last_seen >= ASSET_TIMEOUT) {
                        os_asset *otmp = tmp_oa;
                        tmp_oa = tmp_oa->next;
                        del_os_asset(&rec->os, otmp);
                    } else {
                        tmp_oa = tmp_oa->next;
                    }
                }
            }

            /* If nothing in the asset has been updated for some time - delete it! */
            if (tstamp - rec->last_seen >= ASSET_TIMEOUT) {
                asset *tmp = rec;
                rec = rec->next;
                del_asset(tmp, &passet[akey]);
            } else {
                rec = rec->next;
            }
        }
    }
}
