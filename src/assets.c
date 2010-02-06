#include "common.h"
#include "prads.h"
#include "assets.h"
#include "sys_func.h"
#include "output-plugins/log_dispatch.h"
#include "config.h"

extern globalconfig config;
// static strings for comparison
extern bstring UNKNOWN;

/* looks to see if asset exists and update timestamp. If not, create the asset */
void update_asset(int af, struct in6_addr ip_addr)
{
    extern asset *passet[BUCKET_SIZE];
    extern time_t tstamp;
    extern uint64_t hash;
    if (af == AF_INET) {
        hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
        asset *rec = passet[hash];
        while (rec != NULL) {
            if (rec->af == AF_INET
                && rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0]) {
                rec->last_seen = tstamp;
                return;
            }
            rec = rec->next;
        }
    } else if (af == AF_INET6) {
        hash = ((ip_addr.s6_addr32[3])) % BUCKET_SIZE;
        asset *rec = passet[hash];
        while (rec != NULL) {
            if (rec->af == AF_INET6 
                && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3]
                && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
                && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
                && rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0]) {
                rec->last_seen = tstamp;
                return;
            }
            rec = rec->next;
        }
    }
    /* If no match, create the asset */
    add_asset(af, ip_addr);
    return;
}

void update_service_stats(int role, uint16_t proto)
{
    if (role==1) {
        if (proto== 6) config.pr_s.tcp_services++;
        if (proto==17) config.pr_s.udp_services++;
    } else {
        if (proto== 6) config.pr_s.tcp_clients++;
        if (proto==17) config.pr_s.udp_clients++;
    }
}

void update_os_stats(uint8_t detection)
{
    switch (detection) {
        // fallthrough
        case CO_SYN:
        case CO_SYNACK:
        case CO_ACK:
        case CO_FIN:
        case CO_RST:
            config.pr_s.tcp_os_assets++;
            break;
        case CO_UDP:
            config.pr_s.udp_os_assets++;
            break;
        case CO_ICMP:
            config.pr_s.icmp_os_assets++;
            break;
        case CO_DHCP:
            config.pr_s.dhcp_os_assets++;
            break;
        default:
            break;
    }
}

asset *asset_lookup(struct in6_addr ip, int af)
{
    extern asset *passet[BUCKET_SIZE];
    uint64_t hash;
    asset *masset = NULL;

    if (af == AF_INET) {
        hash = ((ip.s6_addr32[0])) % BUCKET_SIZE;
        masset = passet[hash];
        while (masset != NULL) {
            //if (memcmp(&ip_addr,&rec->ip_addr,16)) {
            if (masset->af == AF_INET
                && masset->ip_addr.s6_addr32[0] == ip.s6_addr32[0]) {
                return masset;
            }
            masset = masset->next;
        }
        return NULL;
    } else if (af == AF_INET6) {
        hash = ((ip.s6_addr32[3])) % BUCKET_SIZE;
        masset = passet[hash];
        while (masset != NULL) {
            if (masset->af == AF_INET6
                && masset->ip_addr.s6_addr32[3] == ip.s6_addr32[3]
                && masset->ip_addr.s6_addr32[2] == ip.s6_addr32[2]
                && masset->ip_addr.s6_addr32[1] == ip.s6_addr32[1]
                && masset->ip_addr.s6_addr32[0] == ip.s6_addr32[0]) {
                return masset;
            }
            masset = masset->next;
        }
        return NULL;
    }
    return NULL;
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
 *              : 5 - uptime
 * RETURN       : 0 - Success!
 *              : 1 - Failure!
 * ---------------------------------------------------------- */

short update_asset_shmem(packetinfo *pi)
{
    // flip it upside down: caller packs it?
    // now how would that eat the program from the inside?
    // pass the struct around but store it in a shared mem buffer
    pi->ip_src; // src has the fingerprint
    pi->ip_dst; // we r doing for both, now? - packet payload may be spooft
    pi->s_port;
    // what is detection?
    //detection;
    // must include this
    //pi->raw_fp;
    pi->af;
    //pi->uptime;
    // what more do we need in the *pi?
    switch(pi->type){
        case SIGNATURE:
        // signatures identify HOSTS or SERVICES
        // (or mac resources) .. eventually have graph method
            return 1; // we did the computation straight on the *pi;
        case FINGERPRINT:
            //update_asset_os_shmem(pi);
            return 2; // whatever
        default:
            return 1338; // not leet.
    }
}

short update_asset_os(struct in6_addr ip_addr,
                      u_int16_t port,
                      uint8_t detection, bstring raw_fp, int af, int uptime)
{
    extern time_t tstamp;
    asset *rec = NULL;

    rec = asset_lookup(ip_addr, af);
    if (rec != NULL) {
        goto os_update;
    } else {
        /* If no asset */
        update_asset(af, ip_addr);
        if (update_asset_os(ip_addr, port, detection, raw_fp, af, uptime) == 0) return 0;
        return 1;
    }

os_update:
    //printf("[*] FOUND ASSET\n");
    //dlog("[%lu] Incoming asset, %s: %u:%u [%s]\n",
    //     tstamp, (char*)bdata(detection),ip_addr.s6_addr32[0],ntohs(port),(char*)bdata(raw_fp));
    rec->last_seen = tstamp;
    os_asset *tmp_oa = NULL;
    os_asset *head_oa = NULL;
    tmp_oa = rec->os;
    head_oa = rec->os;

    while (tmp_oa != NULL) {
        if (detection == tmp_oa->detection
            && (biseq(raw_fp, tmp_oa->raw_fp) == 1)) {
            /* Found! */
            tmp_oa->detection = detection;
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
        update_os_stats(detection);
        os_asset *new_oa = NULL;
        // FIXME: allocate resource from shared storage pool
        new_oa = (os_asset *) calloc(1, sizeof(os_asset));
        new_oa->detection = detection;
        // FIXME: don't copy fp, bincode it
        new_oa->raw_fp = bstrcpy(raw_fp);
        //new_oa->i_attempts = 1;
        new_oa->first_seen = tstamp;
        new_oa->last_seen = tstamp;
        new_oa->port = port;
        if (uptime) new_oa->uptime = uptime;
        new_oa->next = head_oa;
        if (head_oa != NULL)
            head_oa->prev = new_oa;
        new_oa->prev = NULL;
        rec->os = new_oa;

        log_asset_os(rec,new_oa);
        return 0;
    }
    return 1;
}

/* ----------------------------------------------------------
 * FUNCTION     : update_asset_service
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
short update_asset_service(packetinfo *pi, bstring service, bstring application)
{
    extern time_t tstamp;
    asset *rec = NULL;
    uint16_t port;

    if (pi->cxt->reversed == 0) {
        rec = asset_lookup(pi->ip_src, pi->af);
        if (pi->sc == SC_CLIENT) {
            port = pi->d_port;
        } else {
            port = pi->s_port;
        }
    } else {
        rec = asset_lookup(pi->ip_dst, pi->af);
        if (pi->sc == SC_CLIENT) {
            port = pi->s_port;
        } else {
            port = pi->d_port;
        }
    }

    if (rec != NULL) {
        goto service_update;
    } else {
        /* If no asset */
        if (pi->cxt->reversed == 0) update_asset(pi->af, pi->ip_src);
            else update_asset(pi->af, pi->ip_dst);
        if (update_asset_service(pi, service, application) == 0) return 0;
        return 1;
    }

service_update:

    //dlog("Incomming Asset: %d:%d:%d\n",ip_addr.s6_addr32[0],port,proto);
    /* Find asset within linked list */
    //printf("[*] FOUND ASSET\n");
    rec->last_seen = tstamp;
    serv_asset *tmp_sa = NULL;
    serv_asset *head_sa = NULL;
    tmp_sa = rec->services;
    head_sa = rec->services;

    while (tmp_sa != NULL) {
        if (port == tmp_sa->port && pi->proto == tmp_sa->proto) {
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
                return 0;

            } else if (!(biseq(application, tmp_sa->application) == 1)) {
                if (tmp_sa->i_attempts > MAX_PKT_CHECK*2) {
                    tmp_sa->i_attempts = 0;
                    bdestroy(tmp_sa->service);
                    bdestroy(tmp_sa->application);
                    tmp_sa->service = bstrcpy(service);
                    tmp_sa->application = bstrcpy(application);
                    tmp_sa->last_seen = tstamp;

                    log_asset_service(rec,tmp_sa);
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
        tmp_sa = tmp_sa->next;
    }

    if (tmp_sa == NULL) {
        update_service_stats(pi->sc, pi->proto);
        serv_asset *new_sa = NULL;
        new_sa = (serv_asset *) calloc(1, sizeof(serv_asset));
        new_sa->port = port;
        new_sa->proto = pi->proto;
        new_sa->service = bstrcpy(service);
        new_sa->application = bstrcpy(application);
        new_sa->role = pi->sc;
        new_sa->i_attempts = 0;
        new_sa->first_seen = tstamp;
        new_sa->last_seen = tstamp;
        new_sa->next = rec->services;
        new_sa->prev = NULL;
        rec->services = new_sa;

        log_asset_service(rec, new_sa);
        return 0;
    }
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
    config.pr_s.assets++;

    if (af == AF_INET) {
        hash = ((ip_addr.s6_addr32[0])) % BUCKET_SIZE;
    } else if (af == AF_INET6) {
        hash = ((ip_addr.s6_addr32[3])) % BUCKET_SIZE;
    }

    /* Assign list to temp structure */
    asset *rec = NULL;
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

    /* verbose info for sanity checking */
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop(ip_addr, af, ip_addr_s);
    dlog("[*] asset added: %s\n",ip_addr_s);
    
    return;
}

short update_asset_arp(u_int8_t arp_sha[MAC_ADDR_LEN],
                         struct in6_addr ip_addr)
{
    extern time_t tstamp;
    asset *rec = NULL;

    rec = asset_lookup(ip_addr, AF_INET);
    if (rec != NULL) {
        goto arp_update;
    } else {
        /* If no asset */
        update_asset(AF_INET, ip_addr);
        if (update_asset_arp(arp_sha, ip_addr) == 0) return 0;
        return 1;
    }

arp_update:
    /* Check the ARP data structure for an existing entry */
    if (memcmp(rec->mac_addr, arp_sha, MAC_ADDR_LEN) == 0) {
        /* UPDATE TIME STAMP */
        rec->last_seen = tstamp;
        return 0;
    } else {
        /* UPDATE MAC AND TIME STAMP */
        memcpy(&rec->mac_addr, arp_sha, MAC_ADDR_LEN);
        rec->last_seen = tstamp;
        log_asset_arp(rec);
        /* For verbos sanity checking */
        //static char ip_addr_s[INET6_ADDRSTRLEN];
        //inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
        //dlog("[*] added mac address to asset: %s\n",ip_addr_s);
        return 0;
    }
    return 1;
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
