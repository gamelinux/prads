//#include "prads.h"

void add_asset (int af, struct in6_addr ip_addr, time_t discovered);
void del_asset (asset *passet, asset **bucket_ptr);
void del_os_assets (asset *passet);
void del_serv_assets (asset *passet);

const char *u_ntop(const struct in6_addr ip_addr, int af, const char *dest){
   if ( af == AF_INET) {
      if (!inet_ntop(AF_INET, &ip_addr.s6_addr32[0], dest, INET_ADDRSTRLEN + 1)){
         perror("Something died in inet_ntop");
         return NULL;
      }
   } else if ( af == AF_INET6) {
      if (!inet_ntop(AF_INET6, &ip_addr, dest, INET6_ADDRSTRLEN + 1)){
         perror("Something died in inet_ntop");
         return NULL;
      }
   }
   return dest;
}

/* looks to see if asset exists and update timestamp. If not, create the asset */
update_asset (int af, struct in6_addr ip_addr) {
   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   extern uint64_t hash;
   hash = (( ip_addr.s6_addr32[0] )) % BUCKET_SIZE;
   asset *rec = passet[hash];

   while ( rec != NULL ) {
      if (  rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] 
         && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
         && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
         && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3] ) {

         /* printf("[*] ASSET Timestamp updated\n"); */
         rec->last_seen = tstamp;
         return;
      }
   rec = rec->next;
  }
  /* If no match, create the asset */
  add_asset (af, ip_addr, tstamp);
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

//update_asset_os(ip_addr, port, detection, raw_fp, af);

short
update_asset_os ( struct in6_addr ip_addr,
                        u_int16_t port,
                        bstring   detection,
                        bstring   raw_fp,
                        int       af)
{

   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   extern uint64_t hash;
   hash = (( ip_addr.s6_addr32[0] )) % BUCKET_SIZE;
   asset *rec = passet[hash];
   //asset *rec = passet;

   int counter = 0;
   int asset_match   = 0;
   //printf("Incomming Asset, %s: %u:%u [%s]\n",(char*)bdata(detection),ip_addr.s6_addr32[0],ntohs(port),(char*)bdata(raw_fp));
   //bdestroy(raw_fp);
   //bdestroy(detection);
   //return 0;

   /* Find asset within linked list.  */
   while ( rec != NULL ) {
      //if (memcmp(&ip_addr,&rec->ip_addr,16)) {
      if (  rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
         && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2] && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3] ) {
         //printf("[*] FOUND ASSET\n");
      
         rec->last_seen = tstamp;
         asset_match = 1;
         os_asset *tmp_oa = NULL;
         os_asset *head_oa = NULL;
         tmp_oa = rec->os;
         head_oa = rec->os;

         while ( tmp_oa != NULL ) {
            if ( (bstricmp(detection,tmp_oa->detection) == 0 )
                  && (bstricmp(raw_fp,tmp_oa->raw_fp) == 0)) {
               /* Found! */
               bdestroy(tmp_oa->detection);
               tmp_oa->detection = bstrcpy(detection);
               bdestroy(tmp_oa->raw_fp);
               tmp_oa->raw_fp = bstrcpy(raw_fp);
               //tmp_sa->i_attempts++;
               tmp_oa->last_seen = tstamp;
               static char ip_addr_s[INET6_ADDRSTRLEN];
               u_ntop(ip_addr, af, ip_addr_s);
               printf("[*] asset %s fp update %16s\n", bdata(detection), ip_addr_s);
               bdestroy(raw_fp);
               bdestroy(detection);
               return 0;
            }
         tmp_oa = tmp_oa->next;
         }
            
         if (tmp_oa == NULL) {
            os_asset *new_oa = NULL;
            new_oa = (os_asset*)calloc(1,sizeof(os_asset));
            new_oa->detection = bstrcpy(detection);
            new_oa->raw_fp = bstrcpy(raw_fp);
            //tmp_oa->i_attempts = 1;
            new_oa->first_seen = tstamp;
            new_oa->last_seen = tstamp;
            new_oa->next = rec->os;
            new_oa->prev = NULL;
            //head_oa->prev = new_oa;
            rec->os = new_oa;

            /* verbose info for sanity checking */
            static char ip_addr_s[INET6_ADDRSTRLEN];
            if ( af == AF_INET) {
               if (!inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }
            else if ( af == AF_INET6) {
               if (!inet_ntop(AF_INET6, &ip_addr, ip_addr_s, INET6_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }
            if (port == 0) {
               printf("[*] client %s fp: %16s [%s]\n",(char *)bdata(detection),ip_addr_s,(char *)bdata(raw_fp));
            }
            else {
               printf("[*] server %s fp: %16s:%-5d [%s]\n",
                            (char *)bdata(detection),ip_addr_s,ntohs(port),(char *)bdata(raw_fp));
            }
            bdestroy(raw_fp);
            bdestroy(detection);
            return 0;
         }
      }
      rec = rec->next;
   }
   /* If no asset: */
   update_asset (af, ip_addr);
   update_asset_os(ip_addr, port, detection, raw_fp, af);
   bdestroy(raw_fp);
   bdestroy(detection);
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
short
update_asset_service ( struct in6_addr ip_addr,
              u_int16_t port,
              unsigned short proto,
              bstring service,
              bstring application,
              int af)
{
   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   extern uint64_t hash;
   hash = (( ip_addr.s6_addr32[0] )) % BUCKET_SIZE;
   asset *rec = passet[hash];
   //asset *rec = passet;

   int counter = 0;
   int asset_match   = 0;
   //printf("Incomming Asset: %d:%d:%d\n",ip_addr.s6_addr32[0],port,proto);
   
   /* Find asset within linked list.  */
   while ( rec != NULL ) {
      //if (memcmp(&ip_addr,&rec->ip_addr,16)) {
      if (  rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1] 
         && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2] && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3] ) {
         //printf("[*] FOUND ASSET\n");
         rec->last_seen = tstamp;
         asset_match = 1;
         serv_asset *tmp_sa = NULL;
         serv_asset *head_sa = NULL;
         tmp_sa = rec->services;
         head_sa = rec->services;

         if (tmp_sa == NULL) {
            serv_asset *new_sa = NULL;
            new_sa = (serv_asset*)calloc(1,sizeof(serv_asset));
            new_sa->port = port;
            new_sa->proto = proto;
            new_sa->service = bstrcpy(service);
            new_sa->application = bstrcpy(application);
            new_sa->i_attempts = 1;
            new_sa->first_seen = tstamp;
            new_sa->last_seen = tstamp;
            new_sa->next = rec->services;
            new_sa->prev = NULL;
            //head_sa->prev = new_sa; <-- head_sa->prev does not exist!
            rec->services = new_sa;

            /* verbose info for sanity checking */
            static char ip_addr_s[INET6_ADDRSTRLEN];
            if ( af == AF_INET) {
               if (!inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }
            else if ( af == AF_INET6) {
               if (!inet_ntop(AF_INET6, &ip_addr, ip_addr_s, INET6_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }
            if (port == 0) {
               printf("[*] new client: %s %s\n",ip_addr_s,(char *)bdata(application));
            }
            else {
               printf("[*] new service: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
            }
            return 0;
         }
         while ( tmp_sa != NULL ) {
            if (port == tmp_sa->port && proto == tmp_sa->proto
                  && (bstricmp(application,tmp_sa->application) == 0)) {
               /* Found! */
               bdestroy(tmp_sa->service);
               tmp_sa->service = bstrcpy(service);
               bdestroy(tmp_sa->application);
               tmp_sa->application = bstrcpy(application);
               //tmp_sa->i_attempts++;
               tmp_sa->last_seen = tstamp;
               if (port == 0) {
                  printf("[*] client asset updated\n");
               }
               else {
                  printf("[*] service asset updated\n");
               }
               return 0;
            }
            if (tmp_sa->next == NULL) {
               serv_asset *new_sa = NULL;
               new_sa = (serv_asset*)calloc(1,sizeof(serv_asset));
               new_sa->port = port;
               new_sa->proto = proto;
               new_sa->service = bstrcpy(service);
               new_sa->application = bstrcpy(application);
               //new_sa->i_attempts = 1;
               new_sa->first_seen = tstamp;
               new_sa->last_seen = tstamp;
               new_sa->next = rec->services;
               new_sa->prev = NULL;
               head_sa->prev = new_sa;
               rec->services = new_sa;

               /* verbose info for sanity checking */
               static char ip_addr_s[INET6_ADDRSTRLEN];
               if ( af == AF_INET) {
                  if (!inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 ))
                     perror("Something died in inet_ntop");
               }
               else if ( af == AF_INET6) {
                  if (!inet_ntop(AF_INET6, &ip_addr, ip_addr_s, INET6_ADDRSTRLEN + 1 ))
                     perror("Something died in inet_ntop");
               }
               if (port == 0) {
                  printf("[*] new client asset: %s %s\n",ip_addr_s,(char *)bdata(application));
               }
               else {
                  printf("[*] new service asset: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));
               }
               return 0;
            }
         tmp_sa = tmp_sa->next;
         }
      }
   rec = rec->next;
   }

   if (asset_match == 1) {
      printf("[*] NEED TO ADD SERVICE: Should not be here!\n"); // Service should have been added above
      return 1;
   }
   else if (asset_match == 0 ) {
      update_asset (af, ip_addr);
      //add_asset (af, ip_addr, time(NULL)); // <-- this should not be nessesary!
      update_asset_service(ip_addr, port, proto, service, application, af);
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
void
add_asset (int af, struct in6_addr ip_addr, time_t discovered) {

   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   extern uint64_t hash;
   hash = (( ip_addr.s6_addr32[0] )) % BUCKET_SIZE;
   //asset *rec = passet[hash];
   asset *rec = NULL;

   /* Assign list to temp structure.  */
   rec = (asset*)calloc(1,sizeof(asset));
   rec->ip_addr = ip_addr;
   rec->af = af;
   rec->i_attempts = 0;

   /* Should remove/rewrite this: */
   if (!discovered) {
      rec->first_seen = rec->last_seen = tstamp;
   } else {
      rec->first_seen = rec->last_seen = discovered;
   }

   /* 
    * Insert record at the head of the data structure.  The logic behind
    * this is to insert it at the head for quick access since it is going 
    * through the identification process.
    */
   //TAILQ_INSERT_HEAD(&assets, rec, next);
   rec->next           = passet[hash];
   rec->prev           = NULL;
   passet[hash] = rec;

   /* verbose info for sanity checking */
   static char ip_addr_s[INET6_ADDRSTRLEN];
   if ( af == AF_INET) {
      if (!inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 ))
         perror("Something died in inet_ntop");
   }
   else if ( af == AF_INET6) {
      if (!inet_ntop(AF_INET6, &ip_addr, ip_addr_s, INET6_ADDRSTRLEN + 1 ))
         perror("Something died in inet_ntop");
   }
   printf("[*] asset added: %s\n",ip_addr_s);
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
char* hex2mac(const char *mac) {

    static char buf[32];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        (mac[0] & 0xFF) , (mac[1] & 0xFF), (mac[2] & 0xFF),
        (mac[3] & 0xFF), (mac[4] & 0xFF), (mac[5] & 0xFF));

    return buf;
}

void update_asset_arp(u_int8_t arp_sha[MAC_ADDR_LEN], u_int8_t arp_spa[4]) {

   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   extern uint64_t hash;
   struct in6_addr ip_addr;
   memcpy(&ip_addr.s6_addr32[0], arp_spa, sizeof(u_int8_t) * 4);
   hash = (( ip_addr.s6_addr32[0] )) % BUCKET_SIZE;
   asset *rec = passet[hash];

   /* Check the ARP data structure for an existing entry. */
   while ( rec != NULL ) {
      if ( rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] ) { 
         if ( memcmp(rec->mac_addr, arp_sha, MAC_ADDR_LEN) == 0)  {
            /* UPDATE TIME STAMP */
            //rec->mac_addr = ;
            rec->last_seen = tstamp;
            return;
         }
         else {
            /* UPDATE MAC AND TIME STAMP */
            memcpy(&rec->mac_addr, arp_sha, MAC_ADDR_LEN);
            rec->last_seen = tstamp;
            /* For verbos sanity checking */
            static char ip_addr_s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
            printf("[*] added mac address to asset: %s\n",ip_addr_s);
            return;
         }
      }
   rec = rec->next;
   }

   /* ELSE add arp asset */
   asset *new = NULL;
   //bstring mac_resolved = NULL;

   new = (asset*) calloc(1,sizeof(asset));
   
   new->af = AF_INET;
   new->ip_addr.s6_addr32[0] = ip_addr.s6_addr32[0];
   new->ip_addr.s6_addr32[1] = 0;
   new->ip_addr.s6_addr32[2] = 0;
   new->ip_addr.s6_addr32[3] = 0;

   memcpy(&new->mac_addr, arp_sha, MAC_ADDR_LEN);
   //printf("MAC:%s\n",hex2mac((const char *)new->mac_addr));

   /* Attempt to resolve the vendor name of the MAC address. */
   //#ifndef DISABLE_VENDOR
   //mac_resolved = (bstring) get_vendor(mac_addr);
   //rec->mac_resolved = bstrcpy(mac_resolved);
   //#else
   //new->mac_addr = ?;
   new->mac_resolved = NULL;
   //#endif

   new->first_seen = tstamp;
   new->last_seen = tstamp;

   /* Insert ARP record into data structure. */
   //TAILQ_INSERT_HEAD(&arpassets, rec, next);
   new->next           = passet[BUCKET_SIZE];
   new->prev           = NULL;
   passet[BUCKET_SIZE] = new;

   static char ip_addr_s[INET6_ADDRSTRLEN];
   inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
   printf("[*] arp asset added: %s\n",ip_addr_s);
   return;
}

void del_assets (int ctime) {
   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   time_t check_time = tstamp;
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

void del_os_assets (asset *passet) {
   os_asset *tmp_oa = NULL;
   os_asset *next_oa = NULL;
   tmp_oa = passet->os;

   while ( tmp_oa != NULL ) {
      bdestroy(tmp_oa->vendor);
      bdestroy(tmp_oa->os);
      bdestroy(tmp_oa->detection);
      bdestroy(tmp_oa->raw_fp);
      bdestroy(tmp_oa->matched_fp);

      next_oa = tmp_oa->next;
      free(tmp_oa);
      tmp_oa=NULL;
      tmp_oa = next_oa;
   }
   return;

}

void del_serv_assets (asset *passet) {
   
   serv_asset *tmp_sa = NULL;
   serv_asset *next_sa = NULL;
   tmp_sa = passet->services;

   while ( tmp_sa != NULL ) {
printf("A\n");
      bdestroy(tmp_sa->service);
      bdestroy(tmp_sa->application);
      next_sa = tmp_sa->next;
      free(tmp_sa);
      tmp_sa=NULL;
      tmp_sa = next_sa;
   }
   return;
}

void del_asset (asset *passet, asset **bucket_ptr ){
   /* remove passet from bucket */
   asset *prev = passet->prev; /* OLDER connections */
   asset *next = passet->next; /* NEWER connections */
   if(prev == NULL){
      // beginning of list
      *bucket_ptr = next;
      // not only entry
      if(next)
         next->prev = NULL;
   } else if(next == NULL){
      // at end of list!
      prev->next = NULL;
   } else {
      // a node.
      prev->next = next;
      next->prev = prev;
   }

   /* Free and set to NULL */
   free(passet);
   passet=NULL;
}

void print_assets() {

   extern asset *passet[BUCKET_SIZE];
   extern time_t tstamp;
   extern uint64_t hash;
   asset *rec = NULL;
   //hash = (( ip_addr.s6_addr32[0] )) % BUCKET_SIZE;
   //asset *rec = passet[hash];
   //asset *rec = passet;
   int akey;

   for ( akey = 0; akey < BUCKET_SIZE; akey++ ) {
      rec = passet[akey];
      while ( rec != NULL ) {
         serv_asset *tmp_sa = NULL;
         os_asset *tmp_oa = NULL;
         tmp_sa = rec->services;
         tmp_oa = rec->os;

         /* verbose info for sanity checking */
         static char ip_addr_s[INET6_ADDRSTRLEN];
         if ( rec->af == AF_INET) {
            if (!inet_ntop(AF_INET, &rec->ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 ))
               perror("Something died in inet_ntop");
         }
         else if ( rec->af == AF_INET6) {
            if (!inet_ntop(AF_INET6, &rec->ip_addr, ip_addr_s, INET6_ADDRSTRLEN + 1 ))
               perror("Something died in inet_ntop");
         }

         printf("\n[*] %s",ip_addr_s);

         // help :)
         if (rec->mac_addr != 0x00000000) {
            //printf(",[arp:%s]",hex2mac((const char *)rec->mac_addr));
         }

         while ( tmp_sa != NULL ) {
            if (tmp_sa->port != 0) {
               //printf(",[service:%s]",(char*)bdata(tmp_sa->application));
            } else {
               //printf(",[client:%s]",(char*)bdata(tmp_sa->application));
            }
            if (tstamp - tmp_sa->last_seen > 600) {
               //printf("[*] we could delete this service-asset!");
               //del_service_asset(rec);
            }
            tmp_sa = tmp_sa->next;
         }

         while ( tmp_oa != NULL ) {
            //printf(",[%s:%s]",(char*)bdata(tmp_oa->detection),(char*)bdata(tmp_oa->raw_fp));
            if (tstamp - tmp_oa->last_seen > 600) {
               //printf("[*] We could delete this os-asset!");
               //del_os_asset(rec);
            }
            tmp_oa = tmp_oa->next;
         }

         if (tstamp - rec->last_seen > 6) {
            //printf("  *deleting this asset*\n");
            asset *tmp = rec;
            rec = rec->next;
            del_asset ( tmp, &passet[akey]);
            //del_asset(rec);
         } else {
            rec = rec->next;
         }
      }
   }
}

