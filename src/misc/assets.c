//#include "prads.h"

void add_asset (int af, struct in6_addr ip_addr, time_t discovered);
void del_asset (asset *passet, asset **bucket_ptr);
void del_os_assets (asset *passet);
void del_serv_assets (asset *passet);

/* looks to see if asset exists and update timestamp. If not, create the asset */
update_asset (int af, struct in6_addr ip_addr) {
   extern asset *passet;
   asset *rec = passet;

   while ( rec != NULL ) {
      if (  rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] 
         && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
         && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
         && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3] ) {

         /* printf("[*] ASSET Timestamp updated\n"); */
         rec->last_seen = time(NULL);
         return;
      }
   rec = rec->next;
  }
  /* If no match, create the asset */
  add_asset (af, ip_addr, time(NULL));
  return;
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
   extern asset *passet;
   asset *rec = passet;
   int counter = 0;
   int asset_match   = 0;
   //printf("Incomming Asset: %d:%d:%d\n",ip_addr.s6_addr32[0],port,proto);
   
   /* Find asset within linked list.  */
   while ( rec != NULL ) {
      //if (memcmp(&ip_addr,&rec->ip_addr,16)) {
      if (  rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1] 
         && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2] && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3] ) {
         printf("[*] FOUND ASSET\n");
         rec->last_seen = time(NULL);
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
            new_sa->first_seen = time(NULL);
            new_sa->last_seen = time(NULL);
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
            printf("[*] ADDED NEW SERVICE TO ASSET: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));

            return 0;
         }
         while ( tmp_sa != NULL ) {
            if (port == tmp_sa->port && proto == tmp_sa->proto) {
               /* Found! */
               bdestroy(tmp_sa->service);
               tmp_sa->service = bstrcpy(service);
               bdestroy(tmp_sa->application);
               tmp_sa->application = bstrcpy(application);
               //tmp_sa->i_attempts++;
               tmp_sa->last_seen = time(NULL);
               printf("[*] SERVICE ASSET UPDATED\n");
               return 0;
            }
            if (tmp_sa->next == NULL) {
               serv_asset *new_sa = NULL;
               new_sa = (serv_asset*)calloc(1,sizeof(serv_asset));
               new_sa->port = port;
               new_sa->proto = proto;
               new_sa->service = bstrcpy(service);
               new_sa->application = bstrcpy(application);
               tmp_sa->i_attempts = 1;
               new_sa->first_seen = time(NULL);
               new_sa->last_seen = time(NULL);
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
               printf("[*] ADDED NEW SERVICE TO ASSET: %s:%d %s\n",ip_addr_s,ntohs(port),(char *)bdata(application));

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

   extern asset *passet;
   asset *rec = NULL;

   /* Assign list to temp structure.  */
   rec = (asset*)calloc(1,sizeof(asset));
   rec->ip_addr = ip_addr;
   rec->af = af;
   rec->i_attempts = 0;

   /* Should remove/rewrite this: */
   if (!discovered) {
      rec->first_seen = rec->last_seen = time(NULL);
   } else {
      rec->first_seen = rec->last_seen = discovered;
   }

   /* 
    * Insert record at the head of the data structure.  The logic behind
    * this is to insert it at the head for quick access since it is going 
    * through the identification process.
    */
   //TAILQ_INSERT_HEAD(&assets, rec, next);
   rec->next           = passet;
   rec->prev           = NULL;
   passet = rec;

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
   printf("[*] ASSET ADDED: %s\n",ip_addr_s);
   return;
}

void update_asset_arp(u_int8_t arp_sha[MAC_ADDR_LEN], u_int8_t arp_spa[4]) {

   extern asset *passet;
   asset *rec = passet;
   struct in6_addr ip_addr;
   memcpy(&ip_addr.s6_addr32[0], arp_spa, sizeof(u_int8_t) * 4);

   /* Check the ARP data structure for an existing entry. */
   while ( rec != NULL ) {
      if ( rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] ) { 
         if ( memcmp(rec->mac_addr, arp_sha, MAC_ADDR_LEN) == 0)  {
            /* UPDATE TIME STAMP */
            //rec->mac_addr = ;
            rec->last_seen = time(NULL);
            return;
         }
         else {
            /* UPDATE MAC AND TIME STAMP */
            memcpy(&rec->mac_addr, arp_sha, MAC_ADDR_LEN);
            rec->last_seen = time(NULL);
            /* For verbos sanity checking */
            static char ip_addr_s[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
            printf("[*] ADDED MAC-ADDRESS TO AN EXISTING ASSET: %s\n",ip_addr_s);
            return;
         }
      }
   rec = rec->next;
   }

   /* ELSE add arp asset */
   asset *new = NULL;
   //bstring mac_resolved = NULL;

   new = (asset*) calloc(1,sizeof(asset));
   new->ip_addr.s6_addr32[0] = ip_addr.s6_addr32[0];
   new->ip_addr.s6_addr32[1] = 0;
   new->ip_addr.s6_addr32[2] = 0;
   new->ip_addr.s6_addr32[3] = 0;

   memcpy(&new->mac_addr, arp_sha, MAC_ADDR_LEN);

   /* Attempt to resolve the vendor name of the MAC address. */
   //#ifndef DISABLE_VENDOR
   //mac_resolved = (bstring) get_vendor(mac_addr);
   //rec->mac_resolved = bstrcpy(mac_resolved);
   //#else
   new->mac_resolved = NULL;
   //#endif

   new->first_seen = time(NULL);
   new->last_seen = time(NULL);

   /* Insert ARP record into data structure. */
   //TAILQ_INSERT_HEAD(&arpassets, rec, next);
   new->next           = passet;
   new->prev           = NULL;
   passet = new;

   static char ip_addr_s[INET6_ADDRSTRLEN];
   inet_ntop(AF_INET, &ip_addr.s6_addr32[0], ip_addr_s, INET_ADDRSTRLEN + 1 );
   printf("[*] ARP ASSET ADDED: %s\n",ip_addr_s);
   return;
}

void del_assets (int ctime) {
   extern asset *passet;
   time_t check_time = time(NULL);
   //extern asset *bucket[BUCKET_SIZE];
   //for ( int akey = 0; akey < BUCKET_SIZE; akey++ ) {
   //   passet = bucket[akey];
   //   xpir = 0;
   while ( passet != NULL ) {
      if ( (passet->last_seen - check_time) >= ctime ) {
         del_serv_assets(passet);
         del_os_assets(passet);
         //del_asset(passet, &bucket[akey]);
      }
   }   
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
   /* remove cxt from bucket */
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

