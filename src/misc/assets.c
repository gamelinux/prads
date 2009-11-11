//#include "prads.h"

void add_asset (int af, struct in6_addr ip_addr, time_t discovered);

/* looks to see if asset exists and update timestamp. If not, create the asset */
update_asset (int af, struct in6_addr ip_addr) {
   extern asset *passet;
   asset *rec = passet;

   while ( rec != NULL ) {
      if (  rec->ip_addr.s6_addr32[0] == ip_addr.s6_addr32[0] 
         && rec->ip_addr.s6_addr32[1] == ip_addr.s6_addr32[1]
         && rec->ip_addr.s6_addr32[2] == ip_addr.s6_addr32[2]
         && rec->ip_addr.s6_addr32[3] == ip_addr.s6_addr32[3] ) {

         printf("[*] ASSET Timestamp updated\n");
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
            printf("[*] ADDED NEW SERVICE ASSET\n");
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
               printf("[*] ADDED NEW SERVICE ASSET\n");
               return 0;
            }
         }
      }
   rec = rec->next;
   }

   if (asset_match == 1) {
      printf("[*] NEED TO ADD SERVICE: Should not be here!\n");
   }
   else if (asset_match == 0 ) {
      add_asset (af, ip_addr, time(NULL));
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

   printf("[*] ASSET ADDED\n");
   return;
}

