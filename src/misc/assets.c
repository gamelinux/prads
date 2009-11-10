//#include "prads.h"

void add_asset (int af, struct in6_addr ip_addr, time_t discovered);

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
    
   /* Find asset within linked list.  */
   while ( rec != NULL ) {
      if (af == rec->af) {
         if (memcmp(&ip_addr,&rec->ip_addr,16)) {
            serv_asset *tmp_sa = NULL;
            tmp_sa = rec->services->next;
            while ( tmp_sa != NULL ) {
               if (port == tmp_sa->port && proto == tmp_sa->proto) {
                  /* Found! */
                  bdestroy(tmp_sa->service);
                  tmp_sa->service = bstrcpy(service);
                  bdestroy(tmp_sa->application);
                  tmp_sa->application = bstrcpy(application);
                  printf("[*] SERVICE ASSET UPDATED\n");
                  return 0; 
               }
               else {
                  printf("[*] NEED TO ADD SERVICE\n");
               }
            rec->services = rec->services->next;
            }
         }
      }
      else {
         printf("[*] NEED TO ADD ASSET\n");
      }
   rec = rec->next;
   }
   printf("[*] NO ASSETS\n");
   add_asset (af, ip_addr, time(NULL));
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

    return;
}

