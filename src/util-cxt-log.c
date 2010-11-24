

void cxtbuffer_write () {

   connection *cxt;
   cxt = NULL;
   cxt = cxt_dequeue(&cxt_log_q);
   if (cxt == NULL) {
      /* no more connections in the queue */
      return;
   }

   connection *next;
   next = NULL;
   char stime[80], ltime[80];
   time_t tot_time;
   static char src_s[INET6_ADDRSTRLEN];
   static char dst_s[INET6_ADDRSTRLEN];
   uint32_t s_ip_t, d_ip_t;

   FILE *cxtFile;
   char *cxtfname;
   cxtfname = "";

   asprintf(&cxtfname, "%s/stats.%s.%ld", dpath, dev, tstamp);
   cxtFile = fopen(cxtfname, "w");

   if (cxtFile == NULL) {
      printf("[*] ERROR: Cant open file %s\n",cxtfname);
   }
   else {

      while ( cxt != NULL ) {

         tot_time = cxt->last_pkt_time - cxt->start_time;
         strftime(stime, 80, "%F %H:%M:%S", gmtime(&cxt->start_time));
         strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cxt->last_pkt_time));

         if ( verbose == 1 ) {
            if (cxt->ipversion == AF_INET) {
               if (!inet_ntop(AF_INET, &cxt->s_ip.s6_addr32[0], src_s, INET_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
               if (!inet_ntop(AF_INET, &cxt->d_ip.s6_addr32[0], dst_s, INET_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }
            else if (cxt->ipversion == AF_INET6) {
               if (!inet_ntop(AF_INET6, &cxt->s_ip, src_s, INET6_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
               if (!inet_ntop(AF_INET6, &cxt->d_ip, dst_s, INET6_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }

            printf("%ld%09ju|%s|%s|%ld|%u|%s|%u|",cxt->start_time,cxt->cxid,stime,ltime,tot_time,
                                                cxt->proto,src_s,ntohs(cxt->s_port));
            printf("%s|%u|%ju|%ju|",dst_s,ntohs(cxt->d_port),cxt->s_total_pkts,cxt->s_total_bytes);
            printf("%ju|%ju|%u|%u\n",cxt->d_total_pkts,cxt->d_total_bytes,cxt->s_tcpFlags,
                                     cxt->d_tcpFlags);
         }

         if ( cxt->ipversion == AF_INET6 ) {
            if ( verbose != 1 ) {
               if (!inet_ntop(AF_INET6, &cxt->s_ip, src_s, INET6_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
               if (!inet_ntop(AF_INET6, &cxt->d_ip, dst_s, INET6_ADDRSTRLEN + 1 ))
                  perror("Something died in inet_ntop");
            }
            fprintf(cxtFile,"%ld%09ju|%s|%s|%ld|%u|%s|%u|",cxt->start_time,cxt->cxid,stime,ltime,tot_time,
                                                         cxt->proto,src_s,ntohs(cxt->s_port));
            fprintf(cxtFile,"%s|%u|%ju|%ju|",dst_s,ntohs(cxt->d_port),cxt->s_total_pkts,
                                             cxt->s_total_bytes);
            fprintf(cxtFile,"%ju|%ju|%u|%u\n",cxt->d_total_pkts,cxt->d_total_bytes,cxt->s_tcpFlags,
                                              cxt->d_tcpFlags);
         }


         connection *tmp = cxt;
         cxt = cxt_dequeue(&cxt_log_q);

         /* cxt_requeue(tmp, &cxt_est_q, &cxt_log_q); */
         cxt_requeue(tmp, &cxt_log_q, &cxt_spare_q);
      }
      free(cxt);
      cxt=NULL;
      free(tmp);
      tmp=NULL;
      fclose(cxtFile);
   }
   cxt = NULL;
   free(cxtfname);
}

