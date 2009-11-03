/*
** Copyright (C) 2009 Redpill Linpro, AS.
** Copyright (C) 2009 Edward Fjellskål <edward.fjellskaal@redpill-linpro.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License Version 2 as
** published by the Free Software Foundation.  You may not use, modify or
** distribute this program under any other version of the GNU General
** Public License.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* $Id$ */

/* servicefp 
 * 
 * Purpose:
 *
 * This file holds essential functions for the service fingerprinting
 *
 * Arguments:
 *   
 * *NONE
 *
 * Effect:
 *
 * HOLDS all the stuff that needs to be initialized.
 *
 * Comments:
 *
 * Old school...
 */


/* ----------------------------------------------------------
 * FUNCTION     : init_identification
 * DESCRIPTION  : This function will read the signature file
 *              : into the signature data structure.
 * INPUT        : 0 - Data Structure
 * RETURN       : -1 - Error
 *              : 0 - Normal Return
 * ---------------------------------------------------------- */
int load_servicefp_file() {

   FILE *fp;
   bstring filename;
   bstring filedata;
   struct bstrList *lines;
   int i;

   //TAILQ_INIT(&signatures);
printf("TEST\n");

   /* Check for a PADS_SIGNATURE_LIST file within the current directory.  */
   if ((fp = fopen(TCP_SIGNATURE_LIST, "r")) != NULL) {
      filename = bformat("./%s", TCP_SIGNATURE_LIST);
      fclose(fp);
//   } else  if (gc.sig_file != NULL) {
//      filename = bstrcpy(gc.sig_file);

   } else {
   //   filename = bformat("%s/%s", INSTALL_SYSCONFDIR, TCP_SIGNATURE_LIST);
      filename = bformat("../etc/tcp-service.sig");
   }

   /* Open Signature File */
   if ((fp = fopen((char *)bdata(filename), "r")) == NULL) {
      printf("Unable to open signature file - %s", bdata(filename));
   }
printf("OK\n");
   /* Read file into 'filedata' and process it accordingly. */
   filedata = bread ((bNread) fread, fp);
   if ((lines = bsplit(filedata, '\n')) != NULL) {
      for (i = 0; i < lines->qty; i++) {
         parse_raw_signature(lines->entry[i], i + 1);
      }
   }

   /* Clean Up */
   bdestroy(filename);
   bdestroy(filedata);
   bstrListDestroy(lines);
   fclose(fp);

   return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : parse_raw_signature
 * DESCRIPTION  : This function will take a line from the
 *              : signature file and parse it into it's data
 *              : structure.
 * INPUT        : 0 - Raw Signature (bstring)
 *              : 1 - The line number this signature is on.
 * RETURN       : 0 - Success
 *              : -1 - Error
 * ---------------------------------------------------------- */
int parse_raw_signature (bstring line, int lineno) {
   struct bstrList *raw_sig = NULL;
   struct bstrList *title = NULL;
   signature *sig, *head;
   extern signature *signatures;
   sig = head = NULL;
   bstring pcre_string = NULL;
   const char *err = NULL;     /* PCRE */
   int erroffset;              /* PCRE */
   int ret = 0;
   int i;

   /* Check to see if this line has something to read. */
   if (line->data[0] == '\0' || line->data[0] == '#')
      return -1;

   /* Split Line */
   if ((raw_sig = bsplit(line, ',')) == NULL)
      return -1;

   /* Reconstruct the PCRE string.  This is needed in case there are PCRE
    * strings containing commas within them. */
   if (raw_sig->qty < 3) {
      ret = -1;
   } else if (raw_sig->qty > 3) {
      pcre_string = bstrcpy(raw_sig->entry[2]);
      for (i = 3; i < raw_sig->qty; i++) {
         bstring tmp = bfromcstr(",");
         if ((bconcat(pcre_string, tmp)) == BSTR_ERR)
            ret = -1;
         if ((bconcat(pcre_string, raw_sig->entry[i])) == BSTR_ERR)
            ret = -1;
         bdestroy(tmp);
      }
   } else {
      pcre_string = bstrcpy(raw_sig->entry[2]);
   }

   /* Split Title */
   if (raw_sig->entry[1] != NULL && ret != -1)
      title = bsplit(raw_sig->entry[1], '/');
      if (title == NULL) {
         bdestroy(pcre_string);
         return -1;
      }
   if (title->qty < 3)
      ret = -1;

   /* Create signature data structure for this record. */
   if (ret != -1) {
      sig = (signature*)calloc(1,sizeof(signature));
      if (raw_sig->entry[0] != NULL)
         sig->service = bstrcpy(raw_sig->entry[0]);
      if (title->entry[1] != NULL)
         sig->title.app = bstrcpy(title->entry[1]);
      if (title->entry[2] != NULL)
         sig->title.ver = bstrcpy(title->entry[2]);
      if (title->entry[3] != NULL)
         sig->title.misc = bstrcpy(title->entry[3]);

      /* PCRE */
      if (pcre_string != NULL) {
         if ((sig->regex = pcre_compile ((char *)bdata(pcre_string), 0, &err, &erroffset, NULL)) == NULL) {
            printf("Unable to compile signature:  %s at line %d (%s)",
            err, lineno, bdata(line));
            ret = -1;
         }
      }
      if (ret != -1) {
         sig->study = pcre_study (sig->regex, 0, &err);
         if (err != NULL)
            printf("Unable to study signature:  %s", err);
      }

      /* Add signature to 'signature_list' data structure. */
      if (ret != -1)
         //add_signature (sig);
         head = signatures;
         sig->next  = head;
         signatures = sig;
   }

   /* Garbage Collection */
   if (raw_sig != NULL)
      bstrListDestroy(raw_sig);
   if (title != NULL)
      bstrListDestroy(title);
   if (pcre_string != NULL)
      bdestroy(pcre_string);

   return ret;
}

