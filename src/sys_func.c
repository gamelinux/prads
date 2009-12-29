#include "common.h"
#include "prads.h"
#include "sys_func.h"

/* ----------------------------------------------------------
 * FUNCTION     : strlcpy
 * DESCRIPTION  : Replacement for strncpy.  This function is
 *              : native in *BSD.  This function was taken
 *              : from Secure Programming Cookbook by
 *              : O'Reilly.
 * INPUT        : 0 - Destination String
 *              : 1 - Source String
 *              : 2 - Size
 * RETURN       : Length of String Created
 *  ---------------------------------------------------------- */
#ifndef HAVE_STRLCPY
#warning no strlcpy
size_t strlcpy(char *dst, const char *src, size_t size) {
  char       *dstptr = dst;
  size_t     tocopy  = size;
  const char *srcptr = src;

  if (tocopy && --tocopy) {
    do {
      if (!(*dstptr++ = *srcptr++)) break;
    } while (--tocopy);
  }
  if (!tocopy) {
    if (size) *dstptr = 0;
    while (*srcptr++);
  }

  return (srcptr - src - 1);
}
#endif

/* ----------------------------------------------------------
 * FUNCTION     : strlcat
 * DESCRIPTION  : Replacement for strcat.  This function is
 *              : native in *BSD.  This function was taken
 *              : from Secure Programming Cookbook by
 *              : O'Reilly.
 * INPUT        : 0 - Destination String
 *              : 1 - Source String
 *              : 2 - Size
 * RETURN       : Length of String Created
 * ---------------------------------------------------------- */
#ifndef HAVE_STRLCAT
#warning no strlcat
size_t strlcat(char *dst, const char *src, size_t len) {
  char       *dstptr = dst;
  size_t     dstlen, tocopy = len;
  const char *srcptr = src;

  while (tocopy-- && *dstptr) dstptr++;
  dstlen = dstptr - dst;
  if (!(tocopy = len - dstlen)) return (dstlen + strlen(src));
  while (*srcptr) {
    if (tocopy != 1) {
      *dstptr++ = *srcptr;
      tocopy--;
    }
    srcptr++;
  }
  *dstptr = 0;

  return (dstlen + (srcptr - src));
}
#endif

void bucket_keys_NULL() {
   int cxkey;
   extern connection *bucket[BUCKET_SIZE];

   for ( cxkey = 0; cxkey < BUCKET_SIZE; cxkey++ ) {
      bucket[cxkey] = NULL;
   }
}

void check_interupt() {
   extern int intr_flag;

   if ( intr_flag == 1 ) {
      game_over();
   }
   else if ( intr_flag == 2 ) {
      print_assets();
   }
   else if ( intr_flag == 3 ) {
      set_end_sessions();
   }
   else {
      intr_flag = 0;
   }
}

void set_end_sessions() {
   extern int inpacket,intr_flag;
   intr_flag = 3;

   if ( inpacket == 0 ) {
      end_sessions();
      print_assets();
      intr_flag = 0;
      alarm(TIMEOUT);
   }
}

void game_over() {
   extern int inpacket,intr_flag;

   if ( inpacket == 0 ) {
      extern pcap_t *handle;
      print_assets();
      end_all_sessions();
      pcap_close(handle);
      //del_assets(0);
      printf("\nprads ended\n");
      exit (0);
   }
   intr_flag = 1;
}

int set_chroot(void) {
   char *absdir;
   char *logdir;
   int abslen;
   extern char *chroot_dir;

   /* logdir = get_abs_path(logpath); */

   /* change to the directory */
   if ( chdir(chroot_dir) != 0 ) {
      printf("set_chroot: Can not chdir to \"%s\": %s\n",chroot_dir,strerror(errno));
   }

   /* always returns an absolute pathname */
   absdir = getcwd(NULL, 0);
   abslen = strlen(absdir);

   /* make the chroot call */
   if ( chroot(absdir) < 0 ) {
      printf("Can not chroot to \"%s\": absolute: %s: %s\n",chroot_dir,absdir,strerror(errno));
   }

   if ( chdir("/") < 0 ) {
        printf("Can not chdir to \"/\" after chroot: %s\n",strerror(errno));
   }

   return 0;
}

int drop_privs(void) {
   struct group *gr;
   struct passwd *pw;
   char *endptr;
   int i;
   int do_setuid = 0;
   int do_setgid = 0;
   unsigned long groupid = 0;
   unsigned long userid = 0;
   extern char *group_name, *user_name;

   if ( group_name != NULL ) {
      do_setgid = 1;
      if( isdigit(group_name[0]) == 0 ) {
         gr = getgrnam(group_name);
         groupid = gr->gr_gid;
      }
      else {
         groupid = strtoul(group_name, &endptr, 10);
      }
   }

   if ( user_name != NULL ) {
      do_setuid = 1;
      do_setgid = 1;
      if ( isdigit(user_name[0]) == 0 ) {
         pw = getpwnam(user_name);
         userid = pw->pw_uid;
      } else {
         userid = strtoul(user_name, &endptr, 10);
         pw = getpwuid(userid);
      }

      if ( group_name == NULL ) {
         groupid = pw->pw_gid;
      }
   }

   if ( do_setgid ) {
      if ( (i = setgid(groupid)) < 0 ) {
         printf("Unable to set group ID: %s", strerror(i));
      }
   }

   endgrent();
   endpwent();

   if ( do_setuid ) {
      if (getuid() == 0 && initgroups(user_name, groupid) < 0 ) {
         printf("Unable to init group names (%s/%lu)", user_name, groupid);
      }
      if ( (i = setuid(userid)) < 0 ) {
         printf("Unable to set user ID: %s\n", strerror(i));
      }
   }
   return 0;
}

int is_valid_path(const char *path) {
   struct stat st;

   if ( path == NULL ) {
      return 0;
   }
   if ( stat(path, &st) != 0 ) {
      return 0;
   }
   if ( !S_ISDIR(st.st_mode) || access(path, W_OK) == -1 ) {
      return 0;
   }
   return 1;
}

int create_pid_file(const char *path, const char *filename) {
   char filepath[STDBUF];
   const char *fp = NULL;
   const char *fn = NULL;
   char pid_buffer[12];
   struct flock lock;
   int rval;
   int fd;
   extern char *pidfile,*pidpath,*true_pid_name;

   memset(filepath, 0, STDBUF);

   if ( !filename ) {
      fn = pidfile;
   }
   else {
      fn = filename;
   }

   if ( !path ) {
      fp = pidpath;
   }
   else {
      fp = path;
   }

   if ( is_valid_path(fp) ) {
      snprintf(filepath, STDBUF-1, "%s/%s", fp, fn);
   }
   else {
      printf("PID path \"%s\" isn't a writeable directory!", fp);
   }

   true_pid_name = strdup(filename);

   if ( (fd = open(filepath, O_CREAT | O_WRONLY,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1 ) {
      return ERROR;
   }

   /* pid file locking */
   lock.l_type = F_WRLCK;
   lock.l_start = 0;
   lock.l_whence = SEEK_SET;
   lock.l_len = 0;

   if ( fcntl(fd, F_SETLK, &lock) == -1 ) {
      if ( errno == EACCES || errno == EAGAIN ) {
         rval = ERROR;
      }
      else {
         rval = ERROR;
      }
      close(fd);
      return rval;
   }
   snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int) getpid());
   if ( ftruncate(fd, 0) != 0 ) { return ERROR; }
   if ( write(fd, pid_buffer, strlen(pid_buffer)) != 0 ) { return ERROR; }
   return SUCCESS;
}

int daemonize() {
   pid_t pid;
   int fd;
   extern int use_syslog;
   extern char *pidfile,*pidpath;

   pid = fork();

   if ( pid > 0 ) {
      exit(0); /* parent */
   }

   use_syslog = 1;
   if ( pid < 0 ) {
      return ERROR;
   }

   /* new process group */
   setsid();

   /* close file handles */
   if ( (fd = open("/dev/null", O_RDWR)) >= 0 ) {
      dup2(fd, 0);
      dup2(fd, 1);
      dup2(fd, 2);
      if ( fd > 2 ) {
         close(fd);
      }
   }

   if ( pidfile ) {
      return create_pid_file(pidpath, pidfile);
   }

   return SUCCESS;
}

