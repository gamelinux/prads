#include "common.h"
#include "prads.h"
#include "sys_func.h"
#include "assets.h"
#include "servicefp/servicefp.h"
#include "config.h"
#include "sig.h"
#include "output-plugins/log.h"

#include <libgen.h> // dirname()

void free_queue(); // util-cxt.c
extern globalconfig config;

const char *u_ntop(const struct in6_addr ip_addr, int af, char *dest)
{
    if (af == AF_INET) {
        if (!inet_ntop
            (AF_INET, 
	     &IP4ADDR(&ip_addr),
		 dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    } else if (af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &ip_addr, dest, INET6_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    return dest;
}
const char *u_ntop_dst(packetinfo *pi, char *dest)
{
    if (pi->af == AF_INET) {
        if (!inet_ntop
            (AF_INET,
             &pi->ip4->ip_dst,
                 dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    } else if (pi->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &pi->ip6->ip_dst, dest, INET6_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    return dest;
}

const char *u_ntop_src(packetinfo *pi, char *dest)
{
    if (pi->af == AF_INET) {
        if (!inet_ntop
            (AF_INET,
             &pi->ip4->ip_src,
                 dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    } else if (pi->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &pi->ip6->ip_src, dest, INET6_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    return dest;
}

uint8_t normalize_ttl (uint8_t ttl)
{
    if (ttl > 128) return 255;
    if (ttl >  64) return 128;
    if (ttl >  32) return  64;
    else  return  32;
}


void unload_tcp_sigs()
{
    if(config.ctf & CO_SYN && config.sig_syn){
        unload_sigs(config.sig_syn, config.sig_hashsize);
    }
    if(config.ctf & CO_SYNACK && config.sig_synack){
        unload_sigs(config.sig_synack, config.sig_hashsize);
    }
    if(config.ctf & CO_ACK && config.sig_ack){
        unload_sigs(config.sig_ack, config.sig_hashsize);
    }
    if(config.ctf & CO_RST && config.sig_rst){
        unload_sigs(config.sig_rst, config.sig_hashsize);
    }    
    if(config.ctf & CO_FIN && config.sig_fin){
        unload_sigs(config.sig_fin, config.sig_hashsize);
    }
}

void print_pcap_stats()
{
    if (config.handle == NULL) return;
    if (pcap_stats(config.handle, &config.ps) == -1) {
        pcap_perror(config.handle, "pcap_stats");
        return;
    }
    olog("-- libpcap:\n");
    olog("-- Total packets received                 :%12u\n",config.ps.ps_recv);
    olog("-- Total packets dropped                  :%12u\n",config.ps.ps_drop);
    olog("-- Total packets dropped by Interface     :%12u\n",config.ps.ps_ifdrop);
}

int set_chroot(void)
{
    char *absdir;
    //char *logdir;

    /*
     * logdir = get_abs_path(logpath); 
     */

    /*
     * change to the directory 
     */
    if (chdir(config.chroot_dir) != 0) {
        elog("set_chroot: Can not chdir to \"%s\": %s\n", config.chroot_dir,
               strerror(errno));
    }

    /*
     * always returns an absolute pathname 
     */
    absdir = getcwd(NULL, 0);

    /*
     * make the chroot call 
     */
    if (chroot(absdir) < 0) {
        elog("Can not chroot to \"%s\": absolute: %s: %s\n", config.chroot_dir,
               absdir, strerror(errno));
        exit(3);
    }

    if (chdir("/") < 0) {
        elog("Can not chdir to \"/\" after chroot: %s\n",
               strerror(errno));
        exit(3);
    }

    return 0;
}

int drop_privs(long userid, long groupid)
{
    int i;

    if ((i = setgid(groupid)) < 0) {
       elog("[!] Unable to set group ID: %s\n", strerror(i));
       exit(i);
    }

    endgrent();
    endpwent();

    if (userid) {
        if ((i = setuid(userid)) < 0) {
            elog("[!] Unable to set user ID: %s\n", strerror(i));
            exit(i);
        }
    }
    return 0;
}

int is_valid_path(const char *path)
{
    char dir[STDBUF];
    struct stat st;

    if (path == NULL) {
        return 0;
    }
    if (stat(path, &st) == 0) {
        // path already exists. is it regular and writable?
        if (!S_ISREG(st.st_mode) || access(path, W_OK) != -1) {
            return 1;
        }
    }

    strcpy(dir, path);
    dirname(dir);

    if (stat(dir, &st) != 0) {
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || access(dir, W_OK) == -1) {
        return 0;
    }
    return 1;
}

int touch_pid_file(const char *path, long uid, long gid)
{ 
   int fd, rc;
   fd = open(path, O_CREAT, 0664);
   if(fd)
      rc = fchown(fd, uid, gid);
      close(fd);
   if(rc || !fd) {
      elog("Failed to create pid file '%s', %d\n", path,rc);
      return 666;
   }
   return 0;
}

long get_gid(const char *group_name)
{
   char *endptr;
   struct group *gr;

   if(!group_name) return 0;
   if (!isdigit(group_name[0])) {
      gr = getgrnam(group_name);
      if(!gr){
         elog("ERROR: couldn't get ID for group %s, group does not exist.\n", group_name);
         return 0;
      }
      return gr->gr_gid;
   }
   return strtoul(group_name, &endptr, 10);
}

long get_uid(const char *user_name, int *out_gid)
{
   char *endptr;
   struct passwd *pw;
   if(!user_name) return 0;
   if (isdigit(user_name[0]) == 0) {
      pw = getpwnam(user_name);
      if (pw != NULL) {
         if (out_gid) 
            if(*out_gid == 0)
               *out_gid = pw->pw_gid;
         return pw->pw_uid;
      }
   }

   return strtoul(config.user_name, &endptr, 10);
}

int create_pid_file(const char *path)
{
    char pid_buffer[12];
    struct flock lock;
    int rval;
    int fd;

    if (!path) {
        path = config.pidfile;
    }
    if (!is_valid_path(path)) {
        printf("PID path \"%s\" aint writable", path);
    }

    if ((fd = open(path, O_CREAT | O_WRONLY,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
        return ERROR;
    }

    /*
     * pid file locking 
     */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            rval = errno;
        } else {
            rval = ERROR;
        }
        close(fd);
        return rval;
    }
    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int)getpid());
    if (ftruncate(fd, 0) != 0) {
        return errno;
    }
    if (write(fd, pid_buffer, strlen(pid_buffer)) == -1) {
        return errno;
    }
    return SUCCESS;
}

int daemonize()
{
    pid_t pid;
    int fd;

    pid = fork();

    if (pid > 0) {
        exit(0);                /* parent */
    }

    if (pid < 0) {
        return ERROR;
    }

    /*
     * new process group 
     */
    setsid();

    /*
     * close file handles 
     */
    if ((fd = open("/dev/null", O_RDWR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) {
            close(fd);
        }
    }

    return SUCCESS;
}

char *hex2mac(const uint8_t *mac)
{

    static char buf[32];

    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             (mac[0] & 0xFF), (mac[1] & 0xFF), (mac[2] & 0xFF),
             (mac[3] & 0xFF), (mac[4] & 0xFF), (mac[5] & 0xFF));

    return buf;
}


