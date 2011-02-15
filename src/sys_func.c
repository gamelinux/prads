#include "common.h"
#include "prads.h"
#include "sys_func.h"
#include "util-cxt.h"
#include "assets.h"
#include "servicefp/servicefp.h"
#include "config.h"
#include "sig.h"

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

uint8_t normalize_ttl (uint8_t ttl)
{
    if (ttl > 128) return 255;
    if (ttl >  64) return 128;
    if (ttl >  32) return  64;
    else  return  32;
}

void bucket_keys_NULL()
{
    int cxkey;
    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++) {
        bucket[cxkey] = NULL;
    }
}

void check_interrupt()
{
    extern int intr_flag;

    if (intr_flag == 1) {
        game_over();
    } else if (intr_flag == 2) {
        update_asset_list();
    } else if (intr_flag == 3) {
        set_end_sessions();
    } else {
        intr_flag = 0;
    }
}

void set_end_sessions()
{
    extern int inpacket, intr_flag;
    intr_flag = 3;

    if (inpacket == 0) {
        extern time_t tstamp;
        tstamp = time(NULL);
        end_sessions();
        /* if no cxtracking is turned on - dont log to disk */
        /* if (log_cxt == 1) log_expired_cxt(); */
        /* if no asset detection is turned on - dont log to disk! */
        /* if (log_assets == 1) update_asset_list(); */
        update_asset_list();
        intr_flag = 0;
        alarm(CHECK_TIMEOUT);
    }
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

void game_over()
{
    extern int inpacket, intr_flag;

    if (inpacket == 0) {
        //update_asset_list();
        clear_asset_list();
        end_all_sessions();
        free_queue();
        del_known_services();
        del_signature_lists();
        unload_tcp_sigs();
        end_logging();
        print_prads_stats();
        print_pcap_stats();
        if (config.handle != NULL) pcap_close(config.handle);
        free_config(); // segfault here !
        printf("\nprads ended\n");
        exit(0);
    }
    intr_flag = 1;
}

void print_pcap_stats()
{
    if (config.handle == NULL) return;
    if (pcap_stats(config.handle, &config.ps) == -1) {
        pcap_perror(config.handle, "pcap_stats");
    }
    printf("\n-- libpcap:");
    printf("\n-- Total packets received                 :%12u",config.ps.ps_recv);
    printf("\n-- Total packets dropped                  :%12u",config.ps.ps_drop);
    printf("\n-- Total packets dropped by Interface     :%12u",config.ps.ps_ifdrop);
}

void print_prads_stats()
{
    extern u_int64_t cxtrackerid;
    printf("\n-- prads:");
    printf("\n-- Total packets received from libpcap    :%12u",config.pr_s.got_packets);
    printf("\n-- Total Ethernet packets received        :%12u",config.pr_s.eth_recv);
    printf("\n-- Total VLAN packets received            :%12u",config.pr_s.vlan_recv);
    printf("\n-- Total ARP packets received             :%12u",config.pr_s.arp_recv);
    printf("\n-- Total IPv4 packets received            :%12u",config.pr_s.ip4_recv);
    printf("\n-- Total IPv6 packets received            :%12u",config.pr_s.ip6_recv);
    printf("\n-- Total Other link packets received      :%12u",config.pr_s.otherl_recv);
    printf("\n-- Total IPinIPv4 packets received        :%12u",config.pr_s.ip4ip_recv);
    printf("\n-- Total IPinIPv6 packets received        :%12u",config.pr_s.ip6ip_recv);
    printf("\n-- Total GRE packets received             :%12u",config.pr_s.gre_recv);
    printf("\n-- Total TCP packets received             :%12u",config.pr_s.tcp_recv);
    printf("\n-- Total UDP packets received             :%12u",config.pr_s.udp_recv);
    printf("\n-- Total ICMP packets received            :%12u",config.pr_s.icmp_recv);
    printf("\n-- Total Other transport packets received :%12u",config.pr_s.othert_recv);
    printf("\n--");
    printf("\n-- Total sessions tracked                 :%12lu", cxtrackerid);
    printf("\n-- Total assets detected                  :%12u",config.pr_s.assets);
    printf("\n-- Total TCP OS fingerprints detected     :%12u",config.pr_s.tcp_os_assets);
    printf("\n-- Total UDP OS fingerprints detected     :%12u",config.pr_s.udp_os_assets);
    printf("\n-- Total ICMP OS fingerprints detected    :%12u",config.pr_s.icmp_os_assets);
    printf("\n-- Total DHCP OS fingerprints detected    :%12u",config.pr_s.dhcp_os_assets);
    printf("\n-- Total TCP service assets detected      :%12u",config.pr_s.tcp_services);
    printf("\n-- Total TCP client assets detected       :%12u",config.pr_s.tcp_clients);
    printf("\n-- Total UDP service assets detected      :%12u",config.pr_s.udp_services);
    printf("\n-- Total UDP client assets detected       :%12u",config.pr_s.udp_clients);
}

int set_chroot(void)
{
    char *absdir;
    //char *logdir;
    int abslen;

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
    abslen = strlen(absdir);

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

int drop_privs(void)
{
    struct group *gr;
    struct passwd *pw;
    char *endptr;
    int i;
    int do_setuid = 0;
    int do_setgid = 0;
    unsigned long groupid = 0;
    unsigned long userid = 0;

    if (config.group_name != NULL) {
        do_setgid = 1;
        if (!isdigit(config.group_name[0])) {
            gr = getgrnam(config.group_name);
            if(!gr){
                if(config.chroot_dir){
                    elog("ERROR: you have chrootetd and must set numeric group ID.\n");
                    exit(1);
                }else{
                    elog("ERROR: couldn't get ID for group %s, group does not exist.", config.group_name)
                    exit(1);
                }
            }
            groupid = gr->gr_gid;
        } else {
            groupid = strtoul(config.group_name, &endptr, 10);
        }
    }

    if (config.user_name != NULL) {
        do_setuid = 1;
        do_setgid = 1;
        if (isdigit(config.user_name[0]) == 0) {
            pw = getpwnam(config.user_name);
            if (pw != NULL) {
                userid = pw->pw_uid;
            } else {
                printf("[E] User %s not found!\n", config.user_name);
            }
        } else {
            userid = strtoul(config.user_name, &endptr, 10);
            pw = getpwuid(userid);
        }

        if (config.group_name == NULL && pw != NULL) {
            groupid = pw->pw_gid;
        }
    }

    if (do_setgid) {
        if ((i = setgid(groupid)) < 0) {
            printf("Unable to set group ID: %s", strerror(i));
        }
    }

    endgrent();
    endpwent();

    if (do_setuid) {
        if (getuid() == 0 && initgroups(config.user_name, groupid) < 0) {
            printf("Unable to init group names (%s/%lu)", config.user_name,
                   groupid);
        }
        if ((i = setuid(userid)) < 0) {
            printf("Unable to set user ID: %s\n", strerror(i));
        }
    }
    return 0;
}

int is_valid_path(const char *path)
{
    struct stat st;

    if (path == NULL) {
        return 0;
    }
    if (stat(path, &st) != 0) {
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || access(path, W_OK) == -1) {
        return 0;
    }
    return 1;
}

int create_pid_file(const char *path, const char *filename)
{
    char filepath[STDBUF];
    const char *fp = NULL;
    const char *fn = NULL;
    char pid_buffer[12];
    struct flock lock;
    int rval;
    int fd;

    memset(filepath, 0, STDBUF);

    if (!filename) {
        fn = config.pidfile;
    } else {
        fn = filename;
    }

    if (!path) {
        fp = config.pidpath;
    } else {
        fp = path;
    }

    if (is_valid_path(fp)) {
        snprintf(filepath, STDBUF - 1, "%s/%s", fp, fn);
    } else {
        printf("PID path \"%s\" isn't a writeable directory!", fp);
    }

    config.true_pid_name = strdup(filename);

    if ((fd = open(filepath, O_CREAT | O_WRONLY,
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
            rval = ERROR;
        } else {
            rval = ERROR;
        }
        close(fd);
        return rval;
    }
    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int)getpid());
    if (ftruncate(fd, 0) != 0) {
        return ERROR;
    }
    if (write(fd, pid_buffer, strlen(pid_buffer)) != 0) {
        return ERROR;
    }
    return SUCCESS;
}

int daemonize()
{
    pid_t pid;
    int fd;
    //extern char *pidfile, *pidpath;

    pid = fork();

    if (pid > 0) {
        exit(0);                /* parent */
    }

    config.use_syslog = 1;
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

    if (config.pidfile) {
        return create_pid_file(config.pidpath, config.pidfile);
    }

    return SUCCESS;
}

