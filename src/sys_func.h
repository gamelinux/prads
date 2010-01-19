#ifndef SYSFUNC_H
#define SYSFUNC_H

#define elog(fmt, ...) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);
#ifdef DEBUG
#define dlog(fmt, ...) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);
#define vlog(v, fmt, ...) do{ if(DEBUG == v) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__); }while(0)
#else
#define dlog(fmt, ...) do { ; } while(0);
#define vlog(fmt, ...) do { ; } while(0);
#endif
size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t len);
void bucket_keys_NULL();
int set_chroot(void);
int drop_privs(void);
int is_valid_path(const char *path);
int create_pid_file(const char *path, const char *filename);
void game_over();
void end_all_sessions();
void del_assets(int ctime);
int daemonize();
void print_assets();
void set_end_sessions();
void end_sessions();
void display_config();
void check_interrupt();
void print_pcap_stats();
void print_prads_stats();

#endif
