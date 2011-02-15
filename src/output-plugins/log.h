/*  D A T A  S T R U C T U R E S  *********************************************/
typedef struct _log_file_conf
{
    FILE *file;         /* File Reference */
    bstring filename;   /* File's OS name */
}   log_file_conf;

/* fill this struct with your logging functions */
typedef struct _output_plugin {
   int flags;
   int (*init)(struct _output_plugin*, const char*, int);
   void (*arp)(struct _output_plugin*, asset *);                   /* call on arp */
   void (*os)(struct _output_plugin*, asset *, os_asset *os);      /* call on os */
   void (*service)(struct _output_plugin*, asset*, serv_asset *);  /* call on service */
   int (*denit)(struct _output_plugin*);                          /* deinitialize */
   const char *path;                                           /* file, socket etc */
   void *data;                                                 /* anything else */
} output_plugin;

enum { LOG_ASCII, LOG_STDOUT, LOG_FILE, LOG_SGUIL, LOG_UNIFIED} log_types;
enum { VERBOSE = 0x01, FLAGS } log_flags;

void log_asset_arp (asset *main);
void log_asset_os (asset *main, os_asset *os);
void log_asset_service (asset *main, serv_asset *service);
