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
   void (*os)(struct _output_plugin*, asset *, os_asset *os, connection *cxt);      /* call on os */
   void (*service)(struct _output_plugin*, asset*, serv_asset *, connection *cxt);  /* call on service */
   void (*connection)(struct _output_plugin*, connection *ctx, int outputmode); /* call on connection */
   int (*denit)(struct _output_plugin*);                          /* deinitialize */
   void (*rotate)(struct _output_plugin*, time_t);
   const char *path;                                           /* file, socket etc */
   void *data;                                                 /* anything else */
} output_plugin;

enum { LOG_STDOUT, LOG_FILE, LOG_FIFO, LOG_UNIFIED, LOG_SGUIL, LOG_RINGBUFFER, LOG_MAX } log_types;
enum { VERBOSE = 0x01, FLAGS } log_flags;

void log_asset_arp (asset *main);
void log_asset_os (asset *main, os_asset *os, connection *cxt);
void log_asset_service (asset *main, serv_asset *service, connection *cxt);
void log_rotate(time_t);
int init_logging(int type, const char *path, int flags);
void end_logging();

// connection tracking logging function
void log_connection(connection *cxt, int cxstatus);

