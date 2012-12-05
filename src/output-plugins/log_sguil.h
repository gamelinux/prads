struct log_sguil {
   FILE *file;
   const char *filename;
   const char *prefix;
};
/*  P R O T O T Y P E S  ******************************************************/
output_plugin *init_log_sguil(void);
int init_output_sguil (output_plugin *p, const char *, int);
void sguil_connection (output_plugin *, connection *cxt, int);
int sguil_end (output_plugin *);
void sguil_rotate(output_plugin *plugin, time_t check_time);
