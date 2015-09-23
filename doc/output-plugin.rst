Howto write PRADS output plugins
================================


PRADS exposes a callback API for its output,
so that you can send the data directly to your application,
or write to a different file format.

The output plugins reside in `src/output-plugins/`.

The classic output plugin is `log_file.c`, it is recommended to use
it as an example.

To write an output plugin you need to create one or more callbacks
for each of the different asset types, and then fill in an output_plugin
struct with one or more callbacks:

::

  output_plugin p_stdout = {
      .init = &init_myoutput,
      .arp = &myoutput_arp,
      .os = &myoutput_os,
      .service = &myoutput_service,
      .connection = NULL,
      .denit = &end_myoutput,
      .data = NULL,
  };

As you can see, you can specify NULL for any output type you are not
interested in. The init and denit functions, which are called upon
PRADS start and end, respectively, are also optional, and `data` is a
void pointer to any arbitrary data you would like to pass around
between calls into your plugin.

For instance, if you want to output asset data you will need to 
write a callback with the type:
`void log_os (output_plugin *log, asset *main, os_asset *os, connection *cxt)`

Here, `*log` is the output_plugin struct, 
`*main` is the main PRADS asset, `*os` is the matching operating system fingerprint and
`*cxt` is PRADS connection data defined in prads.h.

A simple output plugin that only writes IP addresses and OS on new assets would look
thusly:

::

  void simpl_os(output_plugin *log, asset *main, os_asset *os, connection *cxt){
      static char ip_addr_s[INET6_ADDRSTRLEN];
      u_ntop(main->ip_addr, main->af, ip_addr_s);
      printf("%s", ip_addr_s);
      printf(" : ");
      if(os->fp.os != NULL) 
        printf("%s", os->fp.os);
  }

  output_plugin p_stdout = {
      .os = &simpl_os,
      .data = NULL,
  };


The last thing we need to do then is add the plugin to `log.h:log_types`:

`enum { LOG_STDOUT, LOG_FILE, LOG_FIFO, LOG_UNIFIED, LOG_SGUIL, LOG_RINGBUFFER, LOG_SIMPL, LOG_MAX } log_types;`

and `log_dispatch.c:init_logging()`:

::

   #include "log_simpl.h"

and 

::

	switch(logtype)
	{
      case LOG_SIMPL:
         log_fun = init_log_simpl();
         break;

Since prads doesn't auto-load plugns (yet?) you will also need to add it to
the main function, near where we do the other `init_logging()`:

::

    if(config.fifo) {
        olog("logging to FIFO '%s'\n", config.fifo);
        rc = init_logging(LOG_FIFO, config.fifo, config.cflags);
        if(rc) perror("Logging to fifo failed!");
    }
	  init_logging(LOG_SIMPL, NULL, 0);


You will want to add your new files to the build system, so go into `src/Makefile` and add your file:

::

  LOG_OBJ = output-plugins/log_dispatch.o output-plugins/log_stdout.o output-plugins/log_file.o output-plugins/log_fifo.o output-plugins/log_ringbuffer.o output-plugins/log_sguil.o output-plugins/log_simpl.o


Now, when you type `make` in the src/ directory, the build process should compile and link in your very own output plugin!

We deeply encourage you to send us a patch with your output plugins!


