bstrlib.o: bstrlib.c bstrlib.h
sig_tcp.o: sig_tcp.c common.h prads.h bstrlib.h sys_func.h mtu.h tos.h \
  config.h assets.h
config.o: config.c common.h prads.h bstrlib.h sys_func.h config.h
sys_func.o: sys_func.c common.h prads.h bstrlib.h sys_func.h util-cxt.h \
  assets.h servicefp/servicefp.h config.h sig.h
assets.o: assets.c common.h prads.h bstrlib.h assets.h sys_func.h \
  output-plugins/log.h config.h mac.h
prads.o: prads.c common.h prads.h bstrlib.h config.h sys_func.h assets.h \
  cxt.h ipfp/ipfp.h servicefp/servicefp.h util-cxt.h util-cxt-queue.h \
  sig.h mac.h output-plugins/log.h
mac.o: mac.c common.h prads.h bstrlib.h sys_func.h mac.h
servicefp.o: servicefp/servicefp.c servicefp/../common.h \
  servicefp/../sys_func.h servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/servicefp.h
tcpc.o: servicefp/tcpc.c servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/../sys_func.h servicefp/../assets.h \
  servicefp/servicefp.h
tcps.o: servicefp/tcps.c servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/../sys_func.h servicefp/../assets.h \
  servicefp/servicefp.h
udps.o: servicefp/udps.c servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/../assets.h servicefp/servicefp.h \
  servicefp/../util-cxt.h servicefp/../prads.h
ipfp.o: ipfp/ipfp.c ipfp/../common.h ipfp/../prads.h ipfp/../common.h \
  ipfp/../bstrlib.h ipfp/../assets.h ipfp/ipfp.h
udp_fp.o: ipfp/udp_fp.c ipfp/../common.h ipfp/../prads.h ipfp/../common.h \
  ipfp/../bstrlib.h ipfp/ipfp.h
icmp_fp.o: ipfp/icmp_fp.c ipfp/../common.h ipfp/../prads.h \
  ipfp/../common.h ipfp/../bstrlib.h ipfp/ipfp.h
util-cxt-queue.o: util-cxt-queue.c util-cxt-queue.h prads.h common.h \
  bstrlib.h
util-cxt.o: util-cxt.c prads.h common.h bstrlib.h cxt.h util-cxt.h \
  util-cxt-queue.h
cxt.o: cxt.c common.h prads.h bstrlib.h cxt.h sys_func.h util-cxt.h \
  util-cxt-queue.h
log_dispatch.o: output-plugins/log_dispatch.c output-plugins/../prads.h \
  output-plugins/../common.h output-plugins/../bstrlib.h \
  output-plugins/log.h output-plugins/log_dispatch.h \
  output-plugins/../common.h output-plugins/../sys_func.h \
  output-plugins/log_stdout.h output-plugins/log_file.h
log_stdout.o: output-plugins/log_stdout.c output-plugins/../prads.h \
  output-plugins/../common.h output-plugins/../bstrlib.h \
  output-plugins/../sys_func.h output-plugins/../sig.h \
  output-plugins/../ipfp/ipfp.h
log_file.o: output-plugins/log_file.c output-plugins/../prads.h \
  output-plugins/../common.h output-plugins/../bstrlib.h \
  output-plugins/../sys_func.h output-plugins/../sig.h \
  output-plugins/log.h output-plugins/log_file.h
