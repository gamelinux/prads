assets.o: assets.c common.h prads.h bstrlib.h assets.h sys_func.h
bstraux.o: bstraux.c bstrlib.h bstraux.h
bstrlib.o: bstrlib.c bstrlib.h
cxt.o: cxt.c common.h prads.h bstrlib.h cxt.h
prads.o: prads.c common.h prads.h bstrlib.h sys_func.h assets.h cxt.h \
  ipfp/ipfp.h servicefp/servicefp.h
sys_func.o: sys_func.c common.h prads.h bstrlib.h sys_func.h
icmp_fp.o: ipfp/icmp_fp.c ipfp/../common.h ipfp/../prads.h \
  ipfp/../common.h ipfp/../bstrlib.h ipfp/ipfp.h
ipfp.o: ipfp/ipfp.c ipfp/../common.h ipfp/../prads.h ipfp/../common.h \
  ipfp/../bstrlib.h ipfp/ipfp.h
tcp_fp.o: ipfp/tcp_fp.c ipfp/../common.h ipfp/../prads.h ipfp/../common.h \
  ipfp/../bstrlib.h ipfp/ipfp.h
udp_fp.o: ipfp/udp_fp.c ipfp/../common.h ipfp/../prads.h ipfp/../common.h \
  ipfp/../bstrlib.h ipfp/ipfp.h
mac.o: servicefp/mac.c
servicefp.o: servicefp/servicefp.c servicefp/../common.h \
  servicefp/../sys_func.h servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/servicefp.h
tcpc.o: servicefp/tcpc.c servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/../sys_func.h servicefp/servicefp.h
tcps.o: servicefp/tcps.c servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/../sys_func.h servicefp/servicefp.h
udps.o: servicefp/udps.c servicefp/../prads.h servicefp/../common.h \
  servicefp/../bstrlib.h servicefp/servicefp.h
log_ascii.o: output-plugins/log_ascii.c
log_unified.o: output-plugins/log_unified.c
macfp.o: macfp/macfp.c
