#Makefile
#CC=gcc
LDFLAGS=-lpcap -lpcre -lresolv
CFLAGS=-O3 -DCONFDIR='"${CONFDIR}/"'

ifneq (${DEBUG},)
CFLAGS = -g -DDEBUG -Wall -DCONFDIR='"${CONFDIR}/"'
endif
ifneq (${PROFILE},)
CFLAGS=-g -pg -DCONFDIR='"${CONFDIR}/"'
endif
ifneq (${EXTRADEBUG},)
CFLAGS+= -DDUMP_HASH -DDEBUG_HASH -DDEBUG=2 -DDEBUG=2
endif
ifneq (${DEBUG_PACKET},)
CFLAGS+= -DDEBUG_PACKET
endif

BUILD=gnu
ifeq (${BUILD},osx)
CFLAGS+=-I/opt/local/include/ -DOSX
CONFDIR=/opt/etc/prads
else
CFLAGS+=-D__USE_GNU
CONFDIR=../etc
endif

SERVICE_OBJ = servicefp/servicefp.o servicefp/tcpc.o servicefp/tcps.o servicefp/udps.o 

IPFP_OBJ = ipfp/ipfp.o ipfp/udp_fp.o ipfp/icmp_fp.o
LOG_OBJ = output-plugins/log_dispatch.o output-plugins/log_stdout.o output-plugins/log_file.o output-plugins/log_fifo.o
CXT_OBJ = cxt.o
MODULES = dump_dns.o mac.o ${SERVICE_OBJ} ${IPFP_OBJ} ${CXT_OBJ} ${LOG_OBJ}
OBJECTS = bstrlib.o sig_tcp.o config.o sys_func.o assets.o prads.o ${MODULES}

all: prads

osx:
	$(MAKE) BUILD=osx

prads: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

static: $(OBJECTS)
	$(MAKE) CFLAGS+=-static prads

debug:
	 ${MAKE} DEBUG=y

profile:
	${MAKE} PROFILE=y

clean:
	-rm -fv $(OBJECTS)
	-rm -f prads 

indent:
	find -type f -name '*.[ch]' | xargs indent -kr -i4 -cdb -sc -sob -ss -ncs -ts8 -nut

# oldschool header file dependency checking.
deps:
	-rm -f deps.d
	for i in $(subst .o,.c,$(OBJECTS)); do gcc -MM $$i >> deps.d; done

ifneq ($(wildcard deps.d),)
include deps.d
endif

tags: *.h *.c
	ctags -R
