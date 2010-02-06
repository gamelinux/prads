#Makefile
#CC=gcc
LDFLAGS=-lpcap -lpcre
CFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg
ifneq (${DEBUG},)
CFLAGS = -g -DDEBUG -Wall
endif

SERVICE_OBJ = servicefp/servicefp.o servicefp/mac.o servicefp/tcpc.o servicefp/tcps.o servicefp/udps.o 

IPFP_OBJ = ipfp/ipfp.o ipfp/tcp_fp.o ipfp/udp_fp.o ipfp/icmp_fp.o
LOG_OBJ = output-plugins/log_dispatch.o output-plugins/log_stdout.o
CXT_OBJ = util-cxt-queue.o util-cxt.o cxt.o
OBJECTS = bstrlib.o sig.o config.o sys_func.o ${CXT_OBJ} ${LOG_OBJ} assets.o prads.o ${IPFP_OBJ} ${SERVICE_OBJ}

all: prads

prads: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

debug:
	 ${MAKE} DEBUG=y

profile:
	${MAKE} CFLAGS+='${PCFLAGS}'

clean:
	-rm -v $(OBJECTS)
	-rm prads 

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
