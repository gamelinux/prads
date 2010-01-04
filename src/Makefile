#Makefile

CC=gcc
LDFLAGS=-lpcap -lpcre
OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS='-g -pg'
ifneq (${DEBUG},,)
CFLAGS += -g -DDEBUG
endif

SERVICE_OBJ = \
servicefp/servicefp.o \
servicefp/mac.o servicefp/tcpc.o servicefp/tcps.o servicefp/udps.o
IPFP_OBJ = ipfp/ipfp.o ipfp/tcp_fp.o ipfp/udp_fp.o ipfp/icmp_fp.o
OBJECTS = bstrlib.o sys_func.o bstraux.o cxt.o assets.o prads.o ${IPFP_OBJ} ${SERVICE_OBJ}


all: prads

prads: $(OBJECTS)
	gcc $(OCFLAGS) -o $@ $(OBJECTS) $(LDFLAGS)

debug:
	 ${MAKE} DEBUG=y

profile:
	${MAKE} CFLAGS+=${PCFLAGS}

clean:
	-rm -v $(OBJECTS)
	-rm prads 

indent:
	find -type f -name '*.[ch]' | xargs indent -kr -i4 -cdb -sc -sob -ss -ncs -ts8 -nut

# oldschool header file dependency checking.
deps:
	-rm -f deps.d
	for i in *.c ipfp/*.c servicefp/*.c output-plugins/*.c macfp/*.c; do gcc -MM $$i >> deps.d; done

ifneq ($(wildcard deps.d),)
include deps.d
endif

