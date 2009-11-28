#Makefile

CC=gcc
OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg
ifneq (${DEBUG},,)
CFLAGS += -g -DDEBUG
endif

SERVICE_OBJ = \
servicefp/servicefp.o \
servicefp/mac.o servicefp/tcpc.o servicefp/tcps.o servicefp/udps.o
IPFP_OBJ = ipfp/ipfp.o ipfp/tcp_fp.o ipfp/udp_fp.o ipfp/icmp_fp.o
OBJECTS = bstrlib.o sys_func.o bstraux.o cxt.o assets.o prads.o ${IPFP_OBJ} ${SERVICE_OBJ}


all:${OBJECTS}
	gcc $(OCFLAGS) -o prads $(OBJECTS) -lpcap -lpcre

debug:
	 ${MAKE} DEBUG=y

profile:
	gcc $(PCFLAGS) -o prads prads.c -lpcap -lpcre

clean:
	-rm -v $(OBJECTS)
	-rm prads 

