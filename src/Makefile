#Makefile

CC=gcc
OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg


all:
	gcc -o prads prads.c -lpcap -lpcre $(OCFLAGS)

debug:
	gcc -o prads prads.c -lpcap -lpcre $(DCFLAGS)

profile:
	gcc -o prads prads.c -lpcap -lpcre  $(PCFLAGS)

clean:
	rm prads 

