#Makefile

CC=gcc
OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg


all:
	gcc -o prads prads.c -lpcap $(OCFLAGS)

debug:
	gcc -o prads prads.c -lpcap $(DCFLAGS)

profile:
	gcc -o prads prads.c -lpcap $(PCFLAGS)

clean:
	rm prads 

