#Makefile

CC=gcc
OCFLAGS=-O3
DCFLAGS=-g
PCFLAGS=-g -pg


all:
	gcc $(OCFLAGS) -o prads prads.c -lpcap -lpcre

debug:
	gcc $(DCFLAGS) -o prads prads.c -lpcap -lpcre

profile:
	gcc $(PCFLAGS) -o prads prads.c -lpcap -lpcre

clean:
	rm prads 

