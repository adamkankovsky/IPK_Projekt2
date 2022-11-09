CC=gcc
CFLAGS=-g
SOURCE=main

all:
	$(CC) $(CFLAGS) -o ipk-sniffer $(SOURCE).c -lpcap