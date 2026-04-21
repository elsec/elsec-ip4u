CC      = gcc
CFLAGS  = -Wall -Wextra -O2

server: server.c

clean:
	rm -f server

.PHONY: clean
