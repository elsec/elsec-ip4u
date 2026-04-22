CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lpthread

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f server

.PHONY: clean
