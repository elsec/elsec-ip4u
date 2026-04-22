CC      = gcc
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lcrypto

server: server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f server

.PHONY: clean
