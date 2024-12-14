CC 	   = gcc
CFLAGS = -Wall -Wextra -fPIC -I./src
SRC    = src/Crypto.c
LIB    = libCrypto.so

all: $(LIB)

$(LIB): $(SRC)
	$(CC) $(CFLAGS) -shared -o $@ $^

up:
	docker compose up -d --build

down:
	docker compose down -v

clean:
	rm -f $(LIB)

.PHONY: all up down clean
