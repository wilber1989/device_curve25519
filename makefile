CC = gcc
CFLAGS = -Wextra -Wall -std=gnu99 -Iinclude -Wno-unused-parameter -Wno-unused-variable -Wno-duplicate-decl-specifier
CFLAGS_32=-m32 -lpthread 

all: main

main: main.c chachapoly_aead.c poly1305.c chacha.c chachapoly_aead.c curve25519-donna.a 
	$(CC) $^ -I . $(CFLAGS) $(CFLAGS_32) -o $@

curve25519-donna.a: curve25519-donna.o
	ar -rc curve25519-donna.a curve25519-donna.o
	ranlib curve25519-donna.a

curve25519-donna.o: curve25519-donna.c
	gcc -c curve25519-donna.c $(CFLAGS) $(CFLAGS_32)

clean:
	rm -rf main