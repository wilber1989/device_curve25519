CFLAGS=-Wmissing-prototypes -Wdeclaration-after-statement -O2 -Wall
CFLAGS_32=-m32

targets: curve25519-donna.a 

test: test-donna speed-donna test-noncanon-donna 

clean:
	rm -f *.o *.a *.pp test-donna speed-donna test-noncanon-donna

curve25519-donna.a: curve25519-donna.o
	ar -rc curve25519-donna.a curve25519-donna.o
	ranlib curve25519-donna.a

curve25519-donna.o: curve25519-donna.c
	gcc -c curve25519-donna.c $(CFLAGS) $(CFLAGS_32)

test-donna: test-curve25519.c curve25519-donna.a
	gcc -o test-donna test-curve25519.c curve25519-donna.a $(CFLAGS) $(CFLAGS_32)

speed-donna: speed-curve25519.c curve25519-donna.a
	gcc -o speed-donna speed-curve25519.c curve25519-donna.a $(CFLAGS) $(CFLAGS_32)

test-noncanon-donna: test-noncanon.c curve25519-donna.a
	gcc -o test-noncanon-donna test-noncanon.c curve25519-donna.a $(CFLAGS) $(CFLAGS_32)