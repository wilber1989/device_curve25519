targets: tests benchmark
tests:
	gcc -O3 poly1305.c chacha.c chachapoly_aead.c tests.c -o test

benchmark:
	gcc -lm -O3 poly1305.c chacha.c chachapoly_aead.c bench.c -o bench

clean:
	rm -f *.o *.a test bench