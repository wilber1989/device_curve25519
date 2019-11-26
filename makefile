CC = gcc
CFLAGS = -Wextra -Wall -std=gnu99 -Iinclude -Wno-unused-parameter -Wno-unused-variable -Wno-duplicate-decl-specifier
CFLAGS_32=-m32 -lpthread 

SRCS += $(wildcard *.c)
INCLUDE = -I include 
all: main

main: $(SRCS)
	$(CC) -o $@ $^ $(INCLUDE) $(CFLAGS) $(CFLAGS_32) 

clean:
	rm -rf *.o *.a main 