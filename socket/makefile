all: server client
.PHONY:all

client:client.o
	gcc client.o -lpthread -o client
client.o:cclient.c
	gcc -c cclient.c -lpthread -o client.o
server:server.o
	gcc server.o -lpthread -o server
server.o:cservice.c
	gcc -c cservice.c -lpthread -o server.o

.PHONY:clean

clean:            
	rm -rf *.o
	rm -rf server client
