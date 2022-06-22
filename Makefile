CC:=gcc
CCFLAGS:=-g -lgmp

all: client server

client: client.c
	${CC} client.c DH.c ${CCFLAGS}  -o client

server: server.c
	${CC} server.c DH.c ${CCFLAGS}  -o server

clean: 
	rm -rf ./server ./client 