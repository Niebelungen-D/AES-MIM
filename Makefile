CC:=gcc
CCFLAGS:=-g -w -lgmp
PUBLIC_LIB:=aes.c DH.c gmult.c

all: client server

client: client.c 
	${CC} client.c ${PUBLIC_LIB} ${CCFLAGS}  -o client

server: server.c
	${CC} server.c ${PUBLIC_LIB} ${CCFLAGS}  -o server

clean: 
	rm -rf ./server ./client 