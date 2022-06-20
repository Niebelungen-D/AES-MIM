CC:=gcc
CCFLAGS:=-g

all: client server

client: client.c
	${CC} ${CCFLAGS} -o client

server: server.c
	${CC} ${CCFLAGS} -o server

clean: 
	rm -rf ./server ./client