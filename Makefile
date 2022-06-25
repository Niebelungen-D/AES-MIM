CC:=gcc
CCFLAGS:=-w -lgmp
PUBLIC_LIB:=aes.c DH.c gmult.c

all: client server middle

client: client.c ${PUBLIC_LIB}
	${CC} client.c ${PUBLIC_LIB} ${CCFLAGS}  -o client

server: server.c ${PUBLIC_LIB}
	${CC} server.c ${PUBLIC_LIB} ${CCFLAGS}  -o server

middle: middle.c ${PUBLIC_LIB} arp.c arpspoof.c
	${CC} middle.c ${PUBLIC_LIB} arp.c arpspoof.c -O3 ${CCFLAGS} -lpcap  -o middle

clean: 
	rm -rf ./server ./client ./middle