obj-m += rep_mod.o
reptile-objs := rep_mod.o

all:
	mkdir -p bin
	cd sbin && make all
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp rep_mod.ko bin/rep_mod

clean:
	cd sbin && make clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
