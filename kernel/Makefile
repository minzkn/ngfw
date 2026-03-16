# NGFW Kernel Module Makefile
# For Linux Kernel 6.x

obj-m += ngfw_kmod.o

KDIR ?= /lib/modules/$(shell uname -r)/build
KVER ?= 6.12
KROOT ?= $(CURDIR)/../linux

# Use downloaded kernel if available, otherwise use system kernel
ifeq ($(wildcard $(KROOT)),)
    KDIR := /lib/modules/$(shell uname -r)/build
else
    KDIR := $(KROOT)
endif

PWD := $(shell pwd)

ccflags-y := -I$(PWD) -DDEBUG -Wall -Wno-unused-function -Wno-error

EXTRA_CFLAGS := -DDEBUG -Wno-error

all:
	@echo "Building NGFW kernel module..."
	@echo "Kernel source: $(KDIR)"
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.c *.mod *.order *.symvers

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

load:
	@echo "Loading NGFW module..."
	insmod ngfw_kmod.ko

unload:
	@echo "Unloading NGFW module..."
	-rmmod ngfw_kmod

reload:
	$(MAKE) unload
	$(MAKE) load

status:
	@lsmod | grep ngfw || echo "NGFW module not loaded"

help:
	@echo "NGFW Kernel Module Build Help"
	@echo "=============================="
	@echo "make                 - Build kernel module"
	@echo "make clean           - Clean build artifacts"
	@echo "make install         - Install module"
	@echo "make load            - Load module"
	@echo "make unload          - Unload module"
	@echo "make reload          - Reload module"
	@echo ""
	@echo "Options:"
	@echo "KDIR=/path/to/kernel - Specify kernel source directory"
	@echo "KVER=6.12            - Specify kernel version"
