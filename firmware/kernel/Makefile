obj-m += ngfw_mod.o

ccflags-y := -I$(src)/include

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

load:
	insmod ngfw_mod.ko

unload:
	rmmod ngfw_mod

reload:
	rmmod ngfw_mod || true
	insmod ngfw_mod.ko

status:
	@lsmod | grep ngfw || echo "Module not loaded"
	@dmesg | grep NGFW | tail -5

.PHONY: all clean install load unload reload status