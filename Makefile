ifneq ($(KERNELRELEASE),)
	isgx-y := \
		isgx_main.o \
		isgx_page_cache.o \
		isgx_ioctl.o \
		isgx_vma.o \
		isgx_util.o
	obj-m += isgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules

install: default
	$(MAKE) INSTALL_MOD_DIR=kernel/drivers/intel/sgx -C $(KDIR) M=$(PWD) modules_install
	sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
