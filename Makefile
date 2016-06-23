ifneq ($(KERNELRELEASE),)
	isgx-y := \
		isgx_main.o \
		isgx_page_cache.o \
		isgx_ioctl.o \
		isgx_vma.o \
		isgx_util.o
	isgx-$(CONFIG_COMPAT) += isgx_compat_ioctl.o
	obj-m += isgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules
endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
