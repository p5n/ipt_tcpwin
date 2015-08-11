ifneq ($(KERNELRELEASE),)

obj-m += xt_TCPWIN.o
xt_TCPWIN-y := xt_TWIN.o

else

KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

all:	modules

modules:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

endif
