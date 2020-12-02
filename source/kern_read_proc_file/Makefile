
CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)
TARGET = my_kern_read

obj-m := $(TARGET).o 

default:
	$(MAKE) -I /usr/include/x86_64-linux-gnu -C $(KDIR) M=$(PWD) modules
	make clean
clean:
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.mod
	@rm -fR .tmp*
	@rm -rf .tmp_versions
disclean: clean
	@rm *.ko *.symvers
