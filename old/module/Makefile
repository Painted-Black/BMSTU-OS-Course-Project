CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)
TARGET = m_proc_module2

obj-m := $(TARGET).o 

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	make clean
clean:
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.mod
	@rm -fR .tmp*
	@rm -rf .tmp_versions
disclean: clean
	@rm *.ko *.symvers
