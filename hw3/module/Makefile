obj-m += firewall.o
firewall-objs += hw3secws.o ruler.o logging.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement -Wno-unused-variable

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

