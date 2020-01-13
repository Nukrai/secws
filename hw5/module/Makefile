obj-m += firewall.o
firewall-objs += hw5secws.o ruler.o logging.o conn.o netfilter.o
ccflags-y := -std=gnu99 -Wno-declaration-after-statement -Wno-unused-variable 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

