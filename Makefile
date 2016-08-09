CC = gcc
obj-m += ipt_TRASH.o
TARGETS = ipt_TRASH.ko ipt_TRASH.ko.xz libipt_TRASH.so

all:$(TARGETS)
	@echo "== all done =="

clean:
	make -C /usr/src/kernels/$(shell uname -r)/ M=$(PWD) clean
	rm -f $(TARGETS)

ipt_TRASH.ko.xz:ipt_TRASH.ko
	xz -k ipt_TRASH.ko

ipt_TRASH.ko:ipt_TRASH.c
	make -C /usr/src/kernels/$(shell uname -r)/ M=$(PWD) modules

libipt_TRASH.so:libipt_TRASH.c
	$(CC) -fPIC -shared -o $@ $< -lxtables;

install:
	cp ipt_TRASH.ko.xz /lib/modules/$(shell uname -r)/kernel/net/ipv4/netfilter
	cp libipt_TRASH.so /usr/lib64/xtables/

uninstall:
	rm -f /lib/modules/$(shell uname -r)/kernel/net/ipv4/netfilter/ipt_TRASH.ko.xz
	rm -f /usr/lib64/xtables/libipt_TRASH.so
