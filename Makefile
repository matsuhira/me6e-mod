obj-m += me6e.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	@rm -f *.o
	@rm -f *.ko
	@rm -f *.mod.c
	@rm -f *~

