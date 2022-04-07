obj-m += precious-modules.o

all:
	make -C /lib/modules/*/build M=$(PWD) modules

clean:
	make -C /lib/modules/*/build M=$(PWD) clean

