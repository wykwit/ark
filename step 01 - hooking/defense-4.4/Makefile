obj-m += precious-functions.o

all:
	make -C /lib/modules/*/build M=$(PWD) modules

clean:
	make -C /lib/modules/*/build M=$(PWD) clean

