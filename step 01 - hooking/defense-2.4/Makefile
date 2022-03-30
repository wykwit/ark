precious-syscalls.o:
	gcc -c -O3 precious-syscalls.c

load: precious-syscalls.o
	insmod precious-syscalls.o

unload:
	rmmod precious-syscalls

