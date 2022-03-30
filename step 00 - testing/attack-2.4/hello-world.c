#define MODULE
#include <linux/module.h>

int init_module(void)
{
	printk("<1>Hello, world!\n");
	return 0;
}

static void cleanup_module(void)
{
	printk("<1>Goodbye, world!\n");
}

