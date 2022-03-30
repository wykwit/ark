#include <linux/init.h>
#include <linux/module.h>

static int _init(void)
{
	printk(KERN_ALERT "Hello, world!\n");
	return 0;
}

static void _exit(void)
{
	printk(KERN_ALERT "Goodbye, world!\n");
}

module_init(_init);
module_exit(_exit);

MODULE_LICENSE("GPL");
