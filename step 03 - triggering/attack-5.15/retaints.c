#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/panic.h>

static int retaint(struct kprobe *p, struct pt_regs *r)
{
	printk("retaints: called with taint - %ld\n", THIS_MODULE->taints);

	// it's that easy to overwrite!
	THIS_MODULE->taints = 0;

	return 0;
}

static struct kprobe kp = {
	.symbol_name = "add_taint",
	.pre_handler = retaint,
};

static int _mod_init(void)
{
	int err = register_kprobe(&kp);
	if (err != 0)
		return err;

	printk("retaints: module loaded\n");
	printk("retaints: kprobe registered at %p\n", kp.addr);

	return 0;
}

static void _mod_exit(void)
{
	unregister_kprobe(&kp);

	add_taint(TAINT_CRAP, LOCKDEP_STILL_OK);

	printk("retaints: module unloaded\n");
}

module_init(_mod_init);
module_exit(_mod_exit);

MODULE_LICENSE("GPL");
