#include <linux/crc32.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rbtree_latch.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>

#include "targets.h"


#define SYSCALL_LIMIT 285

unsigned long *_sys_call_table;
static unsigned long _sys_call_table_copy[SYSCALL_LIMIT];

unsigned long (*_kallsyms_lookup_name)(const char *);
char *(*_kallsyms_lookup)(unsigned long, unsigned long *, unsigned long *, char **, char*);

struct module *(*_find_module)(const char *);

struct mod_tree_root {
	struct latch_tree_root root;
	unsigned long addr_min;
	unsigned long addr_max;
} *_mod_tree;


static void __attribute__((optimize (0))) restore_syscall(int n)
{
	write_cr0(read_cr0() & ~0x00010000);
	_sys_call_table[n] = _sys_call_table_copy[n];
	write_cr0(read_cr0() | 0x00010000);
}

static void __attribute__((optimize (0))) overwrite_byte(unsigned char *addr, unsigned char val)
{
	write_cr0(read_cr0() & ~0x00010000);
	*addr = val;
	write_cr0(read_cr0() | 0x00010000);
}


// == SCANNNING ==

#define _CRC_SEED 0xDEADC0DE

#define SCAN_MODE_FIX	((scan_results.mode & 1) > 0)

struct kprobe kp_add_taint;

static struct Results {
	int started, finished;		// state
	int mismatches, overwrites;	// results
	int mode;			// settings
} scan_results;

static struct Target {
	unsigned long addr, size, checksum;
	unsigned char *copy;
	struct Target *next;
} *scan_targets;

void scan_targets_add(unsigned long addr)
{
	struct Target *last_target;
	struct Target *new_target;
	unsigned char *new_mem;

	unsigned long size;
	unsigned long offset;
	char *modname;
	char namebuf[KSYM_NAME_LEN];

	(*_kallsyms_lookup)(addr, &size, &offset, &modname, namebuf);

	addr -= offset;

	new_target = (struct Target *) vmalloc(sizeof(struct Target));
	new_mem = (unsigned char *) vmalloc(size);
	if (!new_target || !new_mem) {
		printk("ark: couldn't allocate memory for target - n %s a %lx s %lu\n", namebuf, addr, size);
		return;
	}
	memcpy(new_mem, (const void *) addr, size);

	*new_target = (struct Target) {
		.addr = addr,
		.size = size,
		.checksum = crc32(_CRC_SEED, new_mem, size),
		.copy = new_mem,
		.next = NULL,
	};

	if (scan_targets == NULL) {
		// this first entry becomes the head of scan_targets list
		scan_targets = new_target;
		// and we are done here
		return;
	}

	// set last_target to the last entry of the scan_targets list
	for (last_target = scan_targets; last_target->next != NULL; last_target = last_target->next);
	// append new_target to the list
	last_target->next = new_target;
}

void scan_targets_free(struct Target *t)
{
	if (t == NULL) // && scan_targets != NULL)
		t = scan_targets;
	if (t == NULL) // && scan_targets == NULL)
		return;

	if (t->next != NULL) {
		scan_targets_free(t->next);
		t->next = NULL;
	}

	vfree(t->copy);
	vfree(t);
}

void scan_targets_add_symbol(char *name)
{
	unsigned long addr = (*_kallsyms_lookup_name)(name);
	if (!addr) {
		printk("ark: couldn't find symbol - %s\n", name);
		return;
	}

	scan_targets_add(addr);
}

int scan_targets_check(void)
{
	struct Target *t;

	unsigned long size;
	unsigned long offset;
	char *modname;
	char namebuf[KSYM_NAME_LEN];

	int i;
	int overwritten;
	unsigned char *b, c;

	scan_results.overwrites = 0;
	for (t = scan_targets; t != NULL; t = t->next) {
		overwritten = 0;

		(*_kallsyms_lookup)(t->addr, &size, &offset, &modname, namebuf);

		if (t->checksum != crc32(_CRC_SEED, t->copy, t->size)) {
			printk("ark: checksum mismatch, function copy overwritten - n %s a %lx\n", namebuf, t->addr);
			overwritten = 1;

			if (t->checksum == crc32(_CRC_SEED, (unsigned char const *) t->addr, t->size)) {
				printk("ark: checksum matches real memory, only our copy has been corrupted\n");
				if (SCAN_MODE_FIX && size == t->size) {
					printk("ark: updating our copy - n %s a %lx s %lu\n", namebuf, t->addr, t->size);
					memcpy(t->copy, (const void *) t->addr, size);
				}
			}

			// what if the checksum has been overwritten?
			// it won't match the real memory and it won't match our copy
			// however the copy might still match the real memory
			// should we update our checksum?

			continue;
		}

		for (i = 0; i < t->size && i < size-offset; i++) {
			b = (unsigned char *) t->addr + i;
			c = t->copy[i];
			if (*b == c)
				continue;
			else
				overwritten = 1;

			if (SCAN_MODE_FIX) {
				printk("ark: found a mismatch, function overwritten - n %s a %lx, "
					"attempting to fix - got %02x want %02x\n", namebuf, t->addr, *b, c);
				overwrite_byte(b, c);
			} else {
				// do not fix, report only once
				printk("ark: found a mismatch, function overwritten - n %s a %lx\n", namebuf, t->addr);
				break;
			}
		}

		scan_results.overwrites += overwritten;
	}

	return scan_results.overwrites;
}

int scan_mod_tree_node(struct rb_node *n)
{
	int i;

	// this rb_node is the first latch_tree_node element, so we can cast
	struct latch_tree_node *nn = (struct latch_tree_node *) n;
	// another cast, but with extra steps
	struct mod_tree_node *nnn = container_of(nn, struct mod_tree_node, node);
	struct module *m = nnn->mod;
	struct mod_kallsyms *kallsyms = m->kallsyms;

	if ((*_find_module)(m->name) == NULL) {
		// find_module depends on module list and our module wasn't there
		printk("ark: found hidden module - %s with taint %lu, address %p\n", m->name, m->taints, m);

		for (i = 0; i < kallsyms->num_symtab; i++) {
			if (kallsyms->symtab[i].st_shndx == SHN_UNDEF)
				continue;

			printk("ark: hidden module symbols - m %s n %s a %llx\n", m->name,
				kallsyms->strtab + kallsyms->symtab[i].st_name, kallsyms->symtab[i].st_value);
		}

		return 1;
	} else if (m->taints > 0)
		printk("ark: found tainted module - %s with taint %lu\n", m->name, m->taints);

	return 0;
}

int scan_update(void)
{
	char symbolbuf[KSYM_SYMBOL_LEN];

	struct rb_node *node_current;
	struct rb_root *node_root;

	int i;

	if (scan_results.finished < scan_results.started)
		return -1;

	scan_results.started = scan_results.finished + 1;
	scan_results.mismatches = 0;

	// check #1 (write protection): cr0 WP bit
	if ((read_cr0() & 0x00010000) == 0) {
		printk("ark: write protection was disabled, something fishy might be going on\n");
		write_cr0(read_cr0() | 0x00010000);
	}

	// check #2 (symbol table): sys_call_table entries
	printk("ark: scan sys_call_table check\n");
	for (i = 0; i < SYSCALL_LIMIT; i++) {
		if (_sys_call_table_copy[i] != _sys_call_table[i]) {
			scan_results.mismatches++;
			printk("ark: found a mismatch on syscall %d\n", i);
			sprint_symbol(symbolbuf, _sys_call_table[i]);
			printk("ark: offender - %s\n", symbolbuf);
			if (SCAN_MODE_FIX) {
				printk("ark: attempted to fix syscall %d\n", i);
				restore_syscall(i);
			}
		}
	}

	// check #3 (patching): function and struct integrity
	printk("ark: scan targets check\n");
	// mismatches for this scan type are counted separately as "overwrites"
	scan_targets_check();

	// check #4 (modules): traverse mod_tree to find hidden modules
	if (_mod_tree) {
		printk("ark: scan mod_tree check\n");
		node_root = _mod_tree->root.tree;
		node_current = rb_first_postorder(node_root);
		while (node_current != NULL) {
			scan_results.mismatches += scan_mod_tree_node(node_current);
			node_current = rb_next_postorder(node_current);
		}
	}

	scan_results.finished = scan_results.started + 1;
	printk("ark: scan finished\n");
	return scan_results.mismatches;
}

int scan_update_handler(struct kprobe *p, struct pt_regs *r)
{
	printk("ark: scan triggered by event\n");
	scan_update();

	// we must return 0 if we want to continue execution
	return 0;
}

int scan_init(void)
{
	int i;

	struct kprobe kp_kallsyms_lookup_name = {
		.symbol_name = "kallsyms_lookup_name",
	};

	scan_targets = NULL;
	scan_results.mode = 0;
	scan_results.started = 0;
	scan_results.finished = 0;

	register_kprobe(&kp_kallsyms_lookup_name);
	_kallsyms_lookup_name = (unsigned long (*)(const char *)) kp_kallsyms_lookup_name.addr;
	unregister_kprobe(&kp_kallsyms_lookup_name);

	if (_kallsyms_lookup_name == 0)
		return -ELIBACC;

	_kallsyms_lookup =
		(char *(*)(unsigned long, unsigned long *, unsigned long *, char **, char*))
		(*_kallsyms_lookup_name)("kallsyms_lookup");

	if (_kallsyms_lookup == 0)
		return -ELIBACC;

	_find_module = (struct module *(*)(const char *)) (*_kallsyms_lookup_name)("find_module");
	_mod_tree = (struct mod_tree_root *) (*_kallsyms_lookup_name)("mod_tree");

	if (_find_module == 0)
		_mod_tree = 0;

	_sys_call_table = (unsigned long *) (*_kallsyms_lookup_name)("sys_call_table");

	for (i = 0; i < SYSCALL_LIMIT; i++) {
		_sys_call_table_copy[i] = _sys_call_table[i];
		scan_targets_add(_sys_call_table[i]);
	}

	scan_targets_add((unsigned long) scan_targets_add);
	scan_targets_add((unsigned long) scan_update);

	// targets listed in "targets.h" file
	targets_apply(scan_targets_add_symbol);

	scan_results.finished = 1;

	// register kprobes to execute scan_update per event
	kp_add_taint = (struct kprobe) {
		.symbol_name = "add_taint",
		.pre_handler = scan_update_handler,
	};
	register_kprobe(&kp_add_taint);

	return 0;
}


// == WORKQUEUE ==

unsigned long scan_period;

void wq_handler(struct work_struct *);

DECLARE_DELAYED_WORK(wq, wq_handler);

void wq_handler(struct work_struct *work)
{
	printk("ark: periodic scan triggered, next run in %lu seconds\n", scan_period);
	scan_update();
	schedule_delayed_work(&wq, scan_period * HZ);
}

void scan_period_update(unsigned long period)
{
	cancel_delayed_work_sync(&wq);
	scan_period = period;

	printk("ark: scan period set to %lu seconds\n", scan_period);
	if (period > 0 && period < MAX_SEC_IN_JIFFIES)
		schedule_delayed_work(&wq, period * HZ);
	else
		printk("ark: periodic scans have been canceled\n");
}


// == PROCFS ==

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_period_entry;

#define _PROC_READ_SIZE 9

ssize_t proc_read(struct file *f, char __user *out, size_t count, loff_t *off)
{
	char buf[_PROC_READ_SIZE];
	buf[0] = '0' + (scan_results.mismatches / 100) % 10;
	buf[1] = '0' + (scan_results.mismatches / 10) % 10;
	buf[2] = '0' + (scan_results.mismatches / 1) % 10;
	buf[3] = ' ';
	buf[4] = '0' + (scan_results.overwrites / 100) % 10;
	buf[5] = '0' + (scan_results.overwrites / 10) % 10;
	buf[6] = '0' + (scan_results.overwrites / 1) % 10;
	buf[7] = '\n';
	buf[8] = '\0';

	if (*off > 0)
		return 0;

	if (count > _PROC_READ_SIZE)
		count = _PROC_READ_SIZE;

	if (copy_to_user(out, buf, count))
		return -EFAULT;

	*off = count;
	return count;
}

ssize_t proc_write(struct file *f, const char __user *in, size_t count, loff_t *off)
{
	char buf[1];

	if (count > 0) {
		if (copy_from_user(buf, in, 1))
			return -EFAULT;

		switch (buf[0]) {
		case '1':	// FIX
		case '0':	// none
			scan_results.mode = buf[0] - '0';
			break;
		}

		printk("ark: scan triggered by user\n");
		scan_update();
	}

	return count;
}

#define _PROC_PERIOD_READ_SIZE 10

ssize_t proc_period_write(struct file *f, const char __user *in, size_t count, loff_t *off)
{
	char buf[_PROC_PERIOD_READ_SIZE];
	int n = _PROC_PERIOD_READ_SIZE;
	int m = 1;
	unsigned long r = 0;

	if (count < n)
		n = count;

	if (copy_from_user(buf, in, n))
		return -EFAULT;

	while (n >= 0) {
		if (buf[n] <= '9' && buf[n] >= '0') {
			r += (buf[n] - '0') * m;
			m *= 10;
		}
		n -= 1;
	}

	scan_period_update(r);

	return count;
}

struct proc_ops proc_fops = {
	.proc_read = proc_read,
	.proc_write = proc_write,
};

struct proc_ops proc_period_fops = {
	.proc_write = proc_period_write,
};


// == MODULE ==

static int _mod_init(void)
{
	int err;

	if ((err = scan_init()))
		return err;

	// proc init
	proc_entry = proc_create("ark", 0666, NULL, &proc_fops);
	proc_period_entry = proc_create("ark_period", 0222, NULL, &proc_period_fops);
	if (proc_entry == NULL || proc_period_entry == NULL)
		return -EROFS;

	printk("Anti-rootkit registered.\n");

	return 0;
}

static void _mod_exit(void)
{
	printk("ark: scan triggered on exit\n");
	scan_update();

	scan_period_update(0);
	flush_delayed_work(&wq);

	unregister_kprobe(&kp_add_taint);

	proc_remove(proc_entry);
	proc_remove(proc_period_entry);

	scan_targets_free(NULL);

	printk("Anti-rootkit unregistered.\n");
}

module_init(_mod_init);
module_exit(_mod_exit);

MODULE_LICENSE("GPL");
