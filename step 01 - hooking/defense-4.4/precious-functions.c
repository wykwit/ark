#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/vmalloc.h>


#define SYSCALL_LIMIT 285

unsigned long *_sys_call_table;
static unsigned long _sys_call_table_copy[SYSCALL_LIMIT];

char *(*_kallsyms_lookup)(unsigned long, unsigned long *, unsigned long *, char **, char*);


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

static struct Results {
	int started, finished;		// state
	int mismatches, overwrites;	// results
	int fix;			// settings
} scan_results;

static struct Target {
	unsigned long addr, size;
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
	memcpy(new_mem, (const void *) addr, size);

	*new_target = (struct Target) {
		.addr = addr,
		.size = size,
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
	printk("ark: scan targets check\n");
	for (t = scan_targets; t != NULL; t = t->next) {
		printk("ark: t %lu s %lu\n", t->addr, t->size);

		(*_kallsyms_lookup)(t->addr, &size, &offset, &modname, namebuf);

		overwritten = 0;
		for (i = 0; i < t->size && i < size-offset; i++) {
			b = (unsigned char *) t->addr + i;
			c = t->copy[i];
			if (*b == c)
				continue;
			else
				overwritten = 1;

			if (scan_results.fix < 0) {
				// do not fix, report only once
				printk("ark: found a mismatch, function overwritten - %lu\n", t->addr);
				break;
			}

			printk("ark: found a mismatch, function overwritten - %lu, "
				"attempting to fix - got %02x want %02x\n", t->addr, *b, c);
			overwrite_byte(b, c);
		}
		scan_results.overwrites += overwritten;
	}
	printk("ark: no more targets\n");

	return scan_results.overwrites;
}

int scan_update(void)
{
	char buf[255]; // BUG: this size is chosen arbitrarily
	int i;

	if (scan_results.finished < scan_results.started)
		return -1;

	scan_results.started = scan_results.finished + 1;
	scan_results.mismatches = 0;

	// check #1 (write protection): cr0 WP bit
	if((read_cr0() & 0x00010000) == 0) {
		printk("ark: write protection was disabled, something fishy might be going on\n");
		write_cr0(read_cr0() | 0x00010000);
	}

	// check #2 (symbol table): sys_call_table entries
	for (i = 0; i < SYSCALL_LIMIT; i++) {
		if (_sys_call_table_copy[i] != _sys_call_table[i]) {
			scan_results.mismatches++;
			printk("ark: found a mismatch on syscall %d\n", i);
			sprint_symbol(buf, _sys_call_table[i]); // BUG: this may cause a buffer overflow
			printk("ark: offender - %s\n", buf);
			if (scan_results.fix < 0)
				continue;
			printk("ark: attempted to fix syscall %d\n", i);
			restore_syscall(i);
		}
	}

	// check #3 (interrupt descriptor table): idt_table entries
	// TODO: add IDT integrity check here

	// check #4 (patching): function integrity
	scan_targets_check();

	scan_results.finished = scan_results.started + 1;
	return scan_results.mismatches;
}

void scan_init(void)
{
	int i;

	scan_targets = NULL;
	scan_results.fix = -1;
	scan_results.started = 0;
	scan_results.finished = 0;

	_sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
	_kallsyms_lookup =
		(char *(*)(unsigned long, unsigned long *, unsigned long *, char **, char*))
		kallsyms_lookup_name("kallsyms_lookup");

	for (i = 0; i < SYSCALL_LIMIT; i++) {
		_sys_call_table_copy[i] = _sys_call_table[i];
		scan_targets_add(_sys_call_table[i]);
	}

	scan_targets_add((unsigned long) scan_targets_add);
	scan_targets_add((unsigned long) scan_update);

	scan_results.finished = 1;
}


// == PROCFS ==

static struct proc_dir_entry *proc_entry;

ssize_t proc_read(struct file *f, char __user *out, size_t count, loff_t *off)
{
	const unsigned int size = 8;

	char buf[size];
	buf[0] = '0' + (scan_results.mismatches / 100) % 10;
	buf[1] = '0' + (scan_results.mismatches / 10) % 10;
	buf[2] = '0' + (scan_results.mismatches / 1) % 10;
	buf[3] = ' ';
	buf[4] = '0' + (scan_results.overwrites / 10) % 10;
	buf[5] = '0' + (scan_results.overwrites / 1) % 10;
	buf[6] = '\n';
	buf[7] = '\0';

	if (*off > 0)
		return 0;
	if (count > size)
		count = size;

	copy_to_user(out, buf, count); // BUG: check the return value

	*off = count;
	return count;
}

ssize_t proc_write(struct file *f, const char __user *in, size_t count, loff_t *off)
{
	char buf[1];

	if (count > 0) {
		copy_from_user(buf, in, 1); // BUG: check the return value
		switch (buf[0]) {
		case '1':
			scan_results.fix = 1;
			break;
		case '0':
			scan_results.fix = -1;
			break;
		}

		scan_update();
	}

	return count;
}

struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write,
};


// == MODULE ==

static int _mod_init(void)
{
	scan_init();

	// proc init
	proc_entry = proc_create("ark", 0666, NULL, &proc_fops);
	if (proc_entry == NULL)
		return -1;

	printk("Anti-rootkit registered.\n");

	return 0;
}

static void _mod_exit(void)
{
	proc_remove(proc_entry);

	scan_targets_free(NULL);

	printk("Anti-rootkit unregistered.\n");
}

module_init(_mod_init);
module_exit(_mod_exit);

MODULE_LICENSE("GPL");
