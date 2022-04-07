#define MODULE
#define __KERNEL__

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/unistd.h>

extern void *sys_call_table[];

#define SYSCALL_LIMIT 255
void *sys_call_table_copy[SYSCALL_LIMIT];

static struct Results {
	int started, finished, mismatches, fix;
} scan_results;

int scan_update(void)
{
	if (scan_results.finished < scan_results.started)
		return -1;

	scan_results.started = scan_results.finished + 1;
	scan_results.mismatches = 0;

	int i;
	for (i = 0; i < SYSCALL_LIMIT; i++) {
		if (sys_call_table_copy[i] != sys_call_table[i]) {
			scan_results.mismatches++;
			printk("ARK found mismatch on syscall %d\n", i);
			if (scan_results.fix < 0) continue;
			printk("ARK attempted to fix syscall %d\n", i);
			sys_call_table[i] = sys_call_table_copy[i];
		}
	}

	scan_results.finished = scan_results.started + 1;
	return scan_results.mismatches;
}

static int read_proc_ark(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	const unsigned int size = 5;

	char buf[size];
	buf[0] = '0' + (scan_results.mismatches / 100) % 10;
	buf[1] = '0' + (scan_results.mismatches / 10) % 10;
	buf[2] = '0' + (scan_results.mismatches / 1) % 10;
	buf[3] = '\n';
	buf[4] = '\0';

	if (off >= size) return 0;
	if (count > size-off) count = size-off;

	memcpy(page, buf+off, count);

	return count;
}

static int write_proc_ark(struct file *file, const char *buffer, unsigned long count, void *data)
{
	if (count > 0) {
		switch (buffer[0]) {
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

int init_module(void)
{
	scan_results.fix = -1;
	scan_results.started = 0;
	scan_results.finished = 1;

	int i;
	for (i = 0; i < SYSCALL_LIMIT; i++)
		sys_call_table_copy[i] = sys_call_table[i];

	struct proc_dir_entry *proc_ark;
	proc_ark = create_proc_entry("ark", 0666, NULL);
	if (proc_ark != NULL) {
		proc_ark->read_proc = read_proc_ark;
		proc_ark->write_proc = write_proc_ark;
	}

	printk("Anti-rootkit registered.\n");

	return 0;
}

void cleanup_module(void)
{
	remove_proc_entry("ark", NULL);
	printk("Anti-rootkit unregistered.\n");
}

