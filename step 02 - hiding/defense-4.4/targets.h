#ifndef TARGET
#define TARGET

char *target_generic[] = {
	"idt_table",

	"generic_file_llseek",
	"generic_file_read_iter",

	"do_execve",
	"do_execveat",
	"open_exec",

	"compat_filldir",
	"compat_fillonedir",
	"filldir",
	"filldir64",
	"fillonedir",
	"iterate_dir",

	"vfs_read",
	"vfs_write",
	"vfs_iter_read",
	"vfs_iter_write",
};

char *target_proc[] = {
	"proc_fd_inode_operations",
	"proc_fd_operations",

	"proc_fdinfo_inode_operations",
	"proc_fdinfo_operations",

	"proc_link_inode_operations",

	"proc_root_inode_operations",	
	"proc_root_operations",

	"proc_task_inode_operations",
	"proc_task_operations",
};

char *target_proc_func[] = {
	"get_pid_task",
	"pid_task",
	"proc_fd_permission",
	"proc_follow_link",
	"proc_lookup",
	"proc_lookup_de",
	"proc_lookupfd",
	"proc_lookupfd_common",
	"proc_lookupfdinfo",
	"proc_pid_lookup",
	"proc_pid_permission",
	"proc_pid_readdir",
	"proc_readdir",
	"proc_readdir_de",
	"proc_readfd",
	"proc_readfd_common",
	"proc_readfdinfo",
	"proc_root_getattr",
	"proc_root_lookup",
	"proc_root_readdir",
	"proc_setattr",
	"proc_task_getattr",
	"proc_task_instantiate",
	"proc_task_lookup",
	"proc_task_readdir",
};

char *target_ext4[] = {
	"ext4_dir_inode_operations",
	"ext4_dir_operations",

	"ext4_file_inode_operations",
	"ext4_file_operations",

	"ext4_special_inode_operations",

	"ext4_symlink_inode_operations",
};

char *target_ext4_func[] = {
	"ext4_create",
	"ext4_dir_llseek",
	"ext4_fallocate",
	"ext4_fiemap",
	"ext4_file_mmap",
	"ext4_file_open",
	"ext4_file_write_iter",
	"ext4_find_entry",
	"ext4_get_acl",
	"ext4_getattr",
	"ext4_ioctl",
	"ext4_link",
	"ext4_listxattr",
	"ext4_llseek",
	"ext4_lookup",
	"ext4_mkdir",
	"ext4_mknod",
	"ext4_readdir",
	"ext4_release_file",
	"ext4_rename",
	"ext4_rename2",
	"ext4_rmdir",
	"ext4_set_acl",
	"ext4_setattr",
	"ext4_symlink",
	"ext4_sync_file",
	"ext4_tmpfile",
	"ext4_unlink",
};

char *target_net[] = {
	"tcp4_net_ops",
	"tcp4_seq_afinfo",
	"udp4_net_ops",
	"udp4_seq_afinfo",
};

char *target_net_func[] = {
	"tcp4_seq_show",
	"tcp6_seq_show",
	"udp4_seq_show",
	"udp6_seq_show",
};

#define _TARGET_CALLBACK(x) \
	for (i = 0; i < (sizeof(x)/sizeof(x[0])); i++) \
		(*callback)(x[i]); \
	r += i;

int targets_apply(void (*callback)(char *))
{
	int i, r = 0;

	_TARGET_CALLBACK(target_generic);

	_TARGET_CALLBACK(target_proc);
	_TARGET_CALLBACK(target_proc_func);

	_TARGET_CALLBACK(target_ext4);
	_TARGET_CALLBACK(target_ext4_func);

	_TARGET_CALLBACK(target_net);
	_TARGET_CALLBACK(target_net_func);

	return r;
}

#endif
