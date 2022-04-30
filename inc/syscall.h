#ifndef JOS_INC_SYSCALL_H
#define JOS_INC_SYSCALL_H

/* system call numbers */
enum {
	SYS_cputs = 0,
	SYS_cgetc,
	SYS_getenvid,
	SYS_env_destroy,
	SYS_page_alloc,
	SYS_page_map,
	SYS_page_unmap,
	SYS_exofork,
	SYS_env_set_status,
	SYS_env_set_pgfault_upcall,
	SYS_yield,
	SYS_ipc_try_send,
	SYS_ipc_recv,
	NSYSCALLS
};

const char *syscallname(int syscallno)
{
	static const char * const excnames[] = {
		[SYS_cputs] = "SYS_cputs",
		[SYS_cgetc] = "SYS_cgetc",
		[SYS_getenvid] = "SYS_getenvid",
		[SYS_env_destroy] = "SYS_env_destroy",
		[SYS_page_alloc] = "SYS_page_alloc",
		[SYS_page_map] = "SYS_page_map",
		[SYS_page_unmap] = "SYS_page_unmap",
		[SYS_exofork] = "SYS_exofork",
		[SYS_env_set_status] = "SYS_env_set_status",
		[SYS_env_set_pgfault_upcall] = "SYS_env_set_pgfault_upcall",
		[SYS_yield] = "SYS_yield",
		[SYS_ipc_try_send] = "SYS_ipc_try_send",
		[SYS_ipc_recv] = "SYS_ipc_recv",
		NSYSCALLS
	};

	if (syscallno < ARRAY_SIZE(excnames))
		return excnames[syscallno];
	return "(unknown syscall)";
}

#endif /* !JOS_INC_SYSCALL_H */
