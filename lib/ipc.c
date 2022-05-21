// User-level IPC library routines

#include <inc/lib.h>

// Receive a value via IPC and return it.
// If 'pg' is nonnull, then any page sent by the sender will be mapped at
//	that address.
// If 'from_env_store' is nonnull, then store the IPC sender's envid in
//	*from_env_store.
// If 'perm_store' is nonnull, then store the IPC sender's page permission
//	in *perm_store (this is nonzero iff a page was successfully
//	transferred to 'pg').
// If the system call fails, then store 0 in *fromenv and *perm (if
//	they're nonnull) and return the error.
// Otherwise, return the value sent by the sender
//
// Hint:
//   Use 'thisenv' to discover the value and who sent it.
//   If 'pg' is null, pass sys_ipc_recv a value that it will understand
//   as meaning "no page".  (Zero is not the right value, since that's
//   a perfectly valid place to map a page.)
int32_t
ipc_recv(envid_t *from_env_store, void *pg, int *perm_store)
{
	// LAB 4: Your code here.
	int errno;
	if ((uint32_t)pg > UTOP || (uint32_t)pg % PGSIZE)
	{
		return -E_INVAL;
	}

	if ((errno = sys_ipc_recv(pg)) < 0)
	{
		return errno;
	}
	// cprintf("%s:%d: child: received\n", __FILE__, __LINE__);
	if (from_env_store)
	{
		*from_env_store = thisenv->env_ipc_from;
	}
	// cprintf("%s:%d: child: ipc from\n", __FILE__, __LINE__);
	if (perm_store)
	{
		*perm_store = thisenv->env_ipc_perm;
	}
	// cprintf("%s:%d: child: perm_store\n", __FILE__, __LINE__);
	return thisenv->env_ipc_value;
	// panic("ipc_recv not implemented");
	// return 0;
}

// Send 'val' (and 'pg' with 'perm', if 'pg' is nonnull) to 'toenv'.
// This function keeps trying until it succeeds.
// It should panic() on any error other than -E_IPC_NOT_RECV.
//
// Hint:
//   Use sys_yield() to be CPU-friendly.
//   If 'pg' is null, pass sys_ipc_try_send a value that it will understand
//   as meaning "no page".  (Zero is not the right value.)
void ipc_send(envid_t to_env, uint32_t val, void *pg, int perm)
{
	// LAB 4: Your code here.
	int errno;
	while ((errno = sys_ipc_try_send(to_env, val, pg, perm)) != 0)
	{
		if (errno != -E_IPC_NOT_RECV)
		{
			cprintf("%s:%d: to_env = %x, val = %d, pg = %x, perm = %d\n",
					__FILE__, __LINE__, to_env, val, pg, perm);
			panic("invalid value, err = %e", errno);
		}
		sys_yield();
	}
	// return;
	// panic("ipc_send not implemented");
}

// Find the first environment of the given type.  We'll use this to
// find special environments.
// Returns 0 if no such environment exists.
envid_t
ipc_find_env(enum EnvType type)
{
	int i;
	for (i = 0; i < NENV; i++)
		if (envs[i].env_type == type)
			return envs[i].env_id;
	return 0;
}
