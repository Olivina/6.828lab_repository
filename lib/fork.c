// implement fork from user space

#include <inc/string.h>
#include <inc/lib.h>

// PTE_COW marks copy-on-write page table entries.
// It is one of the bits explicitly allocated to user processes (PTE_AVAIL).
#define PTE_COW 0x800

//
// Custom page fault handler - if faulting page is copy-on-write,
// map in our own private writable copy.
//
static void
pgfault(struct UTrapframe *utf)
{
	void *addr = (void *)utf->utf_fault_va;
	void *va_fault_page = ROUNDDOWN(addr, PGSIZE);
	uint32_t err = utf->utf_err;
	int r;

	int perm = err & FEC_WR ? PTE_P | PTE_U | PTE_W : PTE_P | PTE_U;

	envid_t envid = sys_getenvid();

	// cprintf("[%08x] %s:%d: [Page Fault Handler] enter\n", envid, __FILE__, __LINE__);
	if (err & FEC_PR)
	{
		// page exist, but protection violation
		if (err & FEC_WR)
		{
			// First, check if the page exist
			// second, check if the page is COW or RO
			// write operation
			// cprintf("[%08x] %s:%d: [Page Fault Handler] handle write fault at 0x%x\n", envid, __FILE__, __LINE__, addr);
			if ((r = sys_page_alloc(0, PFTEMP, perm)) < 0)
			{
				cprintf("%s:%d: [Page Fault Handler] %e\n", __FILE__, __LINE__, r);
				exit();
			}

			if (memcpy(PFTEMP, va_fault_page, PGSIZE) != PFTEMP)
			{
				cprintf("%s:%d: [Page Fault Handler] memcpy failed\n", __FILE__, __LINE__);
				exit();
			}
			if ((r = sys_page_unmap(0, va_fault_page)) < 0)
			{
				cprintf("%s:%d: [Page Fault Handler] %e\n", __FILE__, __LINE__, r);
				exit();
			}
			if ((r = sys_page_map(0, PFTEMP, 0, va_fault_page, perm)) < 0)
			{
				cprintf("%s:%d: [Page Fault Handler] %e\n", __FILE__, __LINE__, r);
				exit();
			}
			if ((r = sys_page_unmap(0, PFTEMP)) < 0)
			{
				cprintf("%s:%d: [Page Fault Handler] %e\n", __FILE__, __LINE__, r);
				exit();
			}
		}
		else
		{
			cprintf("%s:%d: [Page Fault Handler] read error\n", __FILE__, __LINE__);
			// read?
		}
	}
	else
	{
		// page not exists, alloc it
		// cprintf("[%08x] %s:%d: [Page Fault Handler] handle not present fault\n", envid, __FILE__, __LINE__);
		if ((r = sys_page_alloc(0, va_fault_page, perm)) < 0)
		{
			cprintf("%s:%d: [Page Fault Handler] alloc error\n", __FILE__, __LINE__);
			exit();
		}
	}

	// Check that the faulting access was (1) a write, and (2) to a
	// copy-on-write page.  If not, panic.
	// Hint:
	//   Use the read-only page table mappings at uvpt
	//   (see <inc/memlayout.h>).

	// LAB 4: Your code here.

	// Allocate a new page, map it at a temporary location (PFTEMP),
	// copy the data from the old page to the new page, then move the new
	// page to the old page's address.
	// Hint:
	//   You should make three system calls.

	// LAB 4: Your code here.
	// cprintf("[%08x] %s:%d: [Page Fault Handler] return\n", envid, __FILE__, __LINE__);
	return;
	// panic("pgfault not implemented");
}

//
// Map our virtual page pn (address pn*PGSIZE) into the target envid
// at the same virtual address.  If the page is writable or copy-on-write,
// the new mapping must be created copy-on-write, and then our mapping must be
// marked copy-on-write as well.  (Exercise: Why do we need to mark ours
// copy-on-write again if it was already copy-on-write at the beginning of
// this function?)
//
// Returns: 0 on success, < 0 on error.
// It is also OK to panic on error.
//
static int
duppage(envid_t envid, unsigned pn)
{
	int r;

	pte_t *pte_ptr = (pte_t *)uvpt;
	pte_ptr += pn;

	if (*pte_ptr & PTE_SHARE)
	{
		return sys_page_map(0, (void *)(pn * PGSIZE), envid, (void *)(pn * PGSIZE), PTE_SYSCALL);
	}

	if (*pte_ptr & PTE_W || *pte_ptr & PTE_COW)
	{
		if ((r = sys_page_map(0, (void *)(pn * PGSIZE), envid, (void *)(pn * PGSIZE), PTE_COW | PTE_P | PTE_U)) < 0)
		{
			cprintf("%s:%d: err = %e\n", __FILE__, __LINE__, r);
			return r;
		}
		if ((r = sys_page_map(envid, (void *)(pn * PGSIZE), 0, (void *)(pn * PGSIZE), PTE_COW | PTE_P | PTE_U)) < 0)
		{
			cprintf("%s:%d: err = %e\n", __FILE__, __LINE__, r);
			return r;
		}
	}
	else
	{
		// READ ONLY
		int perm = *pte_ptr & PTE_SYSCALL;
		if (perm & PTE_SHARE)
			cprintf("%s:%d duppage: PTE_SHARE\n", __FILE__, __LINE__);
		if ((r = sys_page_map(0, (void *)(pn * PGSIZE), envid, (void *)(pn * PGSIZE), perm | PTE_P | PTE_U)) < 0)
		{
			cprintf("%s:%d: err = %e\n", __FILE__, __LINE__, r);
			return r;
		}
	}
	return 0;

	// LAB 4: Your code here.
	// panic("duppage not implemented");
	// return 0;
}

//
// User-level fork with copy-on-write.
// Set up our page fault handler appropriately.
// Create a child.
// Copy our address space and page fault handler setup to the child.
// Then mark the child as runnable and return.
//
// Returns: child's envid to the parent, 0 to the child, < 0 on error.
// It is also OK to panic on error.
//
// Hint:
//   Use uvpd, uvpt, and duppage.
//   Remember to fix "thisenv" in the child process.
//   Neither user exception stack should ever be marked copy-on-write,
//   so you must allocate a new page for the child's user exception stack.
//
envid_t fork(void)
{
	set_pgfault_handler(pgfault);

	envid_t envid;
	uint8_t *addr;
	int errno;
	// extern unsigned char uvpd[];
	// extern unsigned char uvpt[];

	envid = sys_exofork();
	if (envid < 0) // failed
		return envid;
	if (envid == 0) // child
	{
		envid_t this = sys_getenvid();
		int envx = ENVX(sys_getenvid());
		thisenv = &envs[envx];
		return 0;
	}
	pde_t *pde_ptr = (pde_t *)uvpd;
	pte_t *pte_ptr = (pte_t *)uvpt;
	int pn, ppn;
	int count = 0, count_present = 0;

	pte_t *uxstack_entry = pte_ptr + (PDX(UXSTACKBOTTOM) * 1024 + PTX(UXSTACKBOTTOM));

	for (pn = 0; pn <= USTACKTOP / PTSIZE; ++pn)
	{
		// pde
		if (*(pde_ptr + pn) & PTE_P)
		{
			for (ppn = 0; ppn < NPTENTRIES - 1; ++ppn)
			{
				if (*(pte_ptr + pn * NPTENTRIES + ppn) & PTE_P)
				{
					// cprintf("%s:%d: fork: addr to duplicate: 0x%x\n", __FILE__, __LINE__, PGADDR(pn, ppn, 0));
					// cprintf("%s:%d: before duppage: *uxstack_entry = 0x%x\n", __FILE__, __LINE__, *uxstack_entry);
					if ((errno = duppage(envid, pn * NPTENTRIES + ppn)) < 0)
					{
						cprintf("%s:%d: err = %e\n", __FILE__, __LINE__, errno);
						return errno;
					}
					// cprintf("%s:%d: after duppage: *uxstack_entry = 0x%x\n", __FILE__, __LINE__, *uxstack_entry);
				}
			}
		}
	}
	// cprintf("%s:%d: *uxstack_entry = 0x%x\n", __FILE__, __LINE__, *uxstack_entry);
	// panic("stop");
	// 对UXSTACK特别处理
	if ((errno = sys_page_alloc(envid, (void *)UXSTACKBOTTOM, PTE_P | PTE_U | PTE_W)) < 0)
	{
		cprintf("%s:%d: set exception stack failed: %e\n", __FILE__, __LINE__, errno);
		exit();
	}
	// cprintf("%s:%d: called\n", __FILE__, __LINE__);

	if ((errno = sys_env_set_status(envid, ENV_RUNNABLE)) < 0)
	{
		cprintf("%s:%d: called2\n", __FILE__, __LINE__);
		return errno;
	}
	// cprintf("%s:%d: envid = %x\n", __FILE__, __LINE__, envid);
	return envid;
	// LAB 4: Your code here.
	// panic("fork not implemented");
}

// Challenge!
int sfork(void)
{
	panic("sfork not implemented");
	return -E_INVAL;
}
