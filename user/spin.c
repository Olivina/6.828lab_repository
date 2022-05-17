// Test preemption by forking off a child process that just spins forever.
// Let it run for a couple time slices, then kill it.

#include <inc/lib.h>

void umain(int argc, char **argv)
{
	envid_t env;

	cprintf("I am the parent.  Forking the child...\n");
	if ((env = fork()) == 0)
	{
		cprintf("I am the child.  Spinning...\n");
		while (1)
			/* do nothing */;
	}

	cprintf("I am the parent.  Running the child...\n");
	sys_yield();
	cprintf("parent1\n");
	sys_yield();
	cprintf("parent2\n");
	sys_yield();
	cprintf("parent3\n");
	sys_yield();
	cprintf("parent4\n");
	sys_yield();
	cprintf("parent5\n");
	sys_yield();
	cprintf("parent6\n");
	sys_yield();
	cprintf("parent7\n");
	sys_yield();

	cprintf("I am the parent.  Killing the child...\n");
	sys_env_destroy(env);
}
