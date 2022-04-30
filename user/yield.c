// yield the processor to other environments

#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	int i;

	cprintf("Hello, I am environment %08x.\n", thisenv->env_id);
	for (i = 0; i < 5; i++) {
		sys_yield();
		cprintf("cpu[%d]: Back in environment %08x, iteration %d.\n",
			thisenv->env_cpunum, thisenv->env_id, i);
	}
	// cprintf("All done in environment %08x.\n", thisenv->env_id);
	cprintf("cpu[%d]: All done in environment %08x.\n", thisenv->env_cpunum, thisenv->env_id);
}
