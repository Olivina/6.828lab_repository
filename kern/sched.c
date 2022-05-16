#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/spinlock.h>
#include <kern/env.h>
#include <kern/pmap.h>
#include <kern/monitor.h>
// for print_caller()
#include <kern/kdebug.h>

void sched_halt(void);

// Choose a user environment to run and run it.
void sched_yield(void)
{

	static const char *const env_status_name[] = {
		[ENV_FREE] = "ENV_FREE",
		[ENV_DYING] = "ENV_DYING",
		[ENV_RUNNABLE] = "ENV_RUNNABLE",
		[ENV_RUNNING] = "ENV_RUNNING",
		[ENV_NOT_RUNNABLE] = "ENV_NOT_RUNNABLE",
	};

	struct Env *idle;

	// Implement simple round-robin scheduling.
	//
	// Search through 'envs' for an ENV_RUNNABLE environment in
	// circular fashion starting just after the env this CPU was
	// last running.  Switch to the first such environment found.
	//
	// If no envs are runnable, but the environment previously
	// running on this CPU is still ENV_RUNNING, it's okay to
	// choose that environment.
	//
	// Never choose an environment that's currently running on
	// another CPU (env_status == ENV_RUNNING). If there are
	// no runnable environments, simply drop through to the code
	// below to halt the cpu.

	// LAB 4: Your code here.
	int cpu_num = cpunum();
	int start_envid = ENVX(thiscpu->cpu_env ? thiscpu->cpu_env->env_id + 1 : 0);
	int itr_envid;
	bool second_turn = false;
	for (itr_envid = start_envid;
		 envs[itr_envid].env_status != ENV_RUNNABLE;
		 // envs[itr_envid].env_status == ENV_FREE ||
		 // envs[itr_envid].env_status == ENV_NOT_RUNNABLE;
		 itr_envid = (itr_envid + 1) % NENV)
	{
		if (itr_envid == start_envid)
		{
			if (second_turn)
				goto no_runnable;
			else
				second_turn = true;
		}
	}
	// we get the first env that could be
	// RUNNING / RUNNABLE / DYING
	// if(debugflag)
	// 	cprintf("found runnable envid = %d\n", itr_envid);
	struct Env *env_to_run = &envs[itr_envid];
	// envid2env(itr_envid, &env_to_run, false);

	env_run(env_to_run);

	warn("should not reach here!\n");

no_runnable:
	// sched_halt never returns

	for (itr_envid = 0; itr_envid < NENV; ++itr_envid)
	{
		if (envs[itr_envid].env_status == ENV_FREE)
			continue;
		hprintf("envs[0x%x]: %s", itr_envid + 0x1000, env_status_name[envs[itr_envid].env_status]);
	}
	sched_halt();
}

// Halt this CPU when there is nothing to do. Wait until the
// timer interrupt wakes it up. This function never returns.
//
void sched_halt(void)
{
	// hprintf("enter sched_halt");
	// print_caller(read_ebp());
	// hprintf("after calling chain");
	int i;

	// For debugging and testing purposes, if there are no runnable
	// environments in the system, then drop into the kernel monitor.
	for (i = 0; i < NENV; i++)
	{
		if ((envs[i].env_status == ENV_RUNNABLE ||
			 envs[i].env_status == ENV_RUNNING ||
			 envs[i].env_status == ENV_DYING))
			break;
	}
	// hprintf("i = %d", i);
	if (i == NENV)
	{
		// cprintf("No runnable environments in the system!\n");
		cprintf("No runnable environments in the system!\n");
		while (1)
			monitor(NULL);
	}

	// Mark that no environment is running on this CPU
	curenv = NULL;
	lcr3(PADDR(kern_pgdir));

	// Mark that this CPU is in the HALT state, so that when
	// timer interupts come in, we know we should re-acquire the
	// big kernel lock
	xchg(&thiscpu->cpu_status, CPU_HALTED);

	// Release the big kernel lock as if we were "leaving" the kernel
	hprintf("halt");
	unlock_kernel();

	// Reset stack pointer, enable interrupts and then halt.
	asm volatile(
		"movl $0, %%ebp\n"
		"movl %0, %%esp\n"
		"pushl $0\n"
		"pushl $0\n"
		// Uncomment the following line after completing exercise 13
		"sti\n"
		"1:\n"
		"hlt\n"
		"jmp 1b\n"
		:
		: "a"(thiscpu->cpu_ts.ts_esp0));
}
