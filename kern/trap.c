#include <inc/mmu.h>
#include <inc/x86.h>
#include <inc/assert.h>

#include <kern/pmap.h>
#include <kern/trap.h>
#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/env.h>
#include <kern/syscall.h>
#include <kern/sched.h>
#include <kern/kclock.h>
#include <kern/picirq.h>
#include <kern/cpu.h>
#include <kern/spinlock.h>

static struct Taskstate ts;

/* For debugging, so print_trapframe can distinguish between printing
 * a saved trapframe and printing the current trapframe and print some
 * additional information in the latter case.
 */
static struct Trapframe *last_tf; // in case happens a double fault

/* Interrupt descriptor table.  (Must be built at run time because
 * shifted function addresses can't be represented in relocation records.)
 */
struct Gatedesc idt[256] = {{0}};
struct Pseudodesc idt_pd = {
	sizeof(idt) - 1, (uint32_t)idt};

const char *const syscallname(int);

static const char *trapname(int trapno)
{
	static const char *const excnames[] = {
		[T_DIVIDE] = "Divide error",
		[T_DEBUG] = "Debug",
		[T_NMI] = "Non-Maskable Interrupt",
		[T_BRKPT] = "Breakpoint",
		[T_OFLOW] = "Overflow",
		[T_BOUND] = "BOUND Range Exceeded",
		[T_ILLOP] = "Invalid Opcode",
		[T_DEVICE] = "Device Not Available",
		[T_DBLFLT] = "Double Fault",
		[T_COPROC] = "Coprocessor Segment Overrun",
		[T_TSS] = "Invalid TSS",
		[T_SEGNP] = "Segment Not Present",
		[T_STACK] = "Stack Fault",
		[T_GPFLT] = "General Protection",
		[T_PGFLT] = "Page Fault",
		[T_RES] = "(unknown trap)",
		[T_FPERR] = "x87 FPU Floating-Point Error",
		[T_ALIGN] = "Alignment Check",
		[T_MCHK] = "Machine-Check",
		[T_SIMDERR] = "SIMD Floating-Point Exception",
		[T_SYSCALL] = "System Call",
		[IRQ_OFFSET +
			IRQ_TIMER] = "IRQ TIMER",
	};

	if (trapno < ARRAY_SIZE(excnames))
		return excnames[trapno];
	if (trapno == T_SYSCALL)
		return "System call";
	if (trapno >= IRQ_OFFSET && trapno < IRQ_OFFSET + 16)
		return "Hardware Interrupt";
	return "(unknown trap)";
}

void trap_init(void)
{
	extern struct Segdesc gdt[];
	// LAB 3: Your code here.
	extern void t_devide_handler(void);
	extern void t_debug_handler(void);
	extern void t_nmi_handler(void);
	extern void t_brkpt_handler(void);
	extern void t_oflow_handler(void);
	extern void t_bound_handler(void);
	extern void t_illop_handler(void);
	extern void t_device_handler(void);
	extern void t_dblflt_handler(void);
	extern void t_corpoc_handler(void);
	extern void t_tss_handler(void);
	extern void t_segnp_handler(void);
	extern void t_stack_handler(void);
	extern void t_gpflt_handler(void);
	extern void t_pgflt_handler(void);
	extern void t_res_handler(void);
	extern void t_fperr_handler(void);
	extern void t_align_handler(void);
	extern void t_mchk_handler(void);
	extern void t_simderr_handler(void);
	extern void t_syscall_handler(void);
	// interrupt
	extern void i_timer_handler(void);
	extern void i_kbd_handler(void);
	extern void i_2_handler(void);
	extern void i_3_handler(void);
	extern void i_serial_handler(void);
	extern void i_5_handler(void);
	extern void i_6_handler(void);
	extern void i_spurious_handler(void);
	extern void i_8_handler(void);
	extern void i_9_handler(void);
	extern void i_10_handler(void);
	extern void i_11_handler(void);
	extern void i_12_handler(void);
	extern void i_13_handler(void);
	extern void i_ide_handler(void);
	extern void i_15_handler(void);
	extern void i_17_handler(void);
	extern void i_18_handler(void);
	extern void i_error_handler(void);

	SETGATE(idt[T_DIVIDE], 0, GD_KT, t_devide_handler, 0);
	SETGATE(idt[T_DEBUG], 0, GD_KT, t_debug_handler, 3);
	SETGATE(idt[T_NMI], 0, GD_KT, t_nmi_handler, 0);
	SETGATE(idt[T_BRKPT], 0, GD_KT, t_brkpt_handler, 3);
	SETGATE(idt[T_OFLOW], 0, GD_KT, t_oflow_handler, 0);
	SETGATE(idt[T_BOUND], 0, GD_KT, t_bound_handler, 0);
	SETGATE(idt[T_ILLOP], 0, GD_KT, t_illop_handler, 0);
	SETGATE(idt[T_DEVICE], 0, GD_KT, t_device_handler, 0);
	SETGATE(idt[T_DBLFLT], 0, GD_KT, t_dblflt_handler, 0);
	SETGATE(idt[T_COPROC], 0, GD_KT, t_corpoc_handler, 0);
	SETGATE(idt[T_TSS], 0, GD_KT, t_tss_handler, 0);
	SETGATE(idt[T_SEGNP], 0, GD_KT, t_segnp_handler, 0);
	SETGATE(idt[T_STACK], 0, GD_KT, t_stack_handler, 0);
	SETGATE(idt[T_GPFLT], 0, GD_KT, t_gpflt_handler, 0);
	SETGATE(idt[T_PGFLT], 0, GD_KT, t_pgflt_handler, 0);
	SETGATE(idt[T_RES], 0, GD_KT, t_res_handler, 0);
	SETGATE(idt[T_FPERR], 0, GD_KT, t_fperr_handler, 0);
	SETGATE(idt[T_ALIGN], 0, GD_KT, t_align_handler, 0);
	SETGATE(idt[T_MCHK], 0, GD_KT, t_mchk_handler, 0);
	SETGATE(idt[T_SIMDERR], 0, GD_KT, t_simderr_handler, 0);
	SETGATE(idt[T_SYSCALL], 0, GD_KT, t_syscall_handler, 3);
	// interrupts
	SETGATE(idt[IRQ_OFFSET + IRQ_TIMER], 0, GD_KT, i_timer_handler, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_KBD], 0, GD_KT, i_kbd_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 2], 0, GD_KT, i_2_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 3], 0, GD_KT, i_3_handler, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SERIAL], 0, GD_KT, i_serial_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 5], 0, GD_KT, i_5_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 6], 0, GD_KT, i_6_handler, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_SPURIOUS], 0, GD_KT, i_spurious_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 8], 0, GD_KT, i_8_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 9], 0, GD_KT, i_9_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 10], 0, GD_KT, i_10_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 11], 0, GD_KT, i_11_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 12], 0, GD_KT, i_12_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 13], 0, GD_KT, i_13_handler, 0);
	SETGATE(idt[IRQ_OFFSET + IRQ_IDE], 0, GD_KT, i_ide_handler, 0);
	SETGATE(idt[IRQ_OFFSET + 15], 0, GD_KT, i_15_handler, 0);

	SETGATE(idt[IRQ_OFFSET + 17], 0, GD_KT, i_17_handler, 3);
	SETGATE(idt[IRQ_OFFSET + 18], 0, GD_KT, i_18_handler, 3);
	SETGATE(idt[IRQ_OFFSET + IRQ_ERROR], 0, GD_KT, i_error_handler, 3);

	// Per-CPU setup
	trap_init_percpu();
}

// Initialize and load the per-CPU TSS and IDT
void trap_init_percpu(void)
{
	// The example code here sets up the Task State Segment (TSS) and
	// the TSS descriptor for CPU 0. But it is incorrect if we are
	// running on other CPUs because each CPU has its own kernel stack.
	// Fix the code so that it works for all CPUs.
	//
	// Hints:
	//   - The macro "thiscpu" always refers to the current CPU's
	//     struct CpuInfo;
	//   - The ID of the current CPU is given by cpunum() or
	//     thiscpu->cpu_id;
	//   - Use "thiscpu->cpu_ts" as the TSS for the current CPU,
	//     rather than the global "ts" variable;
	//   - Use gdt[(GD_TSS0 >> 3) + i] for CPU i's TSS descriptor;
	//   - You mapped the per-CPU kernel stacks in mem_init_mp()
	//   - Initialize cpu_ts.ts_iomb to prevent unauthorized environments
	//     from doing IO (0 is not the correct value!)
	//
	// ltr sets a 'busy' flag in the TSS selector, so if you
	// accidentally load the same TSS on more than one CPU, you'll
	// get a triple fault.  If you set up an individual CPU's TSS
	// wrong, you may not get a fault until you try to return from
	// user space on that CPU.
	//
	// LAB 4: Your code here:

	thiscpu->cpu_ts.ts_esp0 = KSTACKTOP - cpunum() * (KSTKSIZE + KSTKGAP);
	thiscpu->cpu_ts.ts_ss0 = GD_KD;
	// thiscpu->cpu_ts.ts_iomb = sizeof(struct Taskstate);
	thiscpu->cpu_ts.ts_iomb = (uint16_t)(MMIOBASE >> 16);
	gdt[(GD_TSS0 >> 3) + cpunum()] = SEG16(STS_T32A, (uint32_t)(&(thiscpu->cpu_ts)),
										   sizeof(struct Taskstate) - 1, 0);
	gdt[(GD_TSS0 >> 3) + cpunum()].sd_s = 0;

	// // Setup a TSS so that we get the right stack
	// // when we trap to the kernel.
	// ts.ts_esp0 = KSTACKTOP;
	// ts.ts_ss0 = GD_KD;
	// ts.ts_iomb = sizeof(struct Taskstate);

	// // Initialize the TSS slot of the gdt.
	// gdt[GD_TSS0 >> 3] = SEG16(STS_T32A, (uint32_t) (&ts),
	// 				sizeof(struct Taskstate) - 1, 0);
	// gdt[GD_TSS0 >> 3].sd_s = 0;

	// Load the TSS selector (like other segment selectors, the
	// bottom three bits are special; we leave them 0)
	// CPU0 => 0x28, CPU1 => 0x30, CPU2 => 0x38, ...
	ltr(GD_TSS0 + (cpunum() << 3));

	// Load the IDT
	lidt(&idt_pd);
}

void print_trapframe(struct Trapframe *tf)
{
	cprintf("TRAP frame at %p from CPU %d\n", tf, cpunum());
	print_regs(&tf->tf_regs);
	cprintf("  es   0x----%04x\n", tf->tf_es);
	cprintf("  ds   0x----%04x\n", tf->tf_ds);
	cprintf("  trap 0x%08x %s\n", tf->tf_trapno, trapname(tf->tf_trapno));
	// If this trap was a page fault that just happened
	// (so %cr2 is meaningful), print the faulting linear address.
	if (tf == last_tf && tf->tf_trapno == T_PGFLT)
		cprintf("  cr2  0x%08x\n", rcr2());
	cprintf("  err  0x%08x", tf->tf_err);
	// For page faults, print decoded fault error code:
	// U/K=fault occurred in user/kernel mode
	// W/R=a write/read caused the fault
	// PR=a protection violation caused the fault (NP=page not present).
	if (tf->tf_trapno == T_PGFLT)
		cprintf(" [%s, %s, %s]\n",
				tf->tf_err & FEC_U ? "user" : "kernel",
				tf->tf_err & FEC_WR ? "write" : "read",
				tf->tf_err & FEC_PR ? "protection" : "not-present");
	else
		cprintf("\n");
	cprintf("  eip  0x%08x\n", tf->tf_eip);
	cprintf("  cs   0x----%04x\n", tf->tf_cs);
	cprintf("  flag 0x%08x\n", tf->tf_eflags);
	if ((tf->tf_cs & 3) != 0)
	{
		cprintf("  esp  0x%08x\n", tf->tf_esp);
		cprintf("  ss   0x----%04x\n", tf->tf_ss);
	}
}

void print_regs(struct PushRegs *regs)
{
	cprintf("  edi  0x%08x\n", regs->reg_edi);
	cprintf("  esi  0x%08x\n", regs->reg_esi);
	cprintf("  ebp  0x%08x\n", regs->reg_ebp);
	cprintf("  oesp 0x%08x\n", regs->reg_oesp);
	cprintf("  ebx  0x%08x\n", regs->reg_ebx);
	cprintf("  edx  0x%08x\n", regs->reg_edx);
	cprintf("  ecx  0x%08x\n", regs->reg_ecx);
	cprintf("  eax  0x%08x\n", regs->reg_eax);
}

static void
trap_dispatch(struct Trapframe *tf)
{
	// Handle processor exceptions.
	// LAB 3: Your code here.
	// cprintf("Incoming TRAP frame at 0x%x\n", tf);
	switch (tf->tf_trapno)
	{
	case T_DIVIDE:
		// divide zero
		cprintf("kernel trap: divide zero\n");
		break;
	case T_DEBUG:
	case T_BRKPT:
		monitor(tf);
		cprintf("return from breakpoint\n");
		return;
	// case T_GPFLT:
	case T_PGFLT:
		page_fault_handler(tf);
		return;
	case IRQ_OFFSET + IRQ_TIMER:
		lapic_eoi();
		sched_yield();
		return;
	case IRQ_OFFSET + IRQ_KBD:
		lapic_eoi();
		kbd_intr();
		return;
	case IRQ_OFFSET + IRQ_SERIAL:
		lapic_eoi();
		serial_intr();
		return;
	case T_SYSCALL:
	{
		struct PushRegs *regs = (struct PushRegs *)tf;
		if (regs->reg_eax >= NSYSCALLS)
		{
			cprintf("invalid syscall number\n");
			env_destroy(curenv);
			return;
		}
		// hprintf("syscall name = %s", syscallname(regs->reg_eax));
		regs->reg_eax = syscall(regs->reg_eax, regs->reg_edx,
								regs->reg_ecx, regs->reg_ebx,
								regs->reg_edi, regs->reg_esi);
		// return value has already been written into eax/
		return;
	}
	default:
		hprintf("unknown fuck 0x%x/%d", tf->tf_trapno, tf->tf_trapno);
		uint32_t fault_va;
		fault_va = rcr2();
		hprintf("fault_va =  0x%x, error code = %d", fault_va, tf->tf_err);
		break;
	}

	// Handle spurious interrupts
	// The hardware sometimes raises these because of noise on the
	// IRQ line or other reasons. We don't care.
	if (tf->tf_trapno == IRQ_OFFSET + IRQ_SPURIOUS)
	{
		cprintf("Spurious interrupt on irq 7\n");
		print_trapframe(tf);
		return;
	}

	// Handle clock interrupts. Don't forget to acknowledge the
	// interrupt using lapic_eoi() before calling the scheduler!
	// LAB 4: Your code here.

	// Handle keyboard and serial interrupts.
	// LAB 5: Your code here.

	// Unexpected trap: The user process or the kernel has a bug.
	print_trapframe(tf);
	if (tf->tf_cs == GD_KT)
		panic("unhandled trap in kernel");
	else
	{
		env_destroy(curenv);
		return; // destroy will yield automatically. Should not reach here.
	}
}

const char *const syscallname(int syscallno)
{
	static const char *const excnames[] = {
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
		// NSYSCALLS
	};

	if (syscallno < sizeof(excnames) / sizeof(excnames[0]))
		return excnames[syscallno];
	return "(unknown syscall)";
}

void trap(struct Trapframe *tf)
{
	// entrance of the kernel

	// The environment may have set DF and some versions
	// of GCC rely on DF being clear

	asm volatile("cld" ::
					 : "cc");

	// Halt the CPU if some other CPU has called panic()
	extern char *panicstr;
	if (panicstr)
		asm volatile("hlt");

	// Re-acqurie the big kernel lock if we were halted in
	// sched_yield()
	if (xchg(&thiscpu->cpu_status, CPU_STARTED) == CPU_HALTED)
		lock_kernel();
	// Check that interrupts are disabled.  If this assertion
	// fails, DO NOT be tempted to fix it by inserting a "cli" in
	// the interrupt path.
	// hprintf("into trap, reason = %s from %x", trapname(tf->tf_trapno), curenv->env_id);
	assert(!(read_eflags() & FL_IF));

	if ((tf->tf_cs & 3) == 3)
	{
		// Trapped from user mode.
		// Acquire the big kernel lock before doing any
		// serious kernel work.
		// LAB 4: Your code here.
		lock_kernel();

		assert(curenv);
		// hprintf(">>trap from [%x], reason = %s", curenv->env_id, trapname(tf->tf_trapno));
		// if (tf->tf_trapno == T_SYSCALL)
		// {
		// 	hprintf("\tsyscall = %s", syscallname(tf->tf_regs.reg_eax));
		// }

		// Garbage collect if current enviroment is a zombie
		if (curenv->env_status == ENV_DYING)
		{
			// how could that possible?
			// does that means that in scheduling we need to enter an env even if it's ENV_DYING?
			env_free(curenv);
			curenv = NULL;
			sched_yield();
		}

		// Copy trap frame (which is currently on the stack)
		// into 'curenv->env_tf', so that running the environment
		// will restart at the trap point.
		curenv->env_tf = *tf;
		// The trapframe on the stack should be ignored from here on.
		tf = &curenv->env_tf;
	}

	// Record that tf is the last real trapframe so
	// print_trapframe can print some additional information.
	last_tf = tf;

	// Dispatch based on what type of trap occurred
	trap_dispatch(tf);

	// If we made it to this point, then no other environment was
	// scheduled, so we should return to the current environment
	// if doing so makes sense.
	if (curenv && curenv->env_status == ENV_RUNNING)
		env_run(curenv);
	else
		sched_yield();
}

void page_fault_handler(struct Trapframe *tf)
{
	uint32_t fault_va;

	// Read processor's CR2 register to find the faulting address
	fault_va = rcr2();

	// Handle kernel-mode page faults.
	uint32_t pl = tf->tf_cs & 3;
	if (pl == 0)
	{
		// kernel page fault
		panic("[%08x] kernel page fault va 0x%08x ip 0x%08x\n", curenv->env_id,
			  fault_va, tf->tf_eip);
	}
	// pgflt from user mode

	// LAB 3: Your code here.

	// We've already handled kernel-mode exceptions, so if we get here,
	// the page fault happened in user mode.

	// Call the environment's page fault upcall, if one exists.  Set up a
	// page fault stack frame on the user exception stack (below
	// UXSTACKTOP), then branch to curenv->env_pgfault_upcall.
	//
	// The page fault upcall might cause another page fault, in which case
	// we branch to the page fault upcall recursively, pushing another
	// page fault stack frame on top of the user exception stack.
	//
	// It is convenient for our code which returns from a page fault
	// (lib/pfentry.S) to have one word of scratch space at the top of the
	// trap-time stack; it allows us to more easily restore the eip/esp. In
	// the non-recursive case, we don't have to worry about this because
	// the top of the regular user stack is free.  In the recursive case,
	// this means we have to leave an extra word between the current top of
	// the exception stack and the new stack frame because the exception
	// stack _is_ the trap-time stack.
	//
	// If there's no page fault upcall, the environment didn't allocate a
	// page for its exception stack or can't write to it, or the exception
	// stack overflows, then destroy the environment that caused the fault.
	// Note that the grade script assumes you will first check for the page
	// fault upcall and print the "user fault va" message below if there is
	// none.  The remaining three checks can be combined into a single test.
	//
	// Hints:
	//   user_mem_assert() and env_run() are useful here.
	//   To change what the user environment runs, modify 'curenv->env_tf'
	//   (the 'tf' variable points at 'curenv->env_tf').

	// LAB 4: Your code here.

	struct UTrapframe *utf;
	struct Trapframe *last_tf;

	// protection violation
	// if (tf->tf_err & FEC_PR)
	// {
	// 	// hprintf("fault_va = 0x%x\n", fault_va);
	// 	// goto bad;
	// }
	// pgfalt upcall doesn't exist
	void *fault_page = (void *)ROUNDDOWN(fault_va, PGSIZE);
	int err = tf->tf_err;
	// hprintf("uma1");
	// user_mem_assert(curenv, fault_page, PGSIZE, tf->tf_err & FEC_WR ? PTE_W : 0);
	// hprintf("uma2");
	if (curenv->env_pgfault_upcall)
	{
		// hprintf("[%08x] user has handler", curenv->env_id);
		// didn't allocate exception stack

		// user_mem_assert(curenv, (const void *)fault_va, 0, PTE_U | PTE_P | (err & FEC_WR ? PTE_W : 0));

		if (tf->tf_esp > UXSTACKBOTTOM && tf->tf_esp <= UXSTACKTOP)
		{
			// from uxstack
			// hprintf("[%08x] from uxstack", curenv->env_id);
			utf = (struct UTrapframe *)(tf->tf_esp - 4 - sizeof(struct UTrapframe));
		}
		else
		{
			// from ustack
			// hprintf("[%08x] from ustack", curenv->env_id);
			utf = (struct UTrapframe *)(UXSTACKTOP - sizeof(struct UTrapframe));
		}
		user_mem_assert(curenv, (const void *)utf, 0, PTE_U | PTE_P | PTE_W);
		utf->utf_fault_va = fault_va;
		utf->utf_err = tf->tf_err;
		utf->utf_regs = tf->tf_regs;
		utf->utf_eflags = tf->tf_eflags;
		utf->utf_eip = tf->tf_eip;
		utf->utf_esp = tf->tf_esp;
		curenv->env_tf.tf_eip = (uint32_t)curenv->env_pgfault_upcall;
		curenv->env_tf.tf_esp = (uint32_t)utf;
		env_run(curenv);
	}
	else
	{
		// don't have handler
	bad:
		// Destroy the environment that caused the fault.
		cprintf("[%08x] user fault va %08x ip %08x\n",
				curenv->env_id, fault_va, tf->tf_eip);
		print_trapframe(tf);
		env_destroy(curenv);
	}
}
