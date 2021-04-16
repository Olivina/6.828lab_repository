// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};
typedef struct Stackframe {
	const uint32_t ebp;
	const uint32_t eip;
	const uint32_t arg[5];
} Stackframe;

int mon_fu(int argc, char ** argv, struct Trapframe *tf);
int mon_shut(int argc, char ** argv, struct Trapframe *tf);
int mon_print(int argc, char ** argv, struct Trapframe *tf);

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "fu", "Fu You", mon_fu },
	{ "shutdown", "Turn off your qemu", mon_shut },
	{ "cprintf", "print your string", mon_print },
	{ "backtrace", "print the stack backtrace", mon_backtrace },
};

/***** Implementations of basic kernel monitor commands *****/

int mon_print(int argc, char ** argv, struct Trapframe *tf){
	cprintf(argv[1]);
	cprintf("\n");
	return 0;
}

int mon_fu(int argc, char ** argv, struct Trapframe *tf)
{
	cprintf("\033[36m\033[48mtest\n");
	// debuginfo_eip();
	return 0;
}

int mon_shut(int argc, char ** argv, struct Trapframe *tf)
{
	cprintf("Your qemu is turning off...\n");

	return -1;
}

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	cprintf("Stack backtrace:\n");
	Stackframe * sf = (Stackframe *) read_ebp();
	struct Eipdebuginfo info;
	do{
		cprintf("  ebp %08x ", sf);
		cprintf("eip %08x ", sf->eip);
		cprintf("args %08x %08x %08x %08x %08x\n", sf->arg[0], sf->arg[1], sf->arg[2], sf->arg[3], sf->arg[4]);
		debuginfo_eip((uintptr_t) sf->eip, &info);
		cprintf("\t%s:%d: ", info.eip_file, info.eip_line);
		cprintf("%.*s", info.eip_fn_namelen, info.eip_fn_name);
		cprintf("+%d\n", (int)(sf->eip - info.eip_fn_addr));
	}
	while( (sf= (Stackframe *) sf->ebp ) != NULL);
	
	return 0;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

int
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
	return 0;
}
