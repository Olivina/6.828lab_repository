// Called from entry.S to get us going.
// entry.S already took care of defining envs, pages, uvpd, and uvpt.

#include <inc/lib.h>

extern void umain(int argc, char **argv);

const volatile struct Env *thisenv;
const char *binaryname = "<unknown>";

void
libmain(int argc, char **argv)
{
	// set thisenv to point at our Env structure in envs[].
	// LAB 3: Your code here.
	// extern const volatile struct Env envs[NENV];
	thisenv = envs;
	const volatile struct Env * endenv = envs + NENV;
	// envid_t	sys_getenvid(void);
	envid_t curenvid = sys_getenvid();
	for(thisenv = envs; thisenv != endenv; ++thisenv ){
		if(thisenv -> env_id == curenvid)
			break;
	}
	if(thisenv == endenv)
		panic("libmain: no such envs with envid = %d\n", curenvid);

	// save the name of the program so that panic() can use it
	if (argc > 0)
		binaryname = argv[0];

	// call user main routine
	umain(argc, argv);

	// exit gracefully
	exit();
}

