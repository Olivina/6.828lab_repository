// $ gcc program_entry.c -e __start
// $ ./a.out
// custom program entr

#include <stdio.h>

void program_entry(void);

void _fuckyou(void){
	puts("fuckyoutoo\n");
}
void
_start(void)
{ 
    program_entry();
}


void
program_entry(void)
{
    printf("custom program entry\n");
}
