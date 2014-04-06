// gcc -m32 -O0 -o a.exe a.c
#include <stdio.h>

int main(void)
{
	char b;

	// 1
	__asm__(
		"movl $0,%%eax\n"
		"neg %%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("%d\n", b);

	//
	__asm__(
		"movl $0x7FFFFFFF,%%eax\n"
		"sub $-1,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("%d\n", b);

	return 0;
}
