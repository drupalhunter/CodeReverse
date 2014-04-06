////////////////////////////////////////////////////////////////////////////
// a.c
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

// gcc -m32 -O0 -o a.exe a.c
#include <stdio.h>

int main(void)
{
	char b;
	int n1, n2;

	n1 = 0x7FFFFFFF; n2 = 1;
	__asm__(
		"movl $0x7FFFFFFF,%%eax\n"
		"add $1,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = 0x7FFFFFFF; n2 = -1;
	__asm__(
		"movl $0x7FFFFFFF,%%eax\n"
		"add $-1,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = -1; n2 = 0x7FFFFFFF;
	__asm__(
		"movl $-1,%%eax\n"
		"add $0x7FFFFFFF,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = 1; n2 = 0x7FFFFFFF;
	__asm__(
		"movl $1,%%eax\n"
		"add $0x7FFFFFFF,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = -1; n2 = 1;
	__asm__(
		"movl $-1,%%eax\n"
		"add $1,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = 1; n2 = -1;
	__asm__(
		"movl $1,%%eax\n"
		"add $-1,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = -1; n2 = 2;
	__asm__(
		"movl $-1,%%eax\n"
		"add $2,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = 1; n2 = -2;
	__asm__(
		"movl $1,%%eax\n"
		"add $-2,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = 2; n2 = -2;
	__asm__(
		"movl $2,%%eax\n"
		"add $-2,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = 0x80000000; n2 = 0x80000000;
	__asm__(
		"movl $0x80000000,%%eax\n"
		"add $0x80000000,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	n1 = -1; n2 = -2;
	__asm__(
		"movl $-1,%%eax\n"
		"add $-2,%%eax\n"
		"seto %0\n" :: "m"(b) : "%eax");
	printf("0x%08lX + 0x%08lX = 0x%08lX (%d) ", n1, n2, n1 + n2, b);
	printf("%d\n", (n1 < 0 && n2 < 0 && n1 + n2 >= 0) || (n1 >= 0 && n2 >= 0 && n1 + n2 < 0));

	return 0;
}
