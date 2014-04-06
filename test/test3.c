////////////////////////////////////////////////////////////////////////////
// test3.c
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdarg.h>

// gcc -m32 -O0 -o test3-gcc32.exe test3.c
// gcc -m64 -O0 -o test3-gcc64.exe test3.c
// cl /Od test3.c /Fetest3-vc32.exe
// cl /Od test3.c /Fetest3-vc64.exe
// bcc32 -etest3-bor32.exe -Od test3.c
// wcl386 -d0 -od -fe=test3-wat32.exe test3.c

__declspec(dllexport)
int __fastcall func1(int a, char b, int c, int d, int e, unsigned short f)
{
	d += a + b + c;
	return d + e + f;
}

__declspec(dllexport)
size_t __fastcall func2(size_t a, int b, int c, size_t d, int e, int f)
{
	d += a + b + c;
	return d + e + f;
}

__declspec(dllexport)
size_t __cdecl func3(size_t n, ...)
{
	va_list va;
	size_t i, m = 0;
	va_start(va, n);
	for (i = 0; i < n; i++)
	{
		m += va_arg(va, size_t);
	}
	va_end(va);
	return m;
}

__declspec(dllexport)
int main(void)
{
	int n;
	size_t m;
	n = func1(1, 2, 3, 4, 5, 6);
	printf("%d\n", n);
	m = func2(1, 2, 3, 4, 5, 6);
	printf("%d\n", (int)m);
	m = func3(5, 2, 3, 4, 5, 6);
	printf("%d\n", (int)m);
	return 0;
}
