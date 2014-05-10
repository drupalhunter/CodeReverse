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
    char b1, b2;
    int n1, n2;

    n1 = 0x7FFFFFFF; n2 = 1;
    __asm__(
        "stc\n"
        "movl $0x7FFFFFFF,%%eax\n"
        "sbb $1,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = 0x7FFFFFFF; n2 = -1;
    __asm__(
        "stc\n"
        "movl $0x7FFFFFFF,%%eax\n"
        "sbb $-1,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = -1; n2 = 0x7FFFFFFF;
    __asm__(
        "stc\n"
        "movl $-1,%%eax\n"
        "sbb $0x7FFFFFFF,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = 1; n2 = 0x7FFFFFFF;
    __asm__(
        "stc\n"
        "movl $1,%%eax\n"
        "sbb $0x7FFFFFFF,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = -1; n2 = 1;
    __asm__(
        "stc\n"
        "movl $-1,%%eax\n"
        "sbb $1,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = 0xFFFFFFFF; n2 = 0xFFFFFFFF;
    __asm__(
        "stc\n"
        "movl $0xFFFFFFFF,%%eax\n"
        "sbb $0xFFFFFFFF,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = 1; n2 = 1;
    __asm__(
        "stc\n"
        "movl $1,%%eax\n"
        "sbb $1,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = -1; n2 = 2;
    __asm__(
        "stc\n"
        "movl $-1,%%eax\n"
        "sbb $2,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = 1; n2 = 2;
    __asm__(
        "stc\n"
        "movl $1,%%eax\n"
        "sbb $2,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = 0x80000000; n2 = 0x80000000;
    __asm__(
        "stc\n"
        "movl $0x80000000,%%eax\n"
        "sbb $0x80000000,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    n1 = -1; n2 = -2;
    __asm__(
        "stc\n"
        "movl $-1,%%eax\n"
        "sbb $-2,%%eax\n"
        "sets %0\n"
        "seto %1\n"
        :: "m"(b1),"m"(b2) : "%eax");
    printf("0x%08lX - 0x%08lX = 0x%08lX (%d, %d, %d) ", n1, n2, n1 - n2, b1, b2, b1 == b2);
    printf("%d\n", n1 > n2);

    return 0;
}
