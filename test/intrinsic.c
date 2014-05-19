#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// L00401560: 8B 44 24 04                         mov eax,[esp+0x4]
// L00401564: 99                                  cdq
// L00401565: 31 D0                               xor eax,edx
// L00401567: 29 D0                               sub eax,edx
// L00401569: C3                                  ret
__declspec(dllexport)
int my_abs(int n)
{
    return abs(n);
}

// L00401570: 8B 44 24 04                         mov eax,[esp+0x4]
// L00401574: 99                                  cdq
// L00401575: 31 D0                               xor eax,edx
// L00401577: 29 D0                               sub eax,edx
// L00401579: C3                                  ret
__declspec(dllexport)
long my_labs(long n)
{
    return labs(n);
}

__declspec(dllexport)
char *my__strset(char *x, int n)
{
    return _strset(x, n);
}

__declspec(dllexport)
int my_memcmp(const void *cs, const void *ct, size_t n)
{
    return memcmp(cs, ct, n);
}

__declspec(dllexport)
void *my_memcpy(void *s, const void *ct, size_t n)
{
    return memcpy(s, ct, n);
}

__declspec(dllexport)
void *my_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

__declspec(dllexport)
char *my_strcat(char *s, const char *ct)
{
    return strcat(s, ct);
}

__declspec(dllexport)
int my_strcmp(const char *s, const char *ct)
{
    return strcmp(s, ct);
}

// L0040162E: 57                                  push edi
// L0040162F: 8B 7C 24 08                         mov edi,[esp+0x8]
// L00401633: B8 00 00 00 00                      mov eax,0x00
// L00401638: B9 FF FF FF FF                      mov ecx,0xFFFFFFFF
// L0040163D: F2 AE                               repne scasb 
// L0040163F: F7 D1                               not ecx
// L00401641: 8D 41 FF                            lea eax,[ecx-0x1]
// L00401644: 5F                                  pop edi
// L00401645: C3                                  ret
__declspec(dllexport)
size_t my_strlen(const char *cs)
{
    return strlen(cs);
}

__declspec(dllexport)
int my_strncmp(const char *s1, const char *s2, int len)
{
    return my_strncmp(s1, s2, len);
}

__declspec(dllexport)
char *my_strncpy(char *s1, const char *s2, int len)
{
    return strncpy(s1, s2, len + 1);
}

__declspec(dllexport)
int main(void)
{
    {
        int a = my_abs(2);
        printf("%d\n", a);
    }
    {
        long b = my_labs(3);
        printf("%ld\n", b);
    }

    {
        char buf[123];
        my__strset(buf, 123);
        printf("%s\n", buf);
    }

    if (my_memcmp("test", "test2", 5) == 0)
        printf("OK\n");

    {
        char buf[123] = "klk;jkj;";
        my_memcpy(buf, buf, 3);
        printf("%s\n", buf);
    }

    {
        char buf[123];
        my_memset(buf, 11, 123);
        printf("%s\n", buf);
    }

    {
        char buf1[123] = "TEWT";
        char buf2[123] = "TEWT";
        my_strcat(buf1, buf2);
        printf("%s\n", buf1);
    }

    if (my_strcmp("test", "test2"))
    {
        printf("OK\n");
    }

    {
        printf("%d\n", (int)my_strlen("lkj;"));
    }

    if (my_strncmp("test", "test2", 4) == 0)
    {
        printf("OK\n");
    }

    {
        char buf[123];
        my_strncpy(buf, "test2", 4);
        printf("%s\n", buf);
    }

    return 0;
}
