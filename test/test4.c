#include <windows.h>

// BOR32:
// L00401150: 55                                  push ebp
// L00401151: 8B EC                               mov ebp,esp
// L00401153: 6A 00                               push 0
// L00401155: 6A 00                               push 0
// L00401157: 68 4C 91 40 00                      push 0x0040914C
// L0040115C: 6A 00                               push 0
// L0040115E: E8 CB 7C 00 00                      call L00408E2E
// L00401163: 5D                                  pop ebp
// L00401164: C3                                  ret
// GCC32:
// L00401560: 55                                  push ebp
// L00401561: 89 E5                               mov ebp,esp
// L00401563: 83 EC 18                            sub esp,24
// L00401566: C7 44 24 0C 00 00 00 00             mov dword [esp+0xc],0x00
// L0040156E: C7 44 24 08 00 00 00 00             mov dword [esp+0x8],0x00
// L00401576: C7 44 24 04 24 40 40 00             mov dword [esp+0x4],0x00404024
// L0040157E: C7 04 24 00 00 00 00                mov dword [esp],0x00
// L00401585: A1 F8 71 40 00                      mov eax,M004071F8
// L0040158A: FF D0                               call eax
// L0040158C: 83 EC 10                            sub esp,16
// L0040158F: C9                                  leave
// L00401590: C3                                  ret
// GCC64:
// L00000000004014F0: 55                                              push rbp
// L00000000004014F1: 48 89 E5                                        mov rbp,rsp
// L00000000004014F4: 48 83 EC 20                                     sub rsp,32
// L00000000004014F8: 41 B9 00 00 00 00                               mov r9d,0x00
// L00000000004014FE: 41 B8 00 00 00 00                               mov r8d,0x00
// L0000000000401504: 48 8D 15 F5 2A 00 00                            lea rdx,offset M0000000000404000
// L000000000040150B: B9 00 00 00 00                                  mov ecx,0x00
// L0000000000401510: 48 8B 05 99 7E 00 00                            mov rax,M00000000004093B0
// L0000000000401517: FF D0                                           call rax
// L0000000000401519: 48 83 C4 20                                     add rsp,32
// L000000000040151D: 5D                                              pop rbp
// L000000000040151E: C3                                              ret
// VC32:
// L00401000: 55                                  push ebp
// L00401001: 8B EC                               mov ebp,esp
// L00401003: 6A 00                               push 0
// L00401005: 6A 00                               push 0
// L00401007: 68 00 A0 40 00                      push 0x0040A000
// L0040100C: 6A 00                               push 0
// L0040100E: FF 15 E8 80 40 00                   call MessageBoxA
// L00401014: 5D                                  pop ebp
// L00401015: C3                                  ret
// VC64:
// L0000000140001000: 48 83 EC 28                                     sub rsp,40
// L0000000140001004: 45 33 C9                                        xor r9d,r9d
// L0000000140001007: 45 33 C0                                        xor r8d,r8d
// L000000014000100A: 48 8D 15 EF 9F 00 00                            lea rdx,offset M000000014000B000
// L0000000140001011: 33 C9                                           xor ecx,ecx
// L0000000140001013: FF 15 F7 71 00 00                               call MessageBoxA
// L0000000140001019: 48 83 C4 28                                     add rsp,40
// L000000014000101D: C3                                              ret
__declspec(dllexport)
int __stdcall f(void)
{
    return MessageBoxA(NULL, "Hello, world", NULL, 0);
}

__declspec(dllexport)
int main(void)
{
    f();
    return 0;
}
