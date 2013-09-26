// gcc -m32 -O0 -o test2-32.exe test2.c
// gcc -m64 -O0 -o test2-64.exe test2.c
// cl /Od test2.c
#include <stdio.h>

// GCC:
//  FUNCTION NAME  ORDI. ; RVA      VA      
//  @g@4           @1    ; 00001540 00401540    // __fastcall
//  f              @2    ; 00001500 00401500    // __cdecl
//  h@4            @3    ; 00001583 00401583    // __stdcall
// VC:
//  FUNCTION NAME  ORDI. ; RVA      VA      
//  @g@4           @1    ; 00001040 00401040    // __fastcall
//  _h@4           @3    ; 00001090 00401090    // __stdcall
//  f              @2    ; 00001000 00401000    // __cdecl


// f (GCC):
// L00401500: 55                                  push ebp
// L00401501: 89 E5                               mov ebp,esp
// L00401503: 83 EC 28                            sub esp,40
// L00401506: 8B 45 08                            mov eax,[ebp+0x8]
// L00401509: 89 44 24 04                         mov [esp+0x4],eax
// L0040150D: C7 04 24 20 90 40 00                mov dword [esp],0x00409020
// L00401514: E8 DF 5F 00 00                      call L004074F8
// L00401519: 8B 45 08                            mov eax,[ebp+0x8]
// L0040151C: 83 C0 01                            add eax,1
// L0040151F: 89 45 F4                            mov [ebp-0xc],eax
// L00401522: 8B 45 F4                            mov eax,[ebp-0xc]
// L00401525: 83 C0 02                            add eax,2
// L00401528: 89 45 F0                            mov [ebp-0x10],eax
// L0040152B: 8B 45 F0                            mov eax,[ebp-0x10]
// L0040152E: 89 44 24 04                         mov [esp+0x4],eax
// L00401532: C7 04 24 20 90 40 00                mov dword [esp],0x00409020
// L00401539: E8 BA 5F 00 00                      call L004074F8
// L0040153E: C9                                  leave
// L0040153F: C3                                  ret
// f (VC):
// L00401000: 55                                  push ebp
// L00401001: 8B EC                               mov ebp,esp
// L00401003: 83 EC 08                            sub esp,8
// L00401006: 8B 45 08                            mov eax,[ebp+0x8]
// L00401009: 50                                  push eax
// L0040100A: 68 00 C0 40 00                      push 0x0040C000
// L0040100F: E8 F6 00 00 00                      call L0040110A
// L00401014: 83 C4 08                            add esp,8
// L00401017: 8B 4D 08                            mov ecx,[ebp+0x8]
// L0040101A: 83 C1 01                            add ecx,1
// L0040101D: 89 4D FC                            mov [ebp-0x4],ecx
// L00401020: 8B 55 FC                            mov edx,[ebp-0x4]
// L00401023: 83 C2 02                            add edx,2
// L00401026: 89 55 F8                            mov [ebp-0x8],edx
// L00401029: 8B 45 F8                            mov eax,[ebp-0x8]
// L0040102C: 50                                  push eax
// L0040102D: 68 04 C0 40 00                      push 0x0040C004
// L00401032: E8 D3 00 00 00                      call L0040110A
// L00401037: 83 C4 08                            add esp,8
// L0040103A: 8B E5                               mov esp,ebp
// L0040103C: 5D                                  pop ebp
// L0040103D: C3                                  ret
__declspec(dllexport)
void __cdecl f(int a)
{
    printf("%d\n", a);
    {
        int b, c;
        b = a + 1;
        c = b + 2;
        printf("%d\n", c);
    }
}

// @g@4 (GCC):
// L00401540: 55                                  push ebp
// L00401541: 89 E5                               mov ebp,esp
// L00401543: 83 EC 38                            sub esp,56
// L00401546: 89 4D E4                            mov [ebp-0x1c],ecx
// L00401549: 8B 45 E4                            mov eax,[ebp-0x1c]
// L0040154C: 89 44 24 04                         mov [esp+0x4],eax
// L00401550: C7 04 24 20 90 40 00                mov dword [esp],0x00409020
// L00401557: E8 9C 5F 00 00                      call L004074F8
// L0040155C: 8B 45 E4                            mov eax,[ebp-0x1c]
// L0040155F: 83 C0 01                            add eax,1
// L00401562: 89 45 F4                            mov [ebp-0xc],eax
// L00401565: 8B 45 F4                            mov eax,[ebp-0xc]
// L00401568: 83 C0 02                            add eax,2
// L0040156B: 89 45 F0                            mov [ebp-0x10],eax
// L0040156E: 8B 45 F0                            mov eax,[ebp-0x10]
// L00401571: 89 44 24 04                         mov [esp+0x4],eax
// L00401575: C7 04 24 20 90 40 00                mov dword [esp],0x00409020
// L0040157C: E8 77 5F 00 00                      call L004074F8
// L00401581: C9                                  leave
// L00401582: C3                                  ret
// @g@4 (VC):
// L00401040: 55                                  push ebp
// L00401041: 8B EC                               mov ebp,esp
// L00401043: 83 EC 0C                            sub esp,12
// L00401046: 89 4D FC                            mov [ebp-0x4],ecx
// L00401049: 8B 45 FC                            mov eax,[ebp-0x4]
// L0040104C: 50                                  push eax
// L0040104D: 68 08 C0 40 00                      push 0x0040C008
// L00401052: E8 B3 00 00 00                      call L0040110A
// L00401057: 83 C4 08                            add esp,8
// L0040105A: 8B 4D FC                            mov ecx,[ebp-0x4]
// L0040105D: 83 C1 01                            add ecx,1
// L00401060: 89 4D F8                            mov [ebp-0x8],ecx
// L00401063: 8B 55 F8                            mov edx,[ebp-0x8]
// L00401066: 83 C2 02                            add edx,2
// L00401069: 89 55 F4                            mov [ebp-0xc],edx
// L0040106C: 8B 45 F4                            mov eax,[ebp-0xc]
// L0040106F: 50                                  push eax
// L00401070: 68 0C C0 40 00                      push 0x0040C00C
// L00401075: E8 90 00 00 00                      call L0040110A
// L0040107A: 83 C4 08                            add esp,8
// L0040107D: 8B E5                               mov esp,ebp
// L0040107F: 5D                                  pop ebp
// L00401080: C3                                  ret
__declspec(dllexport)
void __fastcall g(int a)
{
    printf("%d\n", a);
    {
        int b, c;
        b = a + 1;
        c = b + 2;
        printf("%d\n", c);
    }
}

// h@4 (GCC):
// L00401583: 55                                  push ebp
// L00401584: 89 E5                               mov ebp,esp
// L00401586: 83 EC 28                            sub esp,40
// L00401589: 8B 45 08                            mov eax,[ebp+0x8]
// L0040158C: 89 44 24 04                         mov [esp+0x4],eax
// L00401590: C7 04 24 20 90 40 00                mov dword [esp],0x00409020
// L00401597: E8 5C 5F 00 00                      call L004074F8
// L0040159C: 8B 45 08                            mov eax,[ebp+0x8]
// L0040159F: 83 C0 01                            add eax,1
// L004015A2: 89 45 F4                            mov [ebp-0xc],eax
// L004015A5: 8B 45 F4                            mov eax,[ebp-0xc]
// L004015A8: 83 C0 02                            add eax,2
// L004015AB: 89 45 F0                            mov [ebp-0x10],eax
// L004015AE: 8B 45 F0                            mov eax,[ebp-0x10]
// L004015B1: 89 44 24 04                         mov [esp+0x4],eax
// L004015B5: C7 04 24 20 90 40 00                mov dword [esp],0x00409020
// L004015BC: E8 37 5F 00 00                      call L004074F8
// L004015C1: C9                                  leave
// L004015C2: C2 04 00                            ret 0x04
// _h@4 (VC):
// L00401040: 55                                  push ebp
// L00401041: 8B EC                               mov ebp,esp
// L00401043: 83 EC 0C                            sub esp,12
// L00401046: 89 4D FC                            mov [ebp-0x4],ecx
// L00401049: 8B 45 FC                            mov eax,[ebp-0x4]
// L0040104C: 50                                  push eax
// L0040104D: 68 08 C0 40 00                      push 0x0040C008
// L00401052: E8 B3 00 00 00                      call L0040110A
// L00401057: 83 C4 08                            add esp,8
// L0040105A: 8B 4D FC                            mov ecx,[ebp-0x4]
// L0040105D: 83 C1 01                            add ecx,1
// L00401060: 89 4D F8                            mov [ebp-0x8],ecx
// L00401063: 8B 55 F8                            mov edx,[ebp-0x8]
// L00401066: 83 C2 02                            add edx,2
// L00401069: 89 55 F4                            mov [ebp-0xc],edx
// L0040106C: 8B 45 F4                            mov eax,[ebp-0xc]
// L0040106F: 50                                  push eax
// L00401070: 68 0C C0 40 00                      push 0x0040C00C
// L00401075: E8 90 00 00 00                      call L0040110A
// L0040107A: 83 C4 08                            add esp,8
// L0040107D: 8B E5                               mov esp,ebp
// L0040107F: 5D                                  pop ebp
// L00401080: C3                                  ret
__declspec(dllexport)
void __stdcall h(int a)
{
    printf("%d\n", a);
    {
        int b, c;
        b = a + 1;
        c = b + 2;
        printf("%d\n", c);
    }
}

__declspec(dllexport)
int main(void)
{
    f(123);
    g(321);
    h(132);
    return 0;
}
