// gcc -m32 -O0 -o test1-32.exe test1.c
// gcc -m64 -O0 -o test1-64.exe test1.c
// cl /Od test1.c
#include <stdio.h>

// GCC:
//   FUNCTION NAME   ORDI. ; RVA      VA      
//   @func3@0        @1    ; 0000153A 0040153A   // __fastcall
//   @func4@8        @2    ; 0000155E 0040155E   // __fastcall
//   func1           @3    ; 00001500 00401500   // __cdecl
//   func2           @4    ; 00001524 00401524   // __cdecl
//   func5@0         @5    ; 0000157A 0040157A   // __stdcall
//   func6@8         @6    ; 0000159E 0040159E   // __stdcall
// 
// VC:
//   FUNCTION NAME   ORDI. ; RVA      VA      
//   @func3@0        @1    ; 00001050 00401050   // __fastcall
//   @func4@8        @2    ; 00001080 00401080   // __fastcall
//   _func5@0        @5    ; 000010A0 004010A0   // __stdcall
//   _func6@8        @6    ; 000010D0 004010D0   // __stdcall
//   func1           @3    ; 00001000 00401000   // __cdecl
//   func2           @4    ; 00001030 00401030   // __cdecl

// func1 (GCC):
// L00401500: 55                                  push ebp
// L00401501: 89 E5                               mov ebp,esp
// L00401503: 83 EC 10                            sub esp,16
// L00401506: C7 45 FC 01 00 00 00                mov dword [ebp-0x4],0x00000001
// L0040150D: C7 45 F8 02 00 00 00                mov dword [ebp-0x8],0x00000002
// L00401514: 8B 45 F8                            mov eax,[ebp-0x8]
// L00401517: 8B 55 FC                            mov edx,[ebp-0x4]
// L0040151A: 01 D0                               add eax,edx
// L0040151C: 89 45 F4                            mov [ebp-0xc],eax
// L0040151F: 8B 45 F4                            mov eax,[ebp-0xc]
// L00401522: C9                                  leave
// L00401523: C3                                  ret
// func1 (VC):
// L00401000: 55                                  push ebp
// L00401001: 8B EC                               mov ebp,esp
// L00401003: 83 EC 0C                            sub esp,12
// L00401006: C7 45 FC 01 00 00 00                mov dword [ebp-0x4],0x00000001
// L0040100D: C7 45 F8 02 00 00 00                mov dword [ebp-0x8],0x00000002
// L00401014: 8B 45 FC                            mov eax,[ebp-0x4]
// L00401017: 03 45 F8                            add eax,[ebp-0x8]
// L0040101A: 89 45 F4                            mov [ebp-0xc],eax
// L0040101D: 8B 45 F4                            mov eax,[ebp-0xc]
// L00401020: 8B E5                               mov esp,ebp
// L00401022: 5D                                  pop ebp
// L00401023: C3                                  ret
__declspec(dllexport)
int __cdecl func1(void)
{
    int a, b, c;
    a = 1;
    b = 2;
    c = a + b;
    return c;
}

// func2 (GCC):
// L00401524: 55                                  push ebp
// L00401525: 89 E5                               mov ebp,esp
// L00401527: 83 EC 10                            sub esp,16
// L0040152A: 8B 45 0C                            mov eax,[ebp+0xc]
// L0040152D: 8B 55 08                            mov edx,[ebp+0x8]
// L00401530: 01 D0                               add eax,edx
// L00401532: 89 45 FC                            mov [ebp-0x4],eax
// L00401535: 8B 45 FC                            mov eax,[ebp-0x4]
// L00401538: C9                                  leave
// L00401539: C3                                  ret
// func2 (VC):
// L00401030: 55                                  push ebp
// L00401031: 8B EC                               mov ebp,esp
// L00401033: 51                                  push ecx
// L00401034: 8B 45 08                            mov eax,[ebp+0x8]
// L00401037: 03 45 0C                            add eax,[ebp+0xc]
// L0040103A: 89 45 FC                            mov [ebp-0x4],eax
// L0040103D: 8B 45 FC                            mov eax,[ebp-0x4]
// L00401040: 8B E5                               mov esp,ebp
// L00401042: 5D                                  pop ebp
// L00401043: C3                                  ret
__declspec(dllexport)
int __cdecl func2(int a, int b)
{
    int c;
    c = a + b;
    return c;
}

// @func3@0 (GCC):
// L0040153A: 55                                  push ebp
// L0040153B: 89 E5                               mov ebp,esp
// L0040153D: 83 EC 10                            sub esp,16
// L00401540: C7 45 FC 01 00 00 00                mov dword [ebp-0x4],0x00000001
// L00401547: C7 45 F8 02 00 00 00                mov dword [ebp-0x8],0x00000002
// L0040154E: 8B 45 F8                            mov eax,[ebp-0x8]
// L00401551: 8B 55 FC                            mov edx,[ebp-0x4]
// L00401554: 01 D0                               add eax,edx
// L00401556: 89 45 F4                            mov [ebp-0xc],eax
// L00401559: 8B 45 F4                            mov eax,[ebp-0xc]
// L0040155C: C9                                  leave
// L0040155D: C3                                  ret
// @func3@0 (VC):
// L00401050: 55                                  push ebp
// L00401051: 8B EC                               mov ebp,esp
// L00401053: 83 EC 0C                            sub esp,12
// L00401056: C7 45 FC 01 00 00 00                mov dword [ebp-0x4],0x00000001
// L0040105D: C7 45 F8 02 00 00 00                mov dword [ebp-0x8],0x00000002
// L00401064: 8B 45 FC                            mov eax,[ebp-0x4]
// L00401067: 03 45 F8                            add eax,[ebp-0x8]
// L0040106A: 89 45 F4                            mov [ebp-0xc],eax
// L0040106D: 8B 45 F4                            mov eax,[ebp-0xc]
// L00401070: 8B E5                               mov esp,ebp
// L00401072: 5D                                  pop ebp
// L00401073: C3                                  ret
__declspec(dllexport)
int __fastcall func3(void)
{
    int a, b, c;
    a = 1;
    b = 2;
    c = a + b;
    return c;
}

// @func4@8 (GCC):
// L0040155E: 55                                  push ebp
// L0040155F: 89 E5                               mov ebp,esp
// L00401561: 83 EC 18                            sub esp,24
// L00401564: 89 4D EC                            mov [ebp-0x14],ecx
// L00401567: 89 55 E8                            mov [ebp-0x18],edx
// L0040156A: 8B 45 E8                            mov eax,[ebp-0x18]
// L0040156D: 8B 55 EC                            mov edx,[ebp-0x14]
// L00401570: 01 D0                               add eax,edx
// L00401572: 89 45 FC                            mov [ebp-0x4],eax
// L00401575: 8B 45 FC                            mov eax,[ebp-0x4]
// L00401578: C9                                  leave
// L00401579: C3                                  ret
// @func4@8 (VC):
// L00401080: 55                                  push ebp
// L00401081: 8B EC                               mov ebp,esp
// L00401083: 83 EC 0C                            sub esp,12
// L00401086: 89 55 F8                            mov [ebp-0x8],edx
// L00401089: 89 4D FC                            mov [ebp-0x4],ecx
// L0040108C: 8B 45 FC                            mov eax,[ebp-0x4]
// L0040108F: 03 45 F8                            add eax,[ebp-0x8]
// L00401092: 89 45 F4                            mov [ebp-0xc],eax
// L00401095: 8B 45 F4                            mov eax,[ebp-0xc]
// L00401098: 8B E5                               mov esp,ebp
// L0040109A: 5D                                  pop ebp
// L0040109B: C3                                  ret
__declspec(dllexport)
int __fastcall func4(int a, int b)
{
    int c;
    c = a + b;
    return c;
}

// func5@0 (GCC):
// L0040157A: 55                                  push ebp
// L0040157B: 89 E5                               mov ebp,esp
// L0040157D: 83 EC 10                            sub esp,16
// L00401580: C7 45 FC 01 00 00 00                mov dword [ebp-0x4],0x00000001
// L00401587: C7 45 F8 02 00 00 00                mov dword [ebp-0x8],0x00000002
// L0040158E: 8B 45 F8                            mov eax,[ebp-0x8]
// L00401591: 8B 55 FC                            mov edx,[ebp-0x4]
// L00401594: 01 D0                               add eax,edx
// L00401596: 89 45 F4                            mov [ebp-0xc],eax
// L00401599: 8B 45 F4                            mov eax,[ebp-0xc]
// L0040159C: C9                                  leave
// L0040159D: C3                                  ret
// _func5@0 (VC):
// L004010A0: 55                                  push ebp
// L004010A1: 8B EC                               mov ebp,esp
// L004010A3: 83 EC 0C                            sub esp,12
// L004010A6: C7 45 FC 01 00 00 00                mov dword [ebp-0x4],0x00000001
// L004010AD: C7 45 F8 02 00 00 00                mov dword [ebp-0x8],0x00000002
// L004010B4: 8B 45 FC                            mov eax,[ebp-0x4]
// L004010B7: 03 45 F8                            add eax,[ebp-0x8]
// L004010BA: 89 45 F4                            mov [ebp-0xc],eax
// L004010BD: 8B 45 F4                            mov eax,[ebp-0xc]
// L004010C0: 8B E5                               mov esp,ebp
// L004010C2: 5D                                  pop ebp
// L004010C3: C3                                  ret
__declspec(dllexport)
int __stdcall func5(void)
{
    int a, b, c;
    a = 1;
    b = 2;
    c = a + b;
    return c;
}

// func6@8 (GCC):
// L0040159E: 55                                  push ebp
// L0040159F: 89 E5                               mov ebp,esp
// L004015A1: 83 EC 10                            sub esp,16
// L004015A4: 8B 45 0C                            mov eax,[ebp+0xc]
// L004015A7: 8B 55 08                            mov edx,[ebp+0x8]
// L004015AA: 01 D0                               add eax,edx
// L004015AC: 89 45 FC                            mov [ebp-0x4],eax
// L004015AF: 8B 45 FC                            mov eax,[ebp-0x4]
// L004015B2: C9                                  leave
// L004015B3: C2 08 00                            ret 0x00000008
// _func6@8 (VC):
// L004010D0: 55                                  push ebp
// L004010D1: 8B EC                               mov ebp,esp
// L004010D3: 51                                  push ecx
// L004010D4: 8B 45 08                            mov eax,[ebp+0x8]
// L004010D7: 03 45 0C                            add eax,[ebp+0xc]
// L004010DA: 89 45 FC                            mov [ebp-0x4],eax
// L004010DD: 8B 45 FC                            mov eax,[ebp-0x4]
// L004010E0: 8B E5                               mov esp,ebp
// L004010E2: 5D                                  pop ebp
// L004010E3: C2 08 00                            ret 0x00000008
__declspec(dllexport)
int __stdcall func6(int a, int b)
{
    int c;
    c = a + b;
    return c;
}

__declspec(dllexport)
int main(void)
{
    int c;

    c = func1();
    printf("func1: %d\n", c);
    c = func2(1, 2);
    printf("func2: %d\n", c);

    c = func3();
    printf("func3: %d\n", c);
    c = func4(1, 2);
    printf("func4: %d\n", c);

    c = func5();
    printf("func5: %d\n", c);
    c = func6(1, 2);
    printf("func6: %d\n", c);

    return 0;
}
