////////////////////////////////////////////////////////////////////////////
// default.cr - the default parsing file for CodeReverse decompilation
// Copyright (C) 2013 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
//
// CodeReverse is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// CodeReverse is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with CodeReverse.  If not, see <http://www.gnu.org/licenses/>.
////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>

#include <string.h>
#include <malloc.h>
#include <memory.h>

#include <ctype.h>
#include <time.h>
#include <math.h>
#incldue <process.h>
#incldue <search.h>

#include <assert.h>

#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <direct.h>

#include <conio.h>
#include <signal.h>
#include <setjmp.h>

#ifdef JAPAN
    #include <jstring.h>
    #include <jctype.h>
#endif

#if 0   // 16-bit
    #include <dos.h>
    #include <stdrom.h>
    #include <machine.h>
    #include <fcntl.h>
#endif

// Windows related
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <mmsystem.h>
#include <shellapi.h>
#include <vfw.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#include "include/cr.h"

////////////////////////////////////////////////////////////////////////////

int main(void)
{
    cr_register_primitive_type("BOOL", "bool");

    cr_register_primitive_type("INTEGER");
    cr_register_primitive_type("UINTEGER");
    cr_register_primitive_type("XINTEGER");

    cr_register_primitive_type("LPVOID", "void *");
    cr_register_primitive_type("LPCVOID", "const void *");

    cr_register_primitive_type("XINT", "INT", "UINT");
    cr_register_primitive_type("XCHAR", "CHAR", "BYTE");
    cr_register_primitive_type("XSHORT", "SHORT", "WORD");
    cr_register_primitive_type("XLONG", "LONG", "DWORD");
    cr_register_primitive_type("XLONGLONG", "LONGLONG", "DWORDLONG");

    cr_register_primitive_type("INT", "int");
    cr_register_primitive_type("UINT", "unsigned int");
    cr_register_primitive_type("SIZE_T", "size_t");

    cr_register_primitive_type("CHAR", "char");
    cr_register_primitive_type("SHORT", "short");
    cr_register_primitive_type("LONG", "long");
    cr_register_primitive_type("LONGLONG", "long long");

    cr_register_primitive_type("BYTE", "unsigned char");
    cr_register_primitive_type("WORD", "unsigned short");
    cr_register_primitive_type("DWORD", "unsigned long");
    cr_register_primitive_type("DWORDLONG", "unsigned long long");

    cr_register_primitive_type("WCHAR", "wchar_t");

    cr_register_primitive_type("INT_PTR");
    cr_register_primitive_type("UINT_PTR");
    cr_register_primitive_type("LONG_PTR");
    cr_register_primitive_type("DWORD_PTR", "ULONG_PTR");

    cr_register_primitive_type("LPVOID", "void *");
    cr_register_primitive_type("LPCVOID", "const void *");
    cr_register_primitive_type("LPSTR", "char *");
    cr_register_primitive_type("LPWSTR", "wchar_t *");
    cr_register_primitive_type("LPCSTR", "const char *");
    cr_register_primitive_type("LPCWSTR", "const wchar_t *");
    cr_register_primitive_type("LPSHORT", "short *");
    cr_register_primitive_type("LPLONG", "long *");
    cr_register_primitive_type("LPBYTE", "unsigned char *");
    cr_register_primitive_type("LPWORD", "unsigned short *");
    cr_register_primitive_type("LPDWORD", "unsigned long *");

    cr_register_primitive_type("HANDLE");

    cr_register_primitive_type("HACCEL");
    cr_register_primitive_type("HBITMAP");
    cr_register_primitive_type("HBRUSH");
    cr_register_primitive_type("HCOLORSPACE");
    cr_register_primitive_type("HCURSOR");
    cr_register_primitive_type("HDC");
    cr_register_primitive_type("HDESK");
    cr_register_primitive_type("HENHMETAFILE");
    cr_register_primitive_type("HEVENT");
    cr_register_primitive_type("HFONT");
    cr_register_primitive_type("HGDIOBJ");
    cr_register_primitive_type("HICON");
    cr_register_primitive_type("HINSTANCE");
    cr_register_primitive_type("HKEY");
    cr_register_primitive_type("HKL");
    cr_register_primitive_type("HMENU");
    cr_register_primitive_type("HMETAFILE");
    cr_register_primitive_type("HMODULE");
    cr_register_primitive_type("HMONITOR");
    cr_register_primitive_type("HPALETTE");
    cr_register_primitive_type("HPEN");
    cr_register_primitive_type("HRGN");
    cr_register_primitive_type("HRSRC");
    cr_register_primitive_type("HSTR");
    cr_register_primitive_type("HTASK");
    cr_register_primitive_type("HWINEVENTHOOK");
    cr_register_primitive_type("HWINSTA");
    cr_register_primitive_type("HWND");
    cr_register_primitive_type("SC_HANDLE");
    cr_register_primitive_type("SERVICE_STATUS_HANDLE");

    cr_main();
    return 0;
}

////////////////////////////////////////////////////////////////////////////
