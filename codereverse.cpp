// codereverse.cpp
// Copyright (C) 2013 Katayama Hirofumi MZ.  All rights reserved.

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

struct X86_REGINFO
{
    const char *name;
    X86_REGTYPE type;
    INT         bits;
};

const X86_REGINFO g_reg_entries[] =
{
    {"cr0", X86_CRREG,  0},
    {"cr1", X86_CRREG,  0},
    {"cr2", X86_CRREG,  0},
    {"cr3", X86_CRREG,  0},
    {"cr4", X86_CRREG,  0},
    {"cr8", X86_CRREG,  64},
    {"dr0", X86_DRREG,  0},
    {"dr1", X86_DRREG,  0},
    {"dr2", X86_DRREG,  0},
    {"dr3", X86_DRREG,  0},
    {"dr4", X86_DRREG,  0},
    {"dr5", X86_DRREG,  0},
    {"dr6", X86_DRREG,  0},
    {"dr7", X86_DRREG,  0},
    {"st0", X86_FPUREG, 0},
    {"st1", X86_FPUREG, 0},
    {"st2", X86_FPUREG, 0},
    {"st3", X86_FPUREG, 0},
    {"st4", X86_FPUREG, 0},
    {"st5", X86_FPUREG, 0},
    {"st6", X86_FPUREG, 0},
    {"st7", X86_FPUREG, 0},
    {"mm0", X86_MMXREG, 0},
    {"mm1", X86_MMXREG, 0},
    {"mm2", X86_MMXREG, 0},
    {"mm3", X86_MMXREG, 0},
    {"mm4", X86_MMXREG, 0},
    {"mm5", X86_MMXREG, 0},
    {"mm6", X86_MMXREG, 0},
    {"mm7", X86_MMXREG, 0},
    {"xmm0",    X86_XMMREG, 0},
    {"xmm1",    X86_XMMREG, 0},
    {"xmm2",    X86_XMMREG, 0},
    {"xmm3",    X86_XMMREG, 0},
    {"xmm4",    X86_XMMREG, 0},
    {"xmm5",    X86_XMMREG, 0},
    {"xmm6",    X86_XMMREG, 0},
    {"xmm7",    X86_XMMREG, 0},
    {"xmm8",    X86_XMMREG, 64},
    {"xmm9",    X86_XMMREG, 64},
    {"xmm10",   X86_XMMREG, 64},
    {"xmm11",   X86_XMMREG, 64},
    {"xmm12",   X86_XMMREG, 64},
    {"xmm13",   X86_XMMREG, 64},
    {"xmm14",   X86_XMMREG, 64},
    {"xmm15",   X86_XMMREG, 64},
    {"ymm0",    X86_YMMREG, 0},
    {"ymm1",    X86_YMMREG, 0},
    {"ymm2",    X86_YMMREG, 0},
    {"ymm3",    X86_YMMREG, 0},
    {"ymm4",    X86_YMMREG, 0},
    {"ymm5",    X86_YMMREG, 0},
    {"ymm6",    X86_YMMREG, 0},
    {"ymm7",    X86_YMMREG, 0},
    {"ymm8",    X86_YMMREG, 64},
    {"ymm9",    X86_YMMREG, 64},
    {"ymm10",   X86_YMMREG, 64},
    {"ymm11",   X86_YMMREG, 64},
    {"ymm12",   X86_YMMREG, 64},
    {"ymm13",   X86_YMMREG, 64},
    {"ymm14",   X86_YMMREG, 64},
    {"ymm15",   X86_YMMREG, 64},
    {"rax", X86_REG64,  64},
    {"rcx", X86_REG64,  64},
    {"rdx", X86_REG64,  64},
    {"rbx", X86_REG64,  64},
    {"rsp", X86_REG64,  64},
    {"rbp", X86_REG64,  64},
    {"rsi", X86_REG64,  64},
    {"rdi", X86_REG64,  64},
    {"r8",  X86_REG64,  64},
    {"r9",  X86_REG64,  64},
    {"r10", X86_REG64,  64},
    {"r11", X86_REG64,  64},
    {"r12", X86_REG64,  64},
    {"r13", X86_REG64,  64},
    {"r14", X86_REG64,  64},
    {"r15", X86_REG64,  64},
    {"eax", X86_REG32,  32},
    {"ecx", X86_REG32,  32},
    {"edx", X86_REG32,  32},
    {"ebx", X86_REG32,  32},
    {"esp", X86_REG32,  32},
    {"ebp", X86_REG32,  32},
    {"esi", X86_REG32,  32},
    {"edi", X86_REG32,  32},
    {"r8d", X86_REG32,  64},
    {"r9d", X86_REG32,  64},
    {"r10d",    X86_REG32,  64},
    {"r11d",    X86_REG32,  64},
    {"r12d",    X86_REG32,  64},
    {"r13d",    X86_REG32,  64},
    {"r14d",    X86_REG32,  64},
    {"r15d",    X86_REG32,  64},
    {"ax",  X86_REG16,  0},
    {"cx",  X86_REG16,  0},
    {"dx",  X86_REG16,  0},
    {"bx",  X86_REG16,  0},
    {"sp",  X86_REG16,  0},
    {"bp",  X86_REG16,  0},
    {"si",  X86_REG16,  0},
    {"di",  X86_REG16,  0},
    {"r8w", X86_REG16,  64},
    {"r9w", X86_REG16,  64},
    {"r10w",    X86_REG16,  64},
    {"r11w",    X86_REG16,  64},
    {"r12w",    X86_REG16,  64},
    {"r13w",    X86_REG16,  64},
    {"r14w",    X86_REG16,  64},
    {"r15w",    X86_REG16,  64},
    {"al",  X86_REG8,   0},
    {"cl",  X86_REG8,   0},
    {"dl",  X86_REG8,   0},
    {"bl",  X86_REG8,   0},
    {"ah",  X86_REG8,   0},
    {"ch",  X86_REG8,   0},
    {"dh",  X86_REG8,   0},
    {"bh",  X86_REG8,   0},
    {"r8b", X86_REG8,   64},
    {"r9b", X86_REG8,   64},
    {"r10b",    X86_REG8,   64},
    {"r11b",    X86_REG8,   64},
    {"r12b",    X86_REG8,   64},
    {"r13b",    X86_REG8,   64},
    {"r14b",    X86_REG8,   64},
    {"r15b",    X86_REG8,   64},
    {"spl", X86_REG8X,  64},
    {"bpl", X86_REG8X,  64},
    {"sil", X86_REG8X,  64},
    {"dil", X86_REG8X,  64},
    {"ip", X86_REG16,    0},
    {"eip", X86_REG32,    32},
    {"rip", X86_REG64,    64},
    {"es",  X86_SEGREG, 64},
    {"cs",  X86_SEGREG, 0},
    {"ss",  X86_SEGREG, 64},
    {"ds",  X86_SEGREG, 64},
    {"fs",  X86_SEGREG, 32},
    {"gs",  X86_SEGREG, 32},
};

////////////////////////////////////////////////////////////////////////////
// reg_get_type, reg_get_size

X86_REGTYPE reg_get_type(const char *name, int bits)
{
    for (size_t i = 0; i < sizeof(g_reg_entries) / sizeof(g_reg_entries[0]); i++)
    {
        if (bits >= g_reg_entries[i].bits &&
            _stricmp(g_reg_entries[i].name, name) == 0)
        {
            return g_reg_entries[i].type;
        }
    }
    return X86_REGNONE;
}

DWORD reg_get_size(const char *name, int bits)
{
    switch (reg_get_type(name, bits))
    {
    case X86_CRREG:
        if (bits == 32)
            return 32 / 8;
        else if (bits == 64)
            return 64 / 8;
        break;
    case X86_DRREG:     return 32 / 8;
    case X86_FPUREG:    return 80 / 8;
    case X86_MMXREG:    return 64 / 8;
    case X86_REG8:      return 8 / 8;
    case X86_REG8X:     return 8 / 8;
    case X86_REG16:     return 16 / 8;
    case X86_REG32:     return 32 / 8;
    case X86_REG64:     return 64 / 8;
    case X86_SEGREG:    return 32 / 8;
    case X86_XMMREG:    return 128 / 8;
    case X86_YMMREG:    return 256 / 8;
    default:
        ;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////
// parse_operand

void parse_operand(OPERAND& opr, INT bits, bool jump/* = false*/)
{
    char buf[64];
    strcpy(buf, opr.text.c_str());
    char *p = buf;

    DWORD size = reg_get_size(p, bits);
    if (size != 0)
    {
        opr.type = OT_REG;
        opr.size = size;
        return;
    }

    if (_strnicmp(p, "byte ", 5) == 0)
    {
        p += 5;
        opr.size = 1;
    }
    else if (_strnicmp(p, "word ", 5) == 0)
    {
        p += 5;
        opr.size = 2;
    }
    else if (_strnicmp(p, "dword ", 6) == 0)
    {
        p += 6;
        opr.size = 4;
    }
    else if (_strnicmp(p, "qword ", 6) == 0)
    {
        p += 6;
        opr.size = 8;
    }
    else if (_strnicmp(p, "tword ", 6) == 0)
    {
        p += 6;
        opr.size = 10;
    }
    else if (_strnicmp(p, "oword ", 6) == 0)
    {
        p += 6;
        opr.size = 16;
    }
    else if (_strnicmp(p, "yword ", 6) == 0)
    {
        p += 6;
        opr.size = 32;
    }
    else if (_strnicmp(p, "short ", 6) == 0)
    {
        p += 6;
        opr.size = 1;
    }
    else if (_strnicmp(p, "near ", 5) == 0)
    {
        p += 5;
        opr.size = 2;
    }

    // near or far
    if (_strnicmp(p, "near ", 5) == 0)
        p += 5;
    else if (_strnicmp(p, "far ", 4) == 0)
        p += 4;

    if (p[0] == '+' || p[0] == '-')
    {
        char *endptr;
        LONGLONG value = _strtoi64(p, &endptr, 16);
        opr.SetImm(value, true);
    }
    else if (p[0] == '0' && p[1] == 'x')
    {
        char *endptr;
        ULONGLONG value = _strtoui64(p, &endptr, 16);

        if (jump)
        {
            if (bits == 64)
                sprintf(buf, "L%08lX%08lX", HILONG(value), LOLONG(value));
            else if (bits == 32)
                sprintf(buf, "L%08lX", LOLONG(value));
            else
                sprintf(buf, "L%04X", (WORD)value);
            opr.SetLabel(buf);
        }
        else
            opr.SetImm(value, false);
    }
    else if (p[0] == '[')
    {
        p++;
        *strchr(p, ']') = '\0';

        DWORD size;

        if (_strnicmp(p, "word ", 5) == 0)
        {
            p += 5;
        }
        else if (_strnicmp(p, "dword ", 6) == 0)
        {
            p += 6;
        }
        else if (_strnicmp(p, "rel ", 4) == 0)
        {
            p += 4;
        }
        else if (_strnicmp(p, "qword ", 6) == 0)
        {
            p += 6;
        }
        else if ((size = reg_get_size(p, bits)) != 0)
        {
            opr.type = OT_MEMREG;
            return;
        }

        ADDRESS64 addr;
        char *endptr;
        if (isdigit(*p))
        {
            addr = _strtoui64(p, &endptr, 16);
            opr.SetMemImm(addr);
        }
        else
        {
            opr.SetMemExp(p);
        }
    }
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int _tmain(int argc, _TCHAR **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: pedumper exefile.exe\n");
        return 0;
    }

    PEModule module;
    if (module.LoadModule(argv[1]))
    {
        module.DumpHeaders();
        module.DumpImportSymbols();
        module.DumpExportSymbols();
        module.DumpResource();
        module.DumpDisAsm();
    }
    else
    {
#ifdef _UNICODE
        fprintf(stderr, "ERROR: Cannot load file '%ls', LastError = %lu\n",
            argv[1], module.GetLastError());
#else
        fprintf(stderr, "ERROR: Cannot load file '%s', LastError = %lu\n",
            argv[1], module.GetLastError());
#endif
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////
