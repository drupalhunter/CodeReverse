// codereverse.h
// Copyright (C) 2013 Katayama Hirofumi MZ.  All rights reserved.

////////////////////////////////////////////////////////////////////////////
// LOLONG, HILONG

#ifndef LOLONG
    #define LOLONG(dwl) ((DWORD)(dwl))
#endif
#ifndef HILONG
    #define HILONG(dwl) ((DWORD)(((dwl) >> 32) & 0xFFFFFFFF))
#endif

////////////////////////////////////////////////////////////////////////////
// ADDRESS32, ADDRESS64

typedef DWORD     ADDRESS32;
typedef ULONGLONG ADDRESS64;

////////////////////////////////////////////////////////////////////////////
// CCODE - condition code

enum CCODE
{
    C_A, C_AE, C_B, C_BE, C_C, C_E, C_G, C_GE, C_L, C_LE, C_NA, C_NAE,
    C_NB, C_NBE, C_NC, C_NE, C_NG, C_NGE, C_NL, C_NLE, C_NO, C_NP,
    C_NS, C_NZ, C_O, C_P, C_PE, C_PO, C_S, C_Z,
    C_none = -1
};

////////////////////////////////////////////////////////////////////////////
// X86_REGTYPE, X86_REGINFO

enum X86_REGTYPE
{
    X86_CRREG = 0,
    X86_DRREG,
    X86_FPUREG,
    X86_MMXREG,
    X86_REG8,
    X86_REG8X,
    X86_REG16,
    X86_REG32,
    X86_REG64,
    X86_SEGREG,
    X86_XMMREG,
    X86_YMMREG,
    X86_REGNONE = -1
};

X86_REGTYPE reg_get_type(const char *name, int bits);
DWORD reg_get_size(const char *name, int bits);

////////////////////////////////////////////////////////////////////////////
// BRANCHTYPE

enum BRANCHTYPE
{
    BT_GONEXT,
    BT_JMP,
    BT_JCC,
    BT_CALL,
    BT_LOOP,
    BT_RETURN
};

////////////////////////////////////////////////////////////////////////////
// OPERANDTYPE

enum OPERANDTYPE
{
    OT_NONE,    // none
    OT_REG,     // registry
    OT_MEMREG,  // memory access by a register
    OT_MEMIMM,  // memory access by an immediate
    OT_MEMEXP,  // memory access by an expression
    OT_IMM,     // immediate
    OT_LABEL,   // label
    OT_API      // API
};

////////////////////////////////////////////////////////////////////////////
// OPERANDINFO

struct OPERAND
{
    string      text;
    OPERANDTYPE type;
    DWORD       size;
    ULONGLONG   value;
    string      exp;

    OPERAND()
    {
        Clear();
    }

    OPERAND(const OPERAND& opr)
    {
        Init(opr);
    }

    OPERAND& operator=(const OPERAND& opr)
    {
        Init(opr);
        return *this;
    }

    VOID Init(const OPERAND& opr)
    {
        text = opr.text;
        type = opr.type;
        size = opr.size;
        value = opr.value;
        exp = opr.exp;
    }

    VOID Clear()
    {
        text.clear();
        type = OT_NONE;
        size = 0;
        value = 0;
        exp.clear();
    }

    VOID SetAPI(const char *api)
    {
        text = api;
        type = OT_API;
    }

    VOID SetLabel(const char *label)
    {
        text = label;
        type = OT_LABEL;
    }

    VOID SetMemImm(ADDRESS64 addr)
    {
        type = OT_MEMIMM;
        value = addr;
    }

    VOID SetMemExp(const char *exp_)
    {
        type = OT_MEMEXP;
        exp = exp_;
    }

    VOID SetImm(ULONGLONG val, bool is_signed)
    {
        char buf[64];
        if (is_signed)
            sprintf(buf, "%ld", (LONG)(LONGLONG)val);
        else if (HILONG(val) == 0)
            sprintf(buf, "0x%08lX", LOLONG(val));
        else
            sprintf(buf, "0x%08lX%08lX", HILONG(val), LOLONG(val));
        text = buf;
        type = OT_IMM;
        value = val;
    }
};

void parse_operand(OPERAND& opr, INT bits, bool jump = false);

////////////////////////////////////////////////////////////////////////////
// CODEPOINT32, CODEPOINT64

struct CODEPOINT32
{
    DWORD addr;
    string name;
    OPERAND operand1, operand2, operand3;
    vector<BYTE> codes;
    BRANCHTYPE bt;
    CCODE cc;

    CODEPOINT32()
    {
        Clear();
    }

    CODEPOINT32(const CODEPOINT32& cp)
    {
        Init(cp);
    }

    CODEPOINT32& operator=(const CODEPOINT32& cp)
    {
        Init(cp);
        return *this;
    }

    VOID Init(const CODEPOINT32& cp)
    {
        addr = cp.addr;
        name = cp.name;
        operand1 = cp.operand1;
        operand2 = cp.operand2;
        operand3 = cp.operand3;
        codes = cp.codes;
        bt = cp.bt;
        cc = cp.cc;
    }

    VOID Clear()
    {
        addr = 0;
        name.clear();
        operand1.Clear();
        operand2.Clear();
        operand3.Clear();
        codes.clear();
        bt = BT_GONEXT;
        cc = C_none;
    }
};
typedef CODEPOINT32 *LPCODEPOINT32;

struct CODEPOINT64
{
    ULONGLONG addr;
    string name;
    OPERAND operand1, operand2, operand3;
    vector<BYTE> codes;
    BRANCHTYPE bt;
    CCODE cc;

    CODEPOINT64()
    {
        Clear();
    }

    CODEPOINT64(const CODEPOINT64& cp)
    {
        Init(cp);
    }

    CODEPOINT64& operator=(const CODEPOINT64& cp)
    {
        Init(cp);
        return *this;
    }

    VOID Init(const CODEPOINT64& cp)
    {
        addr = cp.addr;
        name = cp.name;
        operand1 = cp.operand1;
        operand2 = cp.operand2;
        operand3 = cp.operand3;
        codes = cp.codes;
        bt = cp.bt;
        cc = cp.cc;
    }

    VOID Clear()
    {
        addr = 0;
        name.clear();
        operand1.Clear();
        operand2.Clear();
        operand3.Clear();
        codes.clear();
        bt = BT_GONEXT;
        cc = C_none;
    }
};
typedef CODEPOINT64 *LPCODEPOINT64;

////////////////////////////////////////////////////////////////////////////
