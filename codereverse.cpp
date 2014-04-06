////////////////////////////////////////////////////////////////////////////
// codereverse.cpp
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

LPCSTR cr_logo =
    "/////////////////////////////////////\n"
    "// CodeReverse 0.0.6                  //\n"
    "// katayama.hirofumi.mz@gmail.com  //\n"
    "/////////////////////////////////////\n";

////////////////////////////////////////////////////////////////////////////
// TBOOL - tri-state logical value

TBOOL::TBOOL()
{
    m_value = TB_UNKNOWN;
}

TBOOL::TBOOL(BOOL b)
{
    m_value = (b ? TB_TRUE : TB_FALSE);
}

TBOOL::TBOOL(const TBOOL& tb)
{
    m_value = tb.m_value;
}

/*virtual*/ TBOOL::~TBOOL()
{
}

TBOOL& TBOOL::operator=(const TBOOL& tb)
{
    m_value = tb.m_value;
    return *this;
}

TBOOL& TBOOL::operator=(BOOL b)
{
    m_value = (b ? TB_TRUE : TB_FALSE);
    return *this;
}

bool TBOOL::operator==(const TBOOL& tb) const
{
    return m_value == tb.m_value;
}

bool TBOOL::operator!=(const TBOOL& tb) const
{
    return m_value != tb.m_value;
}

VOID TBOOL::clear()
{
    m_value = TB_UNKNOWN;
}

BOOL TBOOL::CanBeTrue() const
{
    return m_value != TB_FALSE;
}

BOOL TBOOL::CanBeFalse() const
{
    return m_value != TB_TRUE;
}

BOOL TBOOL::IsUnknown() const
{
    return m_value == TB_UNKNOWN;
}

TBOOL& TBOOL::IsFalse(const TBOOL& tb)
{
    switch (tb.m_value)
    {
    case TB_FALSE:      m_value = TB_TRUE; break;
    case TB_TRUE:       m_value = TB_FALSE; break;
    case TB_UNKNOWN:    m_value = TB_UNKNOWN; break;
    }
    return *this;
}

TBOOL& TBOOL::IsTrue(const TBOOL& tb)
{
    m_value = tb.m_value;
    return *this;
}

TBOOL& TBOOL::LogicalAnd(const TBOOL& tb1, const TBOOL& tb2)
{
    if (tb1.m_value == TB_FALSE || tb2.m_value == TB_FALSE)
        m_value = TB_FALSE;
    else if (tb1.m_value == TB_TRUE)
        m_value = tb2.m_value;
    else if (tb2.m_value == TB_TRUE)
        m_value = tb1.m_value;
    else
        m_value = TB_UNKNOWN;
    return *this;
}

TBOOL& TBOOL::LogicalOr(const TBOOL& tb1, const TBOOL& tb2)
{
    if (tb1.m_value == TB_TRUE || tb2.m_value == TB_TRUE)
        m_value = TB_TRUE;
    else if (tb1.m_value == TB_FALSE)
        m_value = tb2.m_value;
    else if (tb2.m_value == TB_FALSE)
        m_value = tb1.m_value;
    else
        m_value = TB_UNKNOWN;
    return *this;
}

TBOOL& TBOOL::LogicalNot(const TBOOL& tb1)
{
    return IsFalse(tb1);
}

TBOOL& TBOOL::Equal(const TBOOL& tb1, const TBOOL& tb2)
{
    if (tb1.m_value == TB_UNKNOWN || tb2.m_value == TB_UNKNOWN)
    {
        m_value = TB_UNKNOWN;
        return *this;
    }
    m_value = (tb1.m_value == tb2.m_value ? TB_TRUE : TB_FALSE);
    return *this;
}

TBOOL& TBOOL::NotEqual(const TBOOL& tb1, const TBOOL& tb2)
{
    TBOOL tb;
    tb.Equal(tb1, tb2);
    return LogicalNot(tb);
}

////////////////////////////////////////////////////////////////////////////
// x86 registers

struct X86_REGINFO
{
    LPCSTR      name;
    X86_REGTYPE type;
    INT         bits;
};

const X86_REGINFO cr_reg_entries[] =
{
    {"cr0", X86_CRREG, 0},
    {"cr1", X86_CRREG, 0},
    {"cr2", X86_CRREG, 0},
    {"cr3", X86_CRREG, 0},
    {"cr4", X86_CRREG, 0},
    {"cr8", X86_CRREG, 64},
    {"dr0", X86_DRREG, 0},
    {"dr1", X86_DRREG, 0},
    {"dr2", X86_DRREG, 0},
    {"dr3", X86_DRREG, 0},
    {"dr4", X86_DRREG, 0},
    {"dr5", X86_DRREG, 0},
    {"dr6", X86_DRREG, 0},
    {"dr7", X86_DRREG, 0},
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
    {"xmm0", X86_XMMREG, 0},
    {"xmm1", X86_XMMREG, 0},
    {"xmm2", X86_XMMREG, 0},
    {"xmm3", X86_XMMREG, 0},
    {"xmm4", X86_XMMREG, 0},
    {"xmm5", X86_XMMREG, 0},
    {"xmm6", X86_XMMREG, 0},
    {"xmm7", X86_XMMREG, 0},
    {"xmm8", X86_XMMREG, 64},
    {"xmm9", X86_XMMREG, 64},
    {"xmm10", X86_XMMREG, 64},
    {"xmm11", X86_XMMREG, 64},
    {"xmm12", X86_XMMREG, 64},
    {"xmm13", X86_XMMREG, 64},
    {"xmm14", X86_XMMREG, 64},
    {"xmm15", X86_XMMREG, 64},
    {"ymm0", X86_YMMREG, 0},
    {"ymm1", X86_YMMREG, 0},
    {"ymm2", X86_YMMREG, 0},
    {"ymm3", X86_YMMREG, 0},
    {"ymm4", X86_YMMREG, 0},
    {"ymm5", X86_YMMREG, 0},
    {"ymm6", X86_YMMREG, 0},
    {"ymm7", X86_YMMREG, 0},
    {"ymm8", X86_YMMREG, 64},
    {"ymm9", X86_YMMREG, 64},
    {"ymm10", X86_YMMREG, 64},
    {"ymm11", X86_YMMREG, 64},
    {"ymm12", X86_YMMREG, 64},
    {"ymm13", X86_YMMREG, 64},
    {"ymm14", X86_YMMREG, 64},
    {"ymm15", X86_YMMREG, 64},
    {"rax", X86_REG64, 64},
    {"rcx", X86_REG64, 64},
    {"rdx", X86_REG64, 64},
    {"rbx", X86_REG64, 64},
    {"rsp", X86_REG64, 64},
    {"rbp", X86_REG64, 64},
    {"rsi", X86_REG64, 64},
    {"rdi", X86_REG64, 64},
    {"r8", X86_REG64, 64},
    {"r9", X86_REG64, 64},
    {"r10", X86_REG64, 64},
    {"r11", X86_REG64, 64},
    {"r12", X86_REG64, 64},
    {"r13", X86_REG64, 64},
    {"r14", X86_REG64, 64},
    {"r15", X86_REG64, 64},
    {"eax", X86_REG32, 32},
    {"ecx", X86_REG32, 32},
    {"edx", X86_REG32, 32},
    {"ebx", X86_REG32, 32},
    {"esp", X86_REG32, 32},
    {"ebp", X86_REG32, 32},
    {"esi", X86_REG32, 32},
    {"edi", X86_REG32, 32},
    {"r8d", X86_REG32, 64},
    {"r9d", X86_REG32, 64},
    {"r10d", X86_REG32, 64},
    {"r11d", X86_REG32, 64},
    {"r12d", X86_REG32, 64},
    {"r13d", X86_REG32, 64},
    {"r14d", X86_REG32, 64},
    {"r15d", X86_REG32, 64},
    {"ax", X86_REG16, 0},
    {"cx", X86_REG16, 0},
    {"dx", X86_REG16, 0},
    {"bx", X86_REG16, 0},
    {"sp", X86_REG16, 0},
    {"bp", X86_REG16, 0},
    {"si", X86_REG16, 0},
    {"di", X86_REG16, 0},
    {"r8w", X86_REG16, 64},
    {"r9w", X86_REG16, 64},
    {"r10w", X86_REG16, 64},
    {"r11w", X86_REG16, 64},
    {"r12w", X86_REG16, 64},
    {"r13w", X86_REG16, 64},
    {"r14w", X86_REG16, 64},
    {"r15w", X86_REG16, 64},
    {"al", X86_REG8, 0},
    {"cl", X86_REG8, 0},
    {"dl", X86_REG8, 0},
    {"bl", X86_REG8, 0},
    {"ah", X86_REG8, 0},
    {"ch", X86_REG8, 0},
    {"dh", X86_REG8, 0},
    {"bh", X86_REG8, 0},
    {"r8b", X86_REG8, 64},
    {"r9b", X86_REG8, 64},
    {"r10b", X86_REG8, 64},
    {"r11b", X86_REG8, 64},
    {"r12b", X86_REG8, 64},
    {"r13b", X86_REG8, 64},
    {"r14b", X86_REG8, 64},
    {"r15b", X86_REG8, 64},
    {"spl", X86_REG8X, 64},
    {"bpl", X86_REG8X, 64},
    {"sil", X86_REG8X, 64},
    {"dil", X86_REG8X, 64},
    {"ip", X86_REG16, 0},
    {"eip", X86_REG32, 32},
    {"rip", X86_REG64, 64},
    {"es", X86_SEGREG, 64},
    {"cs", X86_SEGREG, 0},
    {"ss", X86_SEGREG, 64},
    {"ds", X86_SEGREG, 64},
    {"fs", X86_SEGREG, 32},
    {"gs", X86_SEGREG, 32},
    {"dx:ax", X86_COMPREG32, 0},
    {"edx:eax", X86_COMPREG64, 32},
    {"rdx:rax", X86_COMPREG128, 64},
    {"CF", X86_FLAG, 0},
    {"PF", X86_FLAG, 0},
    {"AF", X86_FLAG, 0},
    {"ZF", X86_FLAG, 0},
    {"SF", X86_FLAG, 0},
    {"TF", X86_FLAG, 0},
    {"IF", X86_FLAG, 0},
    {"DF", X86_FLAG, 0},
    {"OF", X86_FLAG, 0},
    {"SFeqOF", X86_FLAG, 0}  // extension (means SF == OF)
};

X86_REGTYPE cr_reg_get_type(LPCSTR name, INT bits)
{
    size_t size = sizeof(cr_reg_entries) / sizeof(cr_reg_entries[0]);
    for (size_t i = 0; i < size; i++)
    {
        if (bits >= cr_reg_entries[i].bits &&
            _stricmp(cr_reg_entries[i].name, name) == 0)
        {
            return cr_reg_entries[i].type;
        }
    }
    return X86_REGNONE;
}

DWORD cr_reg_get_size(LPCSTR name, INT bits)
{
    switch (cr_reg_get_type(name, bits))
    {
    case X86_CRREG:
        if (bits == 64)
            return 64 / 8;
        else if (bits == 32)
            return 32 / 8;
        break;
    case X86_DRREG:         return 32 / 8;
    case X86_FPUREG:        return 80 / 8;
    case X86_MMXREG:        return 64 / 8;
    case X86_REG8:          return 8 / 8;
    case X86_REG8X:         return 8 / 8;
    case X86_REG16:         return 16 / 8;
    case X86_REG32:         return 32 / 8;
    case X86_REG64:         return 64 / 8;
    case X86_SEGREG:        return 32 / 8;
    case X86_XMMREG:        return 128 / 8;
    case X86_YMMREG:        return 256 / 8;
    case X86_COMPREG32:     return 32 / 8;
    case X86_COMPREG64:     return 64 / 8;
    case X86_COMPREG128:    return 128 / 8;
    default:
        ;
    }
    return 0;
}

BOOL cr_reg_in_reg(LPCSTR reg1, LPCSTR reg2)
{
    if (strcmp(reg1, reg2) == 0)
        return TRUE;

    static LPCSTR s[][4] =
    {
        {"al", "ax", "eax", "rax"},
        {"bl", "bx", "ebx", "rbx"},
        {"cl", "cx", "ecx", "rcx"},
        {"dl", "dx", "edx", "rdx"},
        {"ah", "ax", "eax", "rax"},
        {"bh", "bx", "ebx", "rbx"},
        {"ch", "cx", "ecx", "rcx"},
        {"dh", "dx", "edx", "rdx"},
        {"spl", "sp", "esp", "rsp"},
        {"bpl", "bp", "ebp", "rbp"},
        {"sil", "si", "esi", "rsi"},
        {"dil", "di", "edi", "rdi"},
        {"ax", "dx:ax", "edx:eax", "rdx:rax"},
        {"dx", "dx:ax", "edx:eax", "rdx:rax"},
        {"eax", "edx:eax", "rdx:rax", NULL},
        {"edx", "edx:eax", "rdx:rax", NULL},
        {"rax", "rdx:rax", NULL, NULL},
        {"rdx", "rdx:rax", NULL, NULL},
        {"ip", "eip", "rip", NULL},
        {"r8b", "r8w", "r8d", "r8"},
        {"r9b", "r9w", "r9d", "r9"},
        {"r10b", "r10w", "r10d", "r10"},
        {"r11b", "r11w", "r11d", "r11"},
        {"r12b", "r12w", "r12d", "r12"},
        {"r13b", "r13w", "r13d", "r13"},
        {"r14b", "r14w", "r14d", "r14"},
        {"r15b", "r15w", "r15d", "r15"},
    };

    size_t i, size = sizeof(s) / sizeof(s[0]);
    for (i = 0; i < size; i++)
    {
        if (strcmp(reg1, s[i][0]) == 0)
        {
            if ((s[i][1] && strcmp(reg2, s[i][1]) == 0) ||
                (s[i][2] && strcmp(reg2, s[i][2]) == 0) ||
                (s[i][3] && strcmp(reg2, s[i][3]) == 0))
            {
                return TRUE;
            }
        }
        if (strcmp(reg1, s[i][1]) == 0)
        {
            if ((s[i][2] && strcmp(reg2, s[i][2]) == 0) ||
                (s[i][3] && strcmp(reg2, s[i][3]) == 0))
            {
                return TRUE;
            }
        }
        if (strcmp(reg1, s[i][2]) == 0)
        {
            if (s[i][3] && strcmp(reg2, s[i][3]) == 0)
                return TRUE;
        }
    }

    return FALSE;
}

BOOL cr_reg_overlaps_reg(LPCSTR reg1, LPCSTR reg2)
{
    return cr_reg_in_reg(reg1, reg2) || cr_reg_in_reg(reg2, reg1);
}

////////////////////////////////////////////////////////////////////////////
// x86 flags

X86_FLAGTYPE cr_flag_get_type(LPCSTR name, INT bits)
{
    if (name[0] != '\0' && name[1] == 'F' && name[2] == '\0')
    {
        switch (name[0])
        {
        case 'C': return X86_FLAG_CF;
        case 'P': return X86_FLAG_PF;
        case 'A': return X86_FLAG_AF;
        case 'Z': return X86_FLAG_ZF;
        case 'S': return X86_FLAG_SF;
        case 'T': return X86_FLAG_TF;
        case 'I': return X86_FLAG_IF;
        case 'D': return X86_FLAG_DF;
        case 'O': return X86_FLAG_OF;
        }
    }
    return X86_FLAG_NONE;
}

LPCSTR cr_flag_get_name(X86_FLAGTYPE type, INT bits)
{
    switch (type)
    {
    case X86_FLAG_CF: return "CF";
    case X86_FLAG_PF: return "PF";
    case X86_FLAG_AF: return "AF";
    case X86_FLAG_ZF: return "ZF";
    case X86_FLAG_SF: return "SF";
    case X86_FLAG_TF: return "TF";
    case X86_FLAG_IF: return "IF";
    case X86_FLAG_DF: return "DF";
    case X86_FLAG_OF: return "OF";
    default: break;
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// OPERAND

OPERAND::OPERAND()
{
    clear();
}

OPERAND::OPERAND(const OPERAND& opr)
{
    Copy(opr);
}

/*virtual*/ OPERAND::~OPERAND()
{
}

OPERAND& OPERAND::operator=(const OPERAND& opr)
{
    Copy(opr);
    return *this;
}

VOID OPERAND::Copy(const OPERAND& opr)
{
    Text() = opr.Text();
    OperandType() = opr.OperandType();
    Size() = opr.Size();
    Value64() = opr.Value64();
    Exp() = opr.Exp();
    DataType() = opr.DataType();
    IsInteger() = opr.IsInteger();
    IsPointer() = opr.IsPointer();
    IsFunction() = opr.IsFunction();
}

VOID OPERAND::clear()
{
    Text().clear();
    OperandType() = OT_NONE;
    Size() = 0;
    Value64() = 0;
    Exp().clear();
    DataType().clear();
    IsInteger().clear();
    IsPointer().clear();
    IsFunction().clear();
}

VOID OPERAND::SetReg(LPCSTR name)
{
    Text() = name;
    OperandType() = OT_REG;
    Size() = cr_reg_get_size(name, 64);
}

VOID OPERAND::SetAPI(LPCSTR api)
{
    Text() = api;
    OperandType() = OT_API;
}

VOID OPERAND::SetLabel(LPCSTR label)
{
    Text() = label;
    OperandType() = OT_IMM;
}

VOID OPERAND::SetMemImm(ADDR64 addr)
{
    OperandType() = OT_MEMIMM;
    Value64() = addr;
}

VOID OPERAND::SetMemExp(LPCSTR exp_)
{
    OperandType() = OT_MEMEXP;
    Exp() = exp_;
}

VOID OPERAND::SetImm32(ADDR32 val, BOOL is_signed)
{
    CHAR buf[64];

    if (is_signed)
        sprintf(buf, "%ld", (LONG)val);
    else
    {
        if (HIWORD(val) == 0)
        {
            if (HIBYTE(LOWORD(LOLONG(val))) == 0)
                sprintf(buf, "0x%02X", (BYTE)(val));
            else
                sprintf(buf, "0x%04X", LOWORD(val));
        }
        else
            sprintf(buf, "0x%08lX", val);
    }

    Text() = buf;
    OperandType() = OT_IMM;
    Value64() = val;
}

VOID OPERAND::SetImm64(ADDR64 val, BOOL is_signed)
{
    CHAR buf[64];

    if (is_signed)
        sprintf(buf, "%ld", (LONG)(LONGLONG)val);
    else if (HILONG(val) == 0)
    {
        if (HIWORD(LOLONG(val)) == 0)
        {
            if (HIBYTE(LOWORD(LOLONG(val))) == 0)
                sprintf(buf, "0x%02X", (BYTE)(val));
            else
                sprintf(buf, "0x%04X", LOWORD(LOLONG(val)));
        }
        else
            sprintf(buf, "0x%08lX", LOLONG(val));
    }
    else
        sprintf(buf, "0x%08lX%08lX", HILONG(val), LOLONG(val));

    Text() = buf;
    OperandType() = OT_IMM;
    Value64() = val;
}

bool OPERAND::operator==(const OPERAND& opr) const
{
    return
        Text() == opr.Text() &&
        OperandType() == opr.OperandType() &&
        Size() == opr.Size() &&
        Value64() == opr.Value64() &&
        Exp() == opr.Exp() &&
        DataType() == opr.DataType();
}

bool OPERAND::operator!=(const OPERAND& opr) const
{
    return
        Text() != opr.Text() ||
        OperandType() != opr.OperandType() ||
        Size() != opr.Size() ||
        Value64() != opr.Value64() ||
        Exp() != opr.Exp() ||
        DataType() != opr.DataType();
}

////////////////////////////////////////////////////////////////////////////
// STACK

STACK::STACK()
{
    resize(64);
    m_minussp = m_minusbp = 64;
}

STACK::STACK(const STACK& s) : OPERANDSET(s)
{
    resize(64);
    m_minussp = m_minusbp = 64;
}

STACK& STACK::operator=(const STACK& s)
{
    Copy(s);
    return *this;
}

/*virtual*/ STACK::~STACK()
{
}

VOID STACK::Copy(const STACK& s)
{
    m_items = s.m_items;
    m_minussp = s.m_minussp;
    m_minusbp = s.m_minusbp;
}

VOID STACK::clear()
{
    m_items.clear();
    m_minussp = m_minusbp = 0;
}

bool STACK::operator==(const STACK& s) const
{
    if (size() != s.size())
        return false;

    size_t size = s.size();
    for (size_t i = 0; i < size; i++)
    {
        if (m_items[i] != s.m_items[i])
            return false;
    }

    return true;
}

bool STACK::operator!=(const STACK& s) const
{
    return !(*this == s);
}

VOID STACK::AddSP(SIZE_T size)
{
    assert(m_items.size() >= size);
    resize(m_items.size() - size);
    m_minussp -= size;
}

VOID STACK::SubSP(SIZE_T size)
{
    resize(m_items.size() + size);
    m_minussp += size;
}

VOID STACK::AddBP(SIZE_T size)
{
    assert(m_items.size() >= size);
    m_minusbp -= size;
}

VOID STACK::SubBP(SIZE_T size)
{
    m_minusbp += size;
}

VOID STACK::Push(const OPERAND& opr)
{
    SubSP(opr.Size());
    m_items[m_minussp + opr.Size() - 1] = opr;
}

VOID STACK::Pop(OPERAND& opr)
{
    opr = m_items[m_minussp + opr.Size() - 1];
    AddSP(opr.Size());
}

VOID STACK::GetFromSP(SIZE_T index, OPERAND& opr)
{
    opr = m_items[m_minussp - index];
}

VOID STACK::SetFromSP(SIZE_T index, const OPERAND& opr)
{
    m_items[m_minussp - index] = opr;
}

VOID STACK::GetFromBP(SIZE_T index, OPERAND& opr)
{
    opr = m_items[m_minusbp - index];
}

VOID STACK::SetFromBP(SIZE_T index, const OPERAND& opr)
{
    m_items[m_minusbp - index] = opr;
}

DWORD STACK::GetBP()
{
    return m_minusbp;
}

VOID STACK::SetBP(DWORD bp)
{
    m_minusbp = bp;
}

DWORD STACK::GetSP()
{
    return m_minussp;
}

VOID STACK::SetSP(DWORD sp)
{
    m_minussp = sp;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE32

ASMCODE32::ASMCODE32()
{
    clear();
}

ASMCODE32::ASMCODE32(const ASMCODE32& ac)
{
    Copy(ac);
}

/*virtual*/ ASMCODE32::~ASMCODE32()
{
}

ASMCODE32& ASMCODE32::operator=(const ASMCODE32& ac)
{
    Copy(ac);
    return *this;
}

VOID ASMCODE32::Copy(const ASMCODE32& ac)
{
    Funcs() = ac.Funcs();
    Addr() = ac.Addr();
    Name() = ac.Name();
    Operands() = ac.Operands();
    Codes() = ac.Codes();
    AsmCodeType() = ac.AsmCodeType();
    CondCode() = ac.CondCode();
}

VOID ASMCODE32::clear()
{
    Funcs().clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    AsmCodeType() = ACT_MISC;
    CondCode() = C_NONE;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE64

ASMCODE64::ASMCODE64()
{
    clear();
}

ASMCODE64::ASMCODE64(const ASMCODE64& ac)
{
    Copy(ac);
}

/*virtual*/ ASMCODE64::~ASMCODE64()
{
}

ASMCODE64& ASMCODE64::operator=(const ASMCODE64& ac)
{
    Copy(ac);
    return *this;
}

VOID ASMCODE64::Copy(const ASMCODE64& ac)
{
    Funcs() = ac.Funcs();
    Addr() = ac.Addr();
    Name() = ac.Name();
    Operands() = ac.Operands();
    Codes() = ac.Codes();
    AsmCodeType() = ac.AsmCodeType();
    CondCode() = ac.CondCode();
}

VOID ASMCODE64::clear()
{
    Funcs().clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    AsmCodeType() = ACT_MISC;
    CondCode() = C_NONE;
}

////////////////////////////////////////////////////////////////////////////
// BLOCK32

BLOCK32::BLOCK32() :
    m_addr(0),
    m_nextblock1(NULL),
    m_nextblock2(NULL),
    m_nextaddr1(0),
    m_nextaddr2(0)
{
}

BLOCK32::BLOCK32(const BLOCK32& b)
{
    Copy(b);
}

BLOCK32& BLOCK32::operator=(const BLOCK32& b)
{
    Copy(b);
    return *this;
}

VOID BLOCK32::Copy(const BLOCK32& b)
{
    Addr() = b.Addr();
    AsmCodes() = b.AsmCodes();
    NextBlock1() = b.NextBlock1();
    NextBlock2() = b.NextBlock2();
}

/*virtual*/ BLOCK32::~BLOCK32()
{
}

VOID BLOCK32::clear()
{
    AsmCodes().clear();
    NextBlock1() = NULL;
    NextBlock2() = NULL;
    NextAddr1() = 0;
    NextAddr2() = 0;
}

////////////////////////////////////////////////////////////////////////////
// BLOCK64

BLOCK64::BLOCK64() :
    m_addr(0),
    m_nextblock1(NULL),
    m_nextblock2(NULL),
    m_nextaddr1(0),
    m_nextaddr2(0)
{
}

BLOCK64::BLOCK64(const BLOCK64& b)
{
    Copy(b);
}

BLOCK64& BLOCK64::operator=(const BLOCK64& b)
{
    Copy(b);
    return *this;
}

VOID BLOCK64::Copy(const BLOCK64& b)
{
    Addr() = b.Addr();
    AsmCodes() = b.AsmCodes();
    NextBlock1() = b.NextBlock1();
    NextBlock2() = b.NextBlock2();
}

/*virtual*/ BLOCK64::~BLOCK64()
{
}

VOID BLOCK64::clear()
{
    AsmCodes().clear();
    NextBlock1() = NULL;
    NextBlock2() = NULL;
    NextAddr1() = 0;
    NextAddr2() = 0;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32

CODEFUNC32::CODEFUNC32()
{
    clear();
}

CODEFUNC32::CODEFUNC32(const CODEFUNC32& cf)
{
    Copy(cf);
}

CODEFUNC32& CODEFUNC32::operator=(const CODEFUNC32& cf)
{
    Copy(cf);
    return *this;
}

/*virtual*/ CODEFUNC32::~CODEFUNC32()
{
}

VOID CODEFUNC32::Copy(const CODEFUNC32& cf)
{
    Addr() = cf.Addr();
    Name() = cf.Name();
    FuncType() = cf.FuncType();
    SizeOfStackArgs() = cf.SizeOfStackArgs();
    Args() = cf.Args();
    Flags() = cf.Flags();
    ReturnDataType() = cf.ReturnDataType();
    Blocks() = cf.Blocks();
}

VOID CODEFUNC32::clear()
{
    Addr() = 0;
    Name().clear();
    FuncType() = FT_UNKNOWN;
    SizeOfStackArgs() = -1;
    Args().clear();
    Flags() = 0;
    ReturnDataType().clear();
    Blocks().clear();
}

BLOCK32* CODEFUNC32::FindBlockOfAddr(ADDR32 addr)
{
    size_t i, size = Blocks().size();
    for (i = 0; i < size; i++)
    {
        if (Blocks()[i].Addr() == addr)
            return &Blocks()[i];
    }
    return NULL;
}

const BLOCK32* CODEFUNC32::FindBlockOfAddr(ADDR32 addr) const
{
    size_t i, size = Blocks().size();
    for (i = 0; i < size; i++)
    {
        if (Blocks()[i].Addr() == addr)
            return &Blocks()[i];
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64

CODEFUNC64::CODEFUNC64()
{
    clear();
}

CODEFUNC64::CODEFUNC64(const CODEFUNC64& cf)
{
    Copy(cf);
}

CODEFUNC64& CODEFUNC64::operator=(const CODEFUNC64& cf)
{
    Copy(cf);
    return *this;
}

/*virtual*/ CODEFUNC64::~CODEFUNC64()
{
}

VOID CODEFUNC64::Copy(const CODEFUNC64& cf)
{
    Addr() = cf.Addr();
    Name() = cf.Name();
    FuncType() = cf.FuncType();
    SizeOfStackArgs() = cf.SizeOfStackArgs();
    Args() = cf.Args();
    Flags() = cf.Flags();
    ReturnDataType() = cf.ReturnDataType();
    Blocks() = cf.Blocks();
}

VOID CODEFUNC64::clear()
{
    Addr() = 0;
    Name().clear();
    FuncType() = FT_UNKNOWN;
    SizeOfStackArgs() = -1;
    Args().clear();
    Flags() = 0;
    ReturnDataType().clear();
    Blocks().clear();
}

BLOCK64* CODEFUNC64::FindBlockOfAddr(ADDR64 addr)
{
    size_t i, size = Blocks().size();
    for (i = 0; i < size; i++)
    {
        if (Blocks()[i].Addr() == addr)
            return &Blocks()[i];
    }
    return NULL;
}

const BLOCK64* CODEFUNC64::FindBlockOfAddr(ADDR64 addr) const
{
    size_t i, size = Blocks().size();
    for (i = 0; i < size; i++)
    {
        if (Blocks()[i].Addr() == addr)
            return &Blocks()[i];
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// cr_get_asmio_16, cr_get_asmio_32, cr_get_asmio_64

void cr_str_split_to_set(set<string>& s, LPCSTR psz, LPCSTR seps)
{
    s.clear();
    LPSTR str = _strdup(psz);
    LPSTR p = strtok(str, seps);
    while (p != NULL)
    {
        s.insert(p);
        p = strtok(NULL, seps);
    }
    free(str);
}

// assembly instruction input/output information
struct X86ASMIO
{
    LPCSTR name;
    INT num_args;
    LPCSTR in;
    LPCSTR out;
    INT osize;
};

static int cr_compare_asmio(const void *a, const void *b)
{
    const X86ASMIO *x = (const X86ASMIO *)a;
    const X86ASMIO *y = (const X86ASMIO *)b;
    int cmp = strcmp(x->name, y->name);
    if (cmp != 0)
        return cmp;

    cmp = x->num_args - y->num_args;
    if (cmp != 0)
        return cmp;
    
    cmp = x->osize - y->osize;
    if (cmp != 0)
        return cmp;

    return 0;
}

BOOL cr_get_asmio_16(X86ASMIO *key, set<string>& in, set<string>& out, INT osize)
{
    static const X86ASMIO s_table[] =
    {
        {"aaa", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"aad", 0, "al,ah", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 0, "al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 1, "$0,al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aas", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"adc", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"add", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"and", 2, "$0,$1", "$0,ZF,SF,CF,OF,AF,PF,SFeqOF", 0},
        {"cbw", 0, "al", "ax", 0},
        {"clc", 0, "", "CF", 0},
        {"cld", 0, "", "DF", 0},
        {"cli", 0, "", "IF", 0},
        {"cmc", 0, "CF", "CF", 0},
        {"cmp", 2, "$0,$1", "OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsb", 0, "si,di,DF,m8(si),m8(di)", "OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "si,di,DF,m16(si),m16(di)", "OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cwd", 0, "ax", "dx", 0},
        {"daa", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"das", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"dec", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"div", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"div", 1, "$0,dx:ax", "ax,dx,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"idiv", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"idiv", 1, "$0,dx:ax", "dx,ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 1, "al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 1, "ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"inc", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"ja", 1, "$0", "", 0},
        {"jae", 1, "$0", "", 0},
        {"jb", 1, "$0", "", 0},
        {"jbe", 1, "$0", "", 0},
        {"jc", 1, "$0", "", 0},
        {"jcxz", 1, "$0,cx", "", 0},
        {"je", 1, "$0", "", 0},
        {"jg", 1, "$0", "", 0},
        {"jge", 1, "$0", "", 0},
        {"jl", 1, "$0", "", 0},
        {"jle", 1, "$0", "", 0},
        {"jmp", 1, "$0", "", 0},
        {"jna", 1, "$0", "", 0},
        {"jnae", 1, "$0", "", 0},
        {"jnb", 1, "$0", "", 0},
        {"jnbe", 1, "$0", "", 0},
        {"jnc", 1, "$0", "", 0},
        {"jne", 1, "$0", "", 0},
        {"jng", 1, "$0", "", 0},
        {"jnge", 1, "$0", "", 0},
        {"jnl", 1, "$0", "", 0},
        {"jnle", 1, "$0", "", 0},
        {"jno", 1, "$0", "", 0},
        {"jnp", 1, "$0", "", 0},
        {"jns", 1, "$0", "", 0},
        {"jnz", 1, "$0", "", 0},
        {"jo", 1, "$0", "", 0},
        {"jp", 1, "$0", "", 0},
        {"jpe", 1, "$0", "", 0},
        {"jpo", 1, "$0", "", 0},
        {"js", 1, "$0", "", 0},
        {"jz", 1, "$0", "", 0},
        {"lea", 2, "$0,$1", "$0", 0},
        {"lodsb", 0, "si,DF,m8(si)", "al,si", 0},
        {"lodsw", 0, "si,DF,m16(si)", "ax,si", 0},
        {"loop", 1, "$0,cx", "cx", 0},
        {"loope", 1, "$0,cx,ZF", "cx", 0},
        {"loopne", 1, "$0,cx,ZF", "cx", 0},
        {"loopz", 1, "$0,cx,ZF", "cx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "di,si,DF,m8(si)", "di,si,m8(di)", 0},
        {"movsw", 0, "di,si,DF,m16(si)", "di,si,m16(di)", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"rep lodsb", 0, "si,DF,cx,m8(si)", "cx,al,si", 0},
        {"rep lodsw", 0, "si,DF,cx,m16(si)", "cx,ax,si", 0},
        {"rep stosb", 0, "di,al,cx,DF", "di,cx,m8(di)", 0},
        {"rep stosw", 0, "di,ax,cx,DF", "di,cx,m16(di)", 0},
        {"repe cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "cx,si,di,DF,m8(si),m8(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "cx,si,di,DF,m16(si),m16(di)", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "di,al,cx,DF,m8(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "di,ax,cx,DF,m16(di)", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "di,al,DF,m8(di)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "di,ax,DF,m16(di)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "di,al,DF", "di,m8(di)", 0},
        {"stosw", 0, "di,ax,DF", "di,m16(di)", 0},
        {"sub", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"test", 2, "$0,$1", "ZF,SF,PF,CF,OF,SFeqOF", 0},
        {"xchg", 2, "$0,$1", "$0,$1", 0},
        {"xlat", 1, "al,$0,mem", "al", 0},
        {"xlatb", 1, "al,$0,mem", "al", 0},
        {"xor", 2, "$0,$1", "$0,ZF,SF,OF,CF,PF,AF,SFeqOF", 0},
    };

    const SIZE_T size = sizeof(s_table) / sizeof(s_table[0]);
    const X86ASMIO *p = 
        (const X86ASMIO *)bsearch(key, s_table, size, sizeof(X86ASMIO),
                                  cr_compare_asmio);
    if (p == NULL)
        return FALSE;

    if (p->osize != 0 && p->osize != osize)
        p++;

    if (strcmp(key->name, p->name) != 0)
        return FALSE;

    cr_str_split_to_set(in, p->in, ",");
    cr_str_split_to_set(out, p->out, ",");
    return TRUE;
}

BOOL cr_get_asmio_32(X86ASMIO *key, set<string>& in, set<string>& out, INT osize)
{
    static const X86ASMIO s_table[] =
    {
        {"aaa", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"aad", 0, "al,ah", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 0, "al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aam", 1, "$0,al", "al,ah,ZF,SF,OF,AF,PF,CF,SFeqOF", 0},
        {"aas", 0, "al,ah,AF", "al,ah,AF,CF,OF,SF,ZF,PF,SFeqOF", 0},
        {"adc", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"add", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"and", 2, "$0,$1", "$0,ZF,SF,CF,OF,AF,PF,SFeqOF", 0},
        {"bsf", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bsr", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bswap", 1, "$0", "$0", 0},
        {"bt", 2, "$1,$2", "CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btc", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btr", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bts", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"cbw", 0, "al", "ax", 0},
        {"cdq", 0, "eax", "edx", 0},
        {"clc", 0, "", "CF", 0},
        {"cld", 0, "", "DF", 0},
        {"cli", 0, "", "IF", 0},
        {"cmc", 0, "CF", "CF", 0},
        {"cmova", 2, "$1,CF,ZF", "$0", 0},
        {"cmovae", 2, "$1,CF", "$0", 0},
        {"cmovb", 2, "$1,CF", "$0", 0},
        {"cmovbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovc", 2, "$1,CF", "$0", 0},
        {"cmove", 2, "$1,ZF", "$0", 0},
        {"cmovg", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovna", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnae", 2, "$1,CF", "$0", 0},
        {"cmovnb", 2, "$1,CF", "$0", 0},
        {"cmovnbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnc", 2, "$1,CF", "$0", 0},
        {"cmovne", 2, "$1,ZF", "$0", 0},
        {"cmovng", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovnge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovno", 2, "$1,OF", "$0", 0},
        {"cmovnp", 2, "$1,PF", "$0", 0},
        {"cmovns", 2, "$1,SF", "$0", 0},
        {"cmovnz", 2, "$1,ZF", "$0", 0},
        {"cmovo", 2, "$1,OF", "$0", 0},
        {"cmovp", 2, "$1,PF", "$0", 0},
        {"cmovpe", 2, "$1,PF", "$0", 0},
        {"cmovpo", 2, "$1,PF", "$0", 0},
        {"cmovs", 2, "$1,SF", "$0", 0},
        {"cmovz", 2, "$1,ZF", "$0", 0},
        {"cmp", 2, "$0,$1", "OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsb", 0, "esi,edi,DF,m8(esi),m8(edi)", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsd", 0, "esi,edi,DF,m32(esi),m32(edi)", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "esi,edi,DF,m16(esi),m16(edi)", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpxchg", 2, "$0,$1", "$0,$1,ZF,SF,CF,PF,AF,SFeqOF", 0},
        {"cwd", 0, "ax", "dx", 0},
        {"cwde", 0, "ax", "eax", 0},
        {"daa", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"das", 0, "al,AF", "al,CF,AF,OF,SF,ZF,PF,SFeqOF", 0},
        {"dec", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"div", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"div", 1, "$0,dx:ax", "ax,dx,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"div", 1, "$0,edx:eax", "eax,edx,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"idiv", 1, "$0,al", "al:ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"idiv", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"idiv", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 1, "al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 1, "ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 1, "eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"inc", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"ja", 1, "$0", "", 0},
        {"jae", 1, "$0", "", 0},
        {"jb", 1, "$0", "", 0},
        {"jbe", 1, "$0", "", 0},
        {"jc", 1, "$0", "", 0},
        {"jcxz", 1, "$0,cx", "", 0},
        {"je", 1, "$0", "", 0},
        {"jg", 1, "$0", "", 0},
        {"jge", 1, "$0", "", 0},
        {"jl", 1, "$0", "", 0},
        {"jle", 1, "$0", "", 0},
        {"jmp", 1, "$0", "", 0},
        {"jna", 1, "$0", "", 0},
        {"jnae", 1, "$0", "", 0},
        {"jnb", 1, "$0", "", 0},
        {"jnbe", 1, "$0", "", 0},
        {"jnc", 1, "$0", "", 0},
        {"jne", 1, "$0", "", 0},
        {"jng", 1, "$0", "", 0},
        {"jnge", 1, "$0", "", 0},
        {"jnl", 1, "$0", "", 0},
        {"jnle", 1, "$0", "", 0},
        {"jno", 1, "$0", "", 0},
        {"jnp", 1, "$0", "", 0},
        {"jns", 1, "$0", "", 0},
        {"jnz", 1, "$0", "", 0},
        {"jo", 1, "$0", "", 0},
        {"jp", 1, "$0", "", 0},
        {"jpe", 1, "$0", "", 0},
        {"jpo", 1, "$0", "", 0},
        {"js", 1, "$0", "", 0},
        {"jz", 1, "$0", "", 0},
        {"lea", 2, "$0,$1", "$0", 0},
        {"lodsb", 0, "esi,DF,m8(esi)", "al,esi", 0},
        {"lodsd", 0, "esi,DF,m32(esi)", "eax,esi", 0},
        {"lodsw", 0, "esi,DF,m16(esi)", "ax,esi", 0},
        {"loop", 1, "$0,ecx", "ecx", 0},
        {"loope", 1, "$0,ecx,ZF", "ecx", 0},
        {"loopne", 1, "$0,ecx,ZF", "ecx", 0},
        {"loopz", 1, "$0,ecx,ZF", "ecx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "edi,esi,DF,m8(esi)", "edi,esi,m8(edi)", 0},
        {"movsd", 0, "edi,esi,DF,m32(esi)", "edi,esi,m32(edi)", 0},
        {"movsw", 0, "edi,esi,DF,m16(esi)", "edi,esi,m16(edi)", 0},
        {"movsx", 2, "$1", "$0", 0},
        {"movzx", 2, "$1", "$0", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"mul", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"nop", 1, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"popcnt", 2, "$1", "$0", 0},
        {"rep lodsb", 0, "esi,DF,ecx,m8(esi)", "ecx,al,esi", 0},
        {"rep lodsd", 0, "esi,DF,ecx,m32(esi)", "ecx,eax,esi", 0},
        {"rep lodsw", 0, "esi,DF,ecx,m16(esi)", "ecx,ax,esi", 0},
        {"rep stosb", 0, "ddi,al,ecx,DF", "edi,ecx,m8(edi)", 0},
        {"rep stosd", 0, "ddi,eax,ecx,DF", "edi,ecx,m32(edi)", 0},
        {"rep stosw", 0, "ddi,ax,ecx,DF", "edi,ecx,m16(edi)", 0},
        {"repe cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "ecx,esi,edi,DF,m8(esi),m8(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsd", 0, "ecx,esi,edi,DF,m32(esi),m32(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "ecx,esi,edi,DF,m16(esi),m16(edi)", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "edi,al,ecx,DF,m8(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasd", 0, "edi,eax,ecx,DF,m32(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "edi,ax,ecx,DF,m16(edi)", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "edi,al,DF,m8(edi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasd", 0, "edi,eax,DF,m32(edi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "edi,ax,DF,m16(edi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"seta", 1, "ZF,CF", "$0", 0},
        {"setae", 1, "CF", "$0", 0},
        {"setb", 1, "CF", "$0", 0},
        {"setc", 1, "CF", "$0", 0},
        {"sete", 1, "ZF", "$0", 0},
        {"setg", 1, "ZF,SFeqOF", "$0", 0},
        {"setge", 1, "SFeqOF", "$0", 0},
        {"setl", 1, "SFeqOF", "$0", 0},
        {"setle", 1, "ZF,SFeqOF", "$0", 0},
        {"setna", 1, "ZF,CF", "$0", 0},
        {"setnae", 1, "CF", "$0", 0},
        {"setnb", 1, "CF", "$0", 0},
        {"setnbe", 1, "ZF,CF", "$0", 0},
        {"setnc", 1, "CF", "$0", 0},
        {"setne", 1, "ZF", "$0", 0},
        {"setng", 1, "ZF,SFeqOF", "$0", 0},
        {"setnge", 1, "SFeqOF", "$0", 0},
        {"setnl", 1, "SFeqOF", "$0", 0},
        {"setnle", 1, "ZF,SFeqOF", "$0", 0},
        {"setno", 1, "OF", "$0", 0},
        {"setnp", 1, "PF", "$0", 0},
        {"setns", 1, "SF", "$0", 0},
        {"setnz", 1, "ZF", "$0", 0},
        {"seto", 1, "OF", "$0", 0},
        {"setp", 1, "PF", "$0", 0},
        {"setpe", 1, "PF", "$0", 0},
        {"setpo", 1, "PF", "$0", 0},
        {"sets", 1, "SF", "$0", 0},
        {"setz", 1, "ZF", "$0", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "edi,al,DF", "edi,m8(edi)", 0},
        {"stosd", 0, "edi,eax,DF", "edi,m32(edi)", 0},
        {"stosw", 0, "edi,ax,DF", "edi,m16(edi)", 0},
        {"sub", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"test", 2, "$0,$1", "ZF,SF,PF,CF,OF,SFeqOF", 0},
        {"xadd", 2, "$0,$1", "$0,$1,OF,CF,PF,AF,SF,ZF,SFeqOF", 0},
        {"xchg", 2, "$0,$1", "$0,$1", 0},
        {"xlat", 1, "al,$0,mem", "al", 0},
        {"xlatb", 1, "al,$0,mem", "al", 0},
        {"xor", 2, "$0,$1", "$0,ZF,SF,OF,CF,PF,AF,SFeqOF", 0},
    };

    const SIZE_T size = sizeof(s_table) / sizeof(s_table[0]);
    const X86ASMIO *p =
        (const X86ASMIO *)bsearch(key, s_table, size, sizeof(X86ASMIO),
                                  cr_compare_asmio);
    if (p == NULL)
        return FALSE;

    if (p->osize != 0 && p->osize != osize)
        p++;
    if (p->osize != 0 && p->osize != osize)
        p++;

    if (strcmp(key->name, p->name) != 0)
        return FALSE;

    cr_str_split_to_set(in, p->in, ",");
    cr_str_split_to_set(out, p->out, ",");
    return TRUE;
}

BOOL cr_get_asmio_64(X86ASMIO *key, set<string>& in, set<string>& out, INT osize)
{
    static const X86ASMIO s_table[] =
    {
        {"adc", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"add", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"and", 2, "$0,$1", "$0,ZF,SF,CF,OF,AF,PF,SFeqOF", 0},
        {"bsf", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bsr", 2, "$1", "$0,ZF,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bswap", 1, "$0", "$0", 0},
        {"bt", 2, "$1,$2", "CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btc", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"btr", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"bts", 2, "$0,$1", "$0,CF,OF,SF,AF,PF,SFeqOF", 0},
        {"cbw", 0, "al", "ax", 0},
        {"cdq", 0, "eax", "edx", 0},
        {"cdqe", 0, "rax", "eax", 0},
        {"clc", 0, "", "CF", 0},
        {"cld", 0, "", "DF", 0},
        {"cli", 0, "", "IF", 0},
        {"cmc", 0, "CF", "CF", 0},
        {"cmova", 2, "$1,CF,ZF", "$0", 0},
        {"cmovae", 2, "$1,CF", "$0", 0},
        {"cmovb", 2, "$1,CF", "$0", 0},
        {"cmovbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovc", 2, "$1,CF", "$0", 0},
        {"cmove", 2, "$1,ZF", "$0", 0},
        {"cmovg", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovna", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnae", 2, "$1,CF", "$0", 0},
        {"cmovnb", 2, "$1,CF", "$0", 0},
        {"cmovnbe", 2, "$1,CF,ZF", "$0", 0},
        {"cmovnc", 2, "$1,CF", "$0", 0},
        {"cmovne", 2, "$1,ZF", "$0", 0},
        {"cmovng", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovnge", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnl", 2, "$1,SFeqOF", "$0", 0},
        {"cmovnle", 2, "$1,ZF,SFeqOF", "$0", 0},
        {"cmovno", 2, "$1,OF", "$0", 0},
        {"cmovnp", 2, "$1,PF", "$0", 0},
        {"cmovns", 2, "$1,SF", "$0", 0},
        {"cmovnz", 2, "$1,ZF", "$0", 0},
        {"cmovo", 2, "$1,OF", "$0", 0},
        {"cmovp", 2, "$1,PF", "$0", 0},
        {"cmovpe", 2, "$1,PF", "$0", 0},
        {"cmovpo", 2, "$1,PF", "$0", 0},
        {"cmovs", 2, "$1,SF", "$0", 0},
        {"cmovz", 2, "$1,ZF", "$0", 0},
        {"cmp", 2, "$0,$1", "OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsb", 0, "rsi,rdi,DF,m8(rsi),m8(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsd", 0, "rsi,rdi,DF,m32(rsi),m32(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsq", 0, "rsi,rdi,DF,m64(rsi),m64(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "rsi,rdi,DF,m16(rsi),m16(rdi)", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpxchg", 2, "$0,$1", "$0,$1,ZF,SF,CF,PF,AF,SFeqOF", 0},
        {"cwd", 0, "ax", "dx", 0},
        {"cwde", 0, "ax", "eax", 0},
        {"cqo", 0, "rax", "rdx", 0},
        {"dec", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"div", 1, "$0,ax", "al,ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"div", 1, "$0,dx:ax", "ax,dx,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"div", 1, "$0,edx:eax", "eax,edx,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"div", 1, "$0,rdx:rax", "rax,rdx,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"idiv", 1, "$0,al", "al:ah,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"idiv", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"idiv", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"idiv", 1, "$0,rax", "rdx:rax,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"imul", 1, "al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 1, "ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 1, "eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 1, "rax", "rdx:rax,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 2, "$0,$1", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"imul", 3, "$1,$2", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"inc", 1, "$0", "$0,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"ja", 1, "$0", "", 0},
        {"jae", 1, "$0", "", 0},
        {"jb", 1, "$0", "", 0},
        {"jbe", 1, "$0", "", 0},
        {"jc", 1, "$0", "", 0},
        {"jcxz", 1, "$0,cx", "", 0},
        {"je", 1, "$0", "", 0},
        {"jg", 1, "$0", "", 0},
        {"jge", 1, "$0", "", 0},
        {"jl", 1, "$0", "", 0},
        {"jle", 1, "$0", "", 0},
        {"jmp", 1, "$0", "", 0},
        {"jna", 1, "$0", "", 0},
        {"jnae", 1, "$0", "", 0},
        {"jnb", 1, "$0", "", 0},
        {"jnbe", 1, "$0", "", 0},
        {"jnc", 1, "$0", "", 0},
        {"jne", 1, "$0", "", 0},
        {"jng", 1, "$0", "", 0},
        {"jnge", 1, "$0", "", 0},
        {"jnl", 1, "$0", "", 0},
        {"jnle", 1, "$0", "", 0},
        {"jno", 1, "$0", "", 0},
        {"jnp", 1, "$0", "", 0},
        {"jns", 1, "$0", "", 0},
        {"jnz", 1, "$0", "", 0},
        {"jo", 1, "$0", "", 0},
        {"jp", 1, "$0", "", 0},
        {"jpe", 1, "$0", "", 0},
        {"jpo", 1, "$0", "", 0},
        {"js", 1, "$0", "", 0},
        {"jz", 1, "$0", "", 0},
        {"lea", 2, "$0,$1", "$0", 0},
        {"lodsb", 0, "rsi,DF,m8(rsi)", "al,rsi", 0},
        {"lodsd", 0, "rsi,DF,m32(rsi)", "eax,rsi", 0},
        {"lodsq", 0, "rsi,DF,m64(rsi)", "rax,rsi", 0},
        {"lodsw", 0, "rsi,DF,m16(rsi)", "ax,rsi", 0},
        {"loop", 1, "$0,rcx", "rcx", 0},
        {"loope", 1, "$0,rcx,ZF", "rcx", 0},
        {"loopne", 1, "$0,rcx,ZF", "rcx", 0},
        {"loopz", 1, "$0,rcx,ZF", "rcx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "rdi,rsi,DF,m8(rsi)", "rdi,rsi,m8(rdi)", 0},
        {"movsd", 0, "rdi,rsi,DF,m32(rsi)", "rdi,rsi,m32(rdi)", 0},
        {"movsq", 0, "rdi,rsi,DF,m64(rsi)", "rdi,rsi,m64(rdi)", 0},
        {"movsw", 0, "rdi,rsi,DF,m16(rsi)", "rdi,rsi,m16(rdi)", 0},
        {"movsx", 2, "$1", "$0", 0},
        {"movzx", 2, "$1", "$0", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"mul", 1, "$0,eax", "edx:eax,CF,OF,SF,ZF,AF,PF,SFeqOF", 4},
        {"mul", 1, "$0,rax", "rdx:rax,CF,OF,SF,ZF,AF,PF,SFeqOF", 8},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"nop", 1, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"popcnt", 2, "$1", "$0", 0},
        {"rep lodsb", 0, "rsi,DF,rcx,m8(rsi)", "rcx,al,rsi", 0},
        {"rep lodsd", 0, "rsi,DF,rcx,m32(rsi)", "rcx,eax,rsi", 0},
        {"rep lodsw", 0, "rsi,DF,rcx,m64(rsi)", "rcx,ax,rsi", 0},
        {"rep lodsq", 0, "rsi,DF,rcx,m16(rsi)", "rcx,rax,rsi", 0},
        {"rep stosb", 0, "ddi,al,rcx,DF", "rdi,rcx,m8(rdi)", 0},
        {"rep stosd", 0, "ddi,eax,rcx,DF", "rdi,rcx,m32(rdi)", 0},
        {"rep stosq", 0, "ddi,rax,rcx,DF", "rdi,rcx,m64(rdi)", 0},
        {"rep stosw", 0, "ddi,ax,rcx,DF", "rdi,rcx,m16(rdi)", 0},
        {"repe cmpsb", 0, "rcx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsd", 0, "rcx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsq", 0, "rcx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "rcx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "ecx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsd", 0, "ecx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsq", 0, "ecx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "ecx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "rcx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsd", 0, "rcx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsq", 0, "rcx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "rcx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "rcx,rsi,rdi,DF,m8(rsi),m8(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsd", 0, "rcx,rsi,rdi,DF,m32(rsi),m32(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsq", 0, "rcx,rsi,rdi,DF,m64(rsi),m64(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "rcx,rsi,rdi,DF,m16(rsi),m16(rdi)", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "rdi,al,rcx,DF,m8(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasd", 0, "rdi,eax,rcx,DF,m32(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasq", 0, "rdi,eax,rcx,DF,m64(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "rdi,ax,rcx,DF,m16(rdi)", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "rdi,al,DF,m8(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasd", 0, "rdi,eax,DF,m32(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasq", 0, "rdi,eax,DF,m64(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "rdi,ax,DF,m16(rdi)", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"seta", 1, "ZF,CF", "$0", 0},
        {"setae", 1, "CF", "$0", 0},
        {"setb", 1, "CF", "$0", 0},
        {"setc", 1, "CF", "$0", 0},
        {"sete", 1, "ZF", "$0", 0},
        {"setg", 1, "ZF,SFeqOF", "$0", 0},
        {"setge", 1, "SFeqOF", "$0", 0},
        {"setl", 1, "SFeqOF", "$0", 0},
        {"setle", 1, "ZF,SFeqOF", "$0", 0},
        {"setna", 1, "ZF,CF", "$0", 0},
        {"setnae", 1, "CF", "$0", 0},
        {"setnb", 1, "CF", "$0", 0},
        {"setnbe", 1, "ZF,CF", "$0", 0},
        {"setnc", 1, "CF", "$0", 0},
        {"setne", 1, "ZF", "$0", 0},
        {"setng", 1, "ZF,SFeqOF", "$0", 0},
        {"setnge", 1, "SFeqOF", "$0", 0},
        {"setnl", 1, "SFeqOF", "$0", 0},
        {"setnle", 1, "ZF,SFeqOF", "$0", 0},
        {"setno", 1, "OF", "$0", 0},
        {"setnp", 1, "PF", "$0", 0},
        {"setns", 1, "SF", "$0", 0},
        {"setnz", 1, "ZF", "$0", 0},
        {"seto", 1, "OF", "$0", 0},
        {"setp", 1, "PF", "$0", 0},
        {"setpe", 1, "PF", "$0", 0},
        {"setpo", 1, "PF", "$0", 0},
        {"sets", 1, "SF", "$0", 0},
        {"setz", 1, "ZF", "$0", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "rdi,al,DF", "rdi,m8(rdi)", 0},
        {"stosd", 0, "rdi,eax,DF", "rdi,m32(rdi)", 0},
        {"stosq", 0, "rdi,rax,DF", "rdi,m64(rdi)", 0},
        {"stosw", 0, "rdi,ax,DF", "rdi,m16(rdi)", 0},
        {"sub", 2, "$0,$1", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"test", 2, "$0,$1", "ZF,SF,PF,CF,OF,SFeqOF", 0},
        {"xadd", 2, "$0,$1", "$0,$1,OF,CF,PF,AF,SF,ZF,SFeqOF", 0},
        {"xchg", 2, "$0,$1", "$0,$1", 0},
        {"xlat", 1, "al,$0,mem", "al", 0},
        {"xlatb", 1, "al,$0,mem", "al", 0},
        {"xor", 2, "$0,$1", "$0,ZF,SF,OF,CF,PF,AF,SFeqOF", 0},
    };

    const SIZE_T size = sizeof(s_table) / sizeof(s_table[0]);
    const X86ASMIO *p =
        (const X86ASMIO *)bsearch(key, s_table, size, sizeof(X86ASMIO),
                                  cr_compare_asmio);
    if (p == NULL)
        return FALSE;

    if (p->osize != 0 && p->osize != osize)
        p++;
    if (p->osize != 0 && p->osize != osize)
        p++;

    if (strcmp(key->name, p->name) != 0)
        return FALSE;

    cr_str_split_to_set(in, p->in, ",");
    cr_str_split_to_set(out, p->out, ",");
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32

DECOMPSTATUS32::DECOMPSTATUS32()
{
}

DECOMPSTATUS32::DECOMPSTATUS32(const DECOMPSTATUS32& status)
{
    Copy(status);
}

DECOMPSTATUS32& DECOMPSTATUS32::operator=(const DECOMPSTATUS32& status)
{
    Copy(status);
    return *this;
}

/*virtual*/ DECOMPSTATUS32::~DECOMPSTATUS32()
{
}

VOID DECOMPSTATUS32::Copy(const DECOMPSTATUS32& status)
{
    MapAddrToAsmCode() = status.MapAddrToAsmCode();
    Entrances() = status.Entrances();
    MapAddrToCodeFunc() = status.MapAddrToCodeFunc();
}

VOID DECOMPSTATUS32::clear()
{
    MapAddrToAsmCode().clear();
    Entrances().clear();
    MapAddrToCodeFunc().clear();
}

CODEFUNC32 *DECOMPSTATUS32::MapAddrToCodeFunc(ADDR32 addr)
{
    map<ADDR32, CODEFUNC32>::iterator it, end;
    end = MapAddrToCodeFunc().end();
    it = MapAddrToCodeFunc().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

const CODEFUNC32 *DECOMPSTATUS32::MapAddrToCodeFunc(ADDR32 addr) const
{
    map<ADDR32, CODEFUNC32>::const_iterator it, end;
    end = MapAddrToCodeFunc().end();
    it = MapAddrToCodeFunc().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

VOID DECOMPSTATUS32::MapAddrToAsmCode(ADDR32 addr, const ASMCODE32& ac)
{
    MapAddrToAsmCode()[addr] = ac;
}

VOID DECOMPSTATUS32::MapAddrToCodeFunc(ADDR32 addr, const CODEFUNC32& cf)
{
    MapAddrToCodeFunc()[addr] = cf;
}

ASMCODE32 *DECOMPSTATUS32::MapAddrToAsmCode(ADDR32 addr)
{
    map<ADDR32, ASMCODE32>::iterator it, end;
    end = MapAddrToAsmCode().end();
    it = MapAddrToAsmCode().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

const ASMCODE32 *DECOMPSTATUS32::MapAddrToAsmCode(ADDR32 addr) const
{
    map<ADDR32, ASMCODE32>::const_iterator it, end;
    end = MapAddrToAsmCode().end();
    it = MapAddrToAsmCode().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////
// analyzing control flow graph

BOOL DECOMPSTATUS32::AnalyzeCFG()
{
    size_t i, size = Entrances().size();
    for (i = 0; i < size; i++)
    {
        AnalyzeFuncCFGStage1(Entrances()[i], Entrances()[i]);
        AnalyzeFuncCFGStage2(Entrances()[i]);
    }
    return TRUE;
}

BOOL DECOMPSTATUS32::AnalyzeFuncCFGStage1(ADDR32 func, ADDR32 addr)
{
    CODEFUNC32 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    ADDR32 va;
    ADDR32SET vJumpees;
    BOOL bEnd = FALSE;
    do
    {
        BLOCK32 block;

        if (cf->FindBlockOfAddr(addr))
            break;

        block.Addr() = addr;
        for (;;)
        {
            ASMCODE32 *ac = MapAddrToAsmCode(addr);
            if (ac == NULL)
            {
                bEnd = TRUE;
                break;
            }

            block.AsmCodes().insert(*ac);
            addr += ac->Codes().size();

            switch (ac->AsmCodeType())
            {
            case ACT_JMP:
            case ACT_RETURN:
                bEnd = TRUE;
                break;

            case ACT_JCC:
            case ACT_LOOP:
                va = ac->Operand(0)->Value32();
                block.NextAddr2() = va;
                vJumpees.insert(va);
                break;

            default:
                break;
            }

            if (bEnd || cf->Jumpees().Find(addr))
                break;
        }

        if (!bEnd)
            block.NextAddr1() = addr;

        if (!block.AsmCodes().empty())
            cf->Blocks().insert(block);
    } while (!bEnd);

    SIZE_T i, size = vJumpees.size();
    for (i = 0; i < size; i++)
    {
        if (cf->FindBlockOfAddr(vJumpees[i]))
            continue;

        AnalyzeFuncCFGStage1(func, vJumpees[i]);
    }

    return TRUE;
}

BOOL DECOMPSTATUS32::AnalyzeFuncCFGStage2(ADDR32 func)
{
    CODEFUNC32 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    size_t i, j, size = cf->Blocks().size();
    for (i = 0; i < size; i++)
    {
        BLOCK32 *b1 = &cf->Blocks()[i];
        for (j = 0; j < size; j++)
        {
            BLOCK32 *b2 = &cf->Blocks()[j];
            if (b2->Addr() == 0)
                continue;
            if (b1->NextAddr1() && b1->NextAddr1() == b2->Addr())
                b1->NextBlock1() = b2;
            if (b1->NextAddr2() && b1->NextAddr2() == b2->Addr())
                b1->NextBlock2() = b2;
        }
    }
    return TRUE;
}

ASMCODE64 *DECOMPSTATUS64::MapAddrToAsmCode(ADDR64 addr)
{
    map<ADDR64, ASMCODE64>::iterator it, end;
    end = MapAddrToAsmCode().end();
    it = MapAddrToAsmCode().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

CODEFUNC64 *DECOMPSTATUS64::MapAddrToCodeFunc(ADDR64 addr)
{
    map<ADDR64, CODEFUNC64>::iterator it, end;
    end = MapAddrToCodeFunc().end();
    it = MapAddrToCodeFunc().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

const ASMCODE64 *DECOMPSTATUS64::MapAddrToAsmCode(ADDR64 addr) const
{
    map<ADDR64, ASMCODE64>::const_iterator it, end;
    end = MapAddrToAsmCode().end();
    it = MapAddrToAsmCode().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

const CODEFUNC64 *DECOMPSTATUS64::MapAddrToCodeFunc(ADDR64 addr) const
{
    map<ADDR64, CODEFUNC64>::const_iterator it, end;
    end = MapAddrToCodeFunc().end();
    it = MapAddrToCodeFunc().find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64

DECOMPSTATUS64::DECOMPSTATUS64()
{
}

DECOMPSTATUS64::DECOMPSTATUS64(const DECOMPSTATUS64& status)
{
    Copy(status);
}

DECOMPSTATUS64& DECOMPSTATUS64::operator=(const DECOMPSTATUS64& status)
{
    Copy(status);
    return *this;
}

/*virtual*/ DECOMPSTATUS64::~DECOMPSTATUS64()
{
}

VOID DECOMPSTATUS64::Copy(const DECOMPSTATUS64& status)
{
    m_mAddrToAsmCode = status.m_mAddrToAsmCode;
    Entrances() = status.Entrances();
    m_mAddrToCodeFunc = status.m_mAddrToCodeFunc;
}

VOID DECOMPSTATUS64::clear()
{
    m_mAddrToAsmCode.clear();
    Entrances().clear();
    m_mAddrToCodeFunc.clear();
}

VOID DECOMPSTATUS64::MapAddrToAsmCode(ADDR64 addr, const ASMCODE64& ac)
{
    m_mAddrToAsmCode[addr] = ac;
}

VOID DECOMPSTATUS64::MapAddrToCodeFunc(ADDR64 addr, const CODEFUNC64& cf)
{
    m_mAddrToCodeFunc[addr] = cf;
}

////////////////////////////////////////////////////////////////////////////
// analyzing control flow graph

BOOL DECOMPSTATUS64::AnalyzeCFG()
{
    size_t i, size = Entrances().size();
    for (i = 0; i < size; i++)
    {
        AnalyzeFuncCFGStage1(Entrances()[i], Entrances()[i]);
        AnalyzeFuncCFGStage2(Entrances()[i]);
    }
    return TRUE;
}

BOOL DECOMPSTATUS64::AnalyzeFuncCFGStage1(ADDR64 func, ADDR64 addr)
{
    CODEFUNC64 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    ADDR64 va;
    ADDR64SET vJumpees;
    BOOL bEnd = FALSE;
    do
    {
        BLOCK64 block;

        if (cf->FindBlockOfAddr(addr))
            break;

        block.Addr() = addr;
        for (;;)
        {
            ASMCODE64 *ac = MapAddrToAsmCode(addr);
            if (ac == NULL)
            {
                bEnd = TRUE;
                break;
            }

            block.AsmCodes().insert(*ac);
            addr += ac->Codes().size();

            switch (ac->AsmCodeType())
            {
            case ACT_JMP:
            case ACT_RETURN:
                bEnd = TRUE;
                break;

            case ACT_JCC:
            case ACT_LOOP:
                va = ac->Operand(0)->Value64();
                block.NextAddr2() = va;
                vJumpees.insert(va);
                break;

            default:
                break;
            }

            if (bEnd || cf->Jumpees().Find(addr))
                break;
        }

        if (!bEnd)
            block.NextAddr1() = addr;

        if (!block.AsmCodes().empty())
            cf->Blocks().insert(block);
    } while (!bEnd);

    SIZE_T i, size = vJumpees.size();
    for (i = 0; i < size; i++)
    {
        if (cf->FindBlockOfAddr(vJumpees[i]))
            continue;

        AnalyzeFuncCFGStage1(func, vJumpees[i]);
    }

    return TRUE;
}

BOOL DECOMPSTATUS64::AnalyzeFuncCFGStage2(ADDR64 func)
{
    CODEFUNC64 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    size_t i, j, size = cf->Blocks().size();
    for (i = 0; i < size; i++)
    {
        BLOCK64 *b1 = &cf->Blocks()[i];
        for (j = 0; j < size; j++)
        {
            BLOCK64 *b2 = &cf->Blocks()[j];
            if (b2->Addr() == 0)
                continue;
            if (b1->NextAddr1() && b1->NextAddr1() == b2->Addr())
                b1->NextBlock1() = b2;
            if (b1->NextAddr2() && b1->NextAddr2() == b2->Addr())
                b1->NextBlock2() = b2;
        }
    }
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int _tmain(int argc, _TCHAR **argv)
{
    puts(cr_logo);

    if (argc != 2)
    {
#ifdef _WIN64
        fprintf(stderr, "Usage: coderev64 exefile.exe\n");
#else
        fprintf(stderr, "Usage: coderev exefile.exe\n");
#endif
        return 0;
    }

    PEMODULE module;
    if (module.LoadModule(argv[1]))
    {
        module.DumpHeaders();
        module.DumpImportSymbols();
        module.DumpExportSymbols();
        module.DumpResource();
        module.DumpDelayLoad();
        if (module.Is64Bit())
        {
            DECOMPSTATUS64 status;
            module.DisAsm64(status);
            module.FixUpAsm64(status);
            //status.AnalyzeCFG();
            module.DumpDisAsm64(status);
        }
        else if (module.Is32Bit())
        {
            DECOMPSTATUS32 status;
            module.DisAsm32(status);
            module.FixUpAsm32(status);
            //status.AnalyzeCFG();
            module.DumpDisAsm32(status);
        }
    }
    else
    {
#ifdef _UNICODE
        fprintf(stderr, "ERROR: Cannot load file '%ls', LastError = %lu\n",
            argv[1], module.LastError());
#else
        fprintf(stderr, "ERROR: Cannot load file '%s', LastError = %lu\n",
            argv[1], module.LastError());
#endif
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////
