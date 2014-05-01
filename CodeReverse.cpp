////////////////////////////////////////////////////////////////////////////
// CodeReverse.cpp
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "CParseHeader.h"

////////////////////////////////////////////////////////////////////////////

const char * const cr_logo =
    "///////////////////////////////////////////////\n"
#ifdef _WIN64
# ifdef __GNUC__
    "// CodeReverse 0.1.0 (64-bit) for gcc        //\n"
# elif defined(_MSC_VER)
    "// CodeReverse 0.1.0 (64-bit) for cl         //\n"
# endif
#else   // ndef _WIN64
# ifdef __GNUC__
    "// CodeReverse 0.1.0 (32-bit) for gcc        //\n"
# elif defined(_MSC_VER)
    "// CodeReverse 0.1.0 (32-bit) for cl         //\n"
# endif
#endif  // ndef _WIN64
    "// https://github.com/katahiromz/CodeReverse //\n"
    "// katayama.hirofumi.mz@gmail.com            //\n"
    "///////////////////////////////////////////////\n";


////////////////////////////////////////////////////////////////////////////
// CR_TriBool - tri-state logical value

CR_TriBool& CR_TriBool::IsFalse(const CR_TriBool& tb)
{
    switch (tb.m_value)
    {
    case TB_FALSE:      m_value = TB_TRUE; break;
    case TB_TRUE:       m_value = TB_FALSE; break;
    case TB_UNKNOWN:    m_value = TB_UNKNOWN; break;
    }
    return *this;
}

CR_TriBool& CR_TriBool::LogicalAnd(const CR_TriBool& tb1, const CR_TriBool& tb2)
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

CR_TriBool& CR_TriBool::LogicalOr(const CR_TriBool& tb1, const CR_TriBool& tb2)
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

CR_TriBool& CR_TriBool::Equal(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    if (tb1.m_value == TB_UNKNOWN || tb2.m_value == TB_UNKNOWN)
    {
        m_value = TB_UNKNOWN;
        return *this;
    }
    m_value = (tb1.m_value == tb2.m_value ? TB_TRUE : TB_FALSE);
    return *this;
}

////////////////////////////////////////////////////////////////////////////
// x86 registers

struct X86_REGINFO
{
    const char *name;
    CR_RegType type;
    int         bits;
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

CR_RegType cr_reg_get_type(const char *name, INT bits)
{
    const std::size_t size =
        sizeof(cr_reg_entries) / sizeof(cr_reg_entries[0]);
    for (std::size_t i = 0; i < size; i++)
    {
        if (bits >= cr_reg_entries[i].bits &&
            _stricmp(cr_reg_entries[i].name, name) == 0)
        {
            return cr_reg_entries[i].type;
        }
    }
    return X86_REGNONE;
}

DWORD cr_reg_get_size(const char *name, INT bits)
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

BOOL cr_reg_in_reg(const char *reg1, const char *reg2)
{
    if (strcmp(reg1, reg2) == 0)
        return TRUE;

    static const char *s[][4] =
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

    const std::size_t size = sizeof(s) / sizeof(s[0]);
    for (std::size_t i = 0; i < size; i++)
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

BOOL cr_reg_overlaps_reg(const char *reg1, const char *reg2)
{
    return cr_reg_in_reg(reg1, reg2) || cr_reg_in_reg(reg2, reg1);
}

////////////////////////////////////////////////////////////////////////////
// x86 flags

CR_FlagType cr_flag_get_type(const char *name, INT bits)
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

const char *cr_flag_get_name(CR_FlagType type, INT bits)
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

void OPERAND::Copy(const OPERAND& opr)
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

void OPERAND::clear()
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

void OPERAND::SetReg(const char *name)
{
    Text() = name;
    OperandType() = OT_REG;
    Size() = cr_reg_get_size(name, 64);
}

void OPERAND::SetAPI(const char *api)
{
    Text() = api;
    OperandType() = OT_API;
}

void OPERAND::SetLabel(const char *label)
{
    Text() = label;
    OperandType() = OT_IMM;
}

void OPERAND::SetMemImm(CR_Addr64 addr)
{
    OperandType() = OT_MEMIMM;
    Value64() = addr;
}

void OPERAND::SetMemExp(const char *exp_)
{
    OperandType() = OT_MEMEXP;
    Exp() = exp_;
}

void OPERAND::SetImm32(CR_Addr32 val, BOOL is_signed)
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

void OPERAND::SetImm64(CR_Addr64 val, BOOL is_signed)
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
// CR_CodeInsn32

CR_CodeInsn32::CR_CodeInsn32()
{
    clear();
}

CR_CodeInsn32::CR_CodeInsn32(const CR_CodeInsn32& ac)
{
    Copy(ac);
}

/*virtual*/ CR_CodeInsn32::~CR_CodeInsn32()
{
}

CR_CodeInsn32& CR_CodeInsn32::operator=(const CR_CodeInsn32& ac)
{
    Copy(ac);
    return *this;
}

void CR_CodeInsn32::Copy(const CR_CodeInsn32& ac)
{
    FuncAddrs() = ac.FuncAddrs();
    Addr() = ac.Addr();
    Name() = ac.Name();
    Operands() = ac.Operands();
    Codes() = ac.Codes();
    CodeInsnType() = ac.CodeInsnType();
    CondCode() = ac.CondCode();
}

void CR_CodeInsn32::clear()
{
    FuncAddrs().clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    CodeInsnType() = CIT_MISC;
    CondCode() = C_NONE;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn64

CR_CodeInsn64::CR_CodeInsn64()
{
    clear();
}

CR_CodeInsn64::CR_CodeInsn64(const CR_CodeInsn64& ac)
{
    Copy(ac);
}

/*virtual*/ CR_CodeInsn64::~CR_CodeInsn64()
{
}

CR_CodeInsn64& CR_CodeInsn64::operator=(const CR_CodeInsn64& ac)
{
    Copy(ac);
    return *this;
}

void CR_CodeInsn64::Copy(const CR_CodeInsn64& ac)
{
    FuncAddrs() = ac.FuncAddrs();
    Addr() = ac.Addr();
    Name() = ac.Name();
    Operands() = ac.Operands();
    Codes() = ac.Codes();
    CodeInsnType() = ac.CodeInsnType();
    CondCode() = ac.CondCode();
}

void CR_CodeInsn64::clear()
{
    FuncAddrs().clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    CodeInsnType() = CIT_MISC;
    CondCode() = C_NONE;
}

////////////////////////////////////////////////////////////////////////////
// CR_Block32

CR_Block32::CR_Block32() :
    m_addr(0),
    m_nextblock1(NULL),
    m_nextblock2(NULL),
    m_nextaddr1(0),
    m_nextaddr2(0)
{
}

CR_Block32::CR_Block32(const CR_Block32& b)
{
    Copy(b);
}

void CR_Block32::operator=(const CR_Block32& b)
{
    Copy(b);
}

void CR_Block32::Copy(const CR_Block32& b)
{
    Addr() = b.Addr();
    AsmCodes() = b.AsmCodes();
    NextBlock1() = b.NextBlock1();
    NextBlock2() = b.NextBlock2();
}

/*virtual*/ CR_Block32::~CR_Block32()
{
}

void CR_Block32::clear()
{
    AsmCodes().clear();
    NextBlock1() = NULL;
    NextBlock2() = NULL;
    NextAddr1() = 0;
    NextAddr2() = 0;
}

////////////////////////////////////////////////////////////////////////////
// CR_Block64

CR_Block64::CR_Block64() :
    m_addr(0),
    m_nextblock1(NULL),
    m_nextblock2(NULL),
    m_nextaddr1(0),
    m_nextaddr2(0)
{
}

CR_Block64::CR_Block64(const CR_Block64& b)
{
    Copy(b);
}

void CR_Block64::operator=(const CR_Block64& b)
{
    Copy(b);
}

void CR_Block64::Copy(const CR_Block64& b)
{
    Addr() = b.Addr();
    AsmCodes() = b.AsmCodes();
    NextBlock1() = b.NextBlock1();
    NextBlock2() = b.NextBlock2();
}

/*virtual*/ CR_Block64::~CR_Block64()
{
}

void CR_Block64::clear()
{
    AsmCodes().clear();
    NextBlock1() = NULL;
    NextBlock2() = NULL;
    NextAddr1() = 0;
    NextAddr2() = 0;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32

CR_CodeFunc32::CR_CodeFunc32()
{
    clear();
}

CR_CodeFunc32::CR_CodeFunc32(const CR_CodeFunc32& cf)
{
    Copy(cf);
}

CR_CodeFunc32& CR_CodeFunc32::operator=(const CR_CodeFunc32& cf)
{
    Copy(cf);
    return *this;
}

/*virtual*/ CR_CodeFunc32::~CR_CodeFunc32()
{
}

void CR_CodeFunc32::Copy(const CR_CodeFunc32& cf)
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

void CR_CodeFunc32::clear()
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

CR_Block32* CR_CodeFunc32::FindBlockOfAddr(CR_Addr32 addr)
{
    const std::size_t size = Blocks().size();
    for (std::size_t i = 0; i < size; i++)
    {
        if (Blocks()[i].Addr() == addr)
            return &Blocks()[i];
    }
    return NULL;
}

const CR_Block32* CR_CodeFunc32::FindBlockOfAddr(CR_Addr32 addr) const
{
    const std::size_t size = Blocks().size();
    for (std::size_t i = 0; i < size; i++)
    {
        if (Blocks()[i].Addr() == addr)
            return &Blocks()[i];
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64

CR_CodeFunc64::CR_CodeFunc64()
{
    clear();
}

CR_CodeFunc64::CR_CodeFunc64(const CR_CodeFunc64& cf)
{
    Copy(cf);
}

CR_CodeFunc64& CR_CodeFunc64::operator=(const CR_CodeFunc64& cf)
{
    Copy(cf);
    return *this;
}

/*virtual*/ CR_CodeFunc64::~CR_CodeFunc64()
{
}

void CR_CodeFunc64::Copy(const CR_CodeFunc64& cf)
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

void CR_CodeFunc64::clear()
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

CR_Block64* CR_CodeFunc64::FindBlockOfAddr(CR_Addr64 addr)
{
    for (auto& block : Blocks())
    {
        if (block.Addr() == addr)
            return &block;
    }
    return NULL;
}

const CR_Block64* CR_CodeFunc64::FindBlockOfAddr(CR_Addr64 addr) const
{
    for (auto& block : Blocks())
    {
        if (block.Addr() == addr)
            return &block;
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// cr_get_asmio_16, cr_get_asmio_32, cr_get_asmio_64

void cr_str_split_to_set(set<string>& s, const char *psz, const char *seps)
{
    s.clear();
    char *str = _strdup(psz);
    char *p = strtok(str, seps);
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
    const char *name;
    INT num_args;
    const char *in;
    const char *out;
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

    const std::size_t size = sizeof(s_table) / sizeof(s_table[0]);
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

    const std::size_t size = sizeof(s_table) / sizeof(s_table[0]);
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

    const std::size_t size = sizeof(s_table) / sizeof(s_table[0]);
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
// CR_DecompStatus32

CR_DecompStatus32::CR_DecompStatus32()
{
}

CR_DecompStatus32::CR_DecompStatus32(const CR_DecompStatus32& status)
{
    Copy(status);
}

CR_DecompStatus32& CR_DecompStatus32::operator=(const CR_DecompStatus32& status)
{
    Copy(status);
    return *this;
}

/*virtual*/ CR_DecompStatus32::~CR_DecompStatus32()
{
}

void CR_DecompStatus32::Copy(const CR_DecompStatus32& status)
{
    MapAddrToAsmCode() = status.MapAddrToAsmCode();
    Entrances() = status.Entrances();
    MapAddrToCodeFunc() = status.MapAddrToCodeFunc();
}

void CR_DecompStatus32::clear()
{
    MapAddrToAsmCode().clear();
    Entrances().clear();
    MapAddrToCodeFunc().clear();
}

CR_CodeFunc32 *CR_DecompStatus32::MapAddrToCodeFunc(CR_Addr32 addr)
{
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return &it->second;
    else
        return NULL;
}

const CR_CodeFunc32 *CR_DecompStatus32::MapAddrToCodeFunc(CR_Addr32 addr) const
{
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return &it->second;
    else
        return NULL;
}

void CR_DecompStatus32::MapAddrToAsmCode(CR_Addr32 addr, const CR_CodeInsn32& ac)
{
    MapAddrToAsmCode()[addr] = ac;
}

void CR_DecompStatus32::MapAddrToCodeFunc(CR_Addr32 addr, const CR_CodeFunc32& cf)
{
    MapAddrToCodeFunc()[addr] = cf;
}

CR_CodeInsn32 *CR_DecompStatus32::MapAddrToAsmCode(CR_Addr32 addr)
{
    auto it = MapAddrToAsmCode().find(addr);
    if (it != MapAddrToAsmCode().end())
        return &it->second;
    else
        return NULL;
}

const CR_CodeInsn32 *CR_DecompStatus32::MapAddrToAsmCode(CR_Addr32 addr) const
{
    auto it = MapAddrToAsmCode().find(addr);
    if (it != MapAddrToAsmCode().end())
        return &it->second;
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////
// analyzing control flow graph (CFG)

BOOL CR_DecompStatus32::AnalyzeCFG()
{
    const std::size_t size = Entrances().size();
    for (std::size_t i = 0; i < size; i++)
    {
        AnalyzeFuncCFGStage1(Entrances()[i], Entrances()[i]);
    }
    for (std::size_t i = 0; i < size; i++)
    {
        AnalyzeFuncCFGStage2(Entrances()[i]);
    }
    return TRUE;
}

BOOL CR_DecompStatus32::AnalyzeFuncCFGStage1(CR_Addr32 func, CR_Addr32 addr)
{
    CR_CodeFunc32 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    CR_Addr32 va;
    CR_Addr32Set vJumpees;
    BOOL bEnd = FALSE;
    do
    {
        CR_Block32 block;

        if (cf->FindBlockOfAddr(addr))
            break;

        block.Addr() = addr;
        for (;;)
        {
            CR_CodeInsn32 *ac = MapAddrToAsmCode(addr);
            if (ac == NULL)
            {
                bEnd = TRUE;
                break;
            }

            block.AsmCodes().insert(*ac);
            addr += ac->Codes().size();

            switch (ac->CodeInsnType())
            {
            case CIT_JMP:
            case CIT_RETURN:
                bEnd = TRUE;
                break;

            case CIT_JCC:
            case CIT_LOOP:
                va = ac->Operand(0)->Value32();
                block.NextAddr2() = va;
                vJumpees.insert(va);
                break;

            default:
                break;
            }

            if (bEnd || cf->Jumpees().Contains(addr))
                break;
        }

        if (!bEnd)
            block.NextAddr1() = addr;

        if (!block.AsmCodes().empty())
            cf->Blocks().insert(block);
    } while (!bEnd);

    std::size_t i, size = vJumpees.size();
    for (i = 0; i < size; i++)
    {
        if (cf->FindBlockOfAddr(vJumpees[i]))
            continue;

        AnalyzeFuncCFGStage1(func, vJumpees[i]);
    }

    return TRUE;
}

BOOL CR_DecompStatus32::AnalyzeFuncCFGStage2(CR_Addr32 func)
{
    CR_CodeFunc32 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    const std::size_t size = cf->Blocks().size();
    for (std::size_t i = 0; i < size; i++)
    {
        CR_Block32 *b1 = &cf->Blocks()[i];
        for (std::size_t j = 0; j < size; j++)
        {
            CR_Block32 *b2 = &cf->Blocks()[j];
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

CR_CodeInsn64 *CR_DecompStatus64::MapAddrToAsmCode(CR_Addr64 addr)
{
    auto it = MapAddrToAsmCode().find(addr);
    if (it != MapAddrToAsmCode().end())
        return &it->second;
    else
        return NULL;
}

CR_CodeFunc64 *CR_DecompStatus64::MapAddrToCodeFunc(CR_Addr64 addr)
{
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return &it->second;
    else
        return NULL;
}

const CR_CodeInsn64 *CR_DecompStatus64::MapAddrToAsmCode(CR_Addr64 addr) const
{
    auto it = MapAddrToAsmCode().find(addr);
    if (it != MapAddrToAsmCode().end())
        return &it->second;
    else
        return NULL;
}

const CR_CodeFunc64 *CR_DecompStatus64::MapAddrToCodeFunc(CR_Addr64 addr) const
{
    auto it = MapAddrToCodeFunc().find(addr);
    if (it != MapAddrToCodeFunc().end())
        return &it->second;
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64

CR_DecompStatus64::CR_DecompStatus64()
{
}

CR_DecompStatus64::CR_DecompStatus64(const CR_DecompStatus64& status)
{
    Copy(status);
}

CR_DecompStatus64& CR_DecompStatus64::operator=(const CR_DecompStatus64& status)
{
    Copy(status);
    return *this;
}

/*virtual*/ CR_DecompStatus64::~CR_DecompStatus64()
{
}

void CR_DecompStatus64::Copy(const CR_DecompStatus64& status)
{
    m_mAddrToAsmCode = status.m_mAddrToAsmCode;
    Entrances() = status.Entrances();
    m_mAddrToCodeFunc = status.m_mAddrToCodeFunc;
}

void CR_DecompStatus64::clear()
{
    m_mAddrToAsmCode.clear();
    Entrances().clear();
    m_mAddrToCodeFunc.clear();
}

void CR_DecompStatus64::MapAddrToAsmCode(CR_Addr64 addr, const CR_CodeInsn64& ac)
{
    m_mAddrToAsmCode[addr] = ac;
}

void CR_DecompStatus64::MapAddrToCodeFunc(CR_Addr64 addr, const CR_CodeFunc64& cf)
{
    m_mAddrToCodeFunc[addr] = cf;
}

////////////////////////////////////////////////////////////////////////////
// analyzing control flow graph

BOOL CR_DecompStatus64::AnalyzeCFG()
{
    const std::size_t size = Entrances().size();
    for (std::size_t i = 0; i < size; i++)
    {
        AnalyzeFuncCFGStage1(Entrances()[i], Entrances()[i]);
    }
    for (std::size_t i = 0; i < size; i++)
    {
        AnalyzeFuncCFGStage2(Entrances()[i]);
    }
    return TRUE;
}

BOOL CR_DecompStatus64::AnalyzeFuncCFGStage1(CR_Addr64 func, CR_Addr64 addr)
{
    CR_CodeFunc64 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    CR_Addr64 va;
    CR_Addr64Set vJumpees;
    BOOL bEnd = FALSE;
    do
    {
        CR_Block64 block;

        if (cf->FindBlockOfAddr(addr))
            break;

        block.Addr() = addr;
        for (;;)
        {
            CR_CodeInsn64 *ac = MapAddrToAsmCode(addr);
            if (ac == NULL)
            {
                bEnd = TRUE;
                break;
            }

            block.AsmCodes().insert(*ac);
            addr += ac->Codes().size();

            switch (ac->CodeInsnType())
            {
            case CIT_JMP:
            case CIT_RETURN:
                bEnd = TRUE;
                break;

            case CIT_JCC:
            case CIT_LOOP:
                va = ac->Operand(0)->Value64();
                block.NextAddr2() = va;
                vJumpees.insert(va);
                break;

            default:
                break;
            }

            if (bEnd || cf->Jumpees().Contains(addr))
                break;
        }

        if (!bEnd)
            block.NextAddr1() = addr;

        if (!block.AsmCodes().empty())
            cf->Blocks().insert(block);
    } while (!bEnd);

    std::size_t i, size = vJumpees.size();
    for (i = 0; i < size; i++)
    {
        if (cf->FindBlockOfAddr(vJumpees[i]))
            continue;

        AnalyzeFuncCFGStage1(func, vJumpees[i]);
    }

    return TRUE;
}

BOOL CR_DecompStatus64::AnalyzeFuncCFGStage2(CR_Addr64 func)
{
    CR_CodeFunc64 *cf = MapAddrToCodeFunc(func);
    if (cf == NULL)
        return FALSE;

    const std::size_t size = cf->Blocks().size();
    for (std::size_t i = 0; i < size; i++)
    {
        CR_Block64 *b1 = &cf->Blocks()[i];
        for (std::size_t j = 0; j < size; j++)
        {
            CR_Block64 *b2 = &cf->Blocks()[j];
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

// temporary file
static char *cr_tmpfile = NULL;

void CrDeleteTempFileAtExit(void)
{
    DeleteFile(cr_tmpfile);
}

////////////////////////////////////////////////////////////////////////////

using namespace cparser;

// do parse
int CrDoParse(shared_ptr<TransUnit>& tu, int argc, char **argv)
{
    LPSTR pchDotExt = MzcFindDotExt(argv[0]);
    // if file extension is ".i",
    if (_stricmp(pchDotExt, ".i") == 0)
    {
        // directly parse
        if (!cparser::parse_file(tu, argv[0]))
        {
            fprintf(stderr, "ERROR: Failed to parse file '%s'\n",
                argv[0]);
            return 1;   // failure
        }
    }
    else if (_stricmp(pchDotExt, ".h") == 0)
    {
        // if file extension is ".h",
        BOOL bOK = FALSE;
        // create temporary file
        MFile hTmpFile;
        char *cr_tmpfile = _tempnam(".", "coderev_temp");
        if (hTmpFile.OpenFileForOutput(cr_tmpfile))
        {
            atexit(CrDeleteTempFileAtExit);

            // setup process maker
            MProcessMaker pmaker;
            pmaker.SetShowWindow(SW_HIDE);
            pmaker.SetCreationFlags(CREATE_NEW_CONSOLE);

            MFile hInputWrite, hOutputRead, hErrorRead;
            if (pmaker.PrepareForRedirect(&hInputWrite, &hOutputRead, &hErrorRead))
            {
                // build command line
#ifdef __GNUC__
                std::string cmdline("gcc -E");
#elif defined(_MSC_VER)
                std::string cmdline("cl /nologo /E");
#endif
                for (int i = 1; i < argc; i++)
                {
                    cmdline += " ";
                    cmdline += argv[i];
                }
                cmdline += " ";
                cmdline += argv[0];

                // create process
                if (pmaker.CreateProcess(NULL, cmdline.c_str()))
                {
                    DWORD cbAvail, cbRead;
                    BYTE szBuf[1024];

                    bOK = TRUE;
                    for (;;)
                    {
                        if (hOutputRead.PeekNamedPipe(NULL, 0, NULL, &cbAvail) &&
                            cbAvail > 0)
                        {
                            // read from child process output
                            if (hOutputRead.ReadFile(szBuf, 1024, &cbRead))
                            {
                                // write to temporary file
                                if (!hTmpFile.WriteFile(szBuf, cbRead, &cbRead))
                                {
                                    fprintf(stderr,
                                        "ERROR: Cannot write to temporary file '%s'\n",
                                        cr_tmpfile);
                                    bOK = FALSE;
                                    break;
                                }
                            }
                            else
                            {
                                DWORD dwError = ::GetLastError();
                                if (dwError != ERROR_MORE_DATA)
                                {
                                    fprintf(stderr, "ERROR: Cannot read input\n");
                                    break;
                                }
                            }
                        }
                        else if (!pmaker.IsRunning())
                            break;
                    }
                    // check error output
                    if (hErrorRead.PeekNamedPipe(NULL, 0, NULL, &cbAvail) &&
                        cbAvail > 0)
                    {
                        while (hErrorRead.PeekNamedPipe(NULL, 0, NULL, &cbAvail) &&
                               cbAvail > 0)
                        {
                            hErrorRead.ReadFile(szBuf, 1024, &cbRead);
                            fwrite(szBuf, cbRead, 1, stderr);
                            if (cbRead == 0)
                                break;
                        }
                    }
                    bOK = (pmaker.GetExitCode() == 0);
                }
                else
                {
                    fprintf(stderr, "ERROR: Cannot create process\n");
                }
            }
            else
            {
                fprintf(stderr, "ERROR: Cannot create process\n");
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Cannot create temporary file '%s'\n",
                cr_tmpfile);
        }

        // close temporary file
        hTmpFile.CloseHandle();

        if (bOK)
        {
            if (!cparser::parse_file(tu, cr_tmpfile))
            {
                fprintf(stderr, "ERROR: Failed to parse file '%s'\n",
                    argv[0]);
                return 2;   // failure
            }
        }
        else
        {
            return 3;   // failure
        }
    }
    else
    {
        fprintf(stderr,
            "ERROR: Unknown input file extension '%s'. Please use .i or .h\n",
            pchDotExt);
        return 4;   // failure
    }
    return 0;   // success
}

////////////////////////////////////////////////////////////////////////////

void CrShowHelp(void)
{
#ifdef _WIN64
    fprintf(stderr,
            " Usage: coderev64 exefile.exe [input-file] [compiler_options]\n");
#else
    fprintf(stderr,
            " Usage: coderev exefile.exe [input-file] [compiler_options]\n");
#endif
}

////////////////////////////////////////////////////////////////////////////
// CrCalcConstInt...Expr functions

int CrCalcConstIntPrimExpr(CR_NameScope& namescope, PrimExpr *pe);
int CrCalcConstIntPostfixExpr(CR_NameScope& namescope, PostfixExpr *pe);
int CrCalcConstIntUnaryExpr(CR_NameScope& namescope, UnaryExpr *ue);
int CrCalcConstIntCastExpr(CR_NameScope& namescope, CastExpr *ce);
int CrCalcConstIntMulExpr(CR_NameScope& namescope, MulExpr *me);
int CrCalcConstIntAddExpr(CR_NameScope& namescope, AddExpr *ae);
int CrCalcConstIntShiftExpr(CR_NameScope& namescope, ShiftExpr *se);
int CrCalcConstIntRelExpr(CR_NameScope& namescope, RelExpr *re);
int CrCalcConstIntEqualExpr(CR_NameScope& namescope, EqualExpr *ee);
int CrCalcConstIntAndExpr(CR_NameScope& namescope, AndExpr *ae);
int CrCalcConstIntExclOrExpr(CR_NameScope& namescope, ExclOrExpr *eoe);
int CrCalcConstIntInclOrExpr(CR_NameScope& namescope, InclOrExpr *ioe);
int CrCalcConstIntLogAndExpr(CR_NameScope& namescope, LogAndExpr *lae);
int CrCalcConstIntLogOrExpr(CR_NameScope& namescope, LogOrExpr *loe);
int CrCalcConstIntAssignExpr(CR_NameScope& namescope, AssignExpr *ae);
int CrCalcConstIntExpr(CR_NameScope& namescope, Expr *e);
int CrCalcConstIntCondExpr(CR_NameScope& namescope, CondExpr *ce);

int CrCalcConstIntPrimExpr(CR_NameScope& namescope, PrimExpr *pe)
{
    int n;
    switch (pe->m_prim_type)
    {
    case PrimExpr::IDENTIFIER:
        n = namescope.GetIntValueFromVarName(pe->m_text);
        return n;

    case PrimExpr::F_CONSTANT:
        return 0;

    case PrimExpr::I_CONSTANT:
        n = std::atoi(pe->m_text.c_str());
        return n;

    case PrimExpr::STRING:
        return 1;

    case PrimExpr::PAREN:
        n = CrCalcConstIntExpr(namescope, pe->m_expr.get());
        return n;

    case PrimExpr::SELECTION:
        // TODO:
        break;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntPostfixExpr(CR_NameScope& namescope, PostfixExpr *pe)
{
    int n;
    switch (pe->m_postfix_type)
    {
    case PostfixExpr::SINGLE:
        n = CrCalcConstIntPrimExpr(namescope, pe->m_prim_expr.get());
        return n;

    case PostfixExpr::ARRAYITEM:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::FUNCCALL1:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::FUNCCALL2:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::DOT:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::ARROW:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::INC:
        n = CrCalcConstIntPostfixExpr(namescope, pe->m_postfix_expr.get());
        return n;

    case PostfixExpr::DEC:
        n = CrCalcConstIntPostfixExpr(namescope, pe->m_postfix_expr.get());
        return n;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcSizeOfUnaryExpr(CR_NameScope& namescope, UnaryExpr *ue)
{
    return 0;
}

CR_TypeID CrAnalyseDeclSpecs(CR_NameScope& namescope, DeclSpecs *ds);

int CrCalcSizeOfTypeName(CR_NameScope& namescope, TypeName *tn)
{
    CR_TypeID tid = CrAnalyseDeclSpecs(namescope, tn->m_decl_specs.get());
    if (tn->m_declor)
    {
        switch (tn->m_declor->m_declor_type)
        {
        case Declor::POINTERS:
        case Declor::FUNCTION:
            return static_cast<int>(sizeof(void *));

        case Declor::ARRAY:
            {
                int count = CrCalcConstIntCondExpr(
                    namescope, tn->m_declor->m_const_expr.get());
                return namescope.GetSizeofType(tid) * count;
            }

        case Declor::BITS:
            return 0;

        default:
            break;
        }
    }
    return namescope.GetSizeofType(tid);
}

int CrCalcConstIntUnaryExpr(CR_NameScope& namescope, UnaryExpr *ue)
{
    int n;
    switch (ue->m_unary_type)
    {
    case UnaryExpr::SINGLE:
        n = CrCalcConstIntPostfixExpr(namescope, ue->m_postfix_expr.get());
        return n;

    case UnaryExpr::INC:
        n = CrCalcConstIntUnaryExpr(namescope, ue->m_unary_expr.get());
        return ++n;

    case UnaryExpr::DEC:
        n = CrCalcConstIntUnaryExpr(namescope, ue->m_unary_expr.get());
        return --n;

    case UnaryExpr::AND:
        return 0;

    case UnaryExpr::ASTERISK:
        return 0;

    case UnaryExpr::PLUS:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return n;

    case UnaryExpr::MINUS:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return n;

    case UnaryExpr::BITWISE_NOT:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return ~n;

    case UnaryExpr::NOT:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return !n;

    case UnaryExpr::SIZEOF1:
        n = CrCalcSizeOfUnaryExpr(namescope, ue->m_unary_expr.get());
        return n;

    case UnaryExpr::SIZEOF2:
        n = CrCalcSizeOfTypeName(namescope, ue->m_type_name.get());
        return n;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntCastExpr(CR_NameScope& namescope, CastExpr *ce)
{
    int n;
    switch (ce->m_cast_type)
    {
    case CastExpr::UNARY:
        n = CrCalcConstIntUnaryExpr(namescope, ce->m_unary_expr.get());
        return n;
    
    case CastExpr::INITERLIST:
        // TODO:
        //ce->m_type_name
        //ce->m_initer_list
        return 0;

    case CastExpr::CAST:
        //ce->m_type_name
        n = CrCalcConstIntCastExpr(namescope, ce->m_cast_expr.get());
        return n;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntMulExpr(CR_NameScope& namescope, MulExpr *me)
{
    int n1, n2;
    switch (me->m_mul_type)
    {
    case MulExpr::SINGLE:
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n2;

    case MulExpr::ASTERISK:
        n1 = CrCalcConstIntMulExpr(namescope, me->m_mul_expr.get());
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n1 * n2;

    case MulExpr::SLASH:
        n1 = CrCalcConstIntMulExpr(namescope, me->m_mul_expr.get());
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n1 / n2;

    case MulExpr::PERCENT:
        n1 = CrCalcConstIntMulExpr(namescope, me->m_mul_expr.get());
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n1 % n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntAddExpr(CR_NameScope& namescope, AddExpr *ae)
{
    int n1, n2;
    switch (ae->m_add_type)
    {
    case AddExpr::SINGLE:
        n2 = CrCalcConstIntMulExpr(namescope, ae->m_mul_expr.get());
        return n2;

    case AddExpr::PLUS:
        n1 = CrCalcConstIntAddExpr(namescope, ae->m_add_expr.get());
        n2 = CrCalcConstIntMulExpr(namescope, ae->m_mul_expr.get());
        return n1 + n2;

    case AddExpr::MINUS:
        n1 = CrCalcConstIntAddExpr(namescope, ae->m_add_expr.get());
        n2 = CrCalcConstIntMulExpr(namescope, ae->m_mul_expr.get());
        return n1 - n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntShiftExpr(CR_NameScope& namescope, ShiftExpr *se)
{
    int n1, n2;
    switch (se->m_shift_type)
    {
    case ShiftExpr::SINGLE:
        n2 = CrCalcConstIntAddExpr(namescope, se->m_add_expr.get());
        return n2;

    case ShiftExpr::L_SHIFT:
        n1 = CrCalcConstIntShiftExpr(namescope, se->m_shift_expr.get());
        n2 = CrCalcConstIntAddExpr(namescope, se->m_add_expr.get());
        return n1 << n2;

    case ShiftExpr::R_SHIFT:
        n1 = CrCalcConstIntShiftExpr(namescope, se->m_shift_expr.get());
        n2 = CrCalcConstIntAddExpr(namescope, se->m_add_expr.get());
        return n1 >> n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntRelExpr(CR_NameScope& namescope, RelExpr *re)
{
    int n1, n2;
    switch (re->m_rel_type)
    {
    case RelExpr::SINGLE:
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n2;

    case RelExpr::LT:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 < n2;

    case RelExpr::GT:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 > n2;

    case RelExpr::LE:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 <= n2;

    case RelExpr::GE:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 >= n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntEqualExpr(CR_NameScope& namescope, EqualExpr *ee)
{
    int n1, n2;
    switch (ee->m_equal_type)
    {
    case EqualExpr::SINGLE:
        return CrCalcConstIntRelExpr(namescope, ee->m_rel_expr.get());

    case EqualExpr::EQUAL:
        n1 = CrCalcConstIntEqualExpr(namescope, ee->m_equal_expr.get());
        n2 = CrCalcConstIntRelExpr(namescope, ee->m_rel_expr.get());
        return n1 == n2;

    case EqualExpr::NE:
        n1 = CrCalcConstIntEqualExpr(namescope, ee->m_equal_expr.get());
        n2 = CrCalcConstIntRelExpr(namescope, ee->m_rel_expr.get());
        return n1 != n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntAndExpr(CR_NameScope& namescope, AndExpr *ae)
{
    int n = CrCalcConstIntEqualExpr(namescope, (*ae)[0].get());
    for (std::size_t i = 1; i < ae->size(); ++i)
    {
        n &= CrCalcConstIntEqualExpr(namescope, (*ae)[i].get());
    }
    return n;
}

int CrCalcConstIntExclOrExpr(CR_NameScope& namescope, ExclOrExpr *eoe)
{
    int n = 0;
    for (auto& ae : *eoe)
    {
        n ^= CrCalcConstIntAndExpr(namescope, ae.get());
    }
    return n;
}

int CrCalcConstIntInclOrExpr(CR_NameScope& namescope, InclOrExpr *ioe)
{
    int n = 0;
    for (auto& eoe : *ioe)
    {
        n |= CrCalcConstIntExclOrExpr(namescope, eoe.get());
    }
    return n;
}

int CrCalcConstIntLogAndExpr(CR_NameScope& namescope, LogAndExpr *lae)
{
    int n = 1;
    for (auto& ioe : *lae)
    {
        n = n && CrCalcConstIntInclOrExpr(namescope, ioe.get());
        if (n == 0)
            break;
    }
    return n;
}

int CrCalcConstIntLogOrExpr(CR_NameScope& namescope, LogOrExpr *loe)
{
    for (auto& lae : *loe)
    {
        if (CrCalcConstIntLogAndExpr(namescope, lae.get()))
            return 1;
    }
    return 0;
}

int CrCalcConstIntAssignExpr(CR_NameScope& namescope, AssignExpr *ae)
{
    int n1, n2;
    switch (ae->m_assign_type)
    {
    case AssignExpr::COND:
        n1 = CrCalcConstIntCondExpr(namescope, ae->m_cond_expr.get());
        return n1;

    case AssignExpr::SINGLE:
        n1 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        return n1;

    case AssignExpr::MUL:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 *= n2;
        return n1;

    case AssignExpr::DIV:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 /= n2;
        return n1;

    case AssignExpr::MOD:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 %= n2;
        return n1;

    case AssignExpr::ADD:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 += n2;
        return n1;

    case AssignExpr::SUB:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 -= n2;
        return n1;

    case AssignExpr::L_SHIFT:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 <<= n2;
        return n1;

    case AssignExpr::R_SHIFT:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 >>= n2;
        return n1;

    case AssignExpr::AND:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 &= n2;
        return n1;

    case AssignExpr::XOR:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 ^= n2;
        return n1;

    case AssignExpr::OR:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 |= n2;
        return n1;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntExpr(CR_NameScope& namescope, Expr *e)
{
    int n = 0;
    for (auto& ae : *e)
    {
        n = CrCalcConstIntAssignExpr(namescope, ae.get());
    }
    return n;
}

int CrCalcConstIntCondExpr(CR_NameScope& namescope, CondExpr *ce)
{
    switch (ce->m_cond_type)
    {
    case CondExpr::SINGLE:
        return CrCalcConstIntLogOrExpr(namescope, ce->m_log_or_expr.get());

    case CondExpr::QUESTION:
        if (CrCalcConstIntLogOrExpr(namescope, ce->m_log_or_expr.get()))
        {
            return CrCalcConstIntExpr(namescope, ce->m_expr.get());
        }
        else
        {
            return CrCalcConstIntCondExpr(namescope, ce->m_cond_expr.get());
        }

    default:
        assert(0);
        break;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////
// CrAnalyse... functions

CR_TypeID CrAnalysePointer(CR_NameScope& namescope, Pointers *pointers,
                           CR_TypeID tid);
void CrAnalyseTypedefDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                                DeclorList *dl);
void CrAnalyseDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                         DeclorList *dl);
void CrAnalyseStructDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                               DeclorList *dl, CR_LogStruct& ls);
void CrAnalyseDeclList(CR_NameScope& namescope, DeclList *dl);
void CrAnalyseParamList(CR_NameScope& namescope, CR_LogFunc& func,
                        ParamList *pl);
void CrAnalyseFunc(CR_NameScope& namescope, CR_TypeID return_type,
                   Declor *declor, DeclList *decl_list);
CR_TypeID CrAnalyseStructDeclList(CR_NameScope& namescope,
                                  const std::string& name, DeclList *dl);
CR_TypeID CrAnalyseUnionDeclList(CR_NameScope& namescope,
                                 const std::string& name, DeclList *dl);
CR_TypeID CrAnalyseEnumorList(CR_NameScope& namescope,
                              const std::string& name, EnumorList *el);
CR_TypeID CrAnalyseAtomic(CR_NameScope& namescope, AtomicTypeSpec *ats);
CR_TypeID CrAnalyseDeclSpecs(CR_NameScope& namescope, DeclSpecs *ds);

////////////////////////////////////////////////////////////////////////////

CR_TypeID CrAnalysePointers(CR_NameScope& namescope, Pointers *pointers,
                            CR_TypeID tid)
{
    assert(pointers);
    for (auto& ac: *pointers)
    {
        tid = namescope.AddPtrType(tid, ac->m_flags);
    }
    return tid;
}

void CrAnalyseTypedefDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                                DeclorList *dl)
{
    CR_TypeID tid2;
    assert(dl);
    for (auto& declor : *dl)
    {
        tid2 = tid;

        int value;
        Declor *d = declor.get();
        while (d)
        {
            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                namescope.AddAliasType(d->m_name, tid2);
                d = NULL;
                break;

            case Declor::TYPEDEF_TAG:
                namescope.AddAliasType(d->m_name, tid2);
                d = NULL;
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                break;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType("", tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    lf.m_return_type = tid2;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                break;

            case Declor::BITS:
                // TODO:
                d = NULL;
                break;

            default:
                assert(0);
                d = NULL;
                break;
            }
        }
    }
}

void CrAnalyseDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                         DeclorList *dl)
{
    CR_TypeID tid2;
    assert(dl);
    for (auto& declor : *dl)
    {
        tid2 = tid;

        int value;
        Declor *d = declor.get();
        while (d)
        {
            #ifdef DEEPDEBUG
                printf("DeclorList#%s\n", namescope.StringOfType(tid2, "").c_str());
            #endif

            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                namescope.AddVar(d->m_name, tid2);
                #ifdef DEEPDEBUG
                    printf("#%s\n", namescope.StringOfType(tid2, d->m_name).c_str());
                #endif
                d = d->m_declor.get();
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                break;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType("", tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    lf.m_return_type = tid2;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                break;

            case Declor::BITS:
                // TODO:
                break;

            default:
                assert(0);
                break;
            }
        }
    }
}

void CrAnalyseStructDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                               DeclorList *dl, CR_LogStruct& ls)
{
    CR_TypeID tid2;
    assert(dl);
    for (auto& declor : *dl)
    {
        tid2 = tid;

        int value;
        std::string name;
        Declor *d = declor.get();
        while (d)
        {
            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                name = d->m_name;
                d = NULL;
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                continue;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType("", tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                break;

            case Declor::BITS:
                // TODO:
                d = NULL;
                break;

            default:
                assert(0);
                d = NULL;
                break;
            }
        }
        ls.m_type_list.push_back(tid2);
        ls.m_name_list.push_back(name);
    }
}

void CrAnalyseDeclList(CR_NameScope& namescope, DeclList *dl)
{
    assert(dl);
    for (auto& decl : *dl)
    {
        CR_TypeID tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
        switch (decl->m_decl_type)
        {
        case Decl::TYPEDEF:
            CrAnalyseTypedefDeclorList(namescope, tid, decl->m_declor_list.get());
            break;

        case Decl::DECLORLIST:
            CrAnalyseDeclorList(namescope, tid, decl->m_declor_list.get());
            break;

        case Decl::STATIC_ASSERT:
            {
                shared_ptr<CondExpr> const_expr =
                    decl->m_static_assert_decl->m_const_expr;
                if (CrCalcConstIntCondExpr(namescope, const_expr.get()) == 0)
                {
                    assert(0);
                }
            }
            break;

        default:
            break;
        }
    }
}

void CrAnalyseParamList(CR_NameScope& namescope, CR_LogFunc& func,
                        ParamList *pl)
{
    func.m_ellipsis = pl->m_ellipsis;

    assert(pl);
    for (auto& decl : *pl)
    {
        assert(decl->m_decl_type == Decl::PARAM);
        assert(decl->m_declor_list->size() <= 1);

        DeclorList *dl = decl->m_declor_list.get();
        Declor *d;
        if (decl->m_declor_list->size())
            d = (*dl)[0].get();
        else
            d = NULL;
        CR_TypeID tid;
        tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());

        #ifdef DEEPDEBUG
            printf("ParamList##%s\n", namescope.StringOfType(tid, "").c_str());
        #endif

        CR_TypeID tid2 = tid;
        int value;
        std::string name;
        while (d)
        {
            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                name = d->m_name;
                d = d->m_declor.get();
                continue;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                continue;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType("", tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    lf.m_return_type = tid2;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                continue;

            case Declor::BITS:
                // TODO:
                d = NULL;
                break;

            default:
                assert(0);
                d = NULL;
                break;
            }
        }
        func.m_type_list.push_back(tid2);
        func.m_name_list.push_back(name);
    }
}

void CrAnalyseFunc(CR_NameScope& namescope, CR_TypeID return_type,
                   Declor *declor, DeclList *decl_list)
{
    CR_LogFunc func;
    assert(declor);

    if (declor->m_declor_type == Declor::FUNCTION)
    {
        if (!declor->m_name.empty())
        {
            if (decl_list)
            {
                CrAnalyseDeclList(namescope, decl_list);
                if (declor->m_param_list)
                {
                    CrAnalyseParamList(namescope, func, declor->m_param_list.get());
                    namescope.AddFuncType(func);
                }
                else
                {
                    assert(0);
                }
            }
            else
            {
                assert(declor->m_param_list);
                if (declor->m_param_list)
                {
                    CrAnalyseParamList(namescope, func, declor->m_param_list.get());
                    namescope.AddFuncType(func);
                }
            }
        }
    }
}

CR_TypeID CrAnalyseStructDeclList(CR_NameScope& namescope,
                                  const std::string& name, DeclList *dl)
{
    CR_LogStruct ls;
    ls.m_struct_or_union = true;    // struct

    CR_TypeID tid;
    assert(dl);
    for (auto& decl : *dl)
    {
        switch (decl->m_decl_type)
        {
        case Decl::DECLORLIST:
            tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
            CrAnalyseStructDeclorList(namescope, tid, decl->m_declor_list.get(), ls);
            break;

        case Decl::SINGLE:
            tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
            if (tid != cr_invalid_id)
            {
                ls.m_type_list.push_back(tid);
                ls.m_name_list.push_back("");
            }
            break;

        case Decl::STATIC_ASSERT:
            {
                shared_ptr<CondExpr> const_expr =
                    decl->m_static_assert_decl->m_const_expr;
                if (CrCalcConstIntCondExpr(namescope, const_expr.get()) == 0)
                {
                    assert(0);
                }
            }
            break;

        default:
            return cr_invalid_id;
        }
    }

    return namescope.AddStructOrUnionType(name, ls);
}

CR_TypeID CrAnalyseUnionDeclList(CR_NameScope& namescope,
                                 const std::string& name, DeclList *dl)
{
    CR_LogStruct ls;
    ls.m_struct_or_union = false;   // union

    assert(dl);
    for (auto& decl : *dl)
    {
        switch (decl->m_decl_type)
        {
        case Decl::DECLORLIST:
            {
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
                CrAnalyseStructDeclorList(namescope, tid, decl->m_declor_list.get(),
                                          ls);
            }
            break;

        case Decl::SINGLE:
            {
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
                if (tid != cr_invalid_id)
                {
                    ls.m_type_list.push_back(tid);
                    ls.m_name_list.push_back("");
                }
            }
            break;

        case Decl::STATIC_ASSERT:
            {
                shared_ptr<CondExpr> const_expr =
                    decl->m_static_assert_decl->m_const_expr;
                if (CrCalcConstIntCondExpr(namescope, const_expr.get()) == 0)
                {
                    assert(0);
                }
            }
            break;

        default:
            return cr_invalid_id;
        }
    }

    return namescope.AddStructOrUnionType(name, ls);
}

CR_TypeID CrAnalyseEnumorList(CR_NameScope& namescope,
                              const std::string& name, EnumorList *el)
{
    CR_LogEnum le;

    int value, next_value = 0;
    assert(el);
    for (auto& e : *el)
    {
        if (e->m_const_expr)
            value = CrCalcConstIntCondExpr(namescope, e->m_const_expr.get());
        else
            value = next_value;
        le.MapNameToValue()[e->m_name.c_str()] = value;
        le.MapValueToName()[value] = e->m_name.c_str();
        namescope.AddVar(e->m_name, CR_LogType(TF_INT));
        next_value = value + 1;
    }

    return namescope.AddEnumType(name, le);
}

CR_TypeID CrAnalyseAtomic(CR_NameScope& namescope, AtomicTypeSpec *ats)
{
    // TODO: TF_ATOMIC
    return 0;
}

CR_TypeID CrAnalyseDeclSpecs(CR_NameScope& namescope, DeclSpecs *ds)
{
    CR_TypeID tid;
    CR_TypeFlags flag, flags = 0;
    if (ds == NULL)
        return namescope.TypeIDFromName("int");

    while (ds)
    {
        std::string name;
        switch (ds->m_spec_type)
        {
        case DeclSpecs::STORCLSSPEC:
            flag = ds->m_stor_cls_spec->m_flag;
            flags |= flag;
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
            break;

        case DeclSpecs::FUNCSPEC:
            flag = ds->m_func_spec->m_flag;
            flags |= flag;
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
            break;

        case DeclSpecs::TYPESPEC:
            assert(ds->m_type_spec);
            flag = ds->m_type_spec->m_flag;
            switch (flag)
            {
            case TF_ALIAS:
                name = ds->m_type_spec->m_name;
                tid = namescope.TypeIDFromName(name);
                assert(tid != cr_invalid_id);
                return tid;

            case TF_STRUCT:
                name = ds->m_type_spec->m_name;
                if (ds->m_type_spec->m_decl_list)
                {
                    tid = CrAnalyseStructDeclList(
                        namescope, name, ds->m_type_spec->m_decl_list.get());
                }
                else
                {
                    CR_LogStruct ls;
                    ls.m_struct_or_union = true;
                    tid = namescope.AddStructOrUnionType(
                        std::string("struct ") + name, ls);
                }
                if (flags == TF_CONST)
                {
                    tid = namescope.AddConstType(tid);
                }
                assert(tid != cr_invalid_id);
                return tid;

            case TF_UNION:
                name = ds->m_type_spec->m_name;
                if (ds->m_type_spec->m_decl_list)
                {
                    tid = CrAnalyseUnionDeclList(
                        namescope, name, ds->m_type_spec->m_decl_list.get());
                }
                else
                {
                    CR_LogStruct ls;
                    ls.m_struct_or_union = false;
                    tid = namescope.AddStructOrUnionType(
                        std::string("union ") + name, ls);
                }
                if (flags == TF_CONST)
                {
                    tid = namescope.AddConstType(tid);
                }
                assert(tid != cr_invalid_id);
                return tid;

            case TF_ENUM:
                name = ds->m_type_spec->m_name;
                if (ds->m_type_spec->m_enumor_list)
                {
                    tid = CrAnalyseEnumorList(
                        namescope, name, ds->m_type_spec->m_enumor_list.get());
                }
                else
                {
                    CR_LogEnum le;
                    tid = namescope.AddEnumType(std::string("enum ") + name, le);
                }
                assert(tid != cr_invalid_id);
                return tid;

            case TF_ATOMIC:
                return CrAnalyseAtomic(namescope,
                    ds->m_type_spec.get()->m_atomic_type_spec.get());

            default:
                flags |= flag;
                if (ds->m_decl_specs)
                {
                    ds = ds->m_decl_specs.get();
                    continue;
                }
            }
            break;

        case DeclSpecs::TYPEQUAL:
            flag = ds->m_type_qual->m_flag;
            flags |= flag;
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
            break;

        case DeclSpecs::ALIGNSPEC:
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
        }
        break;
    }

    flags = CrNormalizeTypeFlags(flags);
    CR_LogType lt(flags);
    tid = namescope.m_types.Insert(lt);
    assert(tid != cr_invalid_id);
    return tid;
}

////////////////////////////////////////////////////////////////////////////
// semantic analysis

int CrSemanticAnalysis(CR_NameScope& namescope, shared_ptr<TransUnit>& tu)
{
    assert(tu.get());
    for (shared_ptr<Decl>& decl : *tu.get())
    {
        switch (decl->m_decl_type)
        {
        case Decl::FUNCTION:
            {
                shared_ptr<DeclSpecs>& ds = decl->m_decl_specs;
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, ds.get());
                shared_ptr<DeclorList>& dl = decl->m_declor_list;
                assert(dl.get());
                auto& declor = (*dl.get())[0];
                CrAnalyseFunc(namescope, tid, declor.get(),
                              decl->m_decl_list.get());
            }
            break;

        case Decl::TYPEDEF:
        case Decl::DECLORLIST:
            {
                shared_ptr<DeclSpecs>& ds = decl->m_decl_specs;
                shared_ptr<DeclorList>& dl = decl->m_declor_list;
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, ds.get());
                if (decl->m_decl_type == Decl::TYPEDEF)
                {
                    CrAnalyseTypedefDeclorList(namescope, tid, dl.get());
                }
                else
                {
                    CrAnalyseDeclorList(namescope, tid, dl.get());
                }
            }
            break;

        default:
            break;
        }
    }

    return 0;   // success
}

////////////////////////////////////////////////////////////////////////////

void CrDumpParsedFuncs(CR_NameScope& namescope)
{
    printf("\n### FUNCTIONS ###\n");
    auto& vars = namescope.m_vars;
    for (CR_VarID i = 0; i < vars.size(); ++i)
    {
        auto& var = vars[i];
        auto& type = namescope.m_types[var.m_type_id];
        if (type.m_flags & TF_FUNCTION)
        {
            auto& name = namescope.m_mVarIDToName[i];
            printf("%s\n",
                   namescope.StringOfType(var.m_type_id, name).c_str());
        }
    }
    printf("\n");
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int main(int argc, char **argv)
{
    puts(cr_logo);

    if (argc <= 1 || argc > 3 ||
        strcmp(argv[1], "/?") == 0 ||
        _stricmp(argv[1], "--help") == 0)
    {
        CrShowHelp();
        return 0;
    }

    if (argc >= 2 && _stricmp(argv[1], "--version") == 0)
    {
        return 0;
    }

    shared_ptr<TransUnit> tu;
    if (argc >= 3)
    {
        int result = CrDoParse(tu, argc - 2, &argv[2]);
        if (result)
            return result;
    }
    else
    {
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);

        char *title = MzcFindFileTitle(path);
        #if 1
            strcpy(title, "coderev-test.h");
            if (GetFileAttributesA(path) == 0xFFFFFFFF)
                strcpy(title, "..\\coderev-test.h");
        #else
            strcpy(title, "coderev-default.h");
            if (GetFileAttributesA(path) == 0xFFFFFFFF)
                strcpy(title, "..\\coderev-default.h");
        #endif

        char *args[1] = {path};
        int result = CrDoParse(tu, 1, args);
        if (result)
            return result;
    }

    CR_NameScope namescope;
    {
        int result = CrSemanticAnalysis(namescope, tu);
        if (result)
            return result;
    }

    #if 1
        CrDumpParsedFuncs(namescope);
    #endif

    CR_Module module;
    if (module.LoadModule(argv[1]))
    {
        module.DumpHeaders();
        module.DumpImportSymbols();
        module.DumpExportSymbols();
        module.DumpResource();
        module.DumpDelayLoad();

        if (module.Is64Bit())
        {
            CR_DecompStatus64 status;
            module.DisAsm64(status);
            module.FixUpAsm64(status);
            status.AnalyzeCFG();
            module.DumpDisAsm64(status);
        }
        else if (module.Is32Bit())
        {
            CR_DecompStatus32 status;
            module.DisAsm32(status);
            module.FixUpAsm32(status);
            status.AnalyzeCFG();
            module.DumpDisAsm32(status);
        }
    }
    else
    {
        fprintf(stderr, "ERROR: Cannot load file '%s', LastError = %lu\n",
            argv[1], module.LastError());
        return 6;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////
