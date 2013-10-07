////////////////////////////////////////////////////////////////////////////
// codereverse.cpp
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

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

LPCSTR cr_logo =
    "/////////////////////////////////////\n"
    "// CodeReverse 0.0.2               //\n"
    "// katayama.hirofumi.mz@gmail.com  //\n"
    "/////////////////////////////////////\n";

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
// OPERAND::OPERANDIMPL

struct OPERAND::OPERANDIMPL
{
    string      text;
    OPERANDTYPE ot;
    DWORD       size;
    union
    {
        ADDR64 value64;
        ADDR32 value32;
    };
    string      exp;
    string      datatype;
};

////////////////////////////////////////////////////////////////////////////
// OPERAND accessors

string& OPERAND::Text()
{
    return m_pImpl->text;
}

OPERANDTYPE& OPERAND::OperandType()
{
    return m_pImpl->ot;
}

DWORD& OPERAND::Size()
{
    return m_pImpl->size;
}

ADDR32& OPERAND::Value32()
{
    return m_pImpl->value32;
}

ADDR64& OPERAND::Value64()
{
    return m_pImpl->value64;
}

string& OPERAND::Exp()
{
    return m_pImpl->exp;
}

string& OPERAND::DataType()
{
    return m_pImpl->datatype;
}

////////////////////////////////////////////////////////////////////////////
// OPERAND const accessors

const string& OPERAND::Text() const
{
    return m_pImpl->text;
}

const OPERANDTYPE& OPERAND::OperandType() const
{
    return m_pImpl->ot;
}

const DWORD& OPERAND::Size() const
{
    return m_pImpl->size;
}

const ADDR32& OPERAND::Value32() const
{
    return m_pImpl->value32;
}

const ADDR64& OPERAND::Value64() const
{
    return m_pImpl->value64;
}

const string& OPERAND::Exp() const
{
    return m_pImpl->exp;
}

const string& OPERAND::DataType() const
{
    return m_pImpl->datatype;
}

////////////////////////////////////////////////////////////////////////////
// OPERAND

OPERAND::OPERAND() : m_pImpl(new OPERAND::OPERANDIMPL)
{
    Clear();
}

OPERAND::OPERAND(const OPERAND& opr)
    : m_pImpl(new OPERAND::OPERANDIMPL)
{
    Copy(opr);
}

/*virtual*/ OPERAND::~OPERAND()
{
    delete m_pImpl;
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
}

VOID OPERAND::Clear()
{
    Text().clear();
    OperandType() = OT_NONE;
    Size() = 0;
    Value64() = 0;
    Exp().clear();
    DataType().clear();
}

VOID OPERAND::SetAPI(LPCSTR api)
{
    Text() = api;
    OperandType() = OT_API;
}

VOID OPERAND::SetLabel(LPCSTR label)
{
    Text() = label;
    OperandType() = OT_LABEL;
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
    Value32() = val;
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

////////////////////////////////////////////////////////////////////////////
// ASMCODE32::ASMCODE32IMPL

struct ASMCODE32::ASMCODE32IMPL
{
    ADDR32SET           funcs;
    ADDR32              addr;
    string              name;
    vector<OPERAND>     operands;
    vector<BYTE>        codes;
    ASMCODETYPE         act;
    CONDCODE            ccode;
};

////////////////////////////////////////////////////////////////////////////
// ASMCODE32 accessors

ADDR32SET& ASMCODE32::Funcs()
{
    return m_pImpl->funcs;
}

ADDR32& ASMCODE32::Addr()
{
    return m_pImpl->addr;
}

string& ASMCODE32::Name()
{
    return m_pImpl->name;
}

vector<OPERAND>& ASMCODE32::Operands()
{
    return m_pImpl->operands;
}

OPERAND* ASMCODE32::Operand(SIZE_T index)
{
    assert(index < m_pImpl->operands.size());
    if (m_pImpl->operands.size() > index)
        return &m_pImpl->operands[index];
    else
        return NULL;
}

vector<BYTE>& ASMCODE32::Codes()
{
    return m_pImpl->codes;
}

ASMCODETYPE& ASMCODE32::AsmCodeType()
{
    return m_pImpl->act;
}

CONDCODE& ASMCODE32::CondCode()
{
    return m_pImpl->ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE32 const accessors

const ADDR32SET& ASMCODE32::Funcs() const
{
    return m_pImpl->funcs;
}

const ADDR32& ASMCODE32::Addr() const
{
    return m_pImpl->addr;
}

const string& ASMCODE32::Name() const
{
    return m_pImpl->name;
}

const vector<OPERAND>& ASMCODE32::Operands() const
{
    return m_pImpl->operands;
}

const OPERAND* ASMCODE32::Operand(SIZE_T index) const
{
    assert(m_pImpl->operands.size() > index);
    if (m_pImpl->operands.size() > index)
        return &m_pImpl->operands[index];
    else
        return NULL;
}

const vector<BYTE>& ASMCODE32::Codes() const
{
    return m_pImpl->codes;
}

const ASMCODETYPE& ASMCODE32::AsmCodeType() const
{
    return m_pImpl->act;
}

const CONDCODE& ASMCODE32::CondCode() const
{
    return m_pImpl->ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE32

ASMCODE32::ASMCODE32() : m_pImpl(new ASMCODE32::ASMCODE32IMPL)
{
    Clear();
}

ASMCODE32::ASMCODE32(const ASMCODE32& ac)
    : m_pImpl(new ASMCODE32::ASMCODE32IMPL)
{
    Copy(ac);
}

/*virtual*/ ASMCODE32::~ASMCODE32()
{
    delete m_pImpl;
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

VOID ASMCODE32::Clear()
{
    Funcs().Clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    AsmCodeType() = ACT_MISC;
    CondCode() = C_NONE;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE64::ASMCODE64IMPL

struct ASMCODE64::ASMCODE64IMPL
{
    ADDR64SET       funcs;
    ADDR64          addr;
    string          name;
    vector<OPERAND> operands;
    vector<BYTE>    codes;
    ASMCODETYPE     act;
    CONDCODE        ccode;
};

////////////////////////////////////////////////////////////////////////////
// ASMCODE64 accessors

ADDR64SET& ASMCODE64::Funcs()
{
    return m_pImpl->funcs;
}

ADDR64& ASMCODE64::Addr()
{
    return m_pImpl->addr;
}

string& ASMCODE64::Name()
{
    return m_pImpl->name;
}

vector<OPERAND>& ASMCODE64::Operands()
{
    return m_pImpl->operands;
}

OPERAND* ASMCODE64::Operand(SIZE_T index)
{
    assert(index < m_pImpl->operands.size());
    if (m_pImpl->operands.size() > index)
        return &m_pImpl->operands[index];
    else
        return NULL;
}

vector<BYTE>& ASMCODE64::Codes()
{
    return m_pImpl->codes;
}

ASMCODETYPE& ASMCODE64::AsmCodeType()
{
    return m_pImpl->act;
}

CONDCODE& ASMCODE64::CondCode()
{
    return m_pImpl->ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE64 const accessors

const ADDR64SET& ASMCODE64::Funcs() const
{
    return m_pImpl->funcs;
}

const ADDR64& ASMCODE64::Addr() const
{
    return m_pImpl->addr;
}

const string& ASMCODE64::Name() const
{
    return m_pImpl->name;
}

const vector<OPERAND>& ASMCODE64::Operands() const
{
    return m_pImpl->operands;
}

const OPERAND* ASMCODE64::Operand(SIZE_T index) const
{
    assert(m_pImpl->operands.size() > index);
    if (m_pImpl->operands.size() > index)
        return &m_pImpl->operands[index];
    else
        return NULL;
}

const vector<BYTE>& ASMCODE64::Codes() const
{
    return m_pImpl->codes;
}

const ASMCODETYPE& ASMCODE64::AsmCodeType() const
{
    return m_pImpl->act;
}

const CONDCODE& ASMCODE64::CondCode() const
{
    return m_pImpl->ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE64

ASMCODE64::ASMCODE64() : m_pImpl(new ASMCODE64IMPL)
{
    Clear();
}

ASMCODE64::ASMCODE64(const ASMCODE64& ac) : m_pImpl(new ASMCODE64IMPL)
{
    Copy(ac);
}

/*virtual*/ ASMCODE64::~ASMCODE64()
{
    delete m_pImpl;
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

VOID ASMCODE64::Clear()
{
    Funcs().Clear();
    Addr() = 0;
    Name().clear();
    Operands().clear();
    Codes().clear();
    AsmCodeType() = ACT_MISC;
    CondCode() = C_NONE;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32::CODEFUNC32IMPL

struct CODEFUNC32::CODEFUNC32IMPL
{
    ADDR32          addr;
    string          name;
    FUNCTYPE        ft;
    INT             sizeofargs;
    vector<OPERAND> args;
    DWORD           flags;
    string          returndatatype;
    ADDR32SET       jumpees;
    ADDR32SET       jumpers;
    ADDR32SET       callees;
    ADDR32SET       callers;
};

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32 accessors

ADDR32& CODEFUNC32::Addr()
{
    return m_pImpl->addr;
}

string& CODEFUNC32::Name()
{
    return m_pImpl->name;
}

FUNCTYPE& CODEFUNC32::FuncType()
{
    return m_pImpl->ft;
}

INT& CODEFUNC32::SizeOfArgs()
{
    return m_pImpl->sizeofargs;
}

vector<OPERAND>& CODEFUNC32::Args()
{
    return m_pImpl->args;
}

DWORD& CODEFUNC32::Flags()
{
    return m_pImpl->flags;
}

string& CODEFUNC32::ReturnDataType()
{
    return m_pImpl->returndatatype;
}

ADDR32SET& CODEFUNC32::Jumpees()
{
    return m_pImpl->jumpees;
}

ADDR32SET& CODEFUNC32::Jumpers()
{
    return m_pImpl->jumpers;
}

ADDR32SET& CODEFUNC32::Callees()
{
    return m_pImpl->callees;
}

ADDR32SET& CODEFUNC32::Callers()
{
    return m_pImpl->callees;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32 const accessors

const ADDR32& CODEFUNC32::Addr() const
{
    return m_pImpl->addr;
}

const string& CODEFUNC32::Name() const
{
    return m_pImpl->name;
}

const FUNCTYPE& CODEFUNC32::FuncType() const
{
    return m_pImpl->ft;
}

const INT& CODEFUNC32::SizeOfArgs() const
{
    return m_pImpl->sizeofargs;
}

const vector<OPERAND>& CODEFUNC32::Args() const
{
    return m_pImpl->args;
}

const DWORD& CODEFUNC32::Flags() const
{
    return m_pImpl->flags;
}

const string& CODEFUNC32::ReturnDataType() const
{
    return m_pImpl->returndatatype;
}

const ADDR32SET& CODEFUNC32::Jumpees() const
{
    return m_pImpl->jumpees;
}

const ADDR32SET& CODEFUNC32::Jumpers() const
{
    return m_pImpl->jumpers;
}

const ADDR32SET& CODEFUNC32::Callees() const
{
    return m_pImpl->callees;
}

const ADDR32SET& CODEFUNC32::Callers() const
{
    return m_pImpl->callees;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32

CODEFUNC32::CODEFUNC32() : m_pImpl(new CODEFUNC32::CODEFUNC32IMPL)
{
    Clear();
}

CODEFUNC32::CODEFUNC32(const CODEFUNC32& cf)
    : m_pImpl(new CODEFUNC32::CODEFUNC32IMPL)
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
    delete m_pImpl;
}

VOID CODEFUNC32::Copy(const CODEFUNC32& cf)
{
    Addr() = cf.Addr();
    Name() = cf.Name();
    FuncType() = cf.FuncType();
    SizeOfArgs() = cf.SizeOfArgs();
    Args() = cf.Args();
    Flags() = cf.Flags();
    ReturnDataType() = cf.ReturnDataType();
}

VOID CODEFUNC32::Clear()
{
    Addr() = 0;
    Name().clear();
    FuncType() = FT_UNKNOWN;
    SizeOfArgs() = -1;
    Args().clear();
    Flags() = 0;
    ReturnDataType().clear();
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32::CODEFUNC32IMPL

struct CODEFUNC64::CODEFUNC64IMPL
{
    ADDR64          addr;
    string          name;
    FUNCTYPE        ft;
    INT             sizeofargs;
    vector<OPERAND> args;
    DWORD           flags;
    string          returndatatype;
    ADDR64SET       jumpees;
    ADDR64SET       jumpers;
    ADDR64SET       callees;
    ADDR64SET       callers;
};

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64 accessors

ADDR64& CODEFUNC64::Addr()
{
    return m_pImpl->addr;
}

string& CODEFUNC64::Name()
{
    return m_pImpl->name;
}

FUNCTYPE& CODEFUNC64::FuncType()
{
    return m_pImpl->ft;
}

INT& CODEFUNC64::SizeOfArgs()
{
    return m_pImpl->sizeofargs;
}

vector<OPERAND>& CODEFUNC64::Args()
{
    return m_pImpl->args;
}

DWORD& CODEFUNC64::Flags()
{
    return m_pImpl->flags;
}

string& CODEFUNC64::ReturnDataType()
{
    return m_pImpl->returndatatype;
}

ADDR64SET& CODEFUNC64::Jumpees()
{
    return m_pImpl->jumpees;
}

ADDR64SET& CODEFUNC64::Jumpers()
{
    return m_pImpl->jumpers;
}

ADDR64SET& CODEFUNC64::Callees()
{
    return m_pImpl->callees;
}

ADDR64SET& CODEFUNC64::Callers()
{
    return m_pImpl->callees;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64 const accessors

const ADDR64& CODEFUNC64::Addr() const
{
    return m_pImpl->addr;
}

const string& CODEFUNC64::Name() const
{
    return m_pImpl->name;
}

const FUNCTYPE& CODEFUNC64::FuncType() const
{
    return m_pImpl->ft;
}

const INT& CODEFUNC64::SizeOfArgs() const
{
    return m_pImpl->sizeofargs;
}

const vector<OPERAND>& CODEFUNC64::Args() const
{
    return m_pImpl->args;
}

const DWORD& CODEFUNC64::Flags() const
{
    return m_pImpl->flags;
}

const string& CODEFUNC64::ReturnDataType() const
{
    return m_pImpl->returndatatype;
}

const ADDR64SET& CODEFUNC64::Jumpees() const
{
    return m_pImpl->jumpees;
}

const ADDR64SET& CODEFUNC64::Jumpers() const
{
    return m_pImpl->jumpers;
}

const ADDR64SET& CODEFUNC64::Callees() const
{
    return m_pImpl->callees;
}

const ADDR64SET& CODEFUNC64::Callers() const
{
    return m_pImpl->callees;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64

CODEFUNC64::CODEFUNC64() : m_pImpl(new CODEFUNC64::CODEFUNC64IMPL)
{
    Clear();
}

CODEFUNC64::CODEFUNC64(const CODEFUNC64& cf)
    : m_pImpl(new CODEFUNC64::CODEFUNC64IMPL)
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
    delete m_pImpl;
}

VOID CODEFUNC64::Copy(const CODEFUNC64& cf)
{
    Addr() = cf.Addr();
    Name() = cf.Name();
    FuncType() = cf.FuncType();
    SizeOfArgs() = cf.SizeOfArgs();
    Args() = cf.Args();
    Flags() = cf.Flags();
    ReturnDataType() = cf.ReturnDataType();
}

VOID CODEFUNC64::Clear()
{
    Addr() = 0;
    Name().clear();
    FuncType() = FT_UNKNOWN;
    SizeOfArgs() = -1;
    Args().clear();
    Flags() = 0;
    ReturnDataType().clear();
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
        {"cmpsb", 0, "si,di,DF,mem", "OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "si,di,DF,mem", "OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
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
        {"lodsb", 0, "si,DF", "al,si,mem", 0},
        {"lodsw", 0, "si,DF", "ax,si,mem", 0},
        {"loop", 1, "$0,cx", "cx", 0},
        {"loope", 1, "$0,cx,ZF", "cx", 0},
        {"loopne", 1, "$0,cx,ZF", "cx", 0},
        {"loopz", 1, "$0,cx,ZF", "cx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "di,si,DF,mem", "di,si,mem", 0},
        {"movsw", 0, "di,si,DF,mem", "di,si,mem", 0},
        {"mul", 1, "$0,al", "ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 1},
        {"mul", 1, "$0,ax", "dx:ax,CF,OF,SF,ZF,AF,PF,SFeqOF", 2},
        {"neg", 1, "$0", "$0,CF,OF,SF,ZF,AF,PF,SFeqOF", 0},
        {"nop", 0, "", "", 0},
        {"not", 1, "$0", "$0", 0},
        {"or", 2, "$0,$1", "$0,SF,PF,SFeqOF,ZF,OF,CF,AF", 0},
        {"rep lodsb", 0, "si,DF,cx", "cx,al,si,mem", 0},
        {"rep lodsw", 0, "si,DF,cx", "cx,ax,si,mem", 0},
        {"rep stosb", 0, "di,al,cx,DF", "di,cx,mem", 0},
        {"rep stosw", 0, "di,ax,cx,DF", "di,cx,mem", 0},
        {"repe cmpsb", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "di,al,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "di,ax,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "di,al,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "di,ax,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "di,al,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "di,ax,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "cx,si,di,DF,mem", "cx,OF,si,di,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "di,al,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "di,ax,cx,DF,mem", "cx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "di,al,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "di,ax,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"shl", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"shr", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"stc", 0, "", "CF", 0},
        {"std", 0, "", "DF", 0},
        {"sti", 0, "", "IF", 0},
        {"stosb", 0, "di,al,DF", "di,mem", 0},
        {"stosw", 0, "di,ax,DF", "di,mem", 0},
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
        {"cmpsb", 0, "esi,edi,DF,mem", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsd", 0, "esi,edi,DF,mem", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "esi,edi,DF,mem", "OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
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
        {"lodsb", 0, "esi,DF", "al,esi,mem", 0},
        {"lodsd", 0, "esi,DF", "eax,esi,mem", 0},
        {"lodsw", 0, "esi,DF", "ax,esi,mem", 0},
        {"loop", 1, "$0,ecx", "ecx", 0},
        {"loope", 1, "$0,ecx,ZF", "ecx", 0},
        {"loopne", 1, "$0,ecx,ZF", "ecx", 0},
        {"loopz", 1, "$0,ecx,ZF", "ecx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "edi,esi,DF,mem", "edi,esi,mem", 0},
        {"movsd", 0, "edi,esi,DF,mem", "edi,esi,mem", 0},
        {"movsw", 0, "edi,esi,DF,mem", "edi,esi,mem", 0},
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
        {"rep lodsb", 0, "esi,DF,ecx", "ecx,al,esi,mem", 0},
        {"rep lodsd", 0, "esi,DF,ecx", "ecx,eax,esi,mem", 0},
        {"rep lodsw", 0, "esi,DF,ecx", "ecx,ax,esi,mem", 0},
        {"rep stosb", 0, "ddi,al,ecx,DF", "edi,ecx,mem", 0},
        {"rep stosd", 0, "ddi,eax,ecx,DF", "edi,ecx,mem", 0},
        {"rep stosw", 0, "ddi,ax,ecx,DF", "edi,ecx,mem", 0},
        {"repe cmpsb", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsd", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "edi,al,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasd", 0, "edi,eax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "edi,ax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsd", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "edi,al,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasd", 0, "edi,eax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "edi,ax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsd", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "edi,al,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasd", 0, "edi,eax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "edi,ax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsd", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "ecx,esi,edi,DF,mem", "ecx,OF,esi,edi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "edi,al,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasd", 0, "edi,eax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "edi,ax,ecx,DF,mem", "ecx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "edi,al,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasd", 0, "edi,eax,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "edi,ax,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
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
        {"stosb", 0, "edi,al,DF", "edi,mem", 0},
        {"stosd", 0, "edi,eax,DF", "edi,mem", 0},
        {"stosw", 0, "edi,ax,DF", "edi,mem", 0},
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
        {"cmpsb", 0, "rsi,rdi,DF,mem", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsd", 0, "rsi,rdi,DF,mem", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsq", 0, "rsi,rdi,DF,mem", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"cmpsw", 0, "rsi,rdi,DF,mem", "OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
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
        {"lodsb", 0, "rsi,DF", "al,rsi,mem", 0},
        {"lodsd", 0, "rsi,DF", "eax,rsi,mem", 0},
        {"lodsq", 0, "rsi,DF", "rax,rsi,mem", 0},
        {"lodsw", 0, "rsi,DF", "ax,rsi,mem", 0},
        {"loop", 1, "$0,rcx", "rcx", 0},
        {"loope", 1, "$0,rcx,ZF", "rcx", 0},
        {"loopne", 1, "$0,rcx,ZF", "rcx", 0},
        {"loopz", 1, "$0,rcx,ZF", "rcx", 0},
        {"mov", 2, "$0,$1", "$0", 0},
        {"movsb", 0, "rdi,rsi,DF,mem", "rdi,rsi,mem", 0},
        {"movsd", 0, "rdi,rsi,DF,mem", "rdi,rsi,mem", 0},
        {"movsq", 0, "rdi,rsi,DF,mem", "rdi,rsi,mem", 0},
        {"movsw", 0, "rdi,rsi,DF,mem", "rdi,rsi,mem", 0},
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
        {"rep lodsb", 0, "rsi,DF,rcx", "rcx,al,rsi,mem", 0},
        {"rep lodsd", 0, "rsi,DF,rcx", "rcx,eax,rsi,mem", 0},
        {"rep lodsw", 0, "rsi,DF,rcx", "rcx,ax,rsi,mem", 0},
        {"rep lodsq", 0, "rsi,DF,rcx", "rcx,rax,rsi,mem", 0},
        {"rep stosb", 0, "ddi,al,rcx,DF", "rdi,rcx,mem", 0},
        {"rep stosd", 0, "ddi,eax,rcx,DF", "rdi,rcx,mem", 0},
        {"rep stosq", 0, "ddi,rax,rcx,DF", "rdi,rcx,mem", 0},
        {"rep stosw", 0, "ddi,ax,rcx,DF", "rdi,rcx,mem", 0},
        {"repe cmpsb", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsd", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsq", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe cmpsw", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repe scasb", 0, "rdi,al,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasd", 0, "rdi,eax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repe scasw", 0, "rdi,ax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne cmpsb", 0, "ecx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsd", 0, "ecx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne cmpsw", 0, "ecx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repne scasb", 0, "rdi,al,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasd", 0, "rdi,eax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repne scasw", 0, "rdi,ax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz cmpsb", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsd", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsq", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz cmpsw", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repnz scasb", 0, "rdi,al,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasd", 0, "rdi,eax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repnz scasw", 0, "rdi,ax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz cmpsb", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsd", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsq", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz cmpsw", 0, "rcx,rsi,rdi,DF,mem", "rcx,OF,rsi,rdi,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"repz scasb", 0, "rdi,al,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasd", 0, "rdi,eax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"repz scasw", 0, "rdi,ax,rcx,DF,mem", "rcx,OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"sal", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sar", 2, "$0,$1", "$0,CF,OF,ZF,SF,PF,AF,SFeqOF", 0},
        {"sbb", 2, "$0,$1,CF", "$0,OF,ZF,SF,CF,AF,PF,SFeqOF", 0},
        {"scasb", 0, "rdi,al,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasd", 0, "rdi,eax,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
        {"scasw", 0, "rdi,ax,DF,mem", "OF,ZF,SF,AF,PF,CF,SFeqOF", 0},
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
        {"stosb", 0, "rdi,al,DF", "rdi,mem", 0},
        {"stosd", 0, "rdi,eax,DF", "rdi,mem", 0},
        {"stosq", 0, "rdi,rax,DF", "rdi,mem", 0},
        {"stosw", 0, "rdi,ax,DF", "rdi,mem", 0},
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
// DECOMPSTATUS32::DECOMPSTATUS32IMPL

struct DECOMPSTATUS32::DECOMPSTATUS32IMPL
{
    // map virtual address to asm code
    map<ADDR32, ASMCODE32>      mAddrToAsmCode;

    // entrances
    ADDR32SET                   sEntrances;

    // map addr to code function
    map<ADDR32, CODEFUNC32>     mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32 accessors

map<ADDR32, ASMCODE32>& DECOMPSTATUS32::MapAddrToAsmCode()
{
    return m_pImpl->mAddrToAsmCode;
}

ADDR32SET& DECOMPSTATUS32::Entrances()
{
    return m_pImpl->sEntrances;
}

map<ADDR32, CODEFUNC32>& DECOMPSTATUS32::MapAddrToCodeFunc()
{
    return m_pImpl->mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32 const accessors

const map<ADDR32, ASMCODE32>& DECOMPSTATUS32::MapAddrToAsmCode() const
{
    return m_pImpl->mAddrToAsmCode;
}

const ADDR32SET& DECOMPSTATUS32::Entrances() const
{
    return m_pImpl->sEntrances;
}

const map<ADDR32, CODEFUNC32>& DECOMPSTATUS32::MapAddrToCodeFunc() const
{
    return m_pImpl->mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32 dumping

BOOL DECOMPSTATUS32::DumpDisAsm()
{
    printf("### DISASSEMBLY ###\n\n");

	Entrances().Sort();
	const SIZE_T size = Entrances().Size();
    for (SIZE_T i = 0; i < size; i++)
    {
        const CODEFUNC32& cf = MapAddrToCodeFunc()[Entrances()[i]];
        if (cf.Flags() & FF_IGNORE)
            continue;

        printf(";; Function %s @ L%08lX\n", cf.Name().c_str(), cf.Addr());
        if (cf.FuncType() == FT_STDCALL)
        {
            printf("ft = FT_STDCALL, ");
        }
        else if (cf.FuncType() == FT_CDECL)
        {
            printf("ft = FT_CDECL, ");
        }
        else if (cf.FuncType() == FT_JUMPER)
        {
            printf("ft = FT_JUMPER, ");
        }
        else if (cf.FuncType() == FT_APIIMP)
        {
            printf("ft = FT_APIIMP, ");
        }
        else if (cf.Flags() & FF_NOTSTDCALL)
        {
            printf("ft = not __stdcall, ");
        }
        else
        {
            printf("ft = unknown, ");
        }
        if (cf.Flags() & FF_HASSTACKFRAME)
        {
            printf("HasStackFrame, ");
        }
        printf("SizeOfArgs == %d\n", cf.SizeOfArgs());
        DumpDisAsmFunc(Entrances()[i]);

        printf(";; End of Function %s @ L%08lX\n\n",
            cf.Name().c_str(), cf.Addr());
    }

    return TRUE;
}

BOOL DECOMPSTATUS32::DumpDisAsmFunc(ADDR32 func)
{
    map<ADDR32, ASMCODE32>::const_iterator it, end;
    end = MapAddrToAsmCode().end();
    for (it = MapAddrToAsmCode().begin(); it != end; it++)
    {
        const ASMCODE32& ac = it->second;

        if (func != 0 && !ac.Funcs().Contains(func))
            continue;

        printf("L%08lX: ", ac.Addr());

        DumpCodes(ac.Codes(), 32);

        switch (ac.Operands().size())
        {
        case 3:
            printf("%s %s,%s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str(),
                ac.Operand(2)->Text().c_str());
            break;

        case 2:
            printf("%s %s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str());
            break;

        case 1:
            printf("%s %s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str());
            break;

        case 0:
            printf("%s\n", ac.Name().c_str());
            break;
        }
    }

    return TRUE;
}

BOOL DECOMPSTATUS32::DumpDecomp()
{
    // TODO:
    return FALSE;
}

BOOL DECOMPSTATUS32::DumpDecompFunc(ADDR32 func)
{
    // TODO:
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32

DECOMPSTATUS32::DECOMPSTATUS32()
    : m_pImpl(new DECOMPSTATUS32::DECOMPSTATUS32IMPL)
{
}

DECOMPSTATUS32::DECOMPSTATUS32(const DECOMPSTATUS32& status)
    : m_pImpl(new DECOMPSTATUS32::DECOMPSTATUS32IMPL)
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
    delete m_pImpl;
}

VOID DECOMPSTATUS32::Copy(const DECOMPSTATUS32& status)
{
    m_pImpl->mAddrToAsmCode = status.m_pImpl->mAddrToAsmCode;
    Entrances() = status.Entrances();
    m_pImpl->mAddrToCodeFunc = status.m_pImpl->mAddrToCodeFunc;
}

VOID DECOMPSTATUS32::Clear()
{
    m_pImpl->mAddrToAsmCode.clear();
    Entrances().Clear();
    m_pImpl->mAddrToCodeFunc.clear();
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64::DECOMPSTATUS64IMPL

struct DECOMPSTATUS64::DECOMPSTATUS64IMPL
{
    // map virtual address to asm code
    map<ADDR64, ASMCODE64>      mAddrToAsmCode;
    // entrances
    ADDR64SET                   sEntrances;
    // map addr to code function
    map<ADDR64, CODEFUNC64>     mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64 accessors

map<ADDR64, ASMCODE64>& DECOMPSTATUS64::MapAddrToAsmCode()
{
    return m_pImpl->mAddrToAsmCode;
}

ADDR64SET& DECOMPSTATUS64::Entrances()
{
    return m_pImpl->sEntrances;
}

map<ADDR64, CODEFUNC64>& DECOMPSTATUS64::MapAddrToCodeFunc()
{
    return m_pImpl->mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64 const accessors

const map<ADDR64, ASMCODE64>& DECOMPSTATUS64::MapAddrToAsmCode() const
{
    return m_pImpl->mAddrToAsmCode;
}

const ADDR64SET& DECOMPSTATUS64::Entrances() const
{
    return m_pImpl->sEntrances;
}

const map<ADDR64, CODEFUNC64>& DECOMPSTATUS64::MapAddrToCodeFunc() const
{
    return m_pImpl->mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64 dumping

BOOL DECOMPSTATUS64::DumpDisAsm()
{
    printf("### DISASSEMBLY ###\n\n");

    Entrances().Sort();
    const SIZE_T size = Entrances().Size();
    for (SIZE_T i = 0; i < size; i++)
    {
        const CODEFUNC64& cf = MapAddrToCodeFunc()[Entrances()[i]];
        if (cf.Flags() & FF_IGNORE)
            continue;

        printf(";; Function %s @ L%08lX%08lX\n", cf.Name().c_str(),
            HILONG(cf.Addr()), LOLONG(cf.Addr()));
        if (cf.FuncType() == FT_JUMPER)
        {
            printf("ft = FT_JUMPER, ");
        }
        else if (cf.FuncType() == FT_APIIMP)
        {
            printf("ft = FT_APIIMP, ");
        }
        else
        {
            printf("ft = normal, ");
        }
        if (cf.Flags() & FF_HASSTACKFRAME)
        {
            printf("HasStackFrame, ");
        }
        printf("SizeOfArgs == %d\n", cf.SizeOfArgs());
        DumpDisAsmFunc(Entrances()[i]);

        printf(";; End of Function %s @ L%08lX%08lX\n\n", cf.Name().c_str(),
            HILONG(cf.Addr()), LOLONG(cf.Addr()));
    }
    return TRUE;
}

BOOL DECOMPSTATUS64::DumpDisAsmFunc(ADDR64 func)
{
    map<ADDR64, ASMCODE64>::const_iterator it, end;
    end = MapAddrToAsmCode().end();
    for (it = MapAddrToAsmCode().begin(); it != end; it++)
    {
        const ASMCODE64& ac = it->second;

        if (func != 0 && !ac.Funcs().Contains(func))
            continue;

        printf("L%08lX%08lX: ", HILONG(ac.Addr()), LOLONG(ac.Addr()));

        DumpCodes(ac.Codes(), 64);

        switch (ac.Operands().size())
        {
        case 3:
            printf("%s %s,%s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str(),
                ac.Operand(2)->Text().c_str());
            break;

        case 2:
            printf("%s %s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str());
            break;

        case 1:
            printf("%s %s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str());
            break;

        case 0:
            printf("%s\n", ac.Name().c_str());
            break;
        }
    }

    return TRUE;
}

BOOL DECOMPSTATUS64::DumpDecomp()
{
    // TODO:
    return FALSE;
}

BOOL DECOMPSTATUS64::DumpDecompFunc(ADDR64 func)
{
    // TODO:
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64

DECOMPSTATUS64::DECOMPSTATUS64()
	: m_pImpl(new DECOMPSTATUS64::DECOMPSTATUS64IMPL)
{
}

DECOMPSTATUS64::DECOMPSTATUS64(const DECOMPSTATUS64& status)
	: m_pImpl(new DECOMPSTATUS64::DECOMPSTATUS64IMPL)
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
    delete m_pImpl;
}

VOID DECOMPSTATUS64::Copy(const DECOMPSTATUS64& status)
{
    m_pImpl->mAddrToAsmCode = status.m_pImpl->mAddrToAsmCode;
    Entrances() = status.Entrances();
    m_pImpl->mAddrToCodeFunc = status.m_pImpl->mAddrToCodeFunc;
}

VOID DECOMPSTATUS64::Clear()
{
    m_pImpl->mAddrToAsmCode.clear();
    Entrances().Clear();
    m_pImpl->mAddrToCodeFunc.clear();
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int _tmain(int argc, _TCHAR **argv)
{
    puts(cr_logo);

    if (argc != 2)
    {
        fprintf(stderr, "Usage: pedumper exefile.exe\n");
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
            status.DumpDisAsm();
        }
        else if (module.Is32Bit())
        {
            DECOMPSTATUS32 status;
            module.DisAsm32(status);
            status.DumpDisAsm();
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
