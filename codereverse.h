////////////////////////////////////////////////////////////////////////////
// codereverse.h
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
// logo

extern LPCSTR cr_logo;

////////////////////////////////////////////////////////////////////////////

#include "include/cr.h"

////////////////////////////////////////////////////////////////////////////
// ADDR32, ADDR64 (virtual address)

typedef DWORD     ADDR32;
typedef ULONGLONG ADDR64;

////////////////////////////////////////////////////////////////////////////
// VECSET<ITEM_T>

template <typename ITEM_T>
class VECSET
{
public:
    VECSET()
    {
    }

    VECSET(const VECSET<ITEM_T>& vs) : m_items(vs.m_items)
    {
    }

    VECSET& operator=(const VECSET<ITEM_T>& vs)
    {
        m_items = vs.m_items;
        return *this;
    }

    virtual ~VECSET()
    {
    }

    ITEM_T& operator[](SIZE_T index)
    {
        return m_items[index];
    }

    const ITEM_T& operator[](SIZE_T index) const
    {
        return m_items[index];
    }

    SIZE_T Size() const
    {
        return m_items.size();
    }

    bool Empty() const
    {
        return m_items.size() == 0;
    }

    VOID Clear()
    {
        m_items.clear();
    }

    VOID Insert(const ITEM_T& item)
    {
        m_items.push_back(item);
    }

    bool operator==(const VECSET<ITEM_T>& vs) const
    {
        if (m_items.size() != vs.m_items.size())
            return false;

        for (SIZE_T i = 0; i < m_items.size(); i++)
        {
            if (m_items[i] != vs.m_items[i])
                return false;
        }
        return true;
    }

    bool operator!=(const VECSET<ITEM_T>& vs) const
    {
        return !(*this == vs);
    }

    SIZE_T Count(const ITEM_T& item) const
    {
        SIZE_T count = 0;
        for (SIZE_T i = 0; i < m_items.size(); i++)
        {
            if (m_items[i] == item)
                count++;
        }
        return count;
    }

    BOOL Contains(const ITEM_T& item) const
    {
        for (SIZE_T i = 0; i < m_items.size(); i++)
        {
            if (m_items[i] == item)
                return TRUE;
        }
        return FALSE;
    }

    VOID Sort()
    {
        std::sort(m_items.begin(), m_items.end());
    }

public:
    std::vector<ITEM_T> m_items;
};

////////////////////////////////////////////////////////////////////////////
// ADDR32SET, ADDR64SET

typedef VECSET<ADDR32> ADDR32SET;
typedef VECSET<ADDR64> ADDR64SET;

////////////////////////////////////////////////////////////////////////////
// CONDCODE - condition code

enum CONDCODE
{
    C_A, C_AE, C_B, C_BE, C_C, C_E, C_G, C_GE, C_L, C_LE, C_NA, C_NAE,
    C_NB, C_NBE, C_NC, C_NE, C_NG, C_NGE, C_NL, C_NLE, C_NO, C_NP,
    C_NS, C_NZ, C_O, C_P, C_PE, C_PO, C_S, C_Z,
    C_NONE = -1
};

////////////////////////////////////////////////////////////////////////////
// x86 registers

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
    X86_COMPREG32,      // compound registry
    X86_COMPREG64,      // compound registry
    X86_COMPREG128,     // compound registry
    X86_FLAG,           // flag
    X86_REGNONE = -1
};

X86_REGTYPE cr_reg_get_type(LPCSTR name, INT bits);
DWORD       cr_reg_get_size(LPCSTR name, INT bits);

////////////////////////////////////////////////////////////////////////////
// x86 flags

enum X86_FLAGTYPE
{
    X86_FLAG_NONE = 0,
    X86_FLAG_CF = (1 << 0),     // carry flag
    X86_FLAG_PF = (1 << 2),     // parity flag
    X86_FLAG_AF = (1 << 4),     // auxiliary flag
    X86_FLAG_ZF = (1 << 6),     // zero flag
    X86_FLAG_SF = (1 << 7),     // sign flag
    X86_FLAG_TF = (1 << 8),     // trap flag
    X86_FLAG_IF = (1 << 9),     // interrupt enable flag
    X86_FLAG_DF = (1 << 10),    // direction flag
    X86_FLAG_OF = (1 << 11),    // overflow flag
};

struct X86_FLAGS
{
    union
    {
        WORD flags;
        DWORD eflags;
        ULONGLONG rflags;
        struct
        {
            DWORD CF        : 1;    // carry flag
            DWORD ignore1   : 1;
            DWORD PF        : 1;    // parity flag
            DWORD ignore2   : 1;
            DWORD AF        : 1;    // auxiliary flag
            DWORD ignore3   : 1;
            DWORD ZF        : 1;    // zero flag
            DWORD SF        : 1;    // sign flag
            DWORD TF        : 1;    // trap flag
            DWORD IF        : 1;    // interrupt flag
            DWORD DF        : 1;    // direction flag
            DWORD OF        : 1;    // overflow flag
            DWORD ignore4   : 4;
            DWORD ignore5   : 16;
        } flag;
    };
};

X86_FLAGTYPE cr_flag_get_type(LPCSTR name, INT bits);
LPCSTR       cr_flag_get_name(X86_FLAGTYPE type, INT bits);

////////////////////////////////////////////////////////////////////////////
// ASMCODETYPE - assembly code type

enum ASMCODETYPE
{
    ACT_MISC,    // misc
    ACT_JMP,     // jump
    ACT_JCC,     // conditional jump
    ACT_CALL,    // call
    ACT_LOOP,    // loop
    ACT_RETURN,  // ret
    ACT_STACKOP, // stack operation
    ACT_UNKNOWN  // unknown
};

////////////////////////////////////////////////////////////////////////////
// OPERANDTYPE - type of operand

enum OPERANDTYPE
{
    OT_NONE,    // none
    OT_REG,     // registry
    OT_MEMREG,  // memory access by a register
    OT_MEMIMM,  // memory access by an immediate
    OT_MEMEXP,  // memory access by an expression
    OT_IMM,     // immediate
    OT_LABEL,   // label
    OT_API,     // API
    OT_APIIMP   // API import
};

////////////////////////////////////////////////////////////////////////////
// OPERAND - operand

class OPERAND
{
public:
    OPERAND();
    OPERAND(const OPERAND& opr);
    OPERAND& operator=(const OPERAND& opr);
    virtual ~OPERAND();
    VOID Copy(const OPERAND& opr);
    VOID Clear();

public:
    VOID SetAPI(LPCSTR api);
    VOID SetLabel(LPCSTR label);
    VOID SetMemImm(ADDR64 addr);
    VOID SetMemExp(LPCSTR exp_);
    VOID SetImm32(ADDR32 val, BOOL is_signed);
    VOID SetImm64(ADDR64 val, BOOL is_signed);

public:
    // accessors
    string&         Text();
    OPERANDTYPE&    OperandType();
    DWORD&          Size();
    ADDR32&         Value32();
    ADDR64&         Value64();
    string&         Exp();
    string&         DataType();
    // const accessors
    const string&         Text() const;
    const OPERANDTYPE&    OperandType() const;
    const DWORD&          Size() const;
    const ADDR32&         Value32() const;
    const ADDR64&         Value64() const;
    const string&         Exp() const;
    const string&         DataType() const;

protected:
    struct OPERANDIMPL;
    OPERANDIMPL *m_pImpl;
};

////////////////////////////////////////////////////////////////////////////
// ASMCODE32 - assembly code of 32-bit mode

class ASMCODE32
{
public:
    ASMCODE32();
    ASMCODE32(const ASMCODE32& ac);
    ASMCODE32& operator=(const ASMCODE32& ac);
    virtual ~ASMCODE32();
    VOID Copy(const ASMCODE32& ac);
    VOID Clear();

public:
    // accessors
    ADDR32SET&          Funcs();
    ADDR32&             Addr();
    string&             Name();
    vector<OPERAND>&    Operands();
    OPERAND*            Operand(SIZE_T index);
    vector<BYTE>&       Codes();
    ASMCODETYPE&        AsmCodeType();
    CONDCODE&           CondCode();
    // const accessors
    const ADDR32SET&          Funcs() const;
    const ADDR32&             Addr() const;
    const string&             Name() const;
    const vector<OPERAND>&    Operands() const;
    const OPERAND*            Operand(SIZE_T index) const;
    const vector<BYTE>&       Codes() const;
    const ASMCODETYPE&        AsmCodeType() const;
    const CONDCODE&           CondCode() const;

protected:
    struct ASMCODE32IMPL;
    ASMCODE32IMPL *m_pImpl;
};
typedef ASMCODE32 *LPASMCODE32;

////////////////////////////////////////////////////////////////////////////
// ASMCODE64 - assembly code of 64-bit mode

class ASMCODE64
{
public:
    ASMCODE64();
    ASMCODE64(const ASMCODE64& ac);
    ASMCODE64& operator=(const ASMCODE64& ac);
    virtual ~ASMCODE64();
    VOID Copy(const ASMCODE64& ac);
    VOID Clear();

public:
    // accessors
    ADDR64SET&          Funcs();
    ADDR64&             Addr();
    string&             Name();
    vector<OPERAND>&    Operands();
    OPERAND*            Operand(SIZE_T index);
    vector<BYTE>&       Codes();
    ASMCODETYPE&        AsmCodeType();
    CONDCODE&           CondCode();
    // const accessors
    const ADDR64SET&          Funcs() const;
    const ADDR64&             Addr() const;
    const string&             Name() const;
    const vector<OPERAND>&    Operands() const;
    const OPERAND*            Operand(SIZE_T index) const;
    const vector<BYTE>&       Codes() const;
    const ASMCODETYPE&        AsmCodeType() const;
    const CONDCODE&           CondCode() const;

protected:
    struct ASMCODE64IMPL;
    ASMCODE64IMPL *m_pImpl;
};
typedef ASMCODE64 *LPASMCODE64;

////////////////////////////////////////////////////////////////////////////
// FUNCTYPE - function type

enum FUNCTYPE
{
    FT_UNKNOWN,             // unknown type

    FT_CDECL,               // __cdecl
    FT_CDECLVA,             // __cdecl (va_list)

    FT_STDCALL,             // __stdcall

    FT_FASTCALL,            // __fastcall
    FT_MSFASTCALL,          // Microsoft fastcall
    FT_BORFASTCALL,         // Borland fastcall
    FT_WCFASTCALL,          // Watcom fastcall

    FT_THISCALL,            // thiscall
    FT_GNUTHISCALL,         // GNU thiscall
    FT_MSTHISCALL,          // Microsoft thiscall

    FT_JUMPER,              // jumper function

    FT_APIIMP,              // __imp

    FT_64BIT,               // 64-bit function
    FT_64BITVA,             // 64-bit function (va_list)

    FT_INVALID              // invalid function
};

////////////////////////////////////////////////////////////////////////////
// FUNCTIONFLAGS - function flags

enum FUNCTIONFLAGS
{
    FF_NOTSTDCALL               = (1 << 0), // not __stdcall
    FF_DONTDECOMPBUTDISASM      = (1 << 1), // don't decompile but disasm
    FF_IGNORE                   = (1 << 2), // ignore
    FF_HASSTACKFRAME            = (1 << 3)  // has stack frame
};

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32 - code function for 32-bit

class CODEFUNC32
{
public:
    CODEFUNC32();
    CODEFUNC32(const CODEFUNC32& cf);
    CODEFUNC32& operator=(const CODEFUNC32& cf);
    virtual ~CODEFUNC32();
    VOID Copy(const CODEFUNC32& cf);
    VOID Clear();

public:
    // accessors
    ADDR32&             Addr();
    string&             Name();
    FUNCTYPE&           FuncType();
    INT&                SizeOfArgs();
    vector<OPERAND>&    Args();
    DWORD&              Flags();
    string&             ReturnDataType();
    ADDR32SET&          Jumpees();
    ADDR32SET&          Jumpers();
    ADDR32SET&          Callees();
    ADDR32SET&          Callers();
    // const accessors
    const ADDR32&             Addr() const;
    const string&             Name() const;
    const FUNCTYPE&           FuncType() const;
    const INT&                SizeOfArgs() const;
    const vector<OPERAND>&    Args() const;
    const DWORD&              Flags() const;
    const string&             ReturnDataType() const;
    const ADDR32SET&          Jumpees() const;
    const ADDR32SET&          Jumpers() const;
    const ADDR32SET&          Callees() const;
    const ADDR32SET&          Callers() const;

protected:
    struct CODEFUNC32IMPL;
    CODEFUNC32IMPL *m_pImpl;
};

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64 - code function for 64-bit

class CODEFUNC64
{
public:
    CODEFUNC64();
    CODEFUNC64(const CODEFUNC64& cf);
    CODEFUNC64& operator=(const CODEFUNC64& cf);
    virtual ~CODEFUNC64();
    VOID Copy(const CODEFUNC64& cf);
    VOID Clear();

public:
    // accessors
    ADDR64&             Addr();
    string&             Name();
    FUNCTYPE&           FuncType();
    INT&                SizeOfArgs();
    vector<OPERAND>&    Args();
    DWORD&              Flags();
    string&             ReturnDataType();
    ADDR64SET&          Jumpees();
    ADDR64SET&          Jumpers();
    ADDR64SET&          Callees();
    ADDR64SET&          Callers();
    // const accessors
    const ADDR64&             Addr() const;
    const string&             Name() const;
    const FUNCTYPE&           FuncType() const;
    const INT&                SizeOfArgs() const;
    const vector<OPERAND>&    Args() const;
    const DWORD&              Flags() const;
    const string&             ReturnDataType() const;
    const ADDR64SET&          Jumpees() const;
    const ADDR64SET&          Jumpers() const;
    const ADDR64SET&          Callees() const;
    const ADDR64SET&          Callers() const;

protected:
    struct CODEFUNC64IMPL;
    CODEFUNC64IMPL *m_pImpl;
};

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32 - decompilation status for 32-bit

class DECOMPSTATUS32
{
public:
    DECOMPSTATUS32();
    DECOMPSTATUS32(const DECOMPSTATUS32& status);
    DECOMPSTATUS32& operator=(const DECOMPSTATUS32& status);
    virtual ~DECOMPSTATUS32();
    VOID Copy(const DECOMPSTATUS32& status);
    VOID Clear();
    BOOL DumpDisAsm();
    BOOL DumpDisAsmFunc(ADDR32 func);
    BOOL DumpDecomp();
    BOOL DumpDecompFunc(ADDR32 func);

public:
    // accessors
    map<ADDR32, ASMCODE32>&         MapAddrToAsmCode();
    ADDR32SET&                      Entrances();
    map<ADDR32, CODEFUNC32>&        MapAddrToCodeFunc();
    // const accessors
    const map<ADDR32, ASMCODE32>&   MapAddrToAsmCode() const;
    const ADDR32SET&                Entrances() const;
    const map<ADDR32, CODEFUNC32>&  MapAddrToCodeFunc() const;

protected:
    struct DECOMPSTATUS32IMPL;
    DECOMPSTATUS32IMPL* m_pImpl;
};

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64 - decompilation status for 64-bit

class DECOMPSTATUS64
{
public:
    DECOMPSTATUS64();
    DECOMPSTATUS64(const DECOMPSTATUS64& status);
    DECOMPSTATUS64& operator=(const DECOMPSTATUS64& status);
    virtual ~DECOMPSTATUS64();
    VOID Copy(const DECOMPSTATUS64& status);
    VOID Clear();
    BOOL DumpDisAsm();
    BOOL DumpDisAsmFunc(ADDR64 func);
    BOOL DumpDecomp();
    BOOL DumpDecompFunc(ADDR64 func);

public:
    // accessors
    map<ADDR64, ASMCODE64>&         MapAddrToAsmCode();
    ADDR64SET&                      Entrances();
    map<ADDR64, CODEFUNC64>&        MapAddrToCodeFunc();
    // const accessors
    const map<ADDR64, ASMCODE64>&   MapAddrToAsmCode() const;
    const ADDR64SET&                Entrances() const;
    const map<ADDR64, CODEFUNC64>&  MapAddrToCodeFunc() const;

protected:
    struct DECOMPSTATUS64IMPL;
    DECOMPSTATUS64IMPL* m_pImpl;
};

////////////////////////////////////////////////////////////////////////////
