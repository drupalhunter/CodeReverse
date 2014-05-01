#ifndef CODEREVERSE_H_
#define CODEREVERSE_H_

////////////////////////////////////////////////////////////////////////////
// CodeReverse.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////
// logo

extern const char * const cr_logo;

////////////////////////////////////////////////////////////////////////////
// LOLONG, HILONG, MAKELONGLONG

#ifndef LOLONG
    #define LOLONG(dwl) static_cast<DWORD>(dwl)
#endif
#ifndef HILONG
    #define HILONG(dwl) static_cast<DWORD>(((dwl) >> 32) & 0xFFFFFFFF)
#endif
#ifndef MAKELONGLONG
    #define MAKELONGLONG(lo,hi) \
        ((static_cast<DWORDLONG>(hi) << 32) | static_cast<DWORD>(lo))
#endif

////////////////////////////////////////////////////////////////////////////
// CR_Addr32, CR_Addr64 (virtual address)

typedef unsigned long       CR_Addr32;
typedef unsigned long long  CR_Addr64;

////////////////////////////////////////////////////////////////////////////
// CR_TriBool - tri-state logical value

class CR_TriBool
{
public:
    CR_TriBool();
    CR_TriBool(BOOL b);
    CR_TriBool(const CR_TriBool& tb);
    virtual ~CR_TriBool();
    CR_TriBool& operator=(BOOL b);
    CR_TriBool& operator=(const CR_TriBool& tb);
    bool operator==(const CR_TriBool& tb) const;
    bool operator!=(const CR_TriBool& tb) const;
    void clear();

    BOOL CanBeTrue() const;
    BOOL CanBeFalse() const;
    BOOL IsUnknown() const;

    CR_TriBool& IsFalse(const CR_TriBool& tb);
    CR_TriBool& IsTrue(const CR_TriBool& tb);
    CR_TriBool& LogicalAnd(const CR_TriBool& tb1, const CR_TriBool& tb2);
    CR_TriBool& LogicalOr(const CR_TriBool& tb1, const CR_TriBool& tb2);
    CR_TriBool& LogicalNot(const CR_TriBool& tb1);
    CR_TriBool& Equal(const CR_TriBool& tb1, const CR_TriBool& tb2);
    CR_TriBool& NotEqual(const CR_TriBool& tb1, const CR_TriBool& tb2);

public:
    enum {
        TB_UNKNOWN, TB_FALSE, TB_TRUE
    } m_value;
};

////////////////////////////////////////////////////////////////////////////
// CR_VecSet<ITEM_T> -- vector and set

template <typename ITEM_T>
class CR_VecSet : public vector<ITEM_T>
{
public:
    CR_VecSet()
    {
    }

    CR_VecSet(const CR_VecSet<ITEM_T>& vs) : vector<ITEM_T>(vs)
    {
    }

    CR_VecSet& operator=(const CR_VecSet<ITEM_T>& vs)
    {
        this->assign(vs.begin(), vs.end());
        return *this;
    }

    virtual ~CR_VecSet()
    {
    }

    void insert(const ITEM_T& item)
    {
        this->push_back(item);
    }

    bool Contains(const ITEM_T& item) const
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++)
        {
            if (this->at(i) == item)
                return true;
        }
        return false;
    }

    std::size_t Find(const ITEM_T& item) const
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++)
        {
            if (this->at(i) == item)
                return i;
        }
        return static_cast<std::size_t>(-1);
    }

    std::size_t Insert(const ITEM_T& item)
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++)
        {
            if (this->at(i) == item)
                return i;
        }
        this->push_back(item);
        return this->size() - 1;
    }

    std::size_t count(const ITEM_T& item) const
    {
        std::size_t count = 0;
        for (std::size_t i : *this)
        {
            if (this->at(i) == item)
                count++;
        }
        return count;
    }

    void sort()
    {
        std::sort(this->begin(), this->end());
    }

    void unique()
    {
        std::unique(this->begin(), this->end());
    }

    void erase(const ITEM_T& item)
    {
        std::size_t i, j;
        const std::size_t count = this->size();
        for (i = j = 0; i < count; i++)
        {
            if (this->at(i) != item)
            {
                this->at(j++) = this->at(i);
            }
        }
        if (i != j)
            this->resize(j);
    }
};

namespace std
{
    template <typename ITEM_T>
    inline void swap(CR_VecSet<ITEM_T>& vs1, CR_VecSet<ITEM_T>& vs2)
    {
        vs1.swap(vs2);
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Addr32Set, CR_Addr64Set

typedef CR_VecSet<CR_Addr32> CR_Addr32Set;
typedef CR_VecSet<CR_Addr64> CR_Addr64Set;

////////////////////////////////////////////////////////////////////////////
// CR_CondCode - condition code

enum CR_CondCode
{
    C_A, C_AE, C_B, C_BE, C_C, C_E, C_G, C_GE, C_L, C_LE, C_NA, C_NAE,
    C_NB, C_NBE, C_NC, C_NE, C_NG, C_NGE, C_NL, C_NLE, C_NO, C_NP,
    C_NS, C_NZ, C_O, C_P, C_PE, C_PO, C_S, C_Z,
    C_NONE = -1
};

////////////////////////////////////////////////////////////////////////////
// x86 registers

enum CR_RegType
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

CR_RegType  cr_reg_get_type(const char *name, INT bits);
DWORD       cr_reg_get_size(const char *name, INT bits);
BOOL        cr_reg_in_reg(const char *reg1, const char *reg2);
BOOL        cr_reg_overlaps_reg(const char *reg1, const char *reg2);

////////////////////////////////////////////////////////////////////////////
// x86 flags

enum CR_FlagType
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

CR_FlagType cr_flag_get_type(const char *name, INT bits);
const char * cr_flag_get_name(CR_FlagType type, INT bits);

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsnType - assembly code instruction type

enum CR_CodeInsnType
{
    CIT_MISC,    // misc
    CIT_JMP,     // jump
    CIT_JCC,     // conditional jump
    CIT_CALL,    // call
    CIT_LOOP,    // loop
    CIT_RETURN,  // ret
    CIT_STACKOP, // stack operation
    CIT_UNKNOWN  // unknown
};

////////////////////////////////////////////////////////////////////////////
// CR_OperandType - type of operand

enum CR_OperandType
{
    OT_NONE,    // none
    OT_REG,     // registry
    OT_MEMREG,  // memory access by a register
    OT_MEMIMM,  // memory access by an immediate
    OT_MEMEXP,  // memory access by an expression
    OT_IMM,     // immediate
    OT_API      // API
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
    void Copy(const OPERAND& opr);
    void clear();
    bool operator==(const OPERAND& opr) const;
    bool operator!=(const OPERAND& opr) const;

public:
    void SetReg(const char *name);
    void SetAPI(const char *api);
    void SetLabel(const char *label);
    void SetMemImm(CR_Addr64 addr);
    void SetMemExp(const char *exp_);
    void SetImm32(CR_Addr32 val, BOOL is_signed);
    void SetImm64(CR_Addr64 val, BOOL is_signed);

public:
    // accessors
    string&                 Text();
    CR_OperandType&         OperandType();
    DWORD&                  Size();
    CR_Addr32&              Value32();
    CR_Addr64&              Value64();
    string&                 Exp();
    string&                 DataType();
    CR_TriBool&             IsInteger();
    CR_TriBool&             IsPointer();
    CR_TriBool&             IsFunction();
    // const accessors
    const string&           Text() const;
    const CR_OperandType&   OperandType() const;
    const DWORD&            Size() const;
    const CR_Addr32&        Value32() const;
    const CR_Addr64&        Value64() const;
    const string&           Exp() const;
    const string&           DataType() const;
    const CR_TriBool&       IsInteger() const;
    const CR_TriBool&       IsPointer() const;
    const CR_TriBool&       IsFunction() const;

protected:
    string                  m_text;
    CR_OperandType          m_ot;
    DWORD                   m_size;
    union
    {
        CR_Addr64           m_value64;
        CR_Addr32           m_value32;
    };
    string                  m_exp;
    string                  m_datatype;
    CR_TriBool              m_is_integer;
    CR_TriBool              m_is_pointer;
    CR_TriBool              m_is_function;
};

////////////////////////////////////////////////////////////////////////////
// OPERANDSET - set of operands

typedef CR_VecSet<OPERAND> OPERANDSET;

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn32 - assembly code of one 32-bit instruction

class CR_CodeInsn32
{
public:
    CR_CodeInsn32();
    CR_CodeInsn32(const CR_CodeInsn32& ac);
    CR_CodeInsn32& operator=(const CR_CodeInsn32& ac);
    virtual ~CR_CodeInsn32();
    void clear();

public:
    // accessors
    CR_Addr32&              Addr();         // address of assembly
    string&                 Name();         // name of instruction
    OPERANDSET&             Operands();     // operands
    OPERAND*                Operand(std::size_t index);
    vector<BYTE>&           Codes();        // code of instruction
    CR_CodeInsnType&        CodeInsnType(); // type of instruction
    CR_CondCode&            CondCode();     // condition type
    CR_Addr32Set&           FuncAddrs();
    // const accessors
    const CR_Addr32&        Addr() const;
    const string&           Name() const;
    const OPERANDSET&       Operands() const;
    const OPERAND*          Operand(std::size_t index) const;
    const vector<BYTE>&     Codes() const;
    const CR_CodeInsnType&  CodeInsnType() const;
    const CR_CondCode&      CondCode() const;
    const CR_Addr32Set&     FuncAddrs() const;

protected:
    CR_Addr32               m_addr;
    string                  m_name;
    OPERANDSET              m_operands;
    std::vector<BYTE>       m_codes;
    CR_CodeInsnType         m_cit;
    CR_CondCode             m_ccode;
    CR_Addr32Set            m_funcaddrs;

    void Copy(const CR_CodeInsn32& ac);
};
typedef CR_CodeInsn32 *LPCODEINSN32;

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn64 - assembly code of one 64-bit instruction

class CR_CodeInsn64
{
public:
    CR_CodeInsn64();
    CR_CodeInsn64(const CR_CodeInsn64& ac);
    CR_CodeInsn64& operator=(const CR_CodeInsn64& ac);
    virtual ~CR_CodeInsn64();
    void clear();

public:
    // accessors
    CR_Addr64&              Addr();         // address of assembly
    string&                 Name();         // name of instruction
    OPERANDSET&             Operands();     // operands
    OPERAND*                Operand(std::size_t index);
    vector<BYTE>&           Codes();        // code of instruction
    CR_CodeInsnType&        CodeInsnType(); // type of instruction
    CR_CondCode&            CondCode();     // condition type
    CR_Addr64Set&           FuncAddrs();
    // const accessors
    const CR_Addr64&        Addr() const;
    const string&           Name() const;
    const OPERANDSET&       Operands() const;
    const OPERAND*          Operand(std::size_t index) const;
    const vector<BYTE>&     Codes() const;
    const CR_CodeInsnType&  CodeInsnType() const;
    const CR_CondCode&      CondCode() const;
    const CR_Addr64Set&     FuncAddrs() const;

protected:
    CR_Addr64               m_addr;
    string                  m_name;
    OPERANDSET              m_operands;
    std::vector<BYTE>       m_codes;
    CR_CodeInsnType         m_cit;
    CR_CondCode             m_ccode;
    CR_Addr64Set            m_funcaddrs;

    void Copy(const CR_CodeInsn64& ac);
};
typedef CR_CodeInsn64 *LPCODEINSN64;

////////////////////////////////////////////////////////////////////////////
// CR_Block32 - a node of control flow graph (CFG) for 32-bit mode

class CR_Block32
{
public:
    CR_Block32();
    CR_Block32(const CR_Block32& b);
    void operator=(const CR_Block32& b);
    virtual ~CR_Block32();
    void clear();

public:
    // accessors
    CR_Addr32&                      Addr();
    CR_VecSet<CR_CodeInsn32>&       AsmCodes();
    CR_Block32*&                    NextBlock1();
    CR_Block32*&                    NextBlock2();
    CR_Addr32&                      NextAddr1();
    CR_Addr32&                      NextAddr2();
    // const accessors
    const CR_Addr32&                Addr() const;
    const CR_VecSet<CR_CodeInsn32>& AsmCodes() const;
    CR_Block32*&                    NextBlock1() const;
    CR_Block32*&                    NextBlock2() const;
    const CR_Addr32&                NextAddr1() const;
    const CR_Addr32&                NextAddr2() const;

protected:
    CR_Addr32                       m_addr;
    CR_VecSet<CR_CodeInsn32>        m_asmcodes;
    CR_Block32 *                    m_nextblock1;
    CR_Block32 *                    m_nextblock2;
    CR_Addr32                       m_nextaddr1;
    CR_Addr32                       m_nextaddr2;

    void Copy(const CR_Block32& b);
};

////////////////////////////////////////////////////////////////////////////
// CR_Block64 - a node of control flow graph (CFG) for 64-bit mode

class CR_Block64
{
public:
    CR_Block64();
    CR_Block64(const CR_Block64& b);
    void operator=(const CR_Block64& b);
    virtual ~CR_Block64();
    void clear();

public:
    // accessors
    CR_Addr64&                      Addr();
    CR_VecSet<CR_CodeInsn64>&       AsmCodes();
    CR_Block64*&                    NextBlock1();
    CR_Block64*&                    NextBlock2();
    CR_Addr64&                      NextAddr1();
    CR_Addr64&                      NextAddr2();
    // const accessors
    const CR_Addr64&                Addr() const;
    const CR_VecSet<CR_CodeInsn64>& AsmCodes() const;
    CR_Block64*&                    NextBlock1() const;
    CR_Block64*&                    NextBlock2() const;
    const CR_Addr64&                NextAddr1() const;
    const CR_Addr64&                NextAddr2() const;

protected:
    CR_Addr64                       m_addr;
    CR_VecSet<CR_CodeInsn64>        m_asmcodes;
    CR_Block64 *                    m_nextblock1;
    CR_Block64 *                    m_nextblock2;
    CR_Addr64                       m_nextaddr1;
    CR_Addr64                       m_nextaddr2;

    void Copy(const CR_Block64& b);
};

////////////////////////////////////////////////////////////////////////////
// CR_FuncType - function type

enum CR_FuncType
{
    FT_UNKNOWN,             // unknown type

    FT_CDECL,               // __cdecl
    FT_CDECLVA,             // __cdecl (varargs)

    FT_STDCALL,             // __stdcall

    FT_FASTCALL,            // __fastcall
    FT_MSFASTCALL,          // Microsoft fastcall
    FT_BORFASTCALL,         // Borland fastcall
    FT_WCFASTCALL,          // Watcom fastcall

    FT_THISCALL,            // thiscall
    FT_GNUTHISCALL,         // GNU thiscall
    FT_MSTHISCALL,          // Microsoft thiscall

    FT_JUMPER,              // jumper function

    FT_64BIT,               // 64-bit function
    FT_64BITVA,             // 64-bit function (varargs)

    FT_INVALID              // invalid function
};

////////////////////////////////////////////////////////////////////////////
// CR_FuncFlags - function flags

enum CR_FuncFlags
{
    FF_NOTSTDCALL               = (1 << 0), // not __stdcall
    FF_DONTDECOMPBUTDISASM      = (1 << 1), // don't decompile but disasm
    FF_IGNORE                   = (1 << 2), // ignore
    FF_HASSTACKFRAME            = (1 << 3), // has stack frame
    FF_FUNCINFUNC               = (1 << 4), // function in function
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 - code function for 32-bit

class CR_CodeFunc32
{
public:
    CR_CodeFunc32();
    CR_CodeFunc32(const CR_CodeFunc32& cf);
    CR_CodeFunc32& operator=(const CR_CodeFunc32& cf);
    virtual ~CR_CodeFunc32();
    void Copy(const CR_CodeFunc32& cf);
    void clear();

public:
    // accessors
    CR_Addr32&                          Addr();
    string&                             Name();
    CR_FuncType&                        FuncType();
    INT&                                SizeOfStackArgs();
    OPERANDSET&                         Args();
    DWORD&                              Flags();
    string&                             ReturnDataType();
    CR_Addr32Set&                       Jumpees();
    CR_Addr32Set&                       Jumpers();
    CR_Addr32Set&                       Callees();
    CR_Addr32Set&                       Callers();
    CR_VecSet<CR_Block32>&              Blocks();
    CR_Block32*                         FindBlockOfAddr(CR_Addr32 addr);
    // const accessors
    const CR_Addr32&                    Addr() const;
    const string&                       Name() const;
    const CR_FuncType&                  FuncType() const;
    const INT&                          SizeOfStackArgs() const;
    const OPERANDSET&                   Args() const;
    const DWORD&                        Flags() const;
    const string&                       ReturnDataType() const;
    const CR_Addr32Set&                 Jumpees() const;
    const CR_Addr32Set&                 Jumpers() const;
    const CR_Addr32Set&                 Callees() const;
    const CR_Addr32Set&                 Callers() const;
    const CR_VecSet<CR_Block32>&        Blocks() const;
    const CR_Block32*                   FindBlockOfAddr(CR_Addr32 addr) const;

protected:
    CR_Addr32                           m_addr;
    string                              m_name;
    CR_FuncType                         m_ft;
    INT                                 m_SizeOfStackArgs;
    OPERANDSET                          m_args;
    DWORD                               m_flags;
    string                              m_returndatatype;
    CR_Addr32Set                        m_jumpees;
    CR_Addr32Set                        m_jumpers;
    CR_Addr32Set                        m_callees;
    CR_Addr32Set                        m_callers;
    CR_VecSet<CR_Block32>               m_blocks;
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 - code function for 64-bit

class CR_CodeFunc64
{
public:
    CR_CodeFunc64();
    CR_CodeFunc64(const CR_CodeFunc64& cf);
    CR_CodeFunc64& operator=(const CR_CodeFunc64& cf);
    virtual ~CR_CodeFunc64();
    void Copy(const CR_CodeFunc64& cf);
    void clear();

public:
    // accessors
    CR_Addr64&                          Addr();
    string&                             Name();
    CR_FuncType&                        FuncType();
    INT&                                SizeOfStackArgs();
    OPERANDSET&                         Args();
    DWORD&                              Flags();
    string&                             ReturnDataType();
    CR_Addr64Set&                       Jumpees();
    CR_Addr64Set&                       Jumpers();
    CR_Addr64Set&                       Callees();
    CR_Addr64Set&                       Callers();
    CR_VecSet<CR_Block64>&              Blocks();
    CR_Block64*                         FindBlockOfAddr(CR_Addr64 addr);
    // const accessors
    const CR_Addr64&                    Addr() const;
    const string&                       Name() const;
    const CR_FuncType&                  FuncType() const;
    const INT&                          SizeOfStackArgs() const;
    const OPERANDSET&                   Args() const;
    const DWORD&                        Flags() const;
    const string&                       ReturnDataType() const;
    const CR_Addr64Set&                 Jumpees() const;
    const CR_Addr64Set&                 Jumpers() const;
    const CR_Addr64Set&                 Callees() const;
    const CR_Addr64Set&                 Callers() const;
    const CR_VecSet<CR_Block64>&        Blocks() const;
    const CR_Block64*                   FindBlockOfAddr(CR_Addr64 addr) const;

protected:
    CR_Addr64                           m_addr;
    string                              m_name;
    CR_FuncType                         m_ft;
    INT                                 m_SizeOfStackArgs;
    OPERANDSET                          m_args;
    DWORD                               m_flags;
    string                              m_returndatatype;
    CR_Addr64Set                        m_jumpees;
    CR_Addr64Set                        m_jumpers;
    CR_Addr64Set                        m_callees;
    CR_Addr64Set                        m_callers;
    CR_VecSet<CR_Block64>               m_blocks;
};

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32 - decompilation status for 32-bit

class CR_DecompStatus32
{
public:
    CR_DecompStatus32();
    CR_DecompStatus32(const CR_DecompStatus32& status);
    CR_DecompStatus32& operator=(const CR_DecompStatus32& status);
    virtual ~CR_DecompStatus32();
    void Copy(const CR_DecompStatus32& status);
    void clear();

public:
    void MapAddrToAsmCode(CR_Addr32 addr, const CR_CodeInsn32& ac);
    void MapAddrToCodeFunc(CR_Addr32 addr, const CR_CodeFunc32& cf);
    BOOL AnalyzeCFG();

public:
    // accessors
    map<CR_Addr32, CR_CodeInsn32>&          MapAddrToAsmCode();
    CR_Addr32Set&                           Entrances();
    map<CR_Addr32, CR_CodeFunc32>&          MapAddrToCodeFunc();
    CR_CodeInsn32 *                         MapAddrToAsmCode(CR_Addr32 addr);
    CR_CodeFunc32 *                         MapAddrToCodeFunc(CR_Addr32 addr);
    // const accessors
    const map<CR_Addr32, CR_CodeInsn32>&    MapAddrToAsmCode() const;
    const CR_Addr32Set&                     Entrances() const;
    const map<CR_Addr32, CR_CodeFunc32>&    MapAddrToCodeFunc() const;
    const CR_CodeInsn32 *                   MapAddrToAsmCode(CR_Addr32 addr) const;
    const CR_CodeFunc32 *                   MapAddrToCodeFunc(CR_Addr32 addr) const;

protected:
    BOOL AnalyzeFuncCFGStage1(CR_Addr32 func, CR_Addr32 addr);
    BOOL AnalyzeFuncCFGStage2(CR_Addr32 func);

protected:
    // map virtual address to asm code
    map<CR_Addr32, CR_CodeInsn32>           m_mAddrToAsmCode;
    // entrances
    CR_Addr32Set                            m_sEntrances;
    // map addr to code function
    map<CR_Addr32, CR_CodeFunc32>           m_mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64 - decompilation status for 64-bit

class CR_DecompStatus64
{
public:
    CR_DecompStatus64();
    CR_DecompStatus64(const CR_DecompStatus64& status);
    CR_DecompStatus64& operator=(const CR_DecompStatus64& status);
    virtual ~CR_DecompStatus64();
    void Copy(const CR_DecompStatus64& status);
    void clear();

public:
    void MapAddrToAsmCode(CR_Addr64 addr, const CR_CodeInsn64& ac);
    void MapAddrToCodeFunc(CR_Addr64 addr, const CR_CodeFunc64& cf);
    BOOL AnalyzeCFG();

public:
    // accessors
    map<CR_Addr64, CR_CodeInsn64>&          MapAddrToAsmCode();
    CR_Addr64Set&                           Entrances();
    map<CR_Addr64, CR_CodeFunc64>&          MapAddrToCodeFunc();
    CR_CodeInsn64 *                         MapAddrToAsmCode(CR_Addr64 addr);
    CR_CodeFunc64 *                         MapAddrToCodeFunc(CR_Addr64 addr);
    // const accessors
    const map<CR_Addr64, CR_CodeInsn64>&    MapAddrToAsmCode() const;
    const CR_Addr64Set&                     Entrances() const;
    const map<CR_Addr64, CR_CodeFunc64>&    MapAddrToCodeFunc() const;
    const CR_CodeInsn64 *                   MapAddrToAsmCode(CR_Addr64 addr) const;
    const CR_CodeFunc64 *                   MapAddrToCodeFunc(CR_Addr64 addr) const;

protected:
    BOOL AnalyzeFuncCFGStage1(CR_Addr64 func, CR_Addr64 addr);
    BOOL AnalyzeFuncCFGStage2(CR_Addr64 func);

protected:
    // map virtual address to asm code
    map<CR_Addr64, CR_CodeInsn64>           m_mAddrToAsmCode;
    // entrances
    CR_Addr64Set                            m_sEntrances;
    // map addr to code function
    map<CR_Addr64, CR_CodeFunc64>           m_mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////

// inline functions
#include "CodeReverse_inl.h"

#endif  // ndef CODEREVERSE_H_
