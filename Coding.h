#ifndef CODING_H_
#define CODING_H_

////////////////////////////////////////////////////////////////////////////
// Coding.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
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
// CR_FuncType - function type

enum CR_FuncType
{
    FT_UNKNOWN,             // unknown type

    FT_CDECL,               // __cdecl
    FT_STDCALL,             // __stdcall
    FT_FASTCALL,            // __fastcall
    FT_THISCALL,            // thiscall

    FT_64BITFUNC,           // 64-bit function

    FT_JUMPERFUNC           // jumper function
};

////////////////////////////////////////////////////////////////////////////
// x86 registers

enum CR_RegType
{
    cr_x86_CRREG = 0,
    cr_x86_DRREG,
    cr_x86_FPUREG,
    cr_x86_MMXREG,
    cr_x86_REG8,
    cr_x86_REG8X,
    cr_x86_REG16,
    cr_x86_REG32,
    cr_x86_REG64,
    cr_x86_SEGREG,
    cr_x86_XMMREG,
    cr_x86_YMMREG,
    cr_x86_COMPREG32,      // compound registry
    cr_x86_COMPREG64,      // compound registry
    cr_x86_COMPREG128,     // compound registry
    cr_x86_FLAG,           // flag
    cr_x86_REGNONE = -1
};

CR_RegType  CrRegGetType(const char *name, int bits);
DWORD       CrRegGetSize(const char *name, int bits);
BOOL        CrRegInReg(const char *reg1, const char *reg2);
BOOL        CrRegOverlapsReg(const char *reg1, const char *reg2);

////////////////////////////////////////////////////////////////////////////
// x86 flags

enum CR_FlagType
{
    cr_x86_FLAG_NONE = 0,
    cr_x86_FLAG_CF = (1 << 0),     // carry flag
    cr_x86_FLAG_PF = (1 << 2),     // parity flag
    cr_x86_FLAG_AF = (1 << 4),     // auxiliary flag
    cr_x86_FLAG_ZF = (1 << 6),     // zero flag
    cr_x86_FLAG_SF = (1 << 7),     // sign flag
    cr_x86_FLAG_TF = (1 << 8),     // trap flag
    cr_x86_FLAG_IF = (1 << 9),     // interrupt enable flag
    cr_x86_FLAG_DF = (1 << 10),    // direction flag
    cr_x86_FLAG_OF = (1 << 11),    // overflow flag
};

struct CR_X86Flags
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

CR_FlagType CrFlagGetType(const char *name, int bits);
const char * CrFlagGetName(CR_FlagType type, int bits);

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
    OT_MEMEXPR, // memory access by an expression
    OT_IMM,     // immediate
    OT_API      // API
};

////////////////////////////////////////////////////////////////////////////
// CR_Operand - operand

class CR_Operand
{
public:
    CR_Operand();
    CR_Operand(const CR_Operand& opr);
    void operator=(const CR_Operand& opr);
    virtual ~CR_Operand();
    void Copy(const CR_Operand& opr);
    void clear();
    bool operator==(const CR_Operand& opr) const;
    bool operator!=(const CR_Operand& opr) const;

public:
    void SetReg(const char *name);
    void SetAPI(const char *api);
    void SetLabel(const char *label);
    void SetMemImm(CR_Addr64 addr);
    void SetMemExpr(const char *expr);
    void SetImm32(CR_Addr32 val, BOOL is_signed);
    void SetImm64(CR_Addr64 val, BOOL is_signed);
    void ParseText(int bits);

public:
    // accessors
    CR_String&              Text();
    CR_OperandType&         OperandType();
    DWORD&                  Size();
    CR_Addr32&              Value32();
    CR_Addr64&              Value64();
    CR_String&              MemExpr();
    CR_TriBool&             IsInteger();
    CR_TriBool&             IsPointer();
    CR_TriBool&             IsFunction();
    // const accessors
    const CR_String&        Text() const;
    const CR_OperandType&   OperandType() const;
    const DWORD&            Size() const;
    const CR_Addr32&        Value32() const;
    const CR_Addr64&        Value64() const;
    const CR_String&        MemExpr() const;
    const CR_TriBool&       IsInteger() const;
    const CR_TriBool&       IsPointer() const;
    const CR_TriBool&       IsFunction() const;

protected:
    CR_String               m_text;
    CR_OperandType          m_ot;
    DWORD                   m_size;
    union
    {
        CR_Addr64           m_value64;
        CR_Addr32           m_value32;
    };
    CR_String               m_memexpr;
    CR_TriBool              m_is_integer;
    CR_TriBool              m_is_pointer;
    CR_TriBool              m_is_function;
};

////////////////////////////////////////////////////////////////////////////
// CR_OperandSet - set of operands

typedef CR_DeqSet<CR_Operand> CR_OperandSet;

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn32 - assembly code of one 32-bit instruction

class CR_CodeInsn32
{
public:
    CR_CodeInsn32();
    CR_CodeInsn32(const CR_CodeInsn32& ac);
    void operator=(const CR_CodeInsn32& ac);
    virtual ~CR_CodeInsn32();
    void clear();

public:
    // accessors
    CR_Addr32&                  Addr();         // address of assembly
    CR_String&                  Name();         // name of instruction
    CR_OperandSet&              Operands();     // operands
    CR_Operand*                 Operand(std::size_t index);
    CR_Binary&                  Codes();        // code of instruction
    CR_CodeInsnType&            CodeInsnType(); // type of instruction
    CR_CondCode&                CondCode();     // condition type
    CR_Addr32Set&               FuncAddrs();
    // const accessors
    const CR_Addr32&            Addr() const;
    const CR_String&            Name() const;
    const CR_OperandSet&        Operands() const;
    const CR_Operand*           Operand(std::size_t index) const;
    const CR_Binary&            Codes() const;
    const CR_CodeInsnType&      CodeInsnType() const;
    const CR_CondCode&          CondCode() const;
    const CR_Addr32Set&         FuncAddrs() const;

protected:
    CR_Addr32                   m_addr;
    CR_String                   m_name;
    CR_OperandSet               m_operands;
    CR_Binary                   m_codes;
    CR_CodeInsnType             m_cit;
    CR_CondCode                 m_ccode;
    CR_Addr32Set                m_funcaddrs;

    void Copy(const CR_CodeInsn32& ac);
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn64 - assembly code of one 64-bit instruction

class CR_CodeInsn64
{
public:
    CR_CodeInsn64();
    CR_CodeInsn64(const CR_CodeInsn64& ac);
    void operator=(const CR_CodeInsn64& ac);
    virtual ~CR_CodeInsn64();
    void clear();

public:
    // accessors
    CR_Addr64&                  Addr();         // address of assembly
    CR_String&                  Name();         // name of instruction
    CR_OperandSet&              Operands();     // operands
    CR_Operand*                 Operand(std::size_t index);
    CR_Binary&                  Codes();        // code of instruction
    CR_CodeInsnType&            CodeInsnType(); // type of instruction
    CR_CondCode&                CondCode();     // condition type
    CR_Addr64Set&               FuncAddrs();
    // const accessors
    const CR_Addr64&            Addr() const;
    const CR_String&            Name() const;
    const CR_OperandSet&        Operands() const;
    const CR_Operand*           Operand(std::size_t index) const;
    const CR_Binary&            Codes() const;
    const CR_CodeInsnType&      CodeInsnType() const;
    const CR_CondCode&          CondCode() const;
    const CR_Addr64Set&         FuncAddrs() const;

protected:
    CR_Addr64                   m_addr;
    CR_String                   m_name;
    CR_OperandSet               m_operands;
    CR_Binary                   m_codes;
    CR_CodeInsnType             m_cit;
    CR_CondCode                 m_ccode;
    CR_Addr64Set                m_funcaddrs;

    void Copy(const CR_CodeInsn64& ac);
};

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
    CR_DeqSet<CR_CodeInsn32>&       AsmCodes();
    CR_Block32*&                    NextBlock1();
    CR_Block32*&                    NextBlock2();
    CR_Addr32&                      NextAddr1();
    CR_Addr32&                      NextAddr2();
    // const accessors
    const CR_Addr32&                Addr() const;
    const CR_DeqSet<CR_CodeInsn32>& AsmCodes() const;
    CR_Block32*&                    NextBlock1() const;
    CR_Block32*&                    NextBlock2() const;
    const CR_Addr32&                NextAddr1() const;
    const CR_Addr32&                NextAddr2() const;

protected:
    CR_Addr32                       m_addr;
    CR_DeqSet<CR_CodeInsn32>        m_asmcodes;
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
    CR_DeqSet<CR_CodeInsn64>&       AsmCodes();
    CR_Block64*&                    NextBlock1();
    CR_Block64*&                    NextBlock2();
    CR_Addr64&                      NextAddr1();
    CR_Addr64&                      NextAddr2();
    // const accessors
    const CR_Addr64&                Addr() const;
    const CR_DeqSet<CR_CodeInsn64>& AsmCodes() const;
    CR_Block64*&                    NextBlock1() const;
    CR_Block64*&                    NextBlock2() const;
    const CR_Addr64&                NextAddr1() const;
    const CR_Addr64&                NextAddr2() const;

protected:
    CR_Addr64                       m_addr;
    CR_DeqSet<CR_CodeInsn64>        m_asmcodes;
    CR_Block64 *                    m_nextblock1;
    CR_Block64 *                    m_nextblock2;
    CR_Addr64                       m_nextaddr1;
    CR_Addr64                       m_nextaddr2;

    void Copy(const CR_Block64& b);
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeByte

class CR_CodeByte
{
public:
    CR_CodeByte();
    CR_CodeByte(const CR_CodeByte& cb);
    void operator=(const CR_CodeByte& cb);
    virtual ~CR_CodeByte();

          CR_String&        Expr();
    const CR_String&        Expr() const;
          CR_TriBool&       IsConst();
    const CR_TriBool&       IsConst() const;
          CR_TriBool&       IsInput();
    const CR_TriBool&       IsInput() const;
          CR_TriBool&       IsOutput();
    const CR_TriBool&       IsOutput() const;
          CR_TriBool&       IsInteger();
    const CR_TriBool&       IsInteger() const;
          CR_TriBool&       IsPointer();
    const CR_TriBool&       IsPointer() const;
          CR_TriBool&       IsFunction();
    const CR_TriBool&       IsFunction() const;

protected:
    CR_TypeSet              m_types;
    CR_StringSet            m_names;
    CR_DataByte             m_data;
    CR_String               m_expr;

    CR_TriBool              m_is_const;
    CR_TriBool              m_is_input;
    CR_TriBool              m_is_output;
    CR_TriBool              m_is_integer;
    CR_TriBool              m_is_pointer;
    CR_TriBool              m_is_function;
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeBinary

class CR_CodeBinary
{
public:
    CR_CodeBinary();
    CR_CodeBinary(const CR_CodeBinary& bin);
    void operator=(const CR_CodeBinary& bin);
    virtual ~CR_CodeBinary();

    bool empty() const;
    std::size_t size() const;
    void resize(std::size_t siz);

          CR_DeqSet<CR_CodeByte>& CodeBytes();
    const CR_DeqSet<CR_CodeByte>& CodeBytes() const;
          CR_DeqSet<CR_DataByte>& DataBytes();
    const CR_DeqSet<CR_DataByte>& DataBytes() const;

          CR_DataByte *Data();
    const CR_DataByte *Data() const;

    void Append(const CR_CodeBinary& cs);
    void MergeAt(std::size_t index, const CR_CodeBinary& cs);

          CR_CodeByte& CodeByteAt(std::size_t index);
    const CR_CodeByte& CodeByteAt(std::size_t index) const;

          CR_DataByte& DataByteAt(std::size_t index);
    const CR_DataByte& DataByteAt(std::size_t index) const;

          CR_TypeSet& TypesAt(std::size_t index);
    const CR_TypeSet& TypesAt(std::size_t index) const;

          CR_StringSet& NamesAt(std::size_t index);
    const CR_StringSet& NamesAt(std::size_t index) const;

protected:
    CR_DeqSet<CR_CodeByte>   m_codebytes;
    CR_DeqSet<CR_DataByte>   m_databytes;
};

////////////////////////////////////////////////////////////////////////////

class CR_CodeStack : public CR_CodeBinary
{
    CR_CodeStack();
    CR_CodeStack(const CR_CodeStack& cs);
    void operator=(const CR_CodeStack& cs);
    virtual ~CR_CodeStack();

    // base pointer
    void AddBP(int plus);
    void SubBP(int minus);

    // stack pointer
    void AddSP(int plus);
    void SubSP(int minus);

protected:
    int m_bp_index;
    int m_bp_minis_sp;  // base pointer minus stack pointer
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 - code function for 32-bit

class CR_CodeFunc32
{
public:
    CR_CodeFunc32();
    CR_CodeFunc32(const CR_CodeFunc32& cf);
    void operator=(const CR_CodeFunc32& cf);
    virtual ~CR_CodeFunc32();
    void Copy(const CR_CodeFunc32& cf);
    void clear();

public:
    // accessors
    CR_Addr32&                          Addr();
    CR_String&                          Name();
    CR_FuncType&                        FuncType();
    int&                                SizeOfStackArgs();
    CR_OperandSet&                      Args();
    DWORD&                              Flags();
    CR_Addr32Set&                       Jumpees();
    CR_Addr32Set&                       Jumpers();
    CR_Addr32Set&                       Callees();
    CR_Addr32Set&                       Callers();
    CR_DeqSet<CR_Block32>&              Blocks();
    CR_Block32*                         BlockOfAddr(CR_Addr32 addr);
    // const accessors
    const CR_Addr32&                    Addr() const;
    const CR_String&                    Name() const;
    const CR_FuncType&                  FuncType() const;
    const int&                          SizeOfStackArgs() const;
    const CR_OperandSet&                Args() const;
    const DWORD&                        Flags() const;
    const CR_Addr32Set&                 Jumpees() const;
    const CR_Addr32Set&                 Jumpers() const;
    const CR_Addr32Set&                 Callees() const;
    const CR_Addr32Set&                 Callers() const;
    const CR_DeqSet<CR_Block32>&        Blocks() const;
    const CR_Block32*                   BlockOfAddr(CR_Addr32 addr) const;

protected:
    CR_Addr32                           m_addr;
    CR_String                           m_name;
    CR_FuncType                         m_ft;
    int                                 m_SizeOfStackArgs;
    CR_OperandSet                       m_args;
    DWORD                               m_flags;
    CR_Addr32Set                        m_jumpees;
    CR_Addr32Set                        m_jumpers;
    CR_Addr32Set                        m_callees;
    CR_Addr32Set                        m_callers;
    CR_DeqSet<CR_Block32>               m_blocks;
};

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 - code function for 64-bit

class CR_CodeFunc64
{
public:
    CR_CodeFunc64();
    CR_CodeFunc64(const CR_CodeFunc64& cf);
    void operator=(const CR_CodeFunc64& cf);
    virtual ~CR_CodeFunc64();
    void Copy(const CR_CodeFunc64& cf);
    void clear();

public:
    // accessors
    CR_Addr64&                          Addr();
    CR_String&                          Name();
    CR_FuncType&                        FuncType();
    int&                                SizeOfStackArgs();
    CR_OperandSet&                      Args();
    DWORD&                              Flags();
    CR_Addr64Set&                       Jumpees();
    CR_Addr64Set&                       Jumpers();
    CR_Addr64Set&                       Callees();
    CR_Addr64Set&                       Callers();
    CR_DeqSet<CR_Block64>&              Blocks();
    CR_Block64*                         BlockOfAddr(CR_Addr64 addr);
    // const accessors
    const CR_Addr64&                    Addr() const;
    const CR_String&                    Name() const;
    const CR_FuncType&                  FuncType() const;
    const int&                          SizeOfStackArgs() const;
    const CR_OperandSet&                Args() const;
    const DWORD&                        Flags() const;
    const CR_Addr64Set&                 Jumpees() const;
    const CR_Addr64Set&                 Jumpers() const;
    const CR_Addr64Set&                 Callees() const;
    const CR_Addr64Set&                 Callers() const;
    const CR_DeqSet<CR_Block64>&        Blocks() const;
    const CR_Block64*                   BlockOfAddr(CR_Addr64 addr) const;

protected:
    CR_Addr64                           m_addr;
    CR_String                           m_name;
    CR_FuncType                         m_ft;
    int                                 m_SizeOfStackArgs;
    CR_OperandSet                       m_args;
    DWORD                               m_flags;
    CR_Addr64Set                        m_jumpees;
    CR_Addr64Set                        m_jumpers;
    CR_Addr64Set                        m_callees;
    CR_Addr64Set                        m_callers;
    CR_DeqSet<CR_Block64>               m_blocks;
};

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32 - decompilation status for 32-bit

class CR_DecompStatus32
{
public:
    CR_DecompStatus32();
    CR_DecompStatus32(const CR_DecompStatus32& status);
    void operator=(const CR_DecompStatus32& status);
    virtual ~CR_DecompStatus32();
    void Copy(const CR_DecompStatus32& status);
    void clear();

public:
    void MapAddrToAsmCode(CR_Addr32 addr, const CR_CodeInsn32& ac);
    void MapAddrToCodeFunc(CR_Addr32 addr, const CR_CodeFunc32& cf);
    BOOL AnalyzeCFG();

public:
    // accessors
    CR_Map<CR_Addr32, CR_CodeInsn32>&           MapAddrToAsmCode();
    CR_Addr32Set&                               Entrances();
    CR_Map<CR_Addr32, CR_CodeFunc32>&           MapAddrToCodeFunc();
    CR_CodeInsn32 *                             MapAddrToAsmCode(CR_Addr32 addr);
    CR_CodeFunc32 *                             MapAddrToCodeFunc(CR_Addr32 addr);
    // const accessors
    const CR_Map<CR_Addr32, CR_CodeInsn32>&     MapAddrToAsmCode() const;
    const CR_Addr32Set&                         Entrances() const;
    const CR_Map<CR_Addr32, CR_CodeFunc32>&     MapAddrToCodeFunc() const;
    const CR_CodeInsn32 *                       MapAddrToAsmCode(CR_Addr32 addr) const;
    const CR_CodeFunc32 *                       MapAddrToCodeFunc(CR_Addr32 addr) const;

protected:
    BOOL AnalyzeFuncCFGStage1(CR_Addr32 func, CR_Addr32 addr);
    BOOL AnalyzeFuncCFGStage2(CR_Addr32 func);

protected:
    // map virtual address to asm code
    CR_Map<CR_Addr32, CR_CodeInsn32>        m_mAddrToAsmCode;
    // entrances
    CR_Addr32Set                            m_sEntrances;
    // map addr to code function
    CR_Map<CR_Addr32, CR_CodeFunc32>        m_mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64 - decompilation status for 64-bit

class CR_DecompStatus64
{
public:
    CR_DecompStatus64();
    CR_DecompStatus64(const CR_DecompStatus64& status);
    void operator=(const CR_DecompStatus64& status);
    virtual ~CR_DecompStatus64();
    void Copy(const CR_DecompStatus64& status);
    void clear();

public:
    void MapAddrToAsmCode(CR_Addr64 addr, const CR_CodeInsn64& ac);
    void MapAddrToCodeFunc(CR_Addr64 addr, const CR_CodeFunc64& cf);
    BOOL AnalyzeCFG();

public:
    // accessors
    CR_Map<CR_Addr64, CR_CodeInsn64>&           MapAddrToAsmCode();
    CR_Addr64Set&                               Entrances();
    CR_Map<CR_Addr64, CR_CodeFunc64>&           MapAddrToCodeFunc();
    CR_CodeInsn64 *                             MapAddrToAsmCode(CR_Addr64 addr);
    CR_CodeFunc64 *                             MapAddrToCodeFunc(CR_Addr64 addr);
    // const accessors
    const CR_Map<CR_Addr64, CR_CodeInsn64>&     MapAddrToAsmCode() const;
    const CR_Addr64Set&                         Entrances() const;
    const CR_Map<CR_Addr64, CR_CodeFunc64>&     MapAddrToCodeFunc() const;
    const CR_CodeInsn64 *                       MapAddrToAsmCode(CR_Addr64 addr) const;
    const CR_CodeFunc64 *                       MapAddrToCodeFunc(CR_Addr64 addr) const;

protected:
    BOOL AnalyzeFuncCFGStage1(CR_Addr64 func, CR_Addr64 addr);
    BOOL AnalyzeFuncCFGStage2(CR_Addr64 func);

protected:
    // map virtual address to asm code
    CR_Map<CR_Addr64, CR_CodeInsn64>        m_mAddrToAsmCode;
    // entrances
    CR_Addr64Set                            m_sEntrances;
    // map addr to code function
    CR_Map<CR_Addr64, CR_CodeFunc64>        m_mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////

#include "Coding_inl.h"

#endif  // ndef CODING_H_
