#ifndef CODING_H_
#define CODING_H_

////////////////////////////////////////////////////////////////////////////
// Coding.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

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

    FT_JUMPERFUNC,          // jumper function
    FT_RETURNONLY           // return-only function
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
// CR_OpCodeType - op. code type

enum CR_OpCodeType
{
    OCT_MISC,    // misc
    OCT_JMP,     // jump
    OCT_JCC,     // conditional jump
    OCT_CALL,    // call
    OCT_LOOP,    // loop
    OCT_RETURN,  // ret
    OCT_STACKOP, // stack operation
    OCT_UNKNOWN  // unknown
};

////////////////////////////////////////////////////////////////////////////
// CR_OperandType - type of operand

enum CR_OperandType
{
    OT_NONE,        // none
    OT_REG,         // registry
    OT_MEMREG,      // memory access by a register
    OT_MEMIMM,      // memory access by an immediate
    OT_MEMEXPR,     // memory access by an expression
    OT_IMM,         // immediate
    OT_FUNCNAME,    // function name
    OT_EXPR         // expression
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
    void SetFuncName(const char *name);
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
}; // class CR_Operand

////////////////////////////////////////////////////////////////////////////
// CR_OperandSet - set of operands

typedef CR_DeqSet<CR_Operand> CR_OperandSet;

////////////////////////////////////////////////////////////////////////////
// CR_OpCode32 - op. code for 32-bit mode

class CR_OpCode32
{
public:
    CR_OpCode32();
    CR_OpCode32(const CR_OpCode32& oc);
    void operator=(const CR_OpCode32& oc);
    virtual ~CR_OpCode32();
    void clear();

    void ParseText(const char *text);

public:
    // accessors
    CR_Addr32&                  Addr();         // address of assembly
    CR_String&                  Name();         // name of instruction
    CR_OperandSet&              Operands();     // operands
    CR_Operand*                 Operand(std::size_t index);
    CR_DataBytes&               Codes();        // code of instruction
    CR_OpCodeType&              OpCodeType(); // type of instruction
    CR_CondCode&                CondCode();     // condition type
    CR_Addr32Set&               FuncAddrs();

    // const accessors
    const CR_Addr32&            Addr() const;
    const CR_String&            Name() const;
    const CR_OperandSet&        Operands() const;
    const CR_Operand*           Operand(std::size_t index) const;
    const CR_DataBytes&         Codes() const;
    const CR_OpCodeType&        OpCodeType() const;
    const CR_CondCode&          CondCode() const;
    const CR_Addr32Set&         FuncAddrs() const;

protected:
    CR_Addr32                   m_addr;
    CR_String                   m_name;
    CR_OperandSet               m_operands;
    CR_DataBytes                m_codes;
    CR_OpCodeType               m_oct;
    CR_CondCode                 m_ccode;
    CR_Addr32Set                m_funcaddrs;

    void Copy(const CR_OpCode32& oc);
}; // class CR_OpCode32

typedef shared_ptr<CR_OpCode32> CR_SharedOpCode32;

////////////////////////////////////////////////////////////////////////////
// CR_OpCode64 - op. code for 64-bit mode

class CR_OpCode64
{
public:
    CR_OpCode64();
    CR_OpCode64(const CR_OpCode64& oc);
    void operator=(const CR_OpCode64& oc);
    virtual ~CR_OpCode64();
    void clear();

    void ParseText(const char *text);

public:
    // accessors
    CR_Addr64&                  Addr();         // address of assembly
    CR_String&                  Name();         // name of instruction
    CR_OperandSet&              Operands();     // operands
    CR_Operand*                 Operand(std::size_t index);
    CR_DataBytes&               Codes();        // code of instruction
    CR_OpCodeType&              OpCodeType(); // type of instruction
    CR_CondCode&                CondCode();     // condition type
    CR_Addr64Set&               FuncAddrs();

    // const accessors
    const CR_Addr64&            Addr() const;
    const CR_String&            Name() const;
    const CR_OperandSet&        Operands() const;
    const CR_Operand*           Operand(std::size_t index) const;
    const CR_DataBytes&         Codes() const;
    const CR_OpCodeType&        OpCodeType() const;
    const CR_CondCode&          CondCode() const;
    const CR_Addr64Set&         FuncAddrs() const;

protected:
    CR_Addr64                   m_addr;
    CR_String                   m_name;
    CR_OperandSet               m_operands;
    CR_DataBytes                m_codes;
    CR_OpCodeType               m_oct;
    CR_CondCode                 m_ccode;
    CR_Addr64Set                m_funcaddrs;

    void Copy(const CR_OpCode64& oc);
}; // class CR_OpCode64

typedef shared_ptr<CR_OpCode64> CR_SharedOpCode64;

////////////////////////////////////////////////////////////////////////////
// CR_DataMemberEntry, CR_DataMemberEntries

struct CR_DataMemberEntry
{
    std::size_t     m_index;
    CR_String       m_name;
    CR_TypeID       m_typeid;
    std::size_t     m_size;

    CR_DataMemberEntry() { }

    CR_DataMemberEntry(const CR_DataMemberEntry& dme) :
        m_index(dme.m_index), m_name(dme.m_name), m_typeid(dme.m_typeid),
        m_size(dme.m_size)
    {
    }

    void operator=(const CR_DataMemberEntry& dme)
    {
        m_index = dme.m_index;
        m_name = dme.m_name;
        m_typeid = dme.m_typeid;
        m_size = dme.m_size;
    }
};

typedef CR_DeqSet<CR_DataMemberEntry> CR_DataMemberEntries;

////////////////////////////////////////////////////////////////////////////
// CR_LogByte, CR_LogBytes

class CR_LogByte
{
public:
    CR_LogByte();
    CR_LogByte(const CR_LogByte& lb);
    void operator=(const CR_LogByte& lb);
    virtual ~CR_LogByte();

          bool& IsAccessed();
    const bool& IsAccessed() const;
          CR_TriBool& IsAlive();
    const CR_TriBool& IsAlive() const;
          CR_TriBool& IsContinuous();
    const CR_TriBool& IsContinuous() const;
          CR_TriBool& IsInteger();
    const CR_TriBool& IsInteger() const;
          CR_TriBool& IsFloating();
    const CR_TriBool& IsFloating() const;
          CR_TriBool& IsPointer();
    const CR_TriBool& IsPointer() const;

protected:
    bool        m_is_accessed;
    CR_TriBool  m_is_alive;
    CR_TriBool  m_is_continuous;
    CR_TriBool  m_is_integer;
    CR_TriBool  m_is_floating;
    CR_TriBool  m_is_pointer;
};

typedef CR_DeqSet<CR_LogByte> CR_LogBytes;

////////////////////////////////////////////////////////////////////////////
// CR_LogBinary -- logical binary

class CR_LogBinary
{
public:
    CR_LogBinary();
    CR_LogBinary(const CR_LogBinary& bin);
    void operator=(const CR_LogBinary& bin);
    virtual ~CR_LogBinary();

    bool empty() const;
    std::size_t size() const;
    void resize(std::size_t siz);
    void clear();

          CR_Operand& TopOffset();
    const CR_Operand& TopOffset() const;

          CR_LogBytes& LogBytes();
    const CR_LogBytes& LogBytes() const;

          CR_DataBytes& DataBytes();
    const CR_DataBytes& DataBytes() const;

          CR_DataMemberEntries& Entries();
    const CR_DataMemberEntries& Entries() const;

          CR_DataByte *DataPtr();
    const CR_DataByte *DataPtr() const;

          CR_DataByte *DataPtrAt(std::size_t index);
    const CR_DataByte *DataPtrAt(std::size_t index) const;

          CR_DataMemberEntry *EntryFromName(const CR_String& name);
    const CR_DataMemberEntry *EntryFromName(const CR_String& name) const;

    CR_DataMemberEntries EntriesFromIndex(std::size_t index) const;

    void AddHead(std::size_t siz);
    void AddTail(std::size_t siz);

    void RemoveHead(std::size_t siz);
    void RemoveTail(std::size_t siz);

    void AddHead(const CR_LogBinary& bin);
    void AddTail(const CR_LogBinary& bin);

    void AddNamePrefix(const CR_String& prefix);
    void SetContinuousArea(std::size_t index, std::size_t count);

protected:
    CR_Operand              m_top_offset;
    CR_LogBytes             m_logbytes;
    CR_DataBytes            m_databytes;
    CR_DataMemberEntries    m_entries;
};

////////////////////////////////////////////////////////////////////////////
// CrTypeToLogBinary -- convert type to logical binary

void CrTypeToLogBinary(
    CR_NameScope&       ns,
    const CR_String&    name,
    CR_TypeID           tid,
    CR_LogBinary&       bin);

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
    DWORD&                              Flags();
    CR_Addr32Set&                       Jumpees();
    CR_Addr32Set&                       Jumpers();
    CR_Addr32Set&                       Callees();
    CR_Addr32Set&                       Callers();
    // const accessors
    const CR_Addr32&                    Addr() const;
    const CR_String&                    Name() const;
    const CR_FuncType&                  FuncType() const;
    const int&                          SizeOfStackArgs() const;
    const DWORD&                        Flags() const;
    const CR_Addr32Set&                 Jumpees() const;
    const CR_Addr32Set&                 Jumpers() const;
    const CR_Addr32Set&                 Callees() const;
    const CR_Addr32Set&                 Callers() const;

protected:
    CR_Addr32                           m_addr;
    CR_String                           m_name;
    CR_FuncType                         m_ft;
    int                                 m_SizeOfStackArgs;
    DWORD                               m_flags;
    CR_Addr32Set                        m_jumpees;
    CR_Addr32Set                        m_jumpers;
    CR_Addr32Set                        m_callees;
    CR_Addr32Set                        m_callers;
}; // class CR_CodeFunc32

typedef shared_ptr<CR_CodeFunc32> CR_SharedCodeFunc32;

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
    DWORD&                              Flags();
    CR_Addr64Set&                       Jumpees();
    CR_Addr64Set&                       Jumpers();
    CR_Addr64Set&                       Callees();
    CR_Addr64Set&                       Callers();
    // const accessors
    const CR_Addr64&                    Addr() const;
    const CR_String&                    Name() const;
    const CR_FuncType&                  FuncType() const;
    const int&                          SizeOfStackArgs() const;
    const DWORD&                        Flags() const;
    const CR_Addr64Set&                 Jumpees() const;
    const CR_Addr64Set&                 Jumpers() const;
    const CR_Addr64Set&                 Callees() const;
    const CR_Addr64Set&                 Callers() const;

protected:
    CR_Addr64                           m_addr;
    CR_String                           m_name;
    CR_FuncType                         m_ft;
    int                                 m_SizeOfStackArgs;
    DWORD                               m_flags;
    CR_Addr64Set                        m_jumpees;
    CR_Addr64Set                        m_jumpers;
    CR_Addr64Set                        m_callees;
    CR_Addr64Set                        m_callers;
}; // class CR_CodeFunc64

typedef shared_ptr<CR_CodeFunc64> CR_SharedCodeFunc64;

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo32 - disassembly info for 32-bit

class CR_DisAsmInfo32
{
public:
    CR_DisAsmInfo32();
    CR_DisAsmInfo32(const CR_DisAsmInfo32& info);
    void operator=(const CR_DisAsmInfo32& info);
    virtual ~CR_DisAsmInfo32();
    void Copy(const CR_DisAsmInfo32& info);
    void clear();

public:
    void MapAddrToOpCode(CR_Addr32 addr, CR_OpCode32 *oc);
    void MapAddrToCodeFunc(CR_Addr32 addr, CR_CodeFunc32 *cf);

public:
    // accessors
    CR_Map<CR_Addr32, CR_SharedOpCode32>&           MapAddrToOpCode();
    CR_Addr32Set&                                   Entrances();
    CR_Map<CR_Addr32, CR_SharedCodeFunc32>&         MapAddrToCodeFunc();
    CR_OpCode32 *                                   MapAddrToOpCode(CR_Addr32 addr);
    CR_CodeFunc32 *                                 MapAddrToCodeFunc(CR_Addr32 addr);
    // const accessors
    const CR_Map<CR_Addr32, CR_SharedOpCode32>&     MapAddrToOpCode() const;
    const CR_Addr32Set&                             Entrances() const;
    const CR_Map<CR_Addr32, CR_SharedCodeFunc32>&   MapAddrToCodeFunc() const;
    const CR_OpCode32 *                             MapAddrToOpCode(CR_Addr32 addr) const;
    const CR_CodeFunc32 *                           MapAddrToCodeFunc(CR_Addr32 addr) const;

protected:
    // map virtual address to asm code
    CR_Map<CR_Addr32, CR_SharedOpCode32>            m_mAddrToOpCode;
    // entrances
    CR_Addr32Set                                    m_sEntrances;
    // map addr to code function
    CR_Map<CR_Addr32, CR_SharedCodeFunc32>          m_mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////
// CR_DisAsmInfo64 - disassembly info for 64-bit

class CR_DisAsmInfo64
{
public:
    CR_DisAsmInfo64();
    CR_DisAsmInfo64(const CR_DisAsmInfo64& info);
    void operator=(const CR_DisAsmInfo64& info);
    virtual ~CR_DisAsmInfo64();
    void Copy(const CR_DisAsmInfo64& info);
    void clear();

public:
    void MapAddrToOpCode(CR_Addr64 addr, CR_OpCode64 *oc);
    void MapAddrToCodeFunc(CR_Addr64 addr, CR_CodeFunc64 *cf);

public:
    // accessors
    CR_Map<CR_Addr64, CR_SharedOpCode64>&           MapAddrToOpCode();
    CR_Addr64Set&                                   Entrances();
    CR_Map<CR_Addr64, CR_SharedCodeFunc64>&         MapAddrToCodeFunc();
    CR_OpCode64 *                                   MapAddrToOpCode(CR_Addr64 addr);
    CR_CodeFunc64 *                                 MapAddrToCodeFunc(CR_Addr64 addr);
    // const accessors
    const CR_Map<CR_Addr64, CR_SharedOpCode64>&     MapAddrToOpCode() const;
    const CR_Addr64Set&                             Entrances() const;
    const CR_Map<CR_Addr64, CR_SharedCodeFunc64>&   MapAddrToCodeFunc() const;
    const CR_OpCode64 *                             MapAddrToOpCode(CR_Addr64 addr) const;
    const CR_CodeFunc64 *                           MapAddrToCodeFunc(CR_Addr64 addr) const;

protected:
    // map virtual address to asm code
    CR_Map<CR_Addr64, CR_SharedOpCode64>            m_mAddrToOpCode;
    // entrances
    CR_Addr64Set                                    m_sEntrances;
    // map addr to code function
    CR_Map<CR_Addr64, CR_SharedCodeFunc64>          m_mAddrToCodeFunc;
};

////////////////////////////////////////////////////////////////////////////

#include "Coding_inl.h"

#endif  // ndef CODING_H_
