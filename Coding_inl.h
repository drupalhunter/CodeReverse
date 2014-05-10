////////////////////////////////////////////////////////////////////////////
// Coding_inl.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// CR_Operand

inline CR_Operand::CR_Operand()
{
    clear();
}

inline CR_Operand::CR_Operand(const CR_Operand& opr)
{
    Copy(opr);
}

inline /*virtual*/ CR_Operand::~CR_Operand()
{
}

inline void CR_Operand::operator=(const CR_Operand& opr)
{
    Copy(opr);
}

inline void CR_Operand::SetReg(const char *name)
{
    Text() = name;
    OperandType() = OT_REG;
    Size() = CrRegGetSize(name, 64);
}

inline void CR_Operand::SetAPI(const char *api)
{
    Text() = api;
    OperandType() = OT_API;
}

inline void CR_Operand::SetLabel(const char *label)
{
    Text() = label;
    OperandType() = OT_IMM;
}

inline void CR_Operand::SetMemImm(CR_Addr64 addr)
{
    OperandType() = OT_MEMIMM;
    Value64() = addr;
}

inline void CR_Operand::SetMemExpr(const char *exp)
{
    OperandType() = OT_MEMEXPR;
    MemExpr() = exp;
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand accessors

inline CR_String& CR_Operand::Text()
{
    return m_text;
}

inline CR_OperandType& CR_Operand::OperandType()
{
    return m_ot;
}

inline DWORD& CR_Operand::Size()
{
    return m_size;
}

inline CR_Addr32& CR_Operand::Value32()
{
    return m_value32;
}

inline CR_Addr64& CR_Operand::Value64()
{
    return m_value64;
}

inline CR_String& CR_Operand::MemExpr()
{
    return m_memexpr;
}

inline CR_TriBool& CR_Operand::IsInteger()
{
    return m_is_integer;
}

inline CR_TriBool& CR_Operand::IsPointer()
{
    return m_is_pointer;
}

inline CR_TriBool& CR_Operand::IsFunction()
{
    return m_is_function;
}

////////////////////////////////////////////////////////////////////////////
// CR_Operand const accessors

inline const CR_String& CR_Operand::Text() const
{
    return m_text;
}

inline const CR_OperandType& CR_Operand::OperandType() const
{
    return m_ot;
}

inline const DWORD& CR_Operand::Size() const
{
    return m_size;
}

inline const CR_Addr32& CR_Operand::Value32() const
{
    return m_value32;
}

inline const CR_Addr64& CR_Operand::Value64() const
{
    return m_value64;
}

inline const CR_String& CR_Operand::MemExpr() const
{
    return m_memexpr;
}

inline const CR_TriBool& CR_Operand::IsInteger() const
{
    return m_is_integer;
}

inline const CR_TriBool& CR_Operand::IsPointer() const
{
    return m_is_pointer;
}

inline const CR_TriBool& CR_Operand::IsFunction() const
{
    return m_is_function;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn32

inline CR_CodeInsn32::CR_CodeInsn32()
{
    clear();
}

inline CR_CodeInsn32::CR_CodeInsn32(const CR_CodeInsn32& ac)
{
    Copy(ac);
}

inline /*virtual*/ CR_CodeInsn32::~CR_CodeInsn32()
{
}

inline void CR_CodeInsn32::operator=(const CR_CodeInsn32& ac)
{
    Copy(ac);
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn32 accessors

inline CR_Addr32Set& CR_CodeInsn32::FuncAddrs()
{
    return m_funcaddrs;
}

inline CR_Addr32& CR_CodeInsn32::Addr()
{
    return m_addr;
}

inline CR_String& CR_CodeInsn32::Name()
{
    return m_name;
}

inline CR_OperandSet& CR_CodeInsn32::Operands()
{
    return m_operands;
}

inline CR_Operand* CR_CodeInsn32::Operand(std::size_t index)
{
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline CR_Binary& CR_CodeInsn32::Codes()
{
    return m_codes;
}

inline CR_CodeInsnType& CR_CodeInsn32::CodeInsnType()
{
    return m_cit;
}

inline CR_CondCode& CR_CodeInsn32::CondCode()
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn32 const accessors

inline const CR_Addr32Set& CR_CodeInsn32::FuncAddrs() const
{
    return m_funcaddrs;
}

inline const CR_Addr32& CR_CodeInsn32::Addr() const
{
    return m_addr;
}

inline const CR_String& CR_CodeInsn32::Name() const
{
    return m_name;
}

inline const CR_OperandSet& CR_CodeInsn32::Operands() const
{
    return m_operands;
}

inline const CR_Operand* CR_CodeInsn32::Operand(std::size_t index) const
{
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const CR_Binary& CR_CodeInsn32::Codes() const
{
    return m_codes;
}

inline const CR_CodeInsnType& CR_CodeInsn32::CodeInsnType() const
{
    return m_cit;
}

inline const CR_CondCode& CR_CodeInsn32::CondCode() const
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn64

inline CR_CodeInsn64::CR_CodeInsn64()
{
    clear();
}

inline CR_CodeInsn64::CR_CodeInsn64(const CR_CodeInsn64& ac)
{
    Copy(ac);
}

inline /*virtual*/ CR_CodeInsn64::~CR_CodeInsn64()
{
}

inline void CR_CodeInsn64::operator=(const CR_CodeInsn64& ac)
{
    Copy(ac);
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn64 accessors

inline CR_Addr64Set& CR_CodeInsn64::FuncAddrs()
{
    return m_funcaddrs;
}

inline CR_Addr64& CR_CodeInsn64::Addr()
{
    return m_addr;
}

inline CR_String& CR_CodeInsn64::Name()
{
    return m_name;
}

inline CR_OperandSet& CR_CodeInsn64::Operands()
{
    return m_operands;
}

inline CR_Operand* CR_CodeInsn64::Operand(std::size_t index)
{
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline CR_Binary& CR_CodeInsn64::Codes()
{
    return m_codes;
}

inline CR_CodeInsnType& CR_CodeInsn64::CodeInsnType()
{
    return m_cit;
}

inline CR_CondCode& CR_CodeInsn64::CondCode()
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeInsn64 const accessors

inline const CR_Addr64Set& CR_CodeInsn64::FuncAddrs() const
{
    return m_funcaddrs;
}

inline const CR_Addr64& CR_CodeInsn64::Addr() const
{
    return m_addr;
}

inline const CR_String& CR_CodeInsn64::Name() const
{
    return m_name;
}

inline const CR_OperandSet& CR_CodeInsn64::Operands() const
{
    return m_operands;
}

inline const CR_Operand* CR_CodeInsn64::Operand(std::size_t index) const
{
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const CR_Binary& CR_CodeInsn64::Codes() const
{
    return m_codes;
}

inline const CR_CodeInsnType& CR_CodeInsn64::CodeInsnType() const
{
    return m_cit;
}

inline const CR_CondCode& CR_CodeInsn64::CondCode() const
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 accessors

inline CR_Addr32& CR_CodeFunc32::Addr()
{
    return m_addr;
}

inline CR_String& CR_CodeFunc32::Name()
{
    return m_name;
}

inline CR_FuncType& CR_CodeFunc32::FuncType()
{
    return m_ft;
}

inline int& CR_CodeFunc32::SizeOfStackArgs()
{
    return m_SizeOfStackArgs;
}

inline CR_OperandSet& CR_CodeFunc32::Args()
{
    return m_args;
}

inline DWORD& CR_CodeFunc32::Flags()
{
    return m_flags;
}

inline CR_Addr32Set& CR_CodeFunc32::Jumpees()
{
    return m_jumpees;
}

inline CR_Addr32Set& CR_CodeFunc32::Jumpers()
{
    return m_jumpers;
}

inline CR_Addr32Set& CR_CodeFunc32::Callees()
{
    return m_callees;
}

inline CR_Addr32Set& CR_CodeFunc32::Callers()
{
    return m_callees;
}

inline CR_DeqSet<CR_Block32>& CR_CodeFunc32::Blocks()
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 const accessors

inline const CR_Addr32& CR_CodeFunc32::Addr() const
{
    return m_addr;
}

inline const CR_String& CR_CodeFunc32::Name() const
{
    return m_name;
}

inline const CR_FuncType& CR_CodeFunc32::FuncType() const
{
    return m_ft;
}

inline const int& CR_CodeFunc32::SizeOfStackArgs() const
{
    return m_SizeOfStackArgs;
}

inline const CR_OperandSet& CR_CodeFunc32::Args() const
{
    return m_args;
}

inline const DWORD& CR_CodeFunc32::Flags() const
{
    return m_flags;
}

inline const CR_Addr32Set& CR_CodeFunc32::Jumpees() const
{
    return m_jumpees;
}

inline const CR_Addr32Set& CR_CodeFunc32::Jumpers() const
{
    return m_jumpers;
}

inline const CR_Addr32Set& CR_CodeFunc32::Callees() const
{
    return m_callees;
}

inline const CR_Addr32Set& CR_CodeFunc32::Callers() const
{
    return m_callees;
}

inline const CR_DeqSet<CR_Block32>& CR_CodeFunc32::Blocks() const
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 accessors

inline CR_Addr64& CR_CodeFunc64::Addr()
{
    return m_addr;
}

inline CR_String& CR_CodeFunc64::Name()
{
    return m_name;
}

inline CR_FuncType& CR_CodeFunc64::FuncType()
{
    return m_ft;
}

inline int& CR_CodeFunc64::SizeOfStackArgs()
{
    return m_SizeOfStackArgs;
}

inline CR_OperandSet& CR_CodeFunc64::Args()
{
    return m_args;
}

inline DWORD& CR_CodeFunc64::Flags()
{
    return m_flags;
}

inline CR_Addr64Set& CR_CodeFunc64::Jumpees()
{
    return m_jumpees;
}

inline CR_Addr64Set& CR_CodeFunc64::Jumpers()
{
    return m_jumpers;
}

inline CR_Addr64Set& CR_CodeFunc64::Callees()
{
    return m_callees;
}

inline CR_Addr64Set& CR_CodeFunc64::Callers()
{
    return m_callees;
}

inline CR_DeqSet<CR_Block64>& CR_CodeFunc64::Blocks()
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 const accessors

inline const CR_Addr64& CR_CodeFunc64::Addr() const
{
    return m_addr;
}

inline const CR_String& CR_CodeFunc64::Name() const
{
    return m_name;
}

inline const CR_FuncType& CR_CodeFunc64::FuncType() const
{
    return m_ft;
}

inline const int& CR_CodeFunc64::SizeOfStackArgs() const
{
    return m_SizeOfStackArgs;
}

inline const CR_OperandSet& CR_CodeFunc64::Args() const
{
    return m_args;
}

inline const DWORD& CR_CodeFunc64::Flags() const
{
    return m_flags;
}

inline const CR_Addr64Set& CR_CodeFunc64::Jumpees() const
{
    return m_jumpees;
}

inline const CR_Addr64Set& CR_CodeFunc64::Jumpers() const
{
    return m_jumpers;
}

inline const CR_Addr64Set& CR_CodeFunc64::Callees() const
{
    return m_callees;
}

inline const CR_Addr64Set& CR_CodeFunc64::Callers() const
{
    return m_callees;
}

inline const CR_DeqSet<CR_Block64>& CR_CodeFunc64::Blocks() const
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_Block32

inline CR_Block32::CR_Block32() :
    m_addr(0),
    m_nextblock1(NULL),
    m_nextblock2(NULL),
    m_nextaddr1(0),
    m_nextaddr2(0)
{
}

inline CR_Block32::CR_Block32(const CR_Block32& b)
{
    Copy(b);
}

inline void CR_Block32::operator=(const CR_Block32& b)
{
    Copy(b);
}

inline /*virtual*/ CR_Block32::~CR_Block32()
{
}

////////////////////////////////////////////////////////////////////////////
// CR_Block32 accessors

inline CR_Addr32& CR_Block32::Addr()
{
    return m_addr;
}

inline const CR_Addr32& CR_Block32::Addr() const
{
    return m_addr;
}

inline CR_DeqSet<CR_CodeInsn32>& CR_Block32::AsmCodes()
{
    return m_asmcodes;
}

inline const CR_DeqSet<CR_CodeInsn32>& CR_Block32::AsmCodes() const
{
    return m_asmcodes;
}

inline CR_Block32*& CR_Block32::NextBlock1()
{
    return m_nextblock1;
}

inline CR_Block32*& CR_Block32::NextBlock2()
{
    return m_nextblock2;
}

inline CR_Block32*& CR_Block32::NextBlock1() const
{
    return const_cast<CR_Block32*&>(m_nextblock1);
}

inline CR_Block32*& CR_Block32::NextBlock2() const
{
    return const_cast<CR_Block32*&>(m_nextblock2);
}

inline CR_Addr32& CR_Block32::NextAddr1()
{
    return m_nextaddr1;
}

inline const CR_Addr32& CR_Block32::NextAddr1() const
{
    return m_nextaddr1;
}

inline CR_Addr32& CR_Block32::NextAddr2()
{
    return m_nextaddr2;
}

inline const CR_Addr32& CR_Block32::NextAddr2() const
{
    return m_nextaddr2;
}

////////////////////////////////////////////////////////////////////////////
// CR_Block64

inline CR_Block64::CR_Block64() :
    m_addr(0),
    m_nextblock1(NULL),
    m_nextblock2(NULL),
    m_nextaddr1(0),
    m_nextaddr2(0)
{
}

inline CR_Block64::CR_Block64(const CR_Block64& b)
{
    Copy(b);
}

inline void CR_Block64::operator=(const CR_Block64& b)
{
    Copy(b);
}

inline /*virtual*/ CR_Block64::~CR_Block64()
{
}

////////////////////////////////////////////////////////////////////////////
// CR_Block64 accessors

inline CR_Addr64& CR_Block64::Addr()
{
    return m_addr;
}

inline const CR_Addr64& CR_Block64::Addr() const
{
    return m_addr;
}

inline CR_DeqSet<CR_CodeInsn64>& CR_Block64::AsmCodes()
{
    return m_asmcodes;
}

inline const CR_DeqSet<CR_CodeInsn64>& CR_Block64::AsmCodes() const
{
    return m_asmcodes;
}

inline CR_Block64*& CR_Block64::NextBlock1()
{
    return m_nextblock1;
}

inline CR_Block64*& CR_Block64::NextBlock2()
{
    return m_nextblock2;
}

inline CR_Block64*& CR_Block64::NextBlock1() const
{
    return const_cast<CR_Block64*&>(m_nextblock1);
}

inline CR_Block64*& CR_Block64::NextBlock2() const
{
    return const_cast<CR_Block64*&>(m_nextblock2);
}

inline CR_Addr64& CR_Block64::NextAddr1()
{
    return m_nextaddr1;
}

inline const CR_Addr64& CR_Block64::NextAddr1() const
{
    return m_nextaddr1;
}

inline CR_Addr64& CR_Block64::NextAddr2()
{
    return m_nextaddr2;
}

inline const CR_Addr64& CR_Block64::NextAddr2() const
{
    return m_nextaddr2;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32

inline CR_CodeFunc32::CR_CodeFunc32()
{
    clear();
}

inline CR_CodeFunc32::CR_CodeFunc32(const CR_CodeFunc32& cf)
{
    Copy(cf);
}

inline void CR_CodeFunc32::operator=(const CR_CodeFunc32& cf)
{
    Copy(cf);
}

inline /*virtual*/ CR_CodeFunc32::~CR_CodeFunc32()
{
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64

inline CR_CodeFunc64::CR_CodeFunc64()
{
    clear();
}

inline CR_CodeFunc64::CR_CodeFunc64(const CR_CodeFunc64& cf)
{
    Copy(cf);
}

inline void CR_CodeFunc64::operator=(const CR_CodeFunc64& cf)
{
    Copy(cf);
}

inline /*virtual*/ CR_CodeFunc64::~CR_CodeFunc64()
{
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32

inline CR_DecompStatus32::CR_DecompStatus32()
{
}

inline CR_DecompStatus32::CR_DecompStatus32(const CR_DecompStatus32& status)
{
    Copy(status);
}

inline void CR_DecompStatus32::operator=(const CR_DecompStatus32& status)
{
    Copy(status);
}

inline /*virtual*/ CR_DecompStatus32::~CR_DecompStatus32()
{
}

inline void CR_DecompStatus32::MapAddrToAsmCode(CR_Addr32 addr, const CR_CodeInsn32& ac)
{
    MapAddrToAsmCode()[addr] = ac;
}

inline void CR_DecompStatus32::MapAddrToCodeFunc(CR_Addr32 addr, const CR_CodeFunc32& cf)
{
    MapAddrToCodeFunc()[addr] = cf;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32 accessors

inline CR_Map<CR_Addr32, CR_CodeInsn32>& CR_DecompStatus32::MapAddrToAsmCode()
{
    return m_mAddrToAsmCode;
}

inline CR_Addr32Set& CR_DecompStatus32::Entrances()
{
    return m_sEntrances;
}

inline CR_Map<CR_Addr32, CR_CodeFunc32>& CR_DecompStatus32::MapAddrToCodeFunc()
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32 const accessors

inline const CR_Map<CR_Addr32, CR_CodeInsn32>& CR_DecompStatus32::MapAddrToAsmCode() const
{
    return m_mAddrToAsmCode;
}

inline const CR_Addr32Set& CR_DecompStatus32::Entrances() const
{
    return m_sEntrances;
}

inline const CR_Map<CR_Addr32, CR_CodeFunc32>& CR_DecompStatus32::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64

inline CR_DecompStatus64::CR_DecompStatus64()
{
}

inline CR_DecompStatus64::CR_DecompStatus64(const CR_DecompStatus64& status)
{
    Copy(status);
}

inline void CR_DecompStatus64::operator=(const CR_DecompStatus64& status)
{
    Copy(status);
}

inline /*virtual*/ CR_DecompStatus64::~CR_DecompStatus64()
{
}

inline void CR_DecompStatus64::MapAddrToAsmCode(CR_Addr64 addr, const CR_CodeInsn64& ac)
{
    m_mAddrToAsmCode[addr] = ac;
}

inline void CR_DecompStatus64::MapAddrToCodeFunc(CR_Addr64 addr, const CR_CodeFunc64& cf)
{
    m_mAddrToCodeFunc[addr] = cf;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64 accessors

inline CR_Map<CR_Addr64, CR_CodeInsn64>& CR_DecompStatus64::MapAddrToAsmCode()
{
    return m_mAddrToAsmCode;
}

inline CR_Addr64Set& CR_DecompStatus64::Entrances()
{
    return m_sEntrances;
}

inline CR_Map<CR_Addr64, CR_CodeFunc64>& CR_DecompStatus64::MapAddrToCodeFunc()
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64 const accessors

inline const CR_Map<CR_Addr64, CR_CodeInsn64>& CR_DecompStatus64::MapAddrToAsmCode() const
{
    return m_mAddrToAsmCode;
}

inline const CR_Addr64Set& CR_DecompStatus64::Entrances() const
{
    return m_sEntrances;
}

inline const CR_Map<CR_Addr64, CR_CodeFunc64>& CR_DecompStatus64::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
