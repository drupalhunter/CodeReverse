////////////////////////////////////////////////////////////////////////////
// CR_TriBool - tri-state logical value

inline CR_TriBool::CR_TriBool()
{
    m_value = TB_UNKNOWN;
}

inline CR_TriBool::CR_TriBool(BOOL b)
{
    m_value = (b ? TB_TRUE : TB_FALSE);
}

inline CR_TriBool::CR_TriBool(const CR_TriBool& tb)
{
    m_value = tb.m_value;
}

inline /*virtual*/ CR_TriBool::~CR_TriBool()
{
}

inline CR_TriBool& CR_TriBool::operator=(const CR_TriBool& tb)
{
    m_value = tb.m_value;
    return *this;
}

inline CR_TriBool& CR_TriBool::operator=(BOOL b)
{
    m_value = (b ? TB_TRUE : TB_FALSE);
    return *this;
}

inline bool CR_TriBool::operator==(const CR_TriBool& tb) const
{
    return m_value == tb.m_value;
}

inline bool CR_TriBool::operator!=(const CR_TriBool& tb) const
{
    return m_value != tb.m_value;
}

inline void CR_TriBool::clear()
{
    m_value = TB_UNKNOWN;
}

inline BOOL CR_TriBool::CanBeTrue() const
{
    return m_value != TB_FALSE;
}

inline BOOL CR_TriBool::CanBeFalse() const
{
    return m_value != TB_TRUE;
}

inline BOOL CR_TriBool::IsUnknown() const
{
    return m_value == TB_UNKNOWN;
}

inline CR_TriBool& CR_TriBool::IsTrue(const CR_TriBool& tb)
{
    m_value = tb.m_value;
    return *this;
}

inline CR_TriBool& CR_TriBool::LogicalNot(const CR_TriBool& tb1)
{
    return IsFalse(tb1);
}

inline CR_TriBool& CR_TriBool::NotEqual(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    CR_TriBool tb;
    tb.Equal(tb1, tb2);
    return LogicalNot(tb);
}

////////////////////////////////////////////////////////////////////////////
// OPERAND accessors

inline string& OPERAND::Text()
{
    return m_text;
}

inline CR_OperandType& OPERAND::OperandType()
{
    return m_ot;
}

inline DWORD& OPERAND::Size()
{
    return m_size;
}

inline CR_Addr32& OPERAND::Value32()
{
    return m_value32;
}

inline CR_Addr64& OPERAND::Value64()
{
    return m_value64;
}

inline string& OPERAND::Exp()
{
    return m_exp;
}

inline string& OPERAND::DataType()
{
    return m_datatype;
}

inline CR_TriBool& OPERAND::IsInteger()
{
    return m_is_integer;
}

inline CR_TriBool& OPERAND::IsPointer()
{
    return m_is_pointer;
}

inline CR_TriBool& OPERAND::IsFunction()
{
    return m_is_function;
}

////////////////////////////////////////////////////////////////////////////
// OPERAND const accessors

inline const string& OPERAND::Text() const
{
    return m_text;
}

inline const CR_OperandType& OPERAND::OperandType() const
{
    return m_ot;
}

inline const DWORD& OPERAND::Size() const
{
    return m_size;
}

inline const CR_Addr32& OPERAND::Value32() const
{
    return m_value32;
}

inline const CR_Addr64& OPERAND::Value64() const
{
    return m_value64;
}

inline const string& OPERAND::Exp() const
{
    return m_exp;
}

inline const string& OPERAND::DataType() const
{
    return m_datatype;
}

inline const CR_TriBool& OPERAND::IsInteger() const
{
    return m_is_integer;
}

inline const CR_TriBool& OPERAND::IsPointer() const
{
    return m_is_pointer;
}

inline const CR_TriBool& OPERAND::IsFunction() const
{
    return m_is_function;
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

inline string& CR_CodeInsn32::Name()
{
    return m_name;
}

inline OPERANDSET& CR_CodeInsn32::Operands()
{
    return m_operands;
}

inline OPERAND* CR_CodeInsn32::Operand(std::size_t index)
{
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline vector<BYTE>& CR_CodeInsn32::Codes()
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

inline const string& CR_CodeInsn32::Name() const
{
    return m_name;
}

inline const OPERANDSET& CR_CodeInsn32::Operands() const
{
    return m_operands;
}

inline const OPERAND* CR_CodeInsn32::Operand(std::size_t index) const
{
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const vector<BYTE>& CR_CodeInsn32::Codes() const
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
// CR_CodeInsn64 accessors

inline CR_Addr64Set& CR_CodeInsn64::FuncAddrs()
{
    return m_funcaddrs;
}

inline CR_Addr64& CR_CodeInsn64::Addr()
{
    return m_addr;
}

inline string& CR_CodeInsn64::Name()
{
    return m_name;
}

inline OPERANDSET& CR_CodeInsn64::Operands()
{
    return m_operands;
}

inline OPERAND* CR_CodeInsn64::Operand(std::size_t index)
{
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline vector<BYTE>& CR_CodeInsn64::Codes()
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

inline const string& CR_CodeInsn64::Name() const
{
    return m_name;
}

inline const OPERANDSET& CR_CodeInsn64::Operands() const
{
    return m_operands;
}

inline const OPERAND* CR_CodeInsn64::Operand(std::size_t index) const
{
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const vector<BYTE>& CR_CodeInsn64::Codes() const
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
// CR_Block32 accessors

inline CR_Addr32& CR_Block32::Addr()
{
    return m_addr;
}

inline const CR_Addr32& CR_Block32::Addr() const
{
    return m_addr;
}

inline CR_VecSet<CR_CodeInsn32>& CR_Block32::AsmCodes()
{
    return m_asmcodes;
}

inline const CR_VecSet<CR_CodeInsn32>& CR_Block32::AsmCodes() const
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
// CR_Block32 accessors

inline CR_Addr64& CR_Block64::Addr()
{
    return m_addr;
}

inline const CR_Addr64& CR_Block64::Addr() const
{
    return m_addr;
}

inline CR_VecSet<CR_CodeInsn64>& CR_Block64::AsmCodes()
{
    return m_asmcodes;
}

inline const CR_VecSet<CR_CodeInsn64>& CR_Block64::AsmCodes() const
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
// CR_CodeFunc32 accessors

inline CR_Addr32& CR_CodeFunc32::Addr()
{
    return m_addr;
}

inline string& CR_CodeFunc32::Name()
{
    return m_name;
}

inline CR_FuncType& CR_CodeFunc32::FuncType()
{
    return m_ft;
}

inline INT& CR_CodeFunc32::SizeOfStackArgs()
{
    return m_SizeOfStackArgs;
}

inline OPERANDSET& CR_CodeFunc32::Args()
{
    return m_args;
}

inline DWORD& CR_CodeFunc32::Flags()
{
    return m_flags;
}

inline string& CR_CodeFunc32::ReturnDataType()
{
    return m_returndatatype;
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

inline CR_VecSet<CR_Block32>& CR_CodeFunc32::Blocks()
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc32 const accessors

inline const CR_Addr32& CR_CodeFunc32::Addr() const
{
    return m_addr;
}

inline const string& CR_CodeFunc32::Name() const
{
    return m_name;
}

inline const CR_FuncType& CR_CodeFunc32::FuncType() const
{
    return m_ft;
}

inline const INT& CR_CodeFunc32::SizeOfStackArgs() const
{
    return m_SizeOfStackArgs;
}

inline const OPERANDSET& CR_CodeFunc32::Args() const
{
    return m_args;
}

inline const DWORD& CR_CodeFunc32::Flags() const
{
    return m_flags;
}

inline const string& CR_CodeFunc32::ReturnDataType() const
{
    return m_returndatatype;
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

inline const CR_VecSet<CR_Block32>& CR_CodeFunc32::Blocks() const
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 accessors

inline CR_Addr64& CR_CodeFunc64::Addr()
{
    return m_addr;
}

inline string& CR_CodeFunc64::Name()
{
    return m_name;
}

inline CR_FuncType& CR_CodeFunc64::FuncType()
{
    return m_ft;
}

inline INT& CR_CodeFunc64::SizeOfStackArgs()
{
    return m_SizeOfStackArgs;
}

inline OPERANDSET& CR_CodeFunc64::Args()
{
    return m_args;
}

inline DWORD& CR_CodeFunc64::Flags()
{
    return m_flags;
}

inline string& CR_CodeFunc64::ReturnDataType()
{
    return m_returndatatype;
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

inline CR_VecSet<CR_Block64>& CR_CodeFunc64::Blocks()
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_CodeFunc64 const accessors

inline const CR_Addr64& CR_CodeFunc64::Addr() const
{
    return m_addr;
}

inline const string& CR_CodeFunc64::Name() const
{
    return m_name;
}

inline const CR_FuncType& CR_CodeFunc64::FuncType() const
{
    return m_ft;
}

inline const INT& CR_CodeFunc64::SizeOfStackArgs() const
{
    return m_SizeOfStackArgs;
}

inline const OPERANDSET& CR_CodeFunc64::Args() const
{
    return m_args;
}

inline const DWORD& CR_CodeFunc64::Flags() const
{
    return m_flags;
}

inline const string& CR_CodeFunc64::ReturnDataType() const
{
    return m_returndatatype;
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

inline const CR_VecSet<CR_Block64>& CR_CodeFunc64::Blocks() const
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32 accessors

inline map<CR_Addr32, CR_CodeInsn32>& CR_DecompStatus32::MapAddrToAsmCode()
{
    return m_mAddrToAsmCode;
}

inline CR_Addr32Set& CR_DecompStatus32::Entrances()
{
    return m_sEntrances;
}

inline map<CR_Addr32, CR_CodeFunc32>& CR_DecompStatus32::MapAddrToCodeFunc()
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus32 const accessors

inline const map<CR_Addr32, CR_CodeInsn32>& CR_DecompStatus32::MapAddrToAsmCode() const
{
    return m_mAddrToAsmCode;
}

inline const CR_Addr32Set& CR_DecompStatus32::Entrances() const
{
    return m_sEntrances;
}

inline const map<CR_Addr32, CR_CodeFunc32>& CR_DecompStatus32::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64 accessors

inline map<CR_Addr64, CR_CodeInsn64>& CR_DecompStatus64::MapAddrToAsmCode()
{
    return m_mAddrToAsmCode;
}

inline CR_Addr64Set& CR_DecompStatus64::Entrances()
{
    return m_sEntrances;
}

inline map<CR_Addr64, CR_CodeFunc64>& CR_DecompStatus64::MapAddrToCodeFunc()
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// CR_DecompStatus64 const accessors

inline const map<CR_Addr64, CR_CodeInsn64>& CR_DecompStatus64::MapAddrToAsmCode() const
{
    return m_mAddrToAsmCode;
}

inline const CR_Addr64Set& CR_DecompStatus64::Entrances() const
{
    return m_sEntrances;
}

inline const map<CR_Addr64, CR_CodeFunc64>& CR_DecompStatus64::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}
