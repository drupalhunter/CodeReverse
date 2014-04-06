////////////////////////////////////////////////////////////////////////////
// OPERAND accessors

inline string& OPERAND::Text()
{
    return m_text;
}

inline OPERANDTYPE& OPERAND::OperandType()
{
    return m_ot;
}

inline DWORD& OPERAND::Size()
{
    return m_size;
}

inline ADDR32& OPERAND::Value32()
{
    return m_value32;
}

inline ADDR64& OPERAND::Value64()
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

inline TBOOL& OPERAND::IsInteger()
{
    return m_is_integer;
}

inline TBOOL& OPERAND::IsPointer()
{
    return m_is_pointer;
}

inline TBOOL& OPERAND::IsFunction()
{
    return m_is_function;
}

////////////////////////////////////////////////////////////////////////////
// OPERAND const accessors

inline const string& OPERAND::Text() const
{
    return m_text;
}

inline const OPERANDTYPE& OPERAND::OperandType() const
{
    return m_ot;
}

inline const DWORD& OPERAND::Size() const
{
    return m_size;
}

inline const ADDR32& OPERAND::Value32() const
{
    return m_value32;
}

inline const ADDR64& OPERAND::Value64() const
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

inline const TBOOL& OPERAND::IsInteger() const
{
    return m_is_integer;
}

inline const TBOOL& OPERAND::IsPointer() const
{
    return m_is_pointer;
}

inline const TBOOL& OPERAND::IsFunction() const
{
    return m_is_function;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE32 accessors

inline ADDR32SET& ASMCODE32::Funcs()
{
    return m_funcs;
}

inline ADDR32& ASMCODE32::Addr()
{
    return m_addr;
}

inline string& ASMCODE32::Name()
{
    return m_name;
}

inline OPERANDSET& ASMCODE32::Operands()
{
    return m_operands;
}

inline OPERAND* ASMCODE32::Operand(SIZE_T index)
{
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline vector<BYTE>& ASMCODE32::Codes()
{
    return m_codes;
}

inline ASMCODETYPE& ASMCODE32::AsmCodeType()
{
    return m_act;
}

inline CONDCODE& ASMCODE32::CondCode()
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE32 const accessors

inline const ADDR32SET& ASMCODE32::Funcs() const
{
    return m_funcs;
}

inline const ADDR32& ASMCODE32::Addr() const
{
    return m_addr;
}

inline const string& ASMCODE32::Name() const
{
    return m_name;
}

inline const OPERANDSET& ASMCODE32::Operands() const
{
    return m_operands;
}

inline const OPERAND* ASMCODE32::Operand(SIZE_T index) const
{
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const vector<BYTE>& ASMCODE32::Codes() const
{
    return m_codes;
}

inline const ASMCODETYPE& ASMCODE32::AsmCodeType() const
{
    return m_act;
}

inline const CONDCODE& ASMCODE32::CondCode() const
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE64 accessors

inline ADDR64SET& ASMCODE64::Funcs()
{
    return m_funcs;
}

inline ADDR64& ASMCODE64::Addr()
{
    return m_addr;
}

inline string& ASMCODE64::Name()
{
    return m_name;
}

inline OPERANDSET& ASMCODE64::Operands()
{
    return m_operands;
}

inline OPERAND* ASMCODE64::Operand(SIZE_T index)
{
    assert(index < m_operands.size());
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline vector<BYTE>& ASMCODE64::Codes()
{
    return m_codes;
}

inline ASMCODETYPE& ASMCODE64::AsmCodeType()
{
    return m_act;
}

inline CONDCODE& ASMCODE64::CondCode()
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// ASMCODE64 const accessors

inline const ADDR64SET& ASMCODE64::Funcs() const
{
    return m_funcs;
}

inline const ADDR64& ASMCODE64::Addr() const
{
    return m_addr;
}

inline const string& ASMCODE64::Name() const
{
    return m_name;
}

inline const OPERANDSET& ASMCODE64::Operands() const
{
    return m_operands;
}

inline const OPERAND* ASMCODE64::Operand(SIZE_T index) const
{
    assert(m_operands.size() > index);
    if (m_operands.size() > index)
        return &m_operands[index];
    else
        return NULL;
}

inline const vector<BYTE>& ASMCODE64::Codes() const
{
    return m_codes;
}

inline const ASMCODETYPE& ASMCODE64::AsmCodeType() const
{
    return m_act;
}

inline const CONDCODE& ASMCODE64::CondCode() const
{
    return m_ccode;
}

////////////////////////////////////////////////////////////////////////////
// BLOCK32 accessors

inline ADDR32& BLOCK32::Addr()
{
    return m_addr;
}

inline const ADDR32& BLOCK32::Addr() const
{
    return m_addr;
}

inline VECSET<ASMCODE32>& BLOCK32::AsmCodes()
{
    return m_asmcodes;
}

inline const VECSET<ASMCODE32>& BLOCK32::AsmCodes() const
{
    return m_asmcodes;
}

inline BLOCK32*& BLOCK32::NextBlock1()
{
    return m_nextblock1;
}

inline BLOCK32*& BLOCK32::NextBlock2()
{
    return m_nextblock2;
}

inline ADDR32& BLOCK32::NextAddr1()
{
    return m_nextaddr1;
}

inline const ADDR32& BLOCK32::NextAddr1() const
{
    return m_nextaddr1;
}

inline ADDR32& BLOCK32::NextAddr2()
{
    return m_nextaddr2;
}

inline const ADDR32& BLOCK32::NextAddr2() const
{
    return m_nextaddr2;
}

////////////////////////////////////////////////////////////////////////////
// BLOCK32 accessors

inline ADDR64& BLOCK64::Addr()
{
    return m_addr;
}

inline const ADDR64& BLOCK64::Addr() const
{
    return m_addr;
}

inline VECSET<ASMCODE64>& BLOCK64::AsmCodes()
{
    return m_asmcodes;
}

inline const VECSET<ASMCODE64>& BLOCK64::AsmCodes() const
{
    return m_asmcodes;
}

inline BLOCK64*& BLOCK64::NextBlock1()
{
    return m_nextblock1;
}

inline BLOCK64*& BLOCK64::NextBlock2()
{
    return m_nextblock2;
}

inline ADDR64& BLOCK64::NextAddr1()
{
    return m_nextaddr1;
}

inline const ADDR64& BLOCK64::NextAddr1() const
{
    return m_nextaddr1;
}

inline ADDR64& BLOCK64::NextAddr2()
{
    return m_nextaddr2;
}

inline const ADDR64& BLOCK64::NextAddr2() const
{
    return m_nextaddr2;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32 accessors

inline ADDR32& CODEFUNC32::Addr()
{
    return m_addr;
}

inline string& CODEFUNC32::Name()
{
    return m_name;
}

inline FUNCTYPE& CODEFUNC32::FuncType()
{
    return m_ft;
}

inline INT& CODEFUNC32::SizeOfStackArgs()
{
    return m_SizeOfStackArgs;
}

inline OPERANDSET& CODEFUNC32::Args()
{
    return m_args;
}

inline DWORD& CODEFUNC32::Flags()
{
    return m_flags;
}

inline string& CODEFUNC32::ReturnDataType()
{
    return m_returndatatype;
}

inline ADDR32SET& CODEFUNC32::Jumpees()
{
    return m_jumpees;
}

inline ADDR32SET& CODEFUNC32::Jumpers()
{
    return m_jumpers;
}

inline ADDR32SET& CODEFUNC32::Callees()
{
    return m_callees;
}

inline ADDR32SET& CODEFUNC32::Callers()
{
    return m_callees;
}

inline VECSET<BLOCK32>& CODEFUNC32::Blocks()
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC32 const accessors

inline const ADDR32& CODEFUNC32::Addr() const
{
    return m_addr;
}

inline const string& CODEFUNC32::Name() const
{
    return m_name;
}

inline const FUNCTYPE& CODEFUNC32::FuncType() const
{
    return m_ft;
}

inline const INT& CODEFUNC32::SizeOfStackArgs() const
{
    return m_SizeOfStackArgs;
}

inline const OPERANDSET& CODEFUNC32::Args() const
{
    return m_args;
}

inline const DWORD& CODEFUNC32::Flags() const
{
    return m_flags;
}

inline const string& CODEFUNC32::ReturnDataType() const
{
    return m_returndatatype;
}

inline const ADDR32SET& CODEFUNC32::Jumpees() const
{
    return m_jumpees;
}

inline const ADDR32SET& CODEFUNC32::Jumpers() const
{
    return m_jumpers;
}

inline const ADDR32SET& CODEFUNC32::Callees() const
{
    return m_callees;
}

inline const ADDR32SET& CODEFUNC32::Callers() const
{
    return m_callees;
}

inline const VECSET<BLOCK32>& CODEFUNC32::Blocks() const
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64 accessors

inline ADDR64& CODEFUNC64::Addr()
{
    return m_addr;
}

inline string& CODEFUNC64::Name()
{
    return m_name;
}

inline FUNCTYPE& CODEFUNC64::FuncType()
{
    return m_ft;
}

inline INT& CODEFUNC64::SizeOfStackArgs()
{
    return m_SizeOfStackArgs;
}

inline OPERANDSET& CODEFUNC64::Args()
{
    return m_args;
}

inline DWORD& CODEFUNC64::Flags()
{
    return m_flags;
}

inline string& CODEFUNC64::ReturnDataType()
{
    return m_returndatatype;
}

inline ADDR64SET& CODEFUNC64::Jumpees()
{
    return m_jumpees;
}

inline ADDR64SET& CODEFUNC64::Jumpers()
{
    return m_jumpers;
}

inline ADDR64SET& CODEFUNC64::Callees()
{
    return m_callees;
}

inline ADDR64SET& CODEFUNC64::Callers()
{
    return m_callees;
}

inline VECSET<BLOCK64>& CODEFUNC64::Blocks()
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// CODEFUNC64 const accessors

inline const ADDR64& CODEFUNC64::Addr() const
{
    return m_addr;
}

inline const string& CODEFUNC64::Name() const
{
    return m_name;
}

inline const FUNCTYPE& CODEFUNC64::FuncType() const
{
    return m_ft;
}

inline const INT& CODEFUNC64::SizeOfStackArgs() const
{
    return m_SizeOfStackArgs;
}

inline const OPERANDSET& CODEFUNC64::Args() const
{
    return m_args;
}

inline const DWORD& CODEFUNC64::Flags() const
{
    return m_flags;
}

inline const string& CODEFUNC64::ReturnDataType() const
{
    return m_returndatatype;
}

inline const ADDR64SET& CODEFUNC64::Jumpees() const
{
    retsurn m_jumpees;
}

inline const ADDR64SET& CODEFUNC64::Jumpers() const
{
    return m_jumpers;
}

inline const ADDR64SET& CODEFUNC64::Callees() const
{
    return m_callees;
}

inline const ADDR64SET& CODEFUNC64::Callers() const
{
    return m_callees;
}

inline const VECSET<BLOCK64>& CODEFUNC64::Blocks() const
{
    return m_blocks;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32 accessors

inline map<ADDR32, ASMCODE32>& DECOMPSTATUS32::MapAddrToAsmCode()
{
    return m_mAddrToAsmCode;
}

inline ADDR32SET& DECOMPSTATUS32::Entrances()
{
    return m_sEntrances;
}

inline map<ADDR32, CODEFUNC32>& DECOMPSTATUS32::MapAddrToCodeFunc()
{
    return m_mAddrToCodeFunc;
}

inline ASMCODE32 *DECOMPSTATUS32::MapAddrToAsmCode(ADDR32 addr)
{
    map<ADDR32, ASMCODE32>::iterator it, end;
    end = m_mAddrToAsmCode.end();
    it = m_mAddrToAsmCode.find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS32 const accessors

inline const map<ADDR32, ASMCODE32>& DECOMPSTATUS32::MapAddrToAsmCode() const
{
    return m_mAddrToAsmCode;
}

inline const ADDR32SET& DECOMPSTATUS32::Entrances() const
{
    return m_sEntrances;
}

inline const map<ADDR32, CODEFUNC32>& DECOMPSTATUS32::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}

inline const ASMCODE32 *DECOMPSTATUS32::MapAddrToAsmCode(ADDR32 addr) const
{
    map<ADDR32, ASMCODE32>::const_iterator it, end;
    end = m_mAddrToAsmCode.end();
    it = m_mAddrToAsmCode.find(addr);
    if (it != end)
        return &it->second;
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64 accessors

inline map<ADDR64, ASMCODE64>& DECOMPSTATUS64::MapAddrToAsmCode()
{
    return m_mAddrToAsmCode;
}

inline ADDR64SET& DECOMPSTATUS64::Entrances()
{
    return m_sEntrances;
}

inline map<ADDR64, CODEFUNC64>& DECOMPSTATUS64::MapAddrToCodeFunc()
{
    return m_mAddrToCodeFunc;
}

////////////////////////////////////////////////////////////////////////////
// DECOMPSTATUS64 const accessors

inline const map<ADDR64, ASMCODE64>& DECOMPSTATUS64::MapAddrToAsmCode() const
{
    return m_mAddrToAsmCode;
}

inline const ADDR64SET& DECOMPSTATUS64::Entrances() const
{
    return m_sEntrances;
}

inline const map<ADDR64, CODEFUNC64>& DECOMPSTATUS64::MapAddrToCodeFunc() const
{
    return m_mAddrToCodeFunc;
}
