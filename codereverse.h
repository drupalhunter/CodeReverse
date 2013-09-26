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

extern const char * const cr_logo;

////////////////////////////////////////////////////////////////////////////
// LOLONG, HILONG

#ifndef LOLONG
    #define LOLONG(dwl) ((DWORD)(dwl))
#endif
#ifndef HILONG
    #define HILONG(dwl) ((DWORD)(((dwl) >> 32) & 0xFFFFFFFF))
#endif

////////////////////////////////////////////////////////////////////////////
// ADDR32, ADDR64 (virtual address)

typedef DWORD     ADDR32;
typedef ULONGLONG ADDR64;

////////////////////////////////////////////////////////////////////////////
// CCODE - condition code

enum CCODE
{
    C_A, C_AE, C_B, C_BE, C_C, C_E, C_G, C_GE, C_L, C_LE, C_NA, C_NAE,
    C_NB, C_NBE, C_NC, C_NE, C_NG, C_NGE, C_NL, C_NLE, C_NO, C_NP,
    C_NS, C_NZ, C_O, C_P, C_PE, C_PO, C_S, C_Z,
    C_none = -1
};

////////////////////////////////////////////////////////////////////////////
// X86_REGTYPE, X86_REGINFO

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
    X86_REGNONE = -1
};

X86_REGTYPE cr_reg_get_type(const char *name, int bits);
DWORD cr_reg_get_size(const char *name, int bits);

////////////////////////////////////////////////////////////////////////////
// BRANCHTYPE

enum BRANCHTYPE
{
    BT_GONEXT,
    BT_JMP,
    BT_JCC,
    BT_CALL,
    BT_LOOP,
    BT_RETURN
};

////////////////////////////////////////////////////////////////////////////
// OPERANDTYPE

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
// OPERANDINFO

struct OPERAND
{
    string      text;
    OPERANDTYPE type;
    DWORD       size;
    ULONGLONG   value;
    string      exp;

    OPERAND()
    {
        Clear();
    }

    OPERAND(const OPERAND& opr)
    {
        Copy(opr);
    }

    OPERAND& operator=(const OPERAND& opr)
    {
        Copy(opr);
        return *this;
    }

    VOID Copy(const OPERAND& opr)
    {
        text = opr.text;
        type = opr.type;
        size = opr.size;
        value = opr.value;
        exp = opr.exp;
    }

    VOID Clear()
    {
        text.clear();
        type = OT_NONE;
        size = 0;
        value = 0;
        exp.clear();
    }

    VOID SetAPI(const char *api)
    {
        text = api;
        type = OT_API;
    }

    VOID SetLabel(const char *label)
    {
        text = label;
        type = OT_LABEL;
    }

    VOID SetMemImm(ADDR64 addr)
    {
        type = OT_MEMIMM;
        value = addr;
    }

    VOID SetMemExp(const char *exp_)
    {
        type = OT_MEMEXP;
        exp = exp_;
    }

    VOID SetImm(ULONGLONG val, bool is_signed);
};

////////////////////////////////////////////////////////////////////////////
// ASMCODE32, ASMCODE64

struct ASMCODE32
{
    ADDR32 func;
    ADDR32 addr;
    string name;
    OPERAND operand1, operand2, operand3;
    vector<BYTE> codes;
    BRANCHTYPE bt;
    CCODE cc;
    vector<ADDR32> jumped_from;

    ASMCODE32()
    {
        Clear();
    }

    ASMCODE32(const ASMCODE32& ac)
    {
        Copy(ac);
    }

    ASMCODE32& operator=(const ASMCODE32& ac)
    {
        Copy(ac);
        return *this;
    }

    VOID Copy(const ASMCODE32& ac)
    {
        func = ac.func;
        addr = ac.addr;
        name = ac.name;
        operand1 = ac.operand1;
        operand2 = ac.operand2;
        operand3 = ac.operand3;
        codes = ac.codes;
        bt = ac.bt;
        cc = ac.cc;
        jumped_from = ac.jumped_from;
    }

    VOID Clear()
    {
        func = 0;
        addr = 0;
        name.clear();
        operand1.Clear();
        operand2.Clear();
        operand3.Clear();
        codes.clear();
        bt = BT_GONEXT;
        cc = C_none;
        jumped_from.clear();
    }
};
typedef ASMCODE32 *LPASMCODE32;

struct ASMCODE64
{
    ADDR64 func;
    ADDR64 addr;
    string name;
    OPERAND operand1, operand2, operand3;
    vector<BYTE> codes;
    BRANCHTYPE bt;
    CCODE cc;
    vector<ADDR32> jumped_from;

    ASMCODE64()
    {
        Clear();
    }

    ASMCODE64(const ASMCODE64& ac)
    {
        Copy(ac);
    }

    ASMCODE64& operator=(const ASMCODE64& ac)
    {
        Copy(ac);
        return *this;
    }

    VOID Copy(const ASMCODE64& ac)
    {
        func = ac.func;
        addr = ac.addr;
        name = ac.name;
        operand1 = ac.operand1;
        operand2 = ac.operand2;
        operand3 = ac.operand3;
        codes = ac.codes;
        bt = ac.bt;
        cc = ac.cc;
        jumped_from = ac.jumped_from;
    }

    VOID Clear()
    {
        func = 0;
        addr = 0;
        name.clear();
        operand1.Clear();
        operand2.Clear();
        operand3.Clear();
        codes.clear();
        bt = BT_GONEXT;
        cc = C_none;
        jumped_from.clear();
    }
};
typedef ASMCODE64 *LPASMCODE64;

////////////////////////////////////////////////////////////////////////////
// FUNCTIONTYPE

enum FUNCTIONTYPE
{
    FT_UNKNOWN,             // unknown type
    FT_CDECL,               // __cdecl
    FT_STDCALL,             // __stdcall
    FT_FASTCALL,            // __fastcall
    FT_JUMPER,              // jumper function
    FT_APIIMP,              // __imp
    FT_INVALID              // invalid function
};

enum FUNCTIONFLAGS
{
    FF_NOTSTDCALL               = (1 << 0), // not __stdcall
    FF_DONTDECOMPBUTDISASM      = (1 << 1), // don't decompile but disasm
    FF_IGNORE                   = (1 << 2), // ignore
    FF_HASSTACKFRAME            = (1 << 3)  // has stack frame
};

////////////////////////////////////////////////////////////////////////////
// CODEARG

struct CODEARG
{
    string type;
    string name;
    int size;
};

////////////////////////////////////////////////////////////////////////////
// CODEFUNC - code function

struct CODEFUNC
{
    union
    {
        ADDR64 Addr64;
        ADDR32 Addr32;
    };
    string Name;
    FUNCTIONTYPE Type;
    INT SizeOfArgs;
    vector<CODEARG> Args;
    DWORD Flags;

    CODEFUNC()
    {
        Clear();
    }

    CODEFUNC(const CODEFUNC& cf)
    {
        Copy(cf);
    }

    CODEFUNC& operator=(const CODEFUNC& cf)
    {
        Copy(cf);
        return *this;
    }

    VOID Copy(const CODEFUNC& cf)
    {
        Addr64 = cf.Addr64;
        Name = cf.Name;
        Type = cf.Type;
        SizeOfArgs = cf.SizeOfArgs;
        Args = cf.Args;
        Flags = cf.Flags;
    }

    VOID Clear()
    {
        Addr64 = 0;
        Name.clear();
        Type = FT_UNKNOWN;
        SizeOfArgs = -1;
        Args.clear();
        Flags = 0;
    }
};

////////////////////////////////////////////////////////////////////////////
// MZC2

#define MzcAssert assert
#define MzcVerify assert

////////////////////////////////////////////////////////////////////////////
// MZC2 MSecurityAttributes

class MSecurityAttributes : public SECURITY_ATTRIBUTES
{
public:
    MSecurityAttributes(BOOL bInherit = TRUE, LPVOID pSecurityDescriptor = NULL);
};

////////////////////////////////////////////////////////////////////////////
// MZC2 MFile

class MFile
{
public:
    MFile();
    MFile(HANDLE hHandle);
    ~MFile();

    operator HANDLE() const;
    operator PHANDLE();
    PHANDLE operator&();
    bool operator!() const;
    bool operator==(HANDLE hHandle) const;
    bool operator!=(HANDLE hHandle) const;

    MFile& operator=(HANDLE hHandle);
    VOID Attach(HANDLE hHandle);
    HANDLE Detach();
    BOOL CloseHandle();

    BOOL DuplicateHandle(PHANDLE phHandle, BOOL bInherit);
    BOOL DuplicateHandle(
        PHANDLE phHandle, BOOL bInherit, DWORD dwDesiredAccess);
    DWORD WaitForSingleObject(DWORD dwTimeout = INFINITE);

    BOOL PeekNamedPipe(
        LPVOID pBuffer = NULL,
        DWORD cbBuffer = 0,
        LPDWORD pcbRead = NULL,
        LPDWORD pcbAvail = NULL,
        LPDWORD pBytesLeft = NULL);
    BOOL ReadFile(LPVOID pBuffer, DWORD cbToRead, LPDWORD pcbRead,
        LPOVERLAPPED pOverlapped = NULL);
    BOOL WriteFile(LPCVOID pBuffer, DWORD cbToWrite, LPDWORD pcbWritten,
        LPOVERLAPPED pOverlapped = NULL);
    BOOL WriteSzA(LPCSTR psz, LPDWORD pcbWritten,
        LPOVERLAPPED pOverlapped = NULL);
    BOOL WriteSzW(LPCWSTR psz, LPDWORD pcbWritten,
        LPOVERLAPPED pOverlapped = NULL);
    BOOL WriteSz(LPCTSTR psz, LPDWORD pcbWritten,
        LPOVERLAPPED pOverlapped = NULL);

    BOOL WriteBinary(LPCVOID pv, DWORD cb);
    BOOL WriteSzA(LPCSTR psz);
    BOOL WriteSzW(LPCWSTR psz);
    BOOL WriteSz(LPCTSTR psz);
    BOOL __cdecl WriteFormatA(LPCSTR pszFormat, ...);
    BOOL __cdecl WriteFormatW(LPCWSTR pszFormat, ...);
    BOOL __cdecl WriteFormat(LPCTSTR pszFormat, ...);

    BOOL OpenFileForInput(
        LPCTSTR pszFileName, DWORD dwFILE_SHARE_ = FILE_SHARE_READ);
    BOOL OpenFileForOutput(
        LPCTSTR pszFileName, DWORD dwFILE_SHARE_ = FILE_SHARE_READ);
    BOOL OpenFileForRandom(
        LPCTSTR pszFileName, DWORD dwFILE_SHARE_ = FILE_SHARE_READ);
    BOOL OpenFileForAppend(
        LPCTSTR pszFileName, DWORD dwFILE_SHARE_ = FILE_SHARE_READ);

    BOOL CreateFile(LPCTSTR pszFileName, DWORD dwDesiredAccess,
        DWORD dwShareMode, LPSECURITY_ATTRIBUTES pSA,
        DWORD dwCreationDistribution,
        DWORD dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL,
        HANDLE hTemplateFile = NULL);
    DWORD GetFileSize(LPDWORD pdwHighPart = NULL) const;
    BOOL SetEndOfFile();
    DWORD SetFilePointer(
        LONG nDeltaLow, PLONG pnDeltaHigh = NULL, DWORD dwOrigin = FILE_BEGIN);
    VOID SeekToBegin();
    DWORD SeekToEnd();
    BOOL FlushFileBuffers();
    BOOL GetFileTime(
        LPFILETIME pftCreate = NULL,
        LPFILETIME pftLastAccess = NULL,
        LPFILETIME pftLastWrite = NULL) const;

protected:
    HANDLE m_hHandle;
};

////////////////////////////////////////////////////////////////////////////
// MZC2 MProcessMaker

class MProcessMaker
{
public:
    MProcessMaker();
    ~MProcessMaker();

    bool operator!() const;
    HANDLE GetHandle() const;
    DWORD GetExitCode() const;

    VOID SetShowWindow(INT nCmdShow = SW_HIDE);
    VOID SetCreationFlags(DWORD dwFlags = CREATE_NEW_CONSOLE);
    VOID SetCurrentDirectory(LPCTSTR pszCurDir);

    VOID SetDesktop(LPTSTR lpDesktop);
    VOID SetTitle(LPTSTR lpTitle);
    VOID SetPosition(DWORD dwX, DWORD dwY);
    VOID SetSize(DWORD dwXSize, DWORD dwYSize);
    VOID SetCountChars(DWORD dwXCountChars, DWORD dwYCountChars);
    VOID SetFillAttirbutes(DWORD dwFillAttribute);

    VOID SetStdInput(HANDLE hStdIn);
    VOID SetStdOutput(HANDLE hStdOut);
    VOID SetStdError(HANDLE hStdErr);
    BOOL PrepareForRedirect(
        PHANDLE phInputWrite, PHANDLE phOutputRead,
        PHANDLE phErrorRead);

    BOOL CreateProcess(
        LPCTSTR pszAppName, LPCTSTR pszCommandLine = NULL,
        LPCTSTR pszzEnvironment = NULL, BOOL bInherit = TRUE,
        LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL,
        LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL);
    BOOL CreateProcessAsUser(
        HANDLE hToken, LPCTSTR pszAppName, LPCTSTR pszCommandLine = NULL,
        LPCTSTR pszzEnvironment = NULL, BOOL bInherit = TRUE,
        LPSECURITY_ATTRIBUTES lpProcessAttributes = NULL,
        LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL);
    DWORD WaitForExit(DWORD dwTimeout = INFINITE);
    BOOL TerminateProcess(UINT uExitCode);
    BOOL IsRunning() const;
    VOID Close();

public:
    PROCESS_INFORMATION m_pi;
    STARTUPINFO m_si;

protected:
    DWORD   m_dwCreationFlags;
    LPCTSTR m_pszCurDir;
};

////////////////////////////////////////////////////////////////////////////
