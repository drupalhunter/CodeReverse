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

const char * const cr_logo =
"/////////////////////////////////////\n"
"// CodeReverse 0.0.1               //\n"
"// katayama.hirofumi.mz@gmail.com  //\n"
"/////////////////////////////////////\n";

////////////////////////////////////////////////////////////////////////////

struct X86_REGINFO
{
    const char * const name;
    X86_REGTYPE type;
    INT         bits;
};

const X86_REGINFO cr_reg_entries[] =
{
    {"cr0", X86_CRREG,  0},
    {"cr1", X86_CRREG,  0},
    {"cr2", X86_CRREG,  0},
    {"cr3", X86_CRREG,  0},
    {"cr4", X86_CRREG,  0},
    {"cr8", X86_CRREG,  64},
    {"dr0", X86_DRREG,  0},
    {"dr1", X86_DRREG,  0},
    {"dr2", X86_DRREG,  0},
    {"dr3", X86_DRREG,  0},
    {"dr4", X86_DRREG,  0},
    {"dr5", X86_DRREG,  0},
    {"dr6", X86_DRREG,  0},
    {"dr7", X86_DRREG,  0},
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
    {"xmm0",    X86_XMMREG, 0},
    {"xmm1",    X86_XMMREG, 0},
    {"xmm2",    X86_XMMREG, 0},
    {"xmm3",    X86_XMMREG, 0},
    {"xmm4",    X86_XMMREG, 0},
    {"xmm5",    X86_XMMREG, 0},
    {"xmm6",    X86_XMMREG, 0},
    {"xmm7",    X86_XMMREG, 0},
    {"xmm8",    X86_XMMREG, 64},
    {"xmm9",    X86_XMMREG, 64},
    {"xmm10",   X86_XMMREG, 64},
    {"xmm11",   X86_XMMREG, 64},
    {"xmm12",   X86_XMMREG, 64},
    {"xmm13",   X86_XMMREG, 64},
    {"xmm14",   X86_XMMREG, 64},
    {"xmm15",   X86_XMMREG, 64},
    {"ymm0",    X86_YMMREG, 0},
    {"ymm1",    X86_YMMREG, 0},
    {"ymm2",    X86_YMMREG, 0},
    {"ymm3",    X86_YMMREG, 0},
    {"ymm4",    X86_YMMREG, 0},
    {"ymm5",    X86_YMMREG, 0},
    {"ymm6",    X86_YMMREG, 0},
    {"ymm7",    X86_YMMREG, 0},
    {"ymm8",    X86_YMMREG, 64},
    {"ymm9",    X86_YMMREG, 64},
    {"ymm10",   X86_YMMREG, 64},
    {"ymm11",   X86_YMMREG, 64},
    {"ymm12",   X86_YMMREG, 64},
    {"ymm13",   X86_YMMREG, 64},
    {"ymm14",   X86_YMMREG, 64},
    {"ymm15",   X86_YMMREG, 64},
    {"rax", X86_REG64,  64},
    {"rcx", X86_REG64,  64},
    {"rdx", X86_REG64,  64},
    {"rbx", X86_REG64,  64},
    {"rsp", X86_REG64,  64},
    {"rbp", X86_REG64,  64},
    {"rsi", X86_REG64,  64},
    {"rdi", X86_REG64,  64},
    {"r8",  X86_REG64,  64},
    {"r9",  X86_REG64,  64},
    {"r10", X86_REG64,  64},
    {"r11", X86_REG64,  64},
    {"r12", X86_REG64,  64},
    {"r13", X86_REG64,  64},
    {"r14", X86_REG64,  64},
    {"r15", X86_REG64,  64},
    {"eax", X86_REG32,  32},
    {"ecx", X86_REG32,  32},
    {"edx", X86_REG32,  32},
    {"ebx", X86_REG32,  32},
    {"esp", X86_REG32,  32},
    {"ebp", X86_REG32,  32},
    {"esi", X86_REG32,  32},
    {"edi", X86_REG32,  32},
    {"r8d", X86_REG32,  64},
    {"r9d", X86_REG32,  64},
    {"r10d",    X86_REG32,  64},
    {"r11d",    X86_REG32,  64},
    {"r12d",    X86_REG32,  64},
    {"r13d",    X86_REG32,  64},
    {"r14d",    X86_REG32,  64},
    {"r15d",    X86_REG32,  64},
    {"ax",  X86_REG16,  0},
    {"cx",  X86_REG16,  0},
    {"dx",  X86_REG16,  0},
    {"bx",  X86_REG16,  0},
    {"sp",  X86_REG16,  0},
    {"bp",  X86_REG16,  0},
    {"si",  X86_REG16,  0},
    {"di",  X86_REG16,  0},
    {"r8w", X86_REG16,  64},
    {"r9w", X86_REG16,  64},
    {"r10w",    X86_REG16,  64},
    {"r11w",    X86_REG16,  64},
    {"r12w",    X86_REG16,  64},
    {"r13w",    X86_REG16,  64},
    {"r14w",    X86_REG16,  64},
    {"r15w",    X86_REG16,  64},
    {"al",  X86_REG8,   0},
    {"cl",  X86_REG8,   0},
    {"dl",  X86_REG8,   0},
    {"bl",  X86_REG8,   0},
    {"ah",  X86_REG8,   0},
    {"ch",  X86_REG8,   0},
    {"dh",  X86_REG8,   0},
    {"bh",  X86_REG8,   0},
    {"r8b", X86_REG8,   64},
    {"r9b", X86_REG8,   64},
    {"r10b",    X86_REG8,   64},
    {"r11b",    X86_REG8,   64},
    {"r12b",    X86_REG8,   64},
    {"r13b",    X86_REG8,   64},
    {"r14b",    X86_REG8,   64},
    {"r15b",    X86_REG8,   64},
    {"spl", X86_REG8X,  64},
    {"bpl", X86_REG8X,  64},
    {"sil", X86_REG8X,  64},
    {"dil", X86_REG8X,  64},
    {"ip", X86_REG16,    0},
    {"eip", X86_REG32,    32},
    {"rip", X86_REG64,    64},
    {"es",  X86_SEGREG, 64},
    {"cs",  X86_SEGREG, 0},
    {"ss",  X86_SEGREG, 64},
    {"ds",  X86_SEGREG, 64},
    {"fs",  X86_SEGREG, 32},
    {"gs",  X86_SEGREG, 32},
};

////////////////////////////////////////////////////////////////////////////
// cr_reg_get_type, cr_reg_get_size

X86_REGTYPE cr_reg_get_type(const char *name, int bits)
{
    for (size_t i = 0; i < sizeof(cr_reg_entries) / sizeof(cr_reg_entries[0]); i++)
    {
        if (bits >= cr_reg_entries[i].bits &&
            _stricmp(cr_reg_entries[i].name, name) == 0)
        {
            return cr_reg_entries[i].type;
        }
    }
    return X86_REGNONE;
}

DWORD cr_reg_get_size(const char *name, int bits)
{
    switch (cr_reg_get_type(name, bits))
    {
    case X86_CRREG:
        if (bits == 32)
            return 32 / 8;
        else if (bits == 64)
            return 64 / 8;
        break;
    case X86_DRREG:     return 32 / 8;
    case X86_FPUREG:    return 80 / 8;
    case X86_MMXREG:    return 64 / 8;
    case X86_REG8:      return 8 / 8;
    case X86_REG8X:     return 8 / 8;
    case X86_REG16:     return 16 / 8;
    case X86_REG32:     return 32 / 8;
    case X86_REG64:     return 64 / 8;
    case X86_SEGREG:    return 32 / 8;
    case X86_XMMREG:    return 128 / 8;
    case X86_YMMREG:    return 256 / 8;
    default:
        ;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////

VOID OPERAND::SetImm(ULONGLONG val, bool is_signed)
{
    char buf[64];

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

    text = buf;
    type = OT_IMM;
    value = val;
}

////////////////////////////////////////////////////////////////////////////
// MZC2 MSecurityAttributes

MSecurityAttributes::MSecurityAttributes(
    BOOL bInherit/* = TRUE*/, LPVOID pSecurityDescriptor/* = NULL*/)
{
    nLength = sizeof(SECURITY_ATTRIBUTES);
    lpSecurityDescriptor = pSecurityDescriptor;
    bInheritHandle = bInherit;
}

////////////////////////////////////////////////////////////////////////////
// MZC2 MFile

MFile::MFile()
    : m_hHandle(NULL)
{
}

MFile::MFile(HANDLE hHandle)
    : m_hHandle(hHandle)
{
}

MFile::~MFile()
{
    if (m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE)
        MzcVerify(::CloseHandle(m_hHandle));
}

MFile::operator HANDLE() const
{
    return m_hHandle;
}

MFile::operator PHANDLE()
{
    return &m_hHandle;
}

PHANDLE MFile::operator&()
{
    return &m_hHandle;
}

MFile& MFile::operator=(HANDLE hHandle)
{
    if (m_hHandle != hHandle)
    {
        if (m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE)
            MzcVerify(::CloseHandle(m_hHandle));
        Attach(hHandle);
    }
    return *this;
}

bool MFile::operator!() const
{
    return m_hHandle == NULL || m_hHandle == INVALID_HANDLE_VALUE;
}

bool MFile::operator==(HANDLE hHandle) const
{
    return m_hHandle == hHandle;
}

bool MFile::operator!=(HANDLE hHandle) const
{
    return m_hHandle != hHandle;
}

BOOL MFile::OpenFileForInput(
    LPCTSTR pszFileName, DWORD dwFILE_SHARE_/* = FILE_SHARE_READ*/)
{
    return MFile::CreateFile(pszFileName, GENERIC_READ,
        dwFILE_SHARE_, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

BOOL MFile::OpenFileForOutput(
    LPCTSTR pszFileName, DWORD dwFILE_SHARE_/* = FILE_SHARE_READ*/)
{
    return MFile::CreateFile(pszFileName, GENERIC_WRITE,
        dwFILE_SHARE_, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
}

BOOL MFile::OpenFileForRandom(
    LPCTSTR pszFileName, DWORD dwFILE_SHARE_/* = FILE_SHARE_READ*/)
{
    return MFile::CreateFile(pszFileName,
        GENERIC_READ | GENERIC_WRITE, dwFILE_SHARE_, NULL, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
}

BOOL MFile::DuplicateHandle(PHANDLE phHandle, BOOL bInherit)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    HANDLE hProcess = ::GetCurrentProcess();
    return ::DuplicateHandle(hProcess, m_hHandle, hProcess, phHandle, 0,
        bInherit, DUPLICATE_SAME_ACCESS);
}

BOOL MFile::DuplicateHandle(
    PHANDLE phHandle, BOOL bInherit, DWORD dwDesiredAccess)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    HANDLE hProcess = ::GetCurrentProcess();
    return ::DuplicateHandle(hProcess, m_hHandle, hProcess, phHandle,
        dwDesiredAccess, bInherit, 0);
}

DWORD MFile::WaitForSingleObject(
    DWORD dwTimeout/* = INFINITE*/)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::WaitForSingleObject(m_hHandle, dwTimeout);
}

VOID MFile::Attach(HANDLE hHandle)
{
    MzcAssert(m_hHandle == NULL || m_hHandle == INVALID_HANDLE_VALUE);
    m_hHandle = hHandle;
}

HANDLE MFile::Detach()
{
    HANDLE hHandle = m_hHandle;
    m_hHandle = NULL;
    return hHandle;
}

BOOL MFile::CloseHandle()
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    BOOL b = ::CloseHandle(m_hHandle);
    MzcAssert(b);
    m_hHandle = INVALID_HANDLE_VALUE;
    return b;
}

BOOL MFile::PeekNamedPipe(
    LPVOID pBuffer/* = NULL*/,
    DWORD cbBuffer/* = 0*/,
    LPDWORD pcbRead/* = NULL*/,
    LPDWORD pcbAvail/* = NULL*/,
    LPDWORD pBytesLeft/* = NULL*/)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::PeekNamedPipe(m_hHandle, pBuffer, cbBuffer,
        pcbRead, pcbAvail, pBytesLeft);
}

BOOL MFile::ReadFile(LPVOID pBuffer, DWORD cbToRead,
    LPDWORD pcbRead, LPOVERLAPPED pOverlapped/* = NULL*/)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::ReadFile(m_hHandle, pBuffer, cbToRead, pcbRead, pOverlapped);
}

BOOL MFile::WriteFile(LPCVOID pBuffer, DWORD cbToWrite,
    LPDWORD pcbWritten, LPOVERLAPPED pOverlapped/* = NULL*/)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::WriteFile(
        m_hHandle, pBuffer, cbToWrite, pcbWritten, pOverlapped);
}

BOOL MFile::WriteSzA(LPCSTR psz,
    LPDWORD pcbWritten, LPOVERLAPPED pOverlapped/* = NULL*/)
{
    return WriteFile(psz, (DWORD)strlen(psz), pcbWritten, pOverlapped);
}

BOOL MFile::WriteSzW(LPCWSTR psz,
    LPDWORD pcbWritten, LPOVERLAPPED pOverlapped/* = NULL*/)
{
    return WriteFile(psz, (DWORD)(wcslen(psz) * sizeof(WCHAR)), pcbWritten,
        pOverlapped);
}

BOOL MFile::WriteSz(LPCTSTR psz,
    LPDWORD pcbWritten, LPOVERLAPPED pOverlapped/* = NULL*/)
{
    return WriteFile(psz, (DWORD)(_tcslen(psz) * sizeof(TCHAR)), pcbWritten, pOverlapped);
}

BOOL MFile::CreateFile(LPCTSTR pszFileName,
    DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES pSA, DWORD dwCreationDistribution,
    DWORD dwFlagsAndAttributes/* = FILE_ATTRIBUTE_NORMAL*/,
    HANDLE hTemplateFile/* = NULL*/)
{
    MzcAssert(m_hHandle == NULL || m_hHandle == INVALID_HANDLE_VALUE);
    m_hHandle = ::CreateFile(pszFileName, dwDesiredAccess, dwShareMode,
        pSA, dwCreationDistribution, dwFlagsAndAttributes, hTemplateFile);
    return (m_hHandle != INVALID_HANDLE_VALUE);
}

DWORD MFile::SetFilePointer(
    LONG nDeltaLow,
    PLONG pnDeltaHigh/* = NULL*/,
    DWORD dwOrigin/* = FILE_BEGIN*/)
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::SetFilePointer(m_hHandle, nDeltaLow, pnDeltaHigh, dwOrigin);
}

DWORD MFile::SeekToEnd()
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return SetFilePointer(0, NULL, FILE_END);
}

VOID MFile::SeekToBegin()
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    SetFilePointer(0, NULL, FILE_BEGIN);
}

DWORD MFile::GetFileSize(
    LPDWORD pdwHighPart/* = NULL*/) const
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::GetFileSize(m_hHandle, pdwHighPart);
}

BOOL MFile::SetEndOfFile()
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::SetEndOfFile(m_hHandle);
}

BOOL MFile::FlushFileBuffers()
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::FlushFileBuffers(m_hHandle);
}

BOOL MFile::WriteSzA(LPCSTR psz)
{
    INT cb = (INT) strlen(psz);
    return WriteBinary(psz, (DWORD) cb);
}

BOOL MFile::WriteSzW(LPCWSTR psz)
{
    INT cb = (INT) (wcslen(psz) * sizeof(WCHAR));
    return WriteBinary(psz, (DWORD) cb);
}

BOOL MFile::WriteSz(LPCTSTR psz)
{
    INT cb = (INT) (_tcslen(psz) * sizeof(TCHAR));
    return WriteBinary(psz, (DWORD) cb);
}

BOOL __cdecl MFile::WriteFormatA(LPCSTR pszFormat, ...)
{
    va_list argList;
    CHAR sz[1024];
    va_start(argList, pszFormat);
    std::vsprintf(sz, pszFormat, argList);
    BOOL b = WriteSzA(sz);
    va_end(argList);
    return b;
}

BOOL __cdecl MFile::WriteFormatW(LPCWSTR pszFormat, ...)
{
    using namespace std;
    va_list argList;
    WCHAR sz[1024];
    va_start(argList, pszFormat);
    vswprintf(sz, pszFormat, argList);
    BOOL b = WriteSzW(sz);
    va_end(argList);
    return b;
}

BOOL __cdecl MFile::WriteFormat(LPCTSTR pszFormat, ...)
{
    using namespace std;
    va_list argList;
    TCHAR sz[1024];
    va_start(argList, pszFormat);
    _vstprintf(sz, pszFormat, argList);
    BOOL b = WriteSz(sz);
    va_end(argList);
    return b;
}

BOOL MFile::GetFileTime(
    LPFILETIME pftCreate/* = NULL*/,
    LPFILETIME pftLastAccess/* = NULL*/,
    LPFILETIME pftLastWrite/* = NULL*/) const
{
    MzcAssert(m_hHandle != NULL && m_hHandle != INVALID_HANDLE_VALUE);
    return ::GetFileTime(m_hHandle, pftCreate, pftLastAccess, pftLastWrite);
}

BOOL MFile::OpenFileForAppend(
    LPCTSTR pszFileName, DWORD dwFILE_SHARE_/* = FILE_SHARE_READ*/)
{
    BOOL bExisted = (::GetFileAttributes(pszFileName) != 0xFFFFFFFF);
    if (!MFile::CreateFile(pszFileName, GENERIC_READ | GENERIC_WRITE,
        dwFILE_SHARE_, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL))
        return FALSE;
    if (SetFilePointer(0, NULL, FILE_END) == 0xFFFFFFFF)
    {
        MzcAssert(FALSE);
        CloseHandle();
        if (!bExisted)
            ::DeleteFile(pszFileName);
        return FALSE;
    }
    return TRUE;
}

BOOL MFile::WriteBinary(LPCVOID pv, DWORD cb)
{
    CONST BYTE *pb = (CONST BYTE *) pv;
    DWORD cbWritten;
    while (cb != 0)
    {
        if (WriteFile(pb, cb, &cbWritten))
        {
            cb -= cbWritten;
            pb += cbWritten;
        }
        else
            break;
    }
    return (cb == 0) && FlushFileBuffers();
}

////////////////////////////////////////////////////////////////////////////
// MZC2 MProcessMaker

MProcessMaker::~MProcessMaker()
{
    Close();
}

BOOL MProcessMaker::TerminateProcess(UINT uExitCode)
{
    return ::TerminateProcess(m_pi.hProcess, uExitCode);
}

VOID MProcessMaker::SetStdInput(HANDLE hStdIn)
{
    if (hStdIn != NULL)
    {
        m_si.hStdInput = hStdIn;
        m_si.dwFlags |= STARTF_USESTDHANDLES;
    }
}

VOID MProcessMaker::SetStdOutput(HANDLE hStdOut)
{
    if (hStdOut != NULL)
    {
        m_si.hStdOutput = hStdOut;
        m_si.dwFlags |= STARTF_USESTDHANDLES;
    }
}

VOID MProcessMaker::SetStdError(HANDLE hStdErr)
{
    if (hStdErr != NULL)
    {
        m_si.hStdError = hStdErr;
        m_si.dwFlags |= STARTF_USESTDHANDLES;
    }
}

VOID MProcessMaker::SetShowWindow(INT nCmdShow/* = SW_HIDE*/)
{
    m_si.wShowWindow = (WORD) nCmdShow;
    m_si.dwFlags |= STARTF_USESHOWWINDOW;
}

VOID MProcessMaker::SetCreationFlags(
    DWORD dwFlags/* = CREATE_NEW_CONSOLE*/)
{
    m_dwCreationFlags = dwFlags;
}

VOID MProcessMaker::SetCurrentDirectory(LPCTSTR pszCurDir)
{
    m_pszCurDir = pszCurDir;
}

VOID MProcessMaker::SetDesktop(LPTSTR lpDesktop)
{
    m_si.lpDesktop = lpDesktop;
}

VOID MProcessMaker::SetTitle(LPTSTR lpTitle)
{
    m_si.lpTitle = lpTitle;
}

VOID MProcessMaker::SetPosition(DWORD dwX, DWORD dwY)
{
    m_si.dwX = dwX;
    m_si.dwY = dwY;
    m_si.dwFlags |= STARTF_USEPOSITION;
}

VOID MProcessMaker::SetSize(DWORD dwXSize, DWORD dwYSize)
{
    m_si.dwXSize = dwXSize;
    m_si.dwYSize = dwYSize;
    m_si.dwFlags |= STARTF_USESIZE;
}

VOID MProcessMaker::SetCountChars(
    DWORD dwXCountChars, DWORD dwYCountChars)
{
    m_si.dwXCountChars = dwXCountChars;
    m_si.dwYCountChars = dwYCountChars;
    m_si.dwFlags |= STARTF_USECOUNTCHARS;
}

VOID MProcessMaker::SetFillAttirbutes(DWORD dwFillAttribute)
{
    m_si.dwFillAttribute = dwFillAttribute;
    m_si.dwFlags |= STARTF_USEFILLATTRIBUTE;
}

HANDLE MProcessMaker::GetHandle() const
{
    return m_pi.hProcess;
}

DWORD MProcessMaker::GetExitCode() const
{
    MzcAssert(m_pi.hProcess != NULL);
    DWORD dwExitCode;
    ::GetExitCodeProcess(m_pi.hProcess, &dwExitCode);
    return dwExitCode;
}

DWORD MProcessMaker::WaitForExit(DWORD dwTimeout/* = INFINITE*/)
{
    MzcAssert(m_pi.hProcess != NULL);
    return ::WaitForSingleObject(m_pi.hProcess, dwTimeout);
}

BOOL MProcessMaker::IsRunning() const
{
    return (m_pi.hProcess != NULL &&
        ::WaitForSingleObject(m_pi.hProcess, 0) == WAIT_TIMEOUT);
}

bool MProcessMaker::operator!() const
{
    return !IsRunning();
}

MProcessMaker::MProcessMaker()
{
    ZeroMemory(&m_si, sizeof(m_si));
    m_si.cb = sizeof(STARTUPINFO);
    ZeroMemory(&m_pi, sizeof(m_pi));
    m_dwCreationFlags = 0;
    m_pszCurDir = NULL;
    m_si.hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    m_si.hStdOutput = ::GetStdHandle(STD_OUTPUT_HANDLE);
    m_si.hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
}

BOOL MProcessMaker::CreateProcess(
    LPCTSTR pszAppName, LPCTSTR pszCommandLine/* = NULL*/,
    LPCTSTR pszzEnvironment/* = NULL*/, BOOL bInherit/* = TRUE*/,
    LPSECURITY_ATTRIBUTES lpProcessAttributes/* = NULL*/,
    LPSECURITY_ATTRIBUTES lpThreadAttributes/* = NULL*/)
{
    BOOL b;
    if (pszCommandLine == NULL)
    {
#ifdef _UNICODE
        b = ::CreateProcess(pszAppName, NULL,
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags | CREATE_UNICODE_ENVIRONMENT,
            (LPVOID) pszzEnvironment, m_pszCurDir, &m_si, &m_pi);
#else
        b = ::CreateProcess(pszAppName, NULL,
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags, (LPVOID) pszzEnvironment,
            m_pszCurDir, &m_si, &m_pi);
#endif
    }
    else
    {
        LPTSTR pszCmdLine = _tcsdup(pszCommandLine);
#ifdef _UNICODE
        b = ::CreateProcess(pszAppName, pszCmdLine, 
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags | CREATE_UNICODE_ENVIRONMENT,
            (LPVOID) pszzEnvironment, m_pszCurDir, &m_si, &m_pi);
#else
        b = ::CreateProcess(pszAppName, pszCmdLine, 
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags, (LPVOID) pszzEnvironment,
            m_pszCurDir, &m_si, &m_pi);
#endif
        free(pszCmdLine);
    }
    MzcAssert(b);
    return b;
}

BOOL MProcessMaker::CreateProcessAsUser(
    HANDLE hToken, LPCTSTR pszAppName, LPCTSTR pszCommandLine/* = NULL*/,
    LPCTSTR pszzEnvironment/* = NULL*/, BOOL bInherit/* = TRUE*/,
    LPSECURITY_ATTRIBUTES lpProcessAttributes/* = NULL*/,
    LPSECURITY_ATTRIBUTES lpThreadAttributes/* = NULL*/)
{
    BOOL b;
    if (pszCommandLine == NULL)
    {
#ifdef _UNICODE
        b = ::CreateProcessAsUser(hToken, pszAppName, NULL, 
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags | CREATE_UNICODE_ENVIRONMENT,
            (LPVOID) pszzEnvironment, m_pszCurDir, &m_si, &m_pi);
#else
        b = ::CreateProcessAsUser(hToken, pszAppName, NULL, 
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags, (LPVOID) pszzEnvironment,
            m_pszCurDir, &m_si, &m_pi);
#endif
    }
    else
    {
        LPTSTR pszCmdLine = _tcsdup(pszCommandLine);
#ifdef _UNICODE
        b = ::CreateProcessAsUser(hToken, pszAppName, pszCmdLine,
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags | CREATE_UNICODE_ENVIRONMENT,
            (LPVOID) pszzEnvironment, m_pszCurDir, &m_si, &m_pi);
#else
        b = ::CreateProcessAsUser(hToken, pszAppName, pszCmdLine,
            lpProcessAttributes, lpThreadAttributes,
            bInherit, m_dwCreationFlags, (LPVOID) pszzEnvironment,
            m_pszCurDir, &m_si, &m_pi);
#endif
        free(pszCmdLine);
    }
    MzcAssert(b);
    return b;
}

VOID MProcessMaker::Close()
{
    if (m_pi.hProcess != NULL)
    {
        ::CloseHandle(m_pi.hProcess);
        m_pi.hProcess = NULL;
    }
    if (m_pi.hThread != NULL)
    {
        ::CloseHandle(m_pi.hThread);
        m_pi.hThread = NULL;
    }
    HANDLE hStdInput = ::GetStdHandle(STD_INPUT_HANDLE);
    if (m_si.hStdInput != hStdInput)
    {
        ::CloseHandle(m_si.hStdInput);
        m_si.hStdInput = hStdInput;
    }
    HANDLE hStdOutput = ::GetStdHandle(STD_OUTPUT_HANDLE);
    if (m_si.hStdOutput != hStdOutput)
    {
        ::CloseHandle(m_si.hStdOutput);
        m_si.hStdOutput = hStdOutput;
    }
    HANDLE hStdError = ::GetStdHandle(STD_ERROR_HANDLE);
    if (m_si.hStdError != hStdError)
    {
        ::CloseHandle(m_si.hStdError);
        m_si.hStdError = hStdError;
    }
}

BOOL MProcessMaker::PrepareForRedirect(
    PHANDLE phInputWrite, PHANDLE phOutputRead,
    PHANDLE phErrorRead)
{
    MSecurityAttributes sa;

    MFile hInputRead, hInputWriteTmp;
    MFile hOutputReadTmp, hOutputWrite;
    MFile hErrorReadTmp, hErrorWrite;

    if (phInputWrite != NULL)
    {
        if (::CreatePipe(&hInputRead, &hInputWriteTmp, &sa, 0))
        {
            if (!hInputWriteTmp.DuplicateHandle(phInputWrite, FALSE))
                return FALSE;
            hInputWriteTmp.CloseHandle();
        }
        else
            return FALSE;
    }

    if (phOutputRead != NULL)
    {
        if (::CreatePipe(&hOutputReadTmp, &hOutputWrite, &sa, 0))
        {
            if (!hOutputReadTmp.DuplicateHandle(phOutputRead, FALSE))
                return FALSE;
            hOutputReadTmp.CloseHandle();
        }
        else
            return FALSE;
    }

    if (phOutputRead != NULL && phOutputRead == phErrorRead)
    {
        if (!hOutputWrite.DuplicateHandle(&hErrorWrite, TRUE))
            return FALSE;
    }
    else if (phErrorRead != NULL)
    {
        if (::CreatePipe(&hErrorReadTmp, &hErrorWrite, &sa, 0))
        {
            if (!hErrorReadTmp.DuplicateHandle(phErrorRead, FALSE))
                return FALSE;
            hErrorReadTmp.CloseHandle();
        }
        else
            return FALSE;
    }

    if (phInputWrite != NULL)
        SetStdInput(hInputRead.Detach());
    if (phOutputRead != NULL)
        SetStdOutput(hOutputWrite.Detach());
    if (phErrorRead != NULL)
        SetStdError(hErrorWrite.Detach());

    return TRUE;
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

    PEModule module;
    if (module.LoadModule(argv[1]))
    {
        module.DumpHeaders();
        module.DumpImportSymbols();
        module.DumpExportSymbols();
        module.DumpResource();
        module.DumpDelayLoad();
        module.DumpDisAsm();
    }
    else
    {
#ifdef _UNICODE
        fprintf(stderr, "ERROR: Cannot load file '%ls', LastError = %lu\n",
            argv[1], module.GetLastError());
#else
        fprintf(stderr, "ERROR: Cannot load file '%s', LastError = %lu\n",
            argv[1], module.GetLastError());
#endif
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////
