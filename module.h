////////////////////////////////////////////////////////////////////////////
// module.h
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

////////////////////////////////////////////////////////////////////////////
// REAL_IMAGE_SECTION_HEADER, REAL_IMAGE_DATA_DIRECTORY

#include <pshpack1.h>
typedef struct _REAL_IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD   RVA;    // Not VirtualAddress!
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
} REAL_IMAGE_SECTION_HEADER, *PREAL_IMAGE_SECTION_HEADER;
#include <poppack.h>

#include <pshpack1.h>
typedef struct _REAL_IMAGE_DATA_DIRECTORY {
    DWORD RVA;  // Not VirtualAddress!
    DWORD Size;
} REAL_IMAGE_DATA_DIRECTORY, *PREAL_IMAGE_DATA_DIRECTORY;
#include <poppack.h>

////////////////////////////////////////////////////////////////////////////
// IMPORT_SYMBOL

struct IMPORT_SYMBOL
{
    DWORD   dwRVA;
    WORD    wHint;
    union
    {
        struct
        {
            WORD wImportByName;
            WORD wOrdinal;
        } Name;
        LPCSTR pszName;
    };
};
typedef IMPORT_SYMBOL *LPIMPORT_SYMBOL;

////////////////////////////////////////////////////////////////////////////
// EXPORT_SYMBOL

struct EXPORT_SYMBOL
{
    DWORD   dwRVA;
    DWORD   dwOrdinal;
    LPCSTR  pszName;
    LPCSTR  pszForwarded;
};
typedef EXPORT_SYMBOL *LPEXPORT_SYMBOL;

////////////////////////////////////////////////////////////////////////////
// SYMBOL

struct SYMBOL
{
    DWORD dwRVA;
    LPCSTR pszName;
};
typedef SYMBOL *LPSYMBOL;

////////////////////////////////////////////////////////////////////////////
// PEModule

class PEModule
{
public:
    PEModule();
    PEModule(LPCTSTR FileName);
    virtual ~PEModule();

    BOOL LoadModule(LPCTSTR FileName);
    VOID UnloadModule();
    BOOL ModuleLoaded() const;

    BOOL Is32Bit() const;
    BOOL Is64Bit() const;

    VOID DumpHeaders();
    VOID DumpImportSymbols();
    VOID DumpExportSymbols();
    VOID DumpResource();
    VOID DumpDelayLoad();

    DWORD GetFileSize() const;
    DWORD GetLastError() const;

    PIMAGE_DOS_HEADER           GetDosHeader();
    PIMAGE_NT_HEADERS           GetNTHeaders();
    PIMAGE_NT_HEADERS32         GetNTHeaders32();
    PIMAGE_NT_HEADERS64         GetNTHeaders64();
    PIMAGE_FILE_HEADER          GetFileHeader();
    PIMAGE_OPTIONAL_HEADER32    GetOptionalHeader32();
    PIMAGE_OPTIONAL_HEADER64    GetOptionalHeader64();

    DWORD                      GetNumberOfSections() const;
    PREAL_IMAGE_SECTION_HEADER GetSectionHeader(DWORD i) const;
    PREAL_IMAGE_SECTION_HEADER GetCodeSectionHeader() const;

    LPBYTE      GetDirEntryData(DWORD index);
    DWORD       GetDirEntryDataSize(DWORD index) const;
    LPBYTE      GetData(DWORD rva);
    BOOL RVAInDirEntry(DWORD rva, DWORD index) const;

    PIMAGE_IMPORT_DESCRIPTOR    GetImportDescriptors();
    PIMAGE_EXPORT_DIRECTORY     GetExportDirectory();
    PIMAGE_RESOURCE_DIRECTORY   GetResourceDirectory();

    BOOL IsValidAddress(ULONGLONG Address) const;

    BOOL IsDLL() const;
    BOOL IsCUIExe() const;
    BOOL IsGUIExe() const;

    BOOL LoadImportTables();
    BOOL LoadExportTable();
    BOOL LoadDelayLoad();

    const IMPORT_SYMBOL *FindImportSymbolByRVA(DWORD rva) const;
    const IMPORT_SYMBOL *FindImportSymbolByName(LPCSTR Name) const;
    const EXPORT_SYMBOL *FindExportSymbolByRVA(DWORD rva) const;
    const EXPORT_SYMBOL *FindExportSymbolByName(LPCSTR Name) const;
    const SYMBOL *FindSymbolByRVA(DWORD rva) const;
    const SYMBOL *FindSymbolByName(LPCSTR Name) const;
    const SYMBOL *FindSymbolByAddr32(ADDR32 addr) const;
    const SYMBOL *FindSymbolByAddr64(ADDR64 addr) const;

    BOOL AddressInCode32(ADDR32 va) const;
    BOOL AddressInData32(ADDR32 va) const;
    BOOL AddressInCode64(ADDR64 va) const;
    BOOL AddressInData64(ADDR64 va) const;

    BOOL DisAsmAddr32(ADDR32 func, ADDR32 va);
    BOOL DisAsmAddr64(ADDR64 func, ADDR64 va);
    BOOL DisAsm32();
    BOOL DisAsm64();
    BOOL DisAsm();
    BOOL DumpDisAsm();
    BOOL DumpDisAsmFunc32(ADDR32 func);
    BOOL DumpDisAsmFunc64(ADDR64 func);

    BOOL DecompileAddr32(ADDR32 va);
    BOOL DecompileAddr64(ADDR64 va);
    BOOL Decompile32();
    BOOL Decompile64();
    BOOL Decompile();
    BOOL DumpDecompile();

    VOID ParseOperand(OPERAND& opr, INT bits, bool jump = false);

    BOOL AnalyseCF32(CODEFUNC& cf);
    BOOL AnalyseCF64(CODEFUNC& cf);

protected:
    LPCTSTR     m_pszFileName;
    HANDLE      m_hFile;
    HANDLE      m_hFileMapping;
    LPBYTE      m_pFileImage;
    DWORD       m_dwFileSize;
    DWORD       m_dwLastError;
    BOOL        m_bModuleLoaded;
    BOOL        m_bDisAsmed;
    BOOL        m_bDecompiled;

    PIMAGE_DOS_HEADER           m_pDosHeader;
    union
    {
        PIMAGE_NT_HEADERS       m_pNTHeaders;
        PIMAGE_NT_HEADERS32     m_pNTHeaders32;
        PIMAGE_NT_HEADERS64     m_pNTHeaders64;
    };
    PIMAGE_FILE_HEADER          m_pFileHeader;
    PIMAGE_OPTIONAL_HEADER32    m_pOptional32;
    PIMAGE_OPTIONAL_HEADER64    m_pOptional64;

    LPBYTE  m_pLoadedImage;
    DWORD   m_dwHeaderSum, m_dwCheckSum;
    DWORD   m_dwSizeOfOptionalHeader;
    DWORD   m_dwAddressOfEntryPoint;
    DWORD   m_dwBaseOfCode;
    DWORD   m_dwSizeOfImage;
    DWORD   m_dwSizeOfHeaders;
    DWORD   m_dwNumberOfSections;

    PIMAGE_SECTION_HEADER       m_pSectionHeaders;
    PREAL_IMAGE_DATA_DIRECTORY  m_pDataDirectories;

    // import symbols
    vector<string>              m_vImportDllNames;
    map<DWORD, IMPORT_SYMBOL>   m_mRVAToImportSymbol;
    map<string, IMPORT_SYMBOL>  m_mNameToImportSymbol;

    // export symbols
    vector<EXPORT_SYMBOL>       m_vExportSymbols;
    map<DWORD, EXPORT_SYMBOL>   m_mRVAToExportSymbol;
    map<string, EXPORT_SYMBOL>  m_mNameToExportSymbol;

    // symbols
    map<DWORD, SYMBOL>          m_mRVAToSymbol;
    map<string, SYMBOL>         m_mNameToSymbol;

    // map virtual address to asm code
    map<ADDR32, ASMCODE32>      m_mAddrToAsmCode32;
    map<ADDR64, ASMCODE64>      m_mAddrToAsmCode64;

    // entrances
    set<ADDR32>                 m_sEntrances32;
    set<ADDR64>                 m_sEntrances64;

    // delay loading
    vector<ImgDelayDescr>       m_vImgDelayDescrs;

    // map addr to code function
    map<ADDR32, CODEFUNC>       m_mAddrToCF32;
    map<ADDR64, CODEFUNC>       m_mAddrToCF64;

    BOOL _LoadImage(LPVOID Data);
    BOOL _LoadNTHeaders(LPVOID Data);

    BOOL _GetImportDllNames(vector<string>& names);
    BOOL _GetImportSymbols(DWORD dll_index, vector<IMPORT_SYMBOL>& symbols);
    BOOL _GetExportSymbols(vector<EXPORT_SYMBOL>& symbols);

    VOID _ParseInsn32(ASMCODE32& ac, ADDR32 offset, const char *insn);
    VOID _ParseInsn64(ASMCODE64& ac, ADDR64 offset, const char *insn);
};

////////////////////////////////////////////////////////////////////////////
// dumpfn.cpp

LPCSTR GetTimeStampString(DWORD TimeStamp);
LPCSTR GetMachineString(WORD Machine);
LPCSTR GetFileCharacteristicsString(WORD w);
LPCSTR GetSectionFlagsString(DWORD dw);
LPCSTR GetDllCharacteristicsString(WORD w);
LPCSTR GetSubsystemString(WORD w);
VOID DumpDataDirectory(LPVOID Data, DWORD index);
VOID DumpDosHeader(LPVOID Data);
VOID DumpFileHeader(LPVOID Data);
VOID DumpOptionalHeader32(LPVOID Data, DWORD CheckSum);
VOID DumpOptionalHeader64(LPVOID Data, DWORD CheckSum);
VOID DumpSectionHeader(LPVOID Data);
VOID DumpCodes(const vector<BYTE>& codes, INT bits);

////////////////////////////////////////////////////////////////////////////
// inline functions

inline DWORD PEModule::GetFileSize() const
{
    return m_dwFileSize;
}

inline DWORD PEModule::GetLastError() const
{
    return m_dwLastError;
}

inline BOOL PEModule::Is32Bit() const
{
    return m_pOptional32 != NULL;
}

inline BOOL PEModule::Is64Bit() const
{
    return m_pOptional64 != NULL;
}

inline BOOL PEModule::ModuleLoaded() const
{
    return m_bModuleLoaded;
}

inline PIMAGE_DOS_HEADER PEModule::GetDosHeader()
{
    return m_pDosHeader;
}

inline PIMAGE_NT_HEADERS PEModule::GetNTHeaders()
{
#ifdef _WIN64
    return GetNTHeaders64();
#else
    return GetNTHeaders32();
#endif
}

inline PIMAGE_NT_HEADERS32 PEModule::GetNTHeaders32()
{
    return Is32Bit() ? m_pNTHeaders32 : NULL;
}

inline PIMAGE_NT_HEADERS64 PEModule::GetNTHeaders64()
{
    return Is64Bit() ? m_pNTHeaders64 : NULL;
}

inline PIMAGE_FILE_HEADER PEModule::GetFileHeader()
{
    return m_pFileHeader;
}

inline PIMAGE_OPTIONAL_HEADER32 PEModule::GetOptionalHeader32()
{
    return m_pOptional32;
}

inline PIMAGE_OPTIONAL_HEADER64 PEModule::GetOptionalHeader64()
{
    return m_pOptional64;
}

inline LPBYTE PEModule::GetData(DWORD rva)
{
    return (m_pLoadedImage ? m_pLoadedImage + rva : NULL);
}

inline PREAL_IMAGE_SECTION_HEADER PEModule::GetSectionHeader(DWORD i) const
{
    if (i < m_dwNumberOfSections && m_pSectionHeaders)
        return reinterpret_cast<PREAL_IMAGE_SECTION_HEADER>(&m_pSectionHeaders[i]);
    return NULL;
}

inline DWORD PEModule::GetNumberOfSections() const
{
    return m_dwNumberOfSections;
}

inline DWORD PEModule::GetDirEntryDataSize(DWORD index) const
{
    return (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ? m_pDataDirectories[index].Size : 0);
}

inline BOOL PEModule::RVAInDirEntry(DWORD rva, DWORD index) const
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        m_pDataDirectories[index].RVA <= rva &&
        rva < m_pDataDirectories[index].RVA + m_pDataDirectories[index].Size)
    {
        return TRUE;
    }
    return FALSE;
}

inline PIMAGE_IMPORT_DESCRIPTOR PEModule::GetImportDescriptors()
{
    return (PIMAGE_IMPORT_DESCRIPTOR)GetDirEntryData(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

inline PIMAGE_EXPORT_DIRECTORY PEModule::GetExportDirectory()
{
    return (PIMAGE_EXPORT_DIRECTORY)GetDirEntryData(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

inline PIMAGE_RESOURCE_DIRECTORY PEModule::GetResourceDirectory()
{
    return (PIMAGE_RESOURCE_DIRECTORY)GetDirEntryData(IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

inline BOOL PEModule::IsValidAddress(ULONGLONG Address) const
{
    if (!ModuleLoaded())
        return FALSE;

    if (Is64Bit())
        return Address - m_pOptional64->ImageBase < m_dwSizeOfImage;
    else
        return Address - m_pOptional32->ImageBase < m_dwSizeOfImage;
}

inline BOOL PEModule::IsDLL() const
{
    if (!ModuleLoaded())
        return FALSE;

    return (m_pFileHeader->Characteristics & IMAGE_FILE_DLL) != 0;
}

inline BOOL PEModule::IsCUIExe() const
{
    if (!ModuleLoaded() || IsDLL())
        return FALSE;
    if (Is64Bit())
        return m_pOptional64->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    else
        return m_pOptional32->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
}

inline BOOL PEModule::IsGUIExe() const
{
    if (!ModuleLoaded() || IsDLL())
        return FALSE;
    if (Is64Bit())
        return m_pOptional64->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
    else
        return m_pOptional32->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
}

inline BOOL PEModule::DisAsm()
{
    if (Is64Bit())
        return DisAsm64();
    else if (Is32Bit())
        return DisAsm32();
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
