// module.h
// Copyright (C) 2013 Katayama Hirofumi MZ.  All rights reserved.

////////////////////////////////////////////////////////////////////////////
// REAL_IMAGE_SECTION_HEADER

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

    const IMPORT_SYMBOL *FindImportSymbolByRVA(DWORD RVA) const;
    const IMPORT_SYMBOL *FindImportSymbolByName(LPCSTR Name) const;
    const EXPORT_SYMBOL *FindExportSymbolByRVA(DWORD RVA) const;
    const EXPORT_SYMBOL *FindExportSymbolByName(LPCSTR Name) const;
    const SYMBOL *FindSymbolByRVA(DWORD RVA) const;
    const SYMBOL *FindSymbolByName(LPCSTR Name) const;

    BOOL AddressInCode32(ADDRESS32 VA) const;
    BOOL AddressInData32(ADDRESS32 VA) const;
    BOOL AddressInCode64(ADDRESS64 VA) const;
    BOOL AddressInData64(ADDRESS64 VA) const;

    BOOL DisAsm32();
    BOOL DisAsm64();
    BOOL DisAsm();
    BOOL DumpDisAsm();

protected:
    LPCTSTR     m_pszFileName;
    HANDLE      m_hFile;
    HANDLE      m_hFileMapping;
    LPBYTE      m_pFileImage;
    DWORD       m_dwFileSize;
    DWORD       m_dwLastError;
    BOOL        m_bModuleLoaded;
    BOOL        m_bDisAsmed;

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
    PIMAGE_DATA_DIRECTORY       m_pDataDirectories;

    // import
    vector<string> m_vImportDllNames;
    map<DWORD, IMPORT_SYMBOL>   m_mRVAToImportSymbol;
    map<string, IMPORT_SYMBOL>  m_mNameToImportSymbol;

    // export
    vector<EXPORT_SYMBOL>       m_vExportSymbols;
    map<DWORD, EXPORT_SYMBOL>   m_mRVAToExportSymbol;
    map<string, EXPORT_SYMBOL>  m_mNameToExportSymbol;

    // symbols
    map<DWORD, SYMBOL>          m_mRVAToSymbol;
    map<string, SYMBOL>         m_mNameToSymbol;

    // map address to codepoint
    map<DWORD, CODEPOINT32>     m_mapAddrToCodePoint32;
    map<ULONGLONG, CODEPOINT64> m_mapAddrToCodePoint64;

    BOOL _LoadImage(LPVOID Data);
    BOOL _LoadNTHeaders(LPVOID Data);

    BOOL _GetImportDllNames(vector<string>& names);
    BOOL _GetImportSymbols(DWORD dll_index, vector<IMPORT_SYMBOL>& symbols);
    BOOL _GetExportSymbols(vector<EXPORT_SYMBOL>& symbols);

    VOID _ParseInsn32(CODEPOINT32& cp, ADDRESS32 offset, const char *insn);
    VOID _ParseInsn64(CODEPOINT64& cp, ADDRESS64 offset, const char *insn);
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
        m_pDataDirectories[index].VirtualAddress <= rva &&
        rva < m_pDataDirectories[index].VirtualAddress + m_pDataDirectories[index].Size)
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
