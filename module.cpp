////////////////////////////////////////////////////////////////////////////
// module.cpp
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
// along with CodeReverse.  If .OperandType(), see <http://www.gnu.org/licenses/>.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////
// PEMODULE::PEMODULEIMPL

struct PEMODULE::PEMODULEIMPL
{
    LPCTSTR     pszFileName;
    HANDLE      hFile;
    HANDLE      hFileMapping;
    LPBYTE      pFileImage;
    DWORD       dwFileSize;
    DWORD       dwLastError;
    BOOL        bModuleLoaded;
    BOOL        bDisAsmed;
    BOOL        bDecompiled;

    PIMAGE_DOS_HEADER           pDOSHeader;
    union
    {
        PIMAGE_NT_HEADERS       pNTHeaders;
        PIMAGE_NT_HEADERS32     pNTHeaders32;
        PIMAGE_NT_HEADERS64     pNTHeaders64;
    };
    PIMAGE_FILE_HEADER          pFileHeader;
    PIMAGE_OPTIONAL_HEADER32    pOptional32;
    PIMAGE_OPTIONAL_HEADER64    pOptional64;

    LPBYTE  pLoadedImage;
    DWORD   dwHeaderSum, dwCheckSum;
    DWORD   dwSizeOfOptionalHeader;
    DWORD   dwAddressOfEntryPoint;
    DWORD   dwBaseOfCode;
    DWORD   dwSizeOfHeaders;

    PREAL_IMAGE_SECTION_HEADER  pSectionHeaders;
    PREAL_IMAGE_DATA_DIRECTORY  pDataDirectories;

    // import symbols
    vector<string>              vImportDllNames;
    map<DWORD, IMPORT_SYMBOL>   mRVAToImportSymbol;
    map<string, IMPORT_SYMBOL>  mNameToImportSymbol;

    // export symbols
    vector<EXPORT_SYMBOL>       vExportSymbols;
    map<DWORD, EXPORT_SYMBOL>   mRVAToExportSymbol;
    map<string, EXPORT_SYMBOL>  mNameToExportSymbol;

    // symbols
    map<DWORD, SYMBOL>          mRVAToSymbol;
    map<string, SYMBOL>         mNameToSymbol;

    // delay loading
    vector<ImgDelayDescr>       vImgDelayDescrs;

    PEMODULEIMPL()
    {
        pszFileName = NULL;
        hFile = INVALID_HANDLE_VALUE;
        hFileMapping = NULL;
        pFileImage = NULL;
        dwFileSize = 0;
        dwLastError = ERROR_SUCCESS;
        bModuleLoaded = FALSE;
        bDisAsmed = FALSE;
        bDecompiled = FALSE;
        pDOSHeader = NULL;
        pNTHeaders = NULL;
        pFileHeader = NULL;
        pOptional32 = NULL;
        pOptional64 = NULL;
        pLoadedImage = NULL;
        dwHeaderSum = 0;
        dwCheckSum = 0;
        dwSizeOfOptionalHeader = 0;
        dwAddressOfEntryPoint = 0;
        dwBaseOfCode = 0;
        dwSizeOfHeaders = 0;
        pSectionHeaders = NULL;
        pDataDirectories = NULL;
    }

    virtual ~PEMODULEIMPL()
    {
        Clear();
    }

    VOID Clear()
    {
        if (pLoadedImage != NULL)
        {
            VirtualFree(pLoadedImage, 0, MEM_RELEASE);
            pLoadedImage = NULL;
        }
        if (pFileImage != NULL)
        {
            UnmapViewOfFile(pFileImage);
            pFileImage = NULL;
        }
        if (hFileMapping != NULL)
        {
            CloseHandle(hFileMapping);
            hFileMapping = NULL;
        }
        if (hFile != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        pszFileName = NULL;
        dwFileSize = 0;
        bModuleLoaded = FALSE;
        pDOSHeader = NULL;
        pNTHeaders = NULL;
        pFileHeader = NULL;
        pOptional32 = NULL;
        pOptional64 = NULL;
        dwHeaderSum = 0;
        dwCheckSum = 0;
        dwSizeOfOptionalHeader = 0;
        dwAddressOfEntryPoint = 0;
        dwBaseOfCode = 0;
        dwSizeOfHeaders = 0;
        pSectionHeaders = NULL;
        pDataDirectories = NULL;

        vImportDllNames.clear();
        vExportSymbols.clear();
        mRVAToImportSymbol.clear();
        mNameToImportSymbol.clear();
        mRVAToExportSymbol.clear();
        mNameToExportSymbol.clear();
        mRVAToSymbol.clear();
        mNameToSymbol.clear();

        bDisAsmed = FALSE;
        bDecompiled = FALSE;

        vImgDelayDescrs.clear();
    }

private:
    // Don't copy this!
    PEMODULEIMPL(const PEMODULE::PEMODULEIMPL& impl);
    PEMODULEIMPL& operator=(const PEMODULE::PEMODULEIMPL& impl);
};

////////////////////////////////////////////////////////////////////////////
// PEMODULE attributes

BOOL PEMODULE::IsDLL() const
{
    if (!IsModuleLoaded())
        return FALSE;

    return (FileHeader()->Characteristics & IMAGE_FILE_DLL) != 0;
}

BOOL PEMODULE::IsCUIExe() const
{
    if (!IsModuleLoaded() || IsDLL())
        return FALSE;

    if (Is64Bit())
        return OptionalHeader64()->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    else if (Is32Bit())
        return OptionalHeader32()->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
    else
        return FALSE;
}

BOOL PEMODULE::IsGUIExe() const
{
    if (!IsModuleLoaded() || IsDLL())
        return FALSE;

    if (Is64Bit())
        return OptionalHeader64()->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
    else if (Is32Bit())
        return OptionalHeader32()->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI;
    else
        return FALSE;
}

DWORD PEMODULE::GetFileSize() const
{
    return m_pImpl->dwFileSize;
}

LPCTSTR PEMODULE::GetFileName() const
{
    return m_pImpl->pszFileName;
}

BOOL PEMODULE::Is32Bit() const
{
    return OptionalHeader32() != NULL;
}

BOOL PEMODULE::Is64Bit() const
{
    return OptionalHeader64() != NULL;
}

BOOL PEMODULE::IsModuleLoaded() const
{
    return m_pImpl->bModuleLoaded;
}

BOOL PEMODULE::RVAInDirEntry(DWORD rva, DWORD index) const
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        DataDirectories()[index].RVA <= rva &&
        rva < DataDirectories()[index].RVA + DataDirectories()[index].Size)
    {
        return TRUE;
    }
    return FALSE;
}

BOOL PEMODULE::IsValidAddress(ULONGLONG Address) const
{
    if (!IsModuleLoaded())
        return FALSE;

    if (Is64Bit())
        return Address - OptionalHeader64()->ImageBase < GetSizeOfImage();
    else
        return Address - OptionalHeader32()->ImageBase < GetSizeOfImage();
}

DWORD PEMODULE::GetBaseOfCode() const
{
    if (Is64Bit())
        return OptionalHeader64()->BaseOfCode;
    else if (Is32Bit())
        return OptionalHeader32()->BaseOfCode;
    else
        return 0;
}

DWORD PEMODULE::GetSizeOfHeaders() const
{
    if (Is64Bit())
        return OptionalHeader64()->SizeOfHeaders;
    else if (Is32Bit())
        return OptionalHeader32()->SizeOfHeaders;
    else
        return 0;
}

DWORD PEMODULE::GetSizeOfImage() const
{
    if (Is64Bit())
        return OptionalHeader64()->SizeOfImage;
    else if (Is32Bit())
        return OptionalHeader32()->SizeOfImage;
    else
        return 0;
}

PIMAGE_IMPORT_DESCRIPTOR PEMODULE::ImportDescriptors()
{
    return (PIMAGE_IMPORT_DESCRIPTOR)DirEntryData(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

PIMAGE_EXPORT_DIRECTORY PEMODULE::ExportDirectory()
{
    return (PIMAGE_EXPORT_DIRECTORY)DirEntryData(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

PIMAGE_RESOURCE_DIRECTORY PEMODULE::ResourceDirectory()
{
    return (PIMAGE_RESOURCE_DIRECTORY)DirEntryData(IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

LPBYTE PEMODULE::GetData(DWORD rva)
{
    return (LoadedImage() ? LoadedImage() + rva : NULL);
}

LPBYTE& PEMODULE::LoadedImage()
{
    return m_pImpl->pLoadedImage;
}

LPBYTE& PEMODULE::FileImage()
{
    return m_pImpl->pFileImage;
}

DWORD PEMODULE::GetSizeOfOptionalHeader() const
{
    if (FileHeader())
        return FileHeader()->SizeOfOptionalHeader;
    else
        return 0;
}

DWORD PEMODULE::DirEntryDataSize(DWORD index) const
{
    return (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ? DataDirectories()[index].Size : 0);
}

LPBYTE PEMODULE::DirEntryData(DWORD index)
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
        if (DataDirectories()[index].RVA != 0 &&
            DataDirectories()[index].Size != 0)
        {
            return LoadedImage() + DataDirectories()[index].RVA;
        }
    }
    return NULL;
}

BOOL PEMODULE::AddressInCode32(ADDR32 va) const
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    DWORD rva = (DWORD)(DWORD_PTR)(va - OptionalHeader32()->ImageBase);

    return (pCode->RVA <= rva && rva < pCode->RVA + pCode->Misc.VirtualSize);
}

BOOL PEMODULE::AddressInData32(ADDR32 va) const
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    DWORD rva;

    const DWORD dwFlags = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
    DWORD size = NumberOfSections();
    for (DWORD i = 0; i < size; i++)
    {
        if (SectionHeader(i)->Characteristics & dwFlags)
            continue;

        rva = va - OptionalHeader32()->ImageBase;

        pHeader = SectionHeader(i);
        if (pHeader->RVA <= rva && rva < pHeader->RVA + pHeader->Misc.VirtualSize)
            return TRUE;
    }
    return FALSE;
}

BOOL PEMODULE::AddressInCode64(ADDR64 va) const
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    DWORD rva = (DWORD)(DWORD_PTR)(va - OptionalHeader64()->ImageBase);

    return (pCode->RVA <= rva && rva < pCode->RVA + pCode->Misc.VirtualSize);
}

BOOL PEMODULE::AddressInData64(ADDR64 va) const
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    DWORD rva;

    const DWORD dwFlags = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
    DWORD size = NumberOfSections();
    for (DWORD i = 0; i < size; i++)
    {
        if (SectionHeader(i)->Characteristics & dwFlags)
            continue;

        rva = (DWORD)(DWORD_PTR)(va - OptionalHeader64()->ImageBase);

        pHeader = SectionHeader(i);
        if (pHeader->RVA <= rva && rva < pHeader->RVA + pHeader->Misc.VirtualSize)
            return TRUE;
    }
    return FALSE;
}

DWORD PEMODULE::RVAOfEntryPoint() const
{
    if (Is64Bit())
        return OptionalHeader64()->AddressOfEntryPoint;
    else if (Is32Bit())
        return OptionalHeader32()->AddressOfEntryPoint;
    else
        return 0;
}

DWORD PEMODULE::RVAFromVA32(ADDR32 va) const
{
    assert(OptionalHeader32());
    return va - OptionalHeader32()->ImageBase;
}

DWORD PEMODULE::RVAFromVA64(ADDR64 va) const
{
    assert(OptionalHeader64());
    return (DWORD)(va - OptionalHeader64()->ImageBase);
}

ADDR32 PEMODULE::VA32FromRVA(DWORD rva) const
{
    assert(OptionalHeader32());
    return OptionalHeader32()->ImageBase + rva;
}

ADDR64 PEMODULE::VA64FromRVA(DWORD rva) const
{
    assert(OptionalHeader64());
    return OptionalHeader64()->ImageBase + rva;
}

DWORD PEMODULE::CheckSum() const
{
    return m_pImpl->dwCheckSum;
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE accessors

WORD& PEMODULE::NumberOfSections()
{
    return FileHeader()->NumberOfSections;
}

DWORD& PEMODULE::LastError()
{
    return m_pImpl->dwLastError;
}

PIMAGE_DOS_HEADER PEMODULE::DOSHeader()
{
    return m_pImpl->pDOSHeader;
}

PIMAGE_NT_HEADERS32 PEMODULE::NTHeaders32()
{
    return Is32Bit() ? m_pImpl->pNTHeaders32 : NULL;
}

PIMAGE_NT_HEADERS64 PEMODULE::NTHeaders64()
{
    return Is64Bit() ? m_pImpl->pNTHeaders64 : NULL;
}

PIMAGE_FILE_HEADER PEMODULE::FileHeader()
{
    return m_pImpl->pFileHeader;
}

PIMAGE_OPTIONAL_HEADER32& PEMODULE::OptionalHeader32()
{
    return m_pImpl->pOptional32;
}

PIMAGE_OPTIONAL_HEADER64& PEMODULE::OptionalHeader64()
{
    return m_pImpl->pOptional64;
}

PREAL_IMAGE_DATA_DIRECTORY& PEMODULE::DataDirectories()
{
    return m_pImpl->pDataDirectories;
}

PREAL_IMAGE_DATA_DIRECTORY PEMODULE::DataDirectory(DWORD index)
{
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    return &m_pImpl->pDataDirectories[index];
}

PREAL_IMAGE_SECTION_HEADER PEMODULE::CodeSectionHeader()
{
    assert(m_pImpl->pSectionHeaders);
    DWORD size = NumberOfSections();
    for (DWORD i = 0; i < size; i++)
    {
        PREAL_IMAGE_SECTION_HEADER pHeader = SectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            return pHeader;
    }
    return NULL;
}

PREAL_IMAGE_SECTION_HEADER& PEMODULE::SectionHeaders()
{
    return m_pImpl->pSectionHeaders;
}

PREAL_IMAGE_SECTION_HEADER PEMODULE::SectionHeader(DWORD index)
{
    assert(m_pImpl->pSectionHeaders);
    if (index < NumberOfSections())
    {
        return &m_pImpl->pSectionHeaders[index];
    }
    return NULL;
}

vector<EXPORT_SYMBOL>& PEMODULE::ExportSymbols()
{
    return m_pImpl->vExportSymbols;
}

vector<string>& PEMODULE::ImportDllNames()
{
    return m_pImpl->vImportDllNames;
}

vector<ImgDelayDescr>& PEMODULE::DelayLoadDescriptors()
{
    return m_pImpl->vImgDelayDescrs;
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE const accessors

const WORD& PEMODULE::NumberOfSections() const
{
    return FileHeader()->NumberOfSections;
}

const DWORD& PEMODULE::LastError() const
{
    return m_pImpl->dwLastError;
}

const PIMAGE_DOS_HEADER PEMODULE::DOSHeader() const
{
    return m_pImpl->pDOSHeader;
}

const PIMAGE_NT_HEADERS32 PEMODULE::NTHeaders32() const
{
    return Is32Bit() ? m_pImpl->pNTHeaders32 : NULL;
}

const PIMAGE_NT_HEADERS64 PEMODULE::NTHeaders64() const
{
    return Is64Bit() ? m_pImpl->pNTHeaders64 : NULL;
}

const PIMAGE_FILE_HEADER PEMODULE::FileHeader() const
{
    return m_pImpl->pFileHeader;
}

const PIMAGE_OPTIONAL_HEADER32& PEMODULE::OptionalHeader32() const
{
    return m_pImpl->pOptional32;
}

const PIMAGE_OPTIONAL_HEADER64& PEMODULE::OptionalHeader64() const
{
    return m_pImpl->pOptional64;
}

const PREAL_IMAGE_DATA_DIRECTORY& PEMODULE::DataDirectories() const
{
    return m_pImpl->pDataDirectories;
}

const PREAL_IMAGE_DATA_DIRECTORY PEMODULE::DataDirectory(DWORD index) const
{
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    return &m_pImpl->pDataDirectories[index];
}

const PREAL_IMAGE_SECTION_HEADER PEMODULE::CodeSectionHeader() const
{
    assert(m_pImpl->pSectionHeaders != NULL);

    DWORD size = NumberOfSections();
    for (DWORD i = 0; i < size; i++)
    {
        PREAL_IMAGE_SECTION_HEADER pHeader = SectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            return pHeader;
    }
    return NULL;
}

const PREAL_IMAGE_SECTION_HEADER& PEMODULE::SectionHeaders() const
{
    return m_pImpl->pSectionHeaders;
}

const PREAL_IMAGE_SECTION_HEADER PEMODULE::SectionHeader(DWORD index) const
{
    assert(m_pImpl->pSectionHeaders);
    if (index < NumberOfSections())
    {
        return &m_pImpl->pSectionHeaders[index];
    }
    return NULL;
}

const vector<EXPORT_SYMBOL>& PEMODULE::ExportSymbols() const
{
    return m_pImpl->vExportSymbols;
}

const vector<string>& PEMODULE::ImportDllNames() const
{
    return m_pImpl->vImportDllNames;
}

const vector<ImgDelayDescr>& PEMODULE::DelayLoadDescriptors() const
{
    return m_pImpl->vImgDelayDescrs;
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE

PEMODULE::PEMODULE() : m_pImpl(new PEMODULE::PEMODULEIMPL)
{
}

PEMODULE::PEMODULE(LPCTSTR FileName) : m_pImpl(new PEMODULE::PEMODULEIMPL)
{
    LoadModule(FileName);
}

/*virtual*/ PEMODULE::~PEMODULE()
{
    if (IsModuleLoaded())
        UnloadModule();

    delete m_pImpl;
}

VOID PEMODULE::UnloadModule()
{
    m_pImpl->Clear();
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE loading

BOOL PEMODULE::_LoadImage(LPVOID Data)
{
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)Data;
    PIMAGE_NT_HEADERS pNTHeaders;

    if (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE && pDOSHeader->e_lfanew)  // "MZ"
    {
        pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)Data + pDOSHeader->e_lfanew);
    }
    else
    {
        pDOSHeader = NULL;
        pNTHeaders = (PIMAGE_NT_HEADERS)Data;
    }
    m_pImpl->pDOSHeader = pDOSHeader;

    if (pNTHeaders->Signature == IMAGE_NT_SIGNATURE) // "PE\0\0"
    {
        if (_LoadNTHeaders(pNTHeaders))
        {
            LoadedImage() = (LPBYTE)VirtualAlloc(
                NULL,
                GetSizeOfImage() + 16,
                MEM_COMMIT,
                PAGE_READWRITE);
            if (LoadedImage() != NULL)
            {
                CopyMemory(LoadedImage(), FileImage(), GetSizeOfHeaders());

                DWORD size = NumberOfSections();
                PREAL_IMAGE_SECTION_HEADER Headers = SectionHeaders();
                for (DWORD i = 0; i < size; i++)
                {
                    CopyMemory(
                        &LoadedImage()[Headers[i].RVA],
                        &FileImage()[Headers[i].PointerToRawData],
                        Headers[i].SizeOfRawData);
                }
                return TRUE;
            }
        }
    }

    return FALSE;
}

BOOL PEMODULE::_LoadNTHeaders(LPVOID Data)
{
#ifndef IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
    #define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER sizeof(IMAGE_OPTIONAL_HEADER32)
#endif
#ifndef IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
    #define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER sizeof(IMAGE_OPTIONAL_HEADER64)
#endif

    PIMAGE_FILE_HEADER pFileHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptional32;
    PIMAGE_OPTIONAL_HEADER64 pOptional64;
    m_pImpl->pNTHeaders = (PIMAGE_NT_HEADERS)Data;
    pFileHeader = &m_pImpl->pNTHeaders->FileHeader;

    LPBYTE pb;
    switch(pFileHeader->SizeOfOptionalHeader)
    {
    case IMAGE_SIZEOF_NT_OPTIONAL32_HEADER:
        m_pImpl->pFileHeader = pFileHeader;
        m_pImpl->pOptional32 = pOptional32 = &m_pImpl->pNTHeaders32->OptionalHeader;;
        if (pOptional32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return FALSE;

        pb = (LPBYTE)pOptional32 + pFileHeader->SizeOfOptionalHeader;
        m_pImpl->pSectionHeaders = (PREAL_IMAGE_SECTION_HEADER)pb;
        DataDirectories() = (PREAL_IMAGE_DATA_DIRECTORY)pOptional32->DataDirectory;
        break;

    case IMAGE_SIZEOF_NT_OPTIONAL64_HEADER:
        m_pImpl->pFileHeader = pFileHeader;
        m_pImpl->pOptional64 = pOptional64 = &m_pImpl->pNTHeaders64->OptionalHeader;
        if (pOptional64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return FALSE;

        pb = (LPBYTE)pOptional64 + pFileHeader->SizeOfOptionalHeader;
        m_pImpl->pSectionHeaders = (PREAL_IMAGE_SECTION_HEADER)pb;
        DataDirectories() = (PREAL_IMAGE_DATA_DIRECTORY)pOptional64->DataDirectory;
        break;

    default:
        m_pImpl->pFileHeader = NULL;
        m_pImpl->pNTHeaders = NULL;
        m_pImpl->pOptional32 = NULL;
        m_pImpl->pOptional64 = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL PEMODULE::LoadModule(LPCTSTR FileName)
{
    m_pImpl->hFile = CreateFile(FileName, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (m_pImpl->hFile == INVALID_HANDLE_VALUE)
    {
        LastError() = GetLastError();
        return FALSE;
    }

    m_pImpl->dwFileSize = ::GetFileSize(m_pImpl->hFile, NULL);
    if (m_pImpl->dwFileSize == 0xFFFFFFFF)
    {
        LastError() = GetLastError();
        CloseHandle(m_pImpl->hFile);
        return FALSE;
    }

    m_pImpl->hFileMapping = CreateFileMappingA(
        m_pImpl->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (m_pImpl->hFileMapping != NULL)
    {
        FileImage() = (LPBYTE)MapViewOfFile(
            m_pImpl->hFileMapping,
            FILE_MAP_READ,
            0, 0,
            m_pImpl->dwFileSize);
        if (FileImage() != NULL)
        {
#ifndef NO_CHECKSUM
            CheckSumMappedFile(
                FileImage(), m_pImpl->dwFileSize,
                &m_pImpl->dwHeaderSum, &m_pImpl->dwCheckSum);
#endif
            if (_LoadImage(FileImage()))
            {
                LoadImportTables();
                LoadExportTable();
                m_pImpl->bModuleLoaded = TRUE;
                m_pImpl->pszFileName = FileName;
                return TRUE;
            }
            LastError() = ERROR_INVALID_DATA;
        }
        else
        {
            LastError() = GetLastError();
        }
        CloseHandle(m_pImpl->hFileMapping);
        m_pImpl->hFileMapping = NULL;
    }
    else
    {
        LastError() = GetLastError();
    }

    CloseHandle(m_pImpl->hFile);
    m_pImpl->hFile = INVALID_HANDLE_VALUE;

    return FALSE;
}

BOOL PEMODULE::LoadImportTables()
{
    vector<IMPORT_SYMBOL> symbols;
    SYMBOL symbol;

    if (!_GetImportDllNames(ImportDllNames()))
        return FALSE;

    DWORD size = (DWORD)ImportDllNames().size();
    for (DWORD i = 0; i < size; i++)
    {
        if (_GetImportSymbols(i, symbols))
        {
            for (DWORD j = 0; j < symbols.size(); j++)
            {
                symbol.dwRVA = symbols[j].dwRVA;
                symbol.pszName = symbols[j].pszName;
                AddMapRVAToSymbol(symbol.dwRVA, symbol);
                AddMapRVAToImportSymbol(symbols[j].dwRVA, symbols[j]);
                if (symbols[j].Name.wImportByName)
                {
                    AddMapNameToImportSymbol(symbols[j].pszName, symbols[j]);
                    AddMapNameToSymbol(symbol.pszName, symbol);
                }
            }
        }
    }
    return TRUE;
}

BOOL PEMODULE::LoadExportTable()
{
    vector<EXPORT_SYMBOL> symbols;
    SYMBOL symbol;

    ExportSymbols().clear();

    if (!_GetExportSymbols(symbols))
        return FALSE;

    ExportSymbols() = symbols;

    for (DWORD i = 0; i < (DWORD)symbols.size(); i++)
    {
        if (symbols[i].dwRVA == 0 || symbols[i].pszForwarded)
            continue;

        if (symbols[i].dwRVA)
            AddMapRVAToExportSymbol(symbols[i].dwRVA, symbols[i]);
        if (symbols[i].pszName)
            AddMapNameToExportSymbol(symbols[i].pszName, symbols[i]);

        symbol.dwRVA = symbols[i].dwRVA;
        symbol.pszName = symbols[i].pszName;
        if (symbol.dwRVA)
            AddMapRVAToSymbol(symbol.dwRVA, symbol);
        if (symbol.pszName)
            AddMapNameToSymbol(symbol.pszName, symbol);
    }

    return TRUE;
}

BOOL PEMODULE::LoadDelayLoad()
{
    if (!IsModuleLoaded())
        return FALSE;

    PREAL_IMAGE_DATA_DIRECTORY pDir = DataDirectory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

    vector<ImgDelayDescr> Descrs;
    ImgDelayDescr *pDescrs;
    pDescrs = (ImgDelayDescr *)(LoadedImage() + pDir->RVA);

    size_t i = 0;
    while (pDescrs[i].rvaHmod)
    {
        Descrs.push_back(pDescrs[i]);
        i++;
    }

    DelayLoadDescriptors() = Descrs;

    // TODO: load IAT and INT

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// dumping

VOID PEMODULE::DumpHeaders()
{
    if (!IsModuleLoaded())
        return;

#ifdef _UNICODE
    printf("FileName: %ls, FileSize: 0x%08lX (%lu)\n",
        GetFileName(), GetFileSize(), GetFileSize());
#else
    printf("FileName: %s, FileSize: 0x%08lX (%lu)\n",
        GetFileName(), GetFileSize(), GetFileSize());
#endif

    if (DOSHeader())
    {
        DumpDOSHeader(DOSHeader());
    }
    if (FileHeader())
    {
        DumpFileHeader(FileHeader());
    }
    if (OptionalHeader32())
    {
        DumpOptionalHeader32(OptionalHeader32(), CheckSum());
    }
    else if (OptionalHeader64())
    {
        DumpOptionalHeader64(OptionalHeader64(), CheckSum());
    }
    if (m_pImpl->pSectionHeaders)
    {
        DWORD size = NumberOfSections();
        for (DWORD i = 0; i < size; i++)
        {
            printf("\n### Section #%lu ###\n", i);
            DumpSectionHeader(SectionHeader(i));
        }
    }
}

VOID PEMODULE::DumpImportSymbols()
{
    PIMAGE_IMPORT_DESCRIPTOR descs;
    vector<string> dll_names;
    vector<IMPORT_SYMBOL> symbols;

    descs = ImportDescriptors();
    if (descs == NULL)
        return;

    printf("\n### IMPORTS ###\n");
    printf("  Characteristics: 0x%08lX\n", descs->Characteristics);
    printf("  TimeDateStamp: 0x%08lX (%s)\n", descs->TimeDateStamp,
        GetTimeStampString(descs->TimeDateStamp));
    printf("  ForwarderChain: 0x%08lX\n", descs->ForwarderChain);
    printf("  Name: 0x%08lX (%s)\n", descs->Name, (LPSTR)GetData(descs->Name));
    printf("  \n");

    if (_GetImportDllNames(dll_names))
    {
        for (DWORD i = 0; i < dll_names.size(); i++)
        {
            printf("  %s\n", dll_names[i].c_str());
            if (Is64Bit())
                printf("    RVA      VA               HINT FUNCTION NAME\n");
            else
                printf("    RVA      VA       HINT FUNCTION NAME\n");
            if (_GetImportSymbols(i, symbols))
            {
                for (DWORD j = 0; j < symbols.size(); j++)
                {
                    if (Is64Bit())
                    {
                        ADDR64 addr = VA64FromRVA(symbols[j].dwRVA);
                        printf("    %08lX %08lX%08lX ", symbols[j].dwRVA,
                            HILONG(addr), LOLONG(addr));
                    }
                    else if (Is32Bit())
                    {
                        ADDR32 addr = VA32FromRVA(symbols[j].dwRVA);
                        printf("    %08lX %08lX ", symbols[j].dwRVA, addr);
                    }
                    if (symbols[j].Name.wImportByName)
                        printf("%4X %s\n", symbols[j].wHint, symbols[j].pszName);
                    else
                        printf("Ordinal %d\n", symbols[j].Name.wOrdinal);
                }
                printf("  \n");
            }
        }
    }
}

VOID PEMODULE::DumpExportSymbols()
{
    PIMAGE_EXPORT_DIRECTORY pDir = ExportDirectory();

    if (pDir == NULL)
        return;

    //DWORD dwNumberOfNames = pDir->NumberOfNames;
    //DWORD dwAddressOfFunctions = pDir->AddressOfFunctions;
    //DWORD dwAddressOfNames = pDir->AddressOfNames;
    //DWORD dwAddressOfOrdinals = pDir->AddressOfNameOrdinals;
    //LPDWORD pEAT = (LPDWORD)GetData(dwAddressOfFunctions);
    //LPDWORD pENPT = (LPDWORD)GetData(dwAddressOfNames);
    //LPWORD pOT = (LPWORD)GetData(dwAddressOfOrdinals);

    printf("\n### EXPORTS ###\n");
    printf("  Characteristics: 0x%08lX\n", pDir->Characteristics);
    printf("  TimeDateStamp: 0x%08lX (%s)\n", pDir->TimeDateStamp, GetTimeStampString(pDir->TimeDateStamp));
    printf("  Version: %u.%u\n", pDir->MajorVersion, pDir->MinorVersion);
    printf("  Name: 0x%08lX (%s)\n", pDir->Name, (LPSTR)GetData(pDir->Name));
    printf("  Base: 0x%08lX (%lu)\n", pDir->Base, pDir->Base);
    printf("  NumberOfFunctions: 0x%08lX (%lu)\n", pDir->NumberOfFunctions, pDir->NumberOfFunctions);
    printf("  NumberOfNames: 0x%08lX (%lu)\n", pDir->NumberOfNames, pDir->NumberOfNames);
    printf("  AddressOfFunctions: 0x%08lX\n", pDir->AddressOfFunctions);
    printf("  AddressOfNames: 0x%08lX\n", pDir->AddressOfNames);
    printf("  AddressOfNameOrdinals: 0x%08lX\n", pDir->AddressOfNameOrdinals);
    printf("  \n");

    printf("  %-50s %-5s ; %-8s %-8s\n", "FUNCTION NAME", "ORDI.", "RVA", "VA");

    for (DWORD i = 0; i < ExportSymbols().size(); i++)
    {
        EXPORT_SYMBOL& symbol = ExportSymbols()[i];
        if (symbol.dwRVA)
        {
            if (Is64Bit())
            {
                ADDR64 va = VA64FromRVA(symbol.dwRVA);
                if (symbol.pszName)
                    printf("  %-50s @%-4lu ; %08lX %08lX%08lX\n", 
                        symbol.pszName, symbol.dwOrdinal, symbol.dwRVA,
                        HILONG(va), LOLONG(va));
                else
                    printf("  %-50s @%-4lu ; %08lX %08lX%08lX\n", 
                        "(No Name)", symbol.dwOrdinal, symbol.dwRVA,
                        HILONG(va), LOLONG(va));
            }
            else if (Is32Bit())
            {
                ADDR32 va = VA32FromRVA(symbol.dwRVA);
                if (symbol.pszName)
                    printf("  %-50s @%-4lu ; %08lX %08lX\n", 
                        symbol.pszName, symbol.dwOrdinal, symbol.dwRVA, va);
                else
                    printf("  %-50s @%-4lu ; %08lX %08lX\n", 
                        "(No Name)", symbol.dwOrdinal, symbol.dwRVA, va);
            }
        }
        else
        {
            if (symbol.pszName)
                printf("  %-50s @%-4lu ; (forwarded to %s)\n", 
                    "(No Name)", symbol.dwOrdinal, symbol.pszForwarded);
            else
                printf("  %-50s @%-4lu ; (forwarded to %s)\n",
                    "(No Name)", symbol.dwOrdinal, symbol.pszForwarded);
        }
    }

    printf("\n\n");
}

VOID PEMODULE::DumpDelayLoad()
{
    if (DelayLoadDescriptors().empty())
    {
        LoadDelayLoad();
        if (DelayLoadDescriptors().empty())
            return;
    }

    printf("### DELAY LOAD ###\n");
    size_t i, size = DelayLoadDescriptors().size();
    DWORD rva;
    if (Is64Bit())
    {
        ADDR64 addr;
        for (i = 0; i < size; i++)
        {
            printf("  ### Descr #%u ###\n", (INT)i);
            printf("    NAME       %-8s %-8s\n", "RVA", "VA");

            rva = DelayLoadDescriptors()[i].grAttrs;
            addr = VA64FromRVA(rva);
            printf("    Attrs:     %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = DelayLoadDescriptors()[i].rvaDLLName;
            addr = VA64FromRVA(rva);
            printf("    DLL Name:  %s\n", (LPCSTR)(LoadedImage() + rva));
            printf("            :  %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = DelayLoadDescriptors()[i].rvaHmod;
            addr = VA64FromRVA(rva);
            printf("    Module:    %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = DelayLoadDescriptors()[i].rvaIAT;
            addr = VA64FromRVA(rva);
            printf("    IAT:       %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = DelayLoadDescriptors()[i].rvaINT;
            addr = VA64FromRVA(rva);
            printf("    INT:       %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = DelayLoadDescriptors()[i].rvaBoundIAT;
            addr = VA64FromRVA(rva);
            printf("    BoundIAT:  %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = DelayLoadDescriptors()[i].rvaUnloadIAT;
            addr = VA64FromRVA(rva);
            printf("    UnloadIAT: %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            LPCSTR pszTime = GetTimeStampString(DelayLoadDescriptors()[i].dwTimeStamp);
            printf("    dwTimeStamp:  0x%08lX (%s)",
                DelayLoadDescriptors()[i].dwTimeStamp, pszTime);
        }
    }
    else if (Is32Bit())
    {
        ADDR32 addr;
        for (i = 0; i < size; i++)
        {
            printf("  ### Descr #%u ###\n", (INT)i);
            printf("    NAME       %-8s %-8s\n", "RVA", "VA");

            rva = DelayLoadDescriptors()[i].grAttrs;
            addr = VA32FromRVA(rva);
            printf("    Attrs:     %08lX %08lX\n", rva, addr);

            rva = DelayLoadDescriptors()[i].rvaDLLName;
            addr = VA32FromRVA(rva);
            printf("    DLL Name:  %s\n", (LPCSTR)(LoadedImage() + rva));
            printf("            :  %08lX %08lX\n", rva, addr);

            rva = DelayLoadDescriptors()[i].rvaHmod;
            addr = VA32FromRVA(rva);
            printf("    Module:    %08lX %08lX\n", rva, addr);

            rva = DelayLoadDescriptors()[i].rvaIAT;
            addr = VA32FromRVA(rva);
            printf("    IAT:       %08lX %08lX\n", rva, addr);

            rva = DelayLoadDescriptors()[i].rvaINT;
            addr = VA32FromRVA(rva);
            printf("    INT:       %08lX %08lX\n", rva, addr);

            rva = DelayLoadDescriptors()[i].rvaBoundIAT;
            addr = VA32FromRVA(rva);
            printf("    BoundIAT:  %08lX %08lX\n", rva, addr);

            rva = DelayLoadDescriptors()[i].rvaUnloadIAT;
            addr = VA32FromRVA(rva);
            printf("    UnloadIAT: %08lX %08lX\n", rva, addr);

            LPCSTR pszTime = GetTimeStampString(DelayLoadDescriptors()[i].dwTimeStamp);
            printf("    dwTimeStamp:  0x%08lX (%s)",
                DelayLoadDescriptors()[i].dwTimeStamp, pszTime);
        }
    }

    printf("\n\n");
}

////////////////////////////////////////////////////////////////////////////

BOOL PEMODULE::_GetImportDllNames(vector<string>& names)
{
    PIMAGE_IMPORT_DESCRIPTOR descs = ImportDescriptors();
    names.clear();

    if (descs == NULL)
        return FALSE;

    for (DWORD i = 0; descs[i].FirstThunk != 0; i++)
        names.push_back((LPSTR)GetData(descs[i].Name));

    return TRUE;
}

BOOL PEMODULE::_GetImportSymbols(DWORD dll_index, vector<IMPORT_SYMBOL>& symbols)
{
    DWORD i, j;
    IMPORT_SYMBOL symbol;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PIMAGE_IMPORT_DESCRIPTOR descs = ImportDescriptors();

    symbols.clear();

    if (descs == NULL || descs[0].OriginalFirstThunk == 0)
        return FALSE;

    for (i = 0; descs[i].FirstThunk != 0; i++)
    {
        if (dll_index == i)
        {
            if (Is64Bit())
            {
                PULONGLONG pIAT64, pINT64;

                pIAT64 = (PULONGLONG)(DWORD_PTR)descs[i].FirstThunk;
                if (descs[i].OriginalFirstThunk)
                    pINT64 = (PULONGLONG)GetData(descs[i].OriginalFirstThunk);
                else
                    pINT64 = pIAT64;

                for (j = 0; pINT64[j] != 0; j++)
                {
                    if (pINT64[j] < GetSizeOfImage())
                    {
                        symbol.dwRVA = descs[i].FirstThunk + j * sizeof(DWORD);

                        if (IMAGE_SNAP_BY_ORDINAL64(pINT64[j]))
                        {
                            symbol.wHint = 0;
                            symbol.Name.wImportByName = 0;
                            symbol.Name.wOrdinal = (WORD)IMAGE_ORDINAL64(pINT64[j]);
                        }
                        else
                        {
                            pIBN = (PIMAGE_IMPORT_BY_NAME)GetData((DWORD)pINT64[j]);
                            symbol.wHint = pIBN->Hint;
                            symbol.pszName = (LPSTR)pIBN->Name;
                        }
                        symbols.push_back(symbol);
                    }
                }
            }
            else
            {
                LPDWORD pIAT, pINT;     // import address table & import name table
                pIAT = (LPDWORD)(DWORD_PTR)descs[i].FirstThunk;
                if (descs[i].OriginalFirstThunk)
                    pINT = (LPDWORD)GetData(descs[i].OriginalFirstThunk);
                else
                    pINT = pIAT;

                for (j = 0; pINT[j] != 0; j++)
                {
                    if (pINT[j] < GetSizeOfImage())
                    {
                        symbol.dwRVA = descs[i].FirstThunk + j * sizeof(DWORD);

                        if (IMAGE_SNAP_BY_ORDINAL32(pINT[j]))
                        {
                            symbol.wHint = 0;
                            symbol.Name.wImportByName = 0;
                            symbol.Name.wOrdinal = (WORD)IMAGE_ORDINAL32(pINT[j]);
                        }
                        else
                        {
                            pIBN = (PIMAGE_IMPORT_BY_NAME)GetData(pINT[j]);
                            symbol.wHint = pIBN->Hint;
                            symbol.pszName = (LPSTR)pIBN->Name;
                        }
                        symbols.push_back(symbol);
                    }
                }
            }
            break;
        }
    }

    return TRUE;
}

BOOL PEMODULE::_GetExportSymbols(vector<EXPORT_SYMBOL>& symbols)
{
    EXPORT_SYMBOL symbol;
    PIMAGE_EXPORT_DIRECTORY pDir = ExportDirectory();

    symbols.clear();

    if (pDir == NULL)
        return FALSE;

    // export address table (EAT)
    LPDWORD pEAT = (LPDWORD)GetData(pDir->AddressOfFunctions);
    // export name pointer table (ENPT)
    LPDWORD pENPT = (LPDWORD)GetData(pDir->AddressOfNames);
    // export ordinal table (EOT)
    LPWORD pEOT = (LPWORD)GetData(pDir->AddressOfNameOrdinals);

    DWORD i, j;
    WORD wOrdinal;
    for (i = 0; i < pDir->NumberOfNames; i++)
    {
        wOrdinal = pEOT[i];
        symbol.dwRVA = pEAT[wOrdinal];
        symbol.pszName = (LPSTR)GetData(pENPT[i]);
        symbol.dwOrdinal = pDir->Base + wOrdinal;
        symbol.pszForwarded = NULL;
        symbols.push_back(symbol);
    }

    for (i = 0; i < pDir->NumberOfFunctions; i++)
    {
        for (j = 0; j < pDir->NumberOfNames; j++)
        {
            if ((DWORD)pEOT[j] == i)
                break;
        }
        if (j < pDir->NumberOfNames)
            continue;

        DWORD dw = pEAT[i];
        if (dw == 0)
            continue;

        symbol.pszName = NULL;
        if (RVAInDirEntry(dw, IMAGE_DIRECTORY_ENTRY_EXPORT))
        {
            symbol.dwRVA = 0;
            symbol.pszForwarded = (LPSTR)GetData(dw);
        }
        else
        {
            symbol.dwRVA = dw;
            symbol.pszForwarded = NULL;
        }
        symbol.dwOrdinal = pDir->Base + i;
        symbols.push_back(symbol);
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// finding

const IMPORT_SYMBOL *PEMODULE::FindImportSymbolByRVA(DWORD rva) const
{
    map<DWORD, IMPORT_SYMBOL>::const_iterator it;
    it = m_pImpl->mRVAToImportSymbol.find(rva);
    if (it != m_pImpl->mRVAToImportSymbol.end())
        return &it->second;
    return NULL;
}

const IMPORT_SYMBOL *PEMODULE::FindImportSymbolByName(LPCSTR Name) const
{
    map<string, IMPORT_SYMBOL>::const_iterator it;
    it = m_pImpl->mNameToImportSymbol.find(Name);
    if (it != m_pImpl->mNameToImportSymbol.end())
        return &it->second;
    return NULL;
}

const EXPORT_SYMBOL *PEMODULE::FindExportSymbolByRVA(DWORD rva) const
{
    map<DWORD, EXPORT_SYMBOL>::const_iterator it;
    it = m_pImpl->mRVAToExportSymbol.find(rva);
    if (it != m_pImpl->mRVAToExportSymbol.end())
        return &it->second;
    return NULL;
}

const EXPORT_SYMBOL *PEMODULE::FindExportSymbolByName(LPCSTR Name) const
{
    map<string, EXPORT_SYMBOL>::const_iterator it;
    it = m_pImpl->mNameToExportSymbol.find(Name);
    if (it != m_pImpl->mNameToExportSymbol.end())
        return &it->second;
    return NULL;
}

const SYMBOL *PEMODULE::FindSymbolByRVA(DWORD rva) const
{
    map<DWORD, SYMBOL>::const_iterator it;
    it = m_pImpl->mRVAToSymbol.find(rva);
    if (it != m_pImpl->mRVAToSymbol.end())
        return &it->second;
    return NULL;
}

const SYMBOL *PEMODULE::FindSymbolByName(LPCSTR Name) const
{
    map<string, SYMBOL>::const_iterator it;
    it = m_pImpl->mNameToSymbol.find(Name);
    if (it != m_pImpl->mNameToSymbol.end())
        return &it->second;
    return NULL;
}

const SYMBOL *PEMODULE::FindSymbolByAddr32(ADDR32 addr) const
{
    if (OptionalHeader32())
        return FindSymbolByRVA(RVAFromVA32(addr));
    else
        return NULL;
}

const SYMBOL *PEMODULE::FindSymbolByAddr64(ADDR64 addr) const
{
    if (OptionalHeader64())
        return FindSymbolByRVA(RVAFromVA64(addr));
    else
        return NULL;
}

////////////////////////////////////////////////////////////////////////////

VOID PEMODULE::AddMapNameToSymbol(const string& name, const SYMBOL& symbol)
{
    m_pImpl->mNameToSymbol.insert(make_pair(name, symbol));
}

VOID PEMODULE::AddMapNameToImportSymbol(const string& name, const IMPORT_SYMBOL& symbol)
{
    m_pImpl->mNameToImportSymbol.insert(make_pair(name, symbol));
}

VOID PEMODULE::AddMapNameToExportSymbol(const string& name, const EXPORT_SYMBOL& symbol)
{
    m_pImpl->mNameToExportSymbol.insert(make_pair(name, symbol));
}

VOID PEMODULE::AddMapRVAToSymbol(DWORD rva, const SYMBOL& symbol)
{
    m_pImpl->mRVAToSymbol.insert(make_pair(rva, symbol));
}

VOID PEMODULE::AddMapRVAToImportSymbol(DWORD rva, const IMPORT_SYMBOL& symbol)
{
    m_pImpl->mRVAToImportSymbol.insert(make_pair(rva, symbol));
}

VOID PEMODULE::AddMapRVAToExportSymbol(DWORD rva, const EXPORT_SYMBOL& symbol)
{
    m_pImpl->mRVAToExportSymbol.insert(make_pair(rva, symbol));
}

////////////////////////////////////////////////////////////////////////////
// disasm

extern "C"
int32_t disasm(uint8_t *data, char *output, int outbufsize, int segsize,
               int64_t offset, int autosync, uint32_t prefer);

BOOL PEMODULE::DisAsmAddr32(DECOMPSTATUS32& status, ADDR32 func, ADDR32 va)
{
    if (!IsModuleLoaded() || !Is32Bit() || !AddressInCode32(va))
        return FALSE;

    DWORD rva = RVAFromVA32(va);
    LPBYTE input = LoadedImage() + rva;
    INT lendis;
    CHAR outbuf[256];
    ADDR32 addr;

    CODEFUNC32& cf = status.MapAddrToCodeFunc()[func];
    if (func == va)
        cf.Addr() = func;

    PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    assert(pCode);

    ADDR32SET vPrevCalls;
    LPBYTE iend = LoadedImage() + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend)
    {
        ASMCODE32& ac = status.MapAddrToAsmCode()[va];
        if (ac.Funcs().Contains(func))
            break;

        ac.Addr() = va;
        ac.Funcs().Insert(func);

        // disasm
        lendis = disasm(input, outbuf, sizeof(outbuf), 32, va, false, 0);

        // parse insn
        if (!lendis || input + lendis > iend)
        {
            lendis = 1;
            ac.Name() = "???";
            ac.AsmCodeType() = ACT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf.Flags() |= FF_DONTDECOMPBUTDISASM;
        }
        else
            _ParseInsn32(ac, va, outbuf);

        // set codes
        for (INT i = 0; i < lendis; i++)
            ac.Codes().push_back(input[i]);

        BOOL bBreak = FALSE;
        switch (ac.AsmCodeType())
        {
        case ACT_JCC:
            // conditional jump
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_LABEL: case OT_API:
                cf.Jumpers().Insert(va);
                addr = ac.Operand(0)->Value32();
                cf.Jumpees().Insert(addr);
                break;

            default: break;
            }
            break;

        case ACT_JMP:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_LABEL:
                if (func == va)
                {
                    // func is jumper
                    cf.FuncType() = FT_JUMPER;
                }
                else
                {
                    cf.Jumpers().Insert(va);
                    addr = ac.Operand(0)->Value32();
                    cf.Jumpees().Insert(addr);
                }
                break;

            case OT_API:
                if (func == va)
                {
                    // func is jumper
                    cf.FuncType() = FT_JUMPER;
                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case ACT_CALL:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_LABEL:
                // function call
                addr = ac.Operand(0)->Value32();
                status.Entrances().Insert(addr);
                cf.Callers().Insert(va);
                status.MapAddrToCodeFunc()[addr].Callees().Insert(func);
                vPrevCalls.Insert(addr);
                break;

            default:
                break;
            }
            break;

        case ACT_RETURN:
            if (!ac.Operands().empty() && ac.Operand(0)->OperandType() == OT_IMM)
            {
                // func is __stdcall
                cf.FuncType() = FT_STDCALL;
                cf.SizeOfArgs() = (INT)ac.Operand(0)->Value32();
            }
            else
            {
                // func is not __stdcall
                cf.Flags() |= FF_NOTSTDCALL;
            }
            bBreak = TRUE;
            break;

        case ACT_STACKOP:
            if (ac.Name() == "add")
            {
                assert(ac.Operand(0)->Text() == "esp");
                if (!vPrevCalls.Empty() && ac.Operand(0)->OperandType() == OT_IMM)
                {
                    for (size_t i = 0; i < vPrevCalls.Size(); i++)
                    {
                        addr = vPrevCalls[i];
                        CODEFUNC32& cf2 = status.MapAddrToCodeFunc()[addr];
                        cf2.FuncType() = FT_CDECL;
                        cf2.SizeOfArgs() = (INT)ac.Operand(0)->Value32();
                    }
                }
            }
            else if (ac.Name() == "sub")
            {
                assert(ac.Operand(0)->Text() == "esp");
            }
            vPrevCalls.Clear();
            break;

        default:
            break;
        }

        if (bBreak)
            break;

        // move to next position
        input += lendis;
        va += lendis;
    }

    return TRUE;
}

BOOL PEMODULE::DisAsmAddr64(DECOMPSTATUS64& status, ADDR64 func, ADDR64 va)
{
    if (!IsModuleLoaded() || !Is64Bit() || !AddressInCode64(va))
        return FALSE;

    // calculate
    DWORD rva = RVAFromVA64(va);
    LPBYTE input = LoadedImage() + rva;
    INT lendis;
    CHAR outbuf[256];
    ADDR64 addr;

    CODEFUNC64& cf = status.MapAddrToCodeFunc()[func];
    if (func == va)
        cf.Addr() = func;

    PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    assert(pCode);

    ADDR64SET vPrevCalls;
    LPBYTE iend = LoadedImage() + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend)
    {
        ASMCODE64& ac = status.MapAddrToAsmCode()[va];
        if (ac.Funcs().Contains(func))
            break;

        ac.Addr() = va;
        ac.Funcs().Insert(func);

        // disasm
        lendis = disasm(input, outbuf, sizeof(outbuf), 64, va, false, 0);

        // parse insn
        if (!lendis || input + lendis > iend)
        {
            lendis = 1;
            ac.Name() = "???";
            ac.AsmCodeType() = ACT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf.Flags() |= FF_DONTDECOMPBUTDISASM;
        }
        else
            _ParseInsn64(ac, va, outbuf);

        // add asm codes
        for (INT i = 0; i < lendis; i++)
            ac.Codes().push_back(input[i]);

        BOOL bBreak = FALSE;
        switch (ac.AsmCodeType())
        {
        case ACT_JCC:
            // conditional jump
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_LABEL:
                cf.Jumpers().Insert(va);
                addr = ac.Operand(0)->Value64();
                cf.Jumpees().Insert(addr);
                break;

            default:
                break;
            }
            break;

        case ACT_JMP:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_LABEL:
                if (func == va)
                {
                    // func is jumper
                    cf.FuncType() = FT_JUMPER;
                }
                else
                {
                    cf.Jumpers().Insert(va);
                    addr = ac.Operand(0)->Value64();
                    cf.Jumpees().Insert(addr);
                }
                break;

            case OT_API:
                if (func == va)
                {
                    // func is jumper
                    cf.FuncType() = FT_JUMPER;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case ACT_CALL:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_LABEL:
                // function call
                addr = ac.Operand(0)->Value64();
                status.Entrances().Insert(addr);
                cf.Callers().Insert(va);
                status.MapAddrToCodeFunc()[addr].Callees().Insert(func);
                vPrevCalls.Insert(addr);
                break;

            default:
                break;
            }
            break;

        case ACT_RETURN:
            if (!ac.Operands().empty() && ac.Operand(0)->OperandType() == OT_IMM)
            {
                // func is __stdcall
                cf.FuncType() = FT_STDCALL;
                cf.SizeOfArgs() = (INT)ac.Operand(0)->Value64();
            }
            else
            {
                // func is not __stdcall
                cf.Flags() |= FF_NOTSTDCALL;
            }
            bBreak = TRUE;
            break;

        case ACT_STACKOP:
            if (ac.Name() == "add")
            {
                assert(ac.Operand(0)->Text() == "rsp");
                if (!vPrevCalls.Empty() && ac.Operand(0)->OperandType() == OT_IMM)
                {
                    for (size_t i = 0; i < vPrevCalls.Size(); i++)
                    {
                        addr = vPrevCalls[i];
                        CODEFUNC64& cf2 = status.MapAddrToCodeFunc()[addr];
                        cf2.FuncType() = FT_CDECL;
                        cf2.SizeOfArgs() = (INT)ac.Operand(0)->Value64();
                    }
                }
            }
            else if (ac.Name() == "sub")
            {
                assert(ac.Operand(0)->Text() == "rsp");
            }
            else if (ac.Name() == "push")
            {
            }
            else if (ac.Name() == "pop")
            {
            }
            else
            {
                // don't decompile if any unknown stack operation
                cf.Flags() |= FF_DONTDECOMPBUTDISASM;
            }
            vPrevCalls.Clear();
            break;

        default:
            break;
        }

        if (bBreak)
            break;

        // move to next position
        input += lendis;
        va += lendis;
    }

    return TRUE;
}

BOOL PEMODULE::DisAsm32(DECOMPSTATUS32& status)
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    // VOID WINAPI WinMainCRTStartup(VOID);
    // BOOL WINAPI _DllMainCRTStartup(HANDLE, DWORD, LPVOID);
    LPCSTR pszEntryPointName;
    if (IsDLL())
        pszEntryPointName = "_DllMainCRTStartup";
    else
        pszEntryPointName = "WinMainCRTStartup";

    SYMBOL symbol;
    symbol.dwRVA = RVAOfEntryPoint();
    symbol.pszName = pszEntryPointName;
    AddMapRVAToSymbol(RVAOfEntryPoint(), symbol);
    string name = symbol.pszName;
    AddMapNameToSymbol(name, symbol);

    // register entrances
    ADDR32 va;
    va = VA32FromRVA(RVAOfEntryPoint());
    status.Entrances().Insert(va);

    status.MapAddrToCodeFunc()[va].Addr() = va;
    status.MapAddrToCodeFunc()[va].Name() = pszEntryPointName;
    if (IsDLL())
    {
        status.MapAddrToCodeFunc()[va].SizeOfArgs() = 3 * sizeof(ADDR32);

        status.MapAddrToCodeFunc()[va].Args().clear();

        OPERAND opr;
        opr.DataType() = "HANDLE";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().push_back(opr);
        opr.DataType() = "DWORD";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().push_back(opr);
        opr.DataType() = "LPVOID";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().push_back(opr);
        status.MapAddrToCodeFunc()[va].ReturnDataType() = "BOOL";
    }
    else
        status.MapAddrToCodeFunc()[va].SizeOfArgs() = 0;

    {
        vector<EXPORT_SYMBOL>::const_iterator it, end;
        end = ExportSymbols().end();
        for (it = ExportSymbols().begin(); it != end; it++)
        {
            va = VA32FromRVA(it->dwRVA);
            status.Entrances().Insert(va);

            status.MapAddrToCodeFunc()[va].Addr() = va;
            status.MapAddrToCodeFunc()[va].Name() = it->pszName;
        }
    }

    // disasm entrances
    {
        SIZE_T i = 0, size;
        do
        {
            ADDR32SET addrset = status.Entrances();
            size = addrset.Size();

            for ( ; i < size; i++)
            {
                DisAsmAddr32(status, addrset[i], addrset[i]);

                CODEFUNC32& cf = status.MapAddrToCodeFunc()[addrset[i]];
                for (SIZE_T j = 0; j < cf.Jumpees().Size(); j++)
                {
                    DisAsmAddr32(status, addrset[i], cf.Jumpees()[j]);
                }
            }

            // status.Entrances() may grow in DisAsmAddr32
        } while(size < status.Entrances().Size());
    }

    return TRUE;
}

BOOL PEMODULE::DisAsm64(DECOMPSTATUS64& status)
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // VOID WINAPI WinMainCRTStartup(VOID);
    // BOOL WINAPI _DllMainCRTStartup(HANDLE, DWORD, LPVOID);
    LPCSTR pszEntryPointName;
    if (IsDLL())
        pszEntryPointName = "_DllMainCRTStartup";
    else
        pszEntryPointName = "WinMainCRTStartup";

    // register entrypoint
    SYMBOL symbol;
    symbol.dwRVA = RVAOfEntryPoint();
    symbol.pszName = pszEntryPointName;
    AddMapRVAToSymbol(RVAOfEntryPoint(), symbol);
    string name = symbol.pszName;
    AddMapNameToSymbol(name, symbol);

    // register entrances
    ADDR64 va;
    va = VA64FromRVA(RVAOfEntryPoint());
    status.Entrances().Insert(va);

    status.MapAddrToCodeFunc()[va].Addr() = va;
    status.MapAddrToCodeFunc()[va].Name() = pszEntryPointName;
    if (IsDLL())
    {
        status.MapAddrToCodeFunc()[va].SizeOfArgs() = 3 * sizeof(ADDR64);

        OPERAND opr;
        opr.DataType() = "HANDLE";
        opr.Size() = 8;
        status.MapAddrToCodeFunc()[va].Args().push_back(opr);
        opr.DataType() = "DWORD";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().push_back(opr);
        opr.DataType() = "LPVOID";
        opr.Size() = 8;
        status.MapAddrToCodeFunc()[va].Args().push_back(opr);
        status.MapAddrToCodeFunc()[va].ReturnDataType() = "BOOL";
    }
    else
        status.MapAddrToCodeFunc()[va].SizeOfArgs() = 0;

    {
        vector<EXPORT_SYMBOL>::const_iterator it, end;
        end = ExportSymbols().end();
        for (it = ExportSymbols().begin(); it != end; it++)
        {
            va = VA64FromRVA(it->dwRVA);
            status.Entrances().Insert(va);
            status.MapAddrToCodeFunc()[va].Addr() = va;
            status.MapAddrToCodeFunc()[va].Name() = it->pszName;
        }
    }

    // disasm entrances
    {
        SIZE_T i = 0, size;
        do
        {
            ADDR64SET addrset = status.Entrances();
            size = addrset.Size();

            for ( ; i < size; i++)
            {
                DisAsmAddr64(status, addrset[i], addrset[i]);

                CODEFUNC64& cf = status.MapAddrToCodeFunc()[addrset[i]];
                for (SIZE_T j = 0; j < cf.Jumpees().Size(); j++)
                {
                    DisAsmAddr64(status, addrset[i], cf.Jumpees()[j]);
                }
            }

            // status.Entrances() may grow in DisAsmAddr64
        } while(size < status.Entrances().Size());
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// resource

extern "C"
BOOL CALLBACK
EnumResLangProc(
    HMODULE hModule,
    LPCTSTR lpszType,
    LPCTSTR lpszName,
    WORD wIDLanguage,
    LPARAM lParam)
{
    CHAR szLangName[64];
    DWORD LCID = MAKELCID(wIDLanguage, SORT_DEFAULT);
    if (GetLocaleInfoA(LCID, LOCALE_SLANGUAGE, szLangName, 64))
        printf("      Language: %s\n", szLangName);
    else
        printf("      Language: #%u\n", (UINT)(UINT_PTR)wIDLanguage);

    HRSRC hRsrc;
    hRsrc = (HRSRC)FindResourceEx(hModule, lpszType, lpszName, wIDLanguage);
    DWORD Size = SizeofResource(hModule, hRsrc);
    printf("        Data Size: 0x%08lX (%lu) Bytes\n", Size, Size);

    return TRUE;
}

extern "C"
BOOL CALLBACK
EnumResNameProc(
    HMODULE hModule,
    LPCTSTR lpszType,
    LPTSTR lpszName,
    LPARAM lParam)
{
    if (IS_INTRESOURCE(lpszName))
        printf("    Resource Name: #%u\n", (UINT)(UINT_PTR)lpszName);
    else
#ifdef _UNICODE
        printf("    Resource Name: %ls\n", lpszName);
#else
        printf("    Resource Name: %s\n", lpszName);
#endif

    EnumResourceLanguages(hModule, lpszType, lpszName, EnumResLangProc, 0);
    return TRUE;
}

const LPCSTR cr_res_types[] =
{
    NULL,               // 0
    "RT_CURSOR",        // 1
    "RT_BITMAP",        // 2
    "RT_ICON",          // 3
    "RT_MENU",          // 4
    "RT_DIALOG",        // 5
    "RT_STRING",        // 6
    "RT_FONTDIR",       // 7
    "RT_FONT",          // 8
    "RT_ACCELERATOR",   // 9
    "RT_RCDATA",        // 10
    "RT_MESSAGETABLE",  // 11
    "RT_GROUP_CURSOR",  // 12
    NULL,               // 13
    "RT_GROUP_ICON",    // 14
    "RT_VERSION",       // 16
    "RT_DLGINCLUDE",    // 17
    NULL,               // 18
    "RT_PLUGPLAY",      // 19
    "RT_VXD",           // 20
    "RT_ANICURSOR",     // 21
    "RT_ANIICON",       // 22
    "RT_HTML",          // 23
    "RT_MANIFEST",      // 24
};

extern "C"
BOOL CALLBACK
EnumResTypeProc(
    HMODULE hModule,
    LPTSTR lpszType,
    LPARAM lParam)
{
    if (IS_INTRESOURCE(lpszType))
    {
        UINT nType = (UINT)(UINT_PTR)lpszType;
        UINT size = (UINT)(sizeof(cr_res_types) / sizeof(cr_res_types[0]));
        if (nType < size && cr_res_types[nType])
        {
            printf("  Resource Type: %s\n", cr_res_types[nType]);
        }
        else
            printf("  Resource Type: #%u\n", nType);
    }
    else
    {
#ifdef _UNICODE
        printf("  Resource Type: %ls\n", lpszType);
#else
        printf("  Resource Type: %s\n", lpszType);
#endif
    }

    EnumResourceNames(hModule, lpszType, EnumResNameProc, 0);
    return TRUE;
}

VOID PEMODULE::DumpResource()
{
    HINSTANCE hInst;
    hInst = LoadLibraryEx(GetFileName(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hInst == NULL)
        return;

    printf("### RESOURCE ###\n");
    if (!EnumResourceTypes(hInst, EnumResTypeProc, 0))
        printf("  No resource data\n");
    FreeLibrary(hInst);

    printf("\n");
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE::_ParseInsn32, PEMODULE::_ParseInsn64

const char * const cr_rep_insns[] =
{
    "rep insb", "rep insw", "rep insd",
    "rep movsb", "rep movsw", "rep movsd", "rep movsq",
    "rep outsb", "rep outsw", "rep outsd",
    "rep stosb", "rep stosw", "rep stosd", "rep stosq",
    "rep lodsb", "rep lodsw", "rep lodsd", "rep lodsq",
    "repe cmpsb", "repe cmpsw", "repe cmpsd", "repe cmpsq",
    "repe scasb", "repe scasw", "repe scasd", "repe scasq",
    "repne cmpsb", "repne cmpsw", "repne cmpsd", "repne cmpsq",
    "repne scasb", "repne scasw", "repne scasd", "repne scasq",
};

struct CCENTRY
{
    const char *name;
    CONDCODE cc;
};

const CCENTRY cr_ccentries[] =
{
    { "call", C_NONE },

    { "loop", C_NONE },
    { "loope", C_E },
    { "loopne", C_NE },

    { "jmp", C_NONE },

    { "ja", C_A },
    { "jae", C_AE },
    { "jb", C_B },
    { "jbe", C_BE },
    { "jc", C_C },
    { "je", C_E },
    { "jg", C_G },
    { "jge", C_GE },
    { "jl", C_L },
    { "jle", C_LE },
    { "jna", C_NA },
    { "jnae", C_NAE },
    { "jnb", C_NB },
    { "jnbe", C_NBE },
    { "jnc", C_NC },
    { "jne", C_NE },
    { "jng", C_NG },
    { "jnge", C_NGE },
    { "jnl", C_NL },
    { "jnle", C_NLE },
    { "jno", C_NO },
    { "jnp", C_NP },
    { "jns", C_NS },
    { "jnz", C_NZ },
    { "jo", C_O },
    { "jp", C_P },
    { "jpe", C_PE },
    { "jpo", C_PO },
    { "js", C_S },
    { "jz", C_Z },
};

VOID PEMODULE::_ParseInsn32(ASMCODE32& ac, ADDR32 offset, const char *insn)
{
    char buf[128];
    strcpy(buf, insn);

    char *q = buf;

    if (_strnicmp(q, "cs ", 3) == 0 ||
        _strnicmp(q, "ss ", 3) == 0 ||
        _strnicmp(q, "ds ", 3) == 0 ||
        _strnicmp(q, "es ", 3) == 0 ||
        _strnicmp(q, "fs ", 3) == 0 ||
        _strnicmp(q, "gs ", 3) == 0)
    {
        q += 3;
    }

    if (_strnicmp(q, "a16 ", 4) == 0 ||
        _strnicmp(q, "o16 ", 4) == 0 ||
        _strnicmp(q, "o32 ", 4) == 0 ||
        _strnicmp(q, "o64 ", 4) == 0)
    {
        q += 4;
    }

    if (q[0] == 'r' && q[1] == 'e')
    {
        const size_t size = sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (size_t i = 0; i < size; i++)
        {
            if (_stricmp(q, cr_rep_insns[i]) == 0)
            {
                ac.Name() = q;
                char *p = q + strlen(q) - 1;

                OPERAND opr;
                if (*p == 'b')
                    opr.Size() = 1;
                else if (*p == 'w')
                    opr.Size() = 2;
                else if (*p == 'd')
                    opr.Size() = 4;

                if (q[3] == 'e')
                    ac.CondCode() = C_E;
                else if (q[3] == 'n')
                    ac.CondCode() = C_NE;
                else
                    ac.CondCode() = C_NONE;

                ac.Operands().clear();
                ac.Operands().push_back(opr);
                return;
            }
        }
    }

    if (_strnicmp(q, "rep ", 4) == 0)
        q += 4;
    if (_strnicmp(q, "repne ", 6) == 0)
        q += 6;

    if (_strnicmp(q, "ret", 3) == 0 || _strnicmp(q, "iret", 4) == 0)
    {
        char *p = strchr(q, ' ');
        if (p)
        {
            *p = '\0';
			OPERAND opr;
			opr.Text() = p + 1;
            ac.Operands().push_back(opr);
            ParseOperand(*ac.Operand(0), 32, false);
        }
        ac.Name() = q;
        ac.AsmCodeType() = ACT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j')
    {
        const size_t size = sizeof(cr_ccentries) / sizeof(cr_ccentries[0]);
        for (size_t i = 0; i < size; i++)
        {
            if (strncmp(q, cr_ccentries[i].name, strlen(cr_ccentries[i].name)) == 0)
            {
                char *p = strchr(q, ' ');
                *p = '\0';
                ac.Name() = cr_ccentries[i].name;
                ac.CondCode() = cr_ccentries[i].cc;

                if (_strnicmp(cr_ccentries[i].name, "loop", 4) == 0)
                {
                    ac.AsmCodeType() = ACT_LOOP;
                }
                else if (ac.CondCode() == C_NONE)
                {
                    if (_stricmp(cr_ccentries[i].name, "call") == 0)
                        ac.AsmCodeType() = ACT_CALL;
                    else
                        ac.AsmCodeType() = ACT_JMP;
                }
                else
                    ac.AsmCodeType() = ACT_JCC;

                p++;
                OPERAND opr;
                opr.Text() = p;
                ParseOperand(opr, 32, true);
                if (opr.OperandType() == OT_MEMIMM)
                {
                    ADDR32 addr = opr.Value32();
                    DWORD rva = RVAFromVA32(addr);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        opr.SetAPI(symbol->pszName);
                }
                else if (ac.AsmCodeType() == ACT_JMP && opr.OperandType() == OT_IMM)
                {
                    ADDR32 addr = opr.Value32();
                    DWORD rva = RVAFromVA32(addr);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        opr.SetAPI(symbol->pszName);
                }
                ac.Operands().clear();
                ac.Operands().push_back(opr);
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL)
    {
        ac.Name() = q;
        return;
    }

    if (_strnicmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    ac.Name() = q;
    if (_stricmp(q, "push") == 0 || _stricmp(q, "pop") == 0 ||
        _stricmp(q, "enter") == 0 || _stricmp(q, "leave") == 0)
    {
        ac.AsmCodeType() = ACT_STACKOP;
    }

    ac.Operands().clear();
    p = strtok(p + 1, ",");
    if (p)
    {
        OPERAND opr;
        opr.Text() = p;
        ac.Operands().push_back(opr);
        p = strtok(NULL, ",");
        if (p)
        {
            if (_stricmp(p, "esp") == 0)
            {
                ac.AsmCodeType() = ACT_STACKOP;
            }
            opr.Text() = p;
            ac.Operands().push_back(opr);
            p = strtok(NULL, ",");
            if (p)
            {
                if (_stricmp(p, "esp") == 0)
                {
                    ac.AsmCodeType() = ACT_STACKOP;
                }
                opr.Text() = p;
                ac.Operands().push_back(opr);
                ParseOperand(*ac.Operand(2), 32);
            }
            ParseOperand(*ac.Operand(1), 32);
        }
        ParseOperand(*ac.Operand(0), 32);
    }
}

VOID PEMODULE::_ParseInsn64(ASMCODE64& ac, ADDR64 offset, const char *insn)
{
    char buf[128];
    strcpy(buf, insn);
    char *q = buf;
    if (_strnicmp(q, "a16 ", 4) == 0 ||
        _strnicmp(q, "o16 ", 4) == 0 ||
        _strnicmp(q, "o32 ", 4) == 0 ||
        _strnicmp(q, "o64 ", 4) == 0)
    {
        q += 4;
    }

    if (q[0] == 'r' && q[1] == 'e')
    {
        const size_t size = sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (size_t i = 0; i < size; i++)
        {
            if (_stricmp(q, cr_rep_insns[i]) == 0)
            {
                ac.Name() = q;
                char *p = q + strlen(q) - 1;

                OPERAND opr;
                if (*p == 'b')
                    opr.Size() = 1;
                else if (*p == 'w')
                    opr.Size() = 2;
                else if (*p == 'd')
                    opr.Size() = 4;
                else if (*p == 'q')
                    opr.Size() = 8;

                if (q[3] == 'e')
                    ac.CondCode() = C_E;
                else if (q[3] == 'n')
                    ac.CondCode() = C_NE;
                else
                    ac.CondCode() = C_NONE;

                ac.Operands().clear();
                ac.Operands().push_back(opr);
                return;
            }
        }
    }

    if (_strnicmp(q, "ret", 3) == 0 || _strnicmp(q, "iret", 4) == 0)
    {
        char *p = strchr(q, ' ');
        if (p)
        {
            *p = '\0';
            OPERAND opr;
            opr.Text() = p + 1;
            ParseOperand(opr, 32, false);
            ac.Operands().clear();
            ac.Operands().push_back(opr);
        }
        ac.Name() = q;
        ac.AsmCodeType() = ACT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j')
    {
        size_t size = sizeof(cr_ccentries) / sizeof(cr_ccentries[0]);
        for (size_t i = 0; i < size; i++)
        {
            if (strncmp(q, cr_ccentries[i].name, strlen(cr_ccentries[i].name)) == 0)
            {
                char *p = strchr(q, ' ');
                *p = '\0';
                ac.Name() = cr_ccentries[i].name;
                ac.CondCode() = cr_ccentries[i].cc;

                if (_strnicmp(cr_ccentries[i].name, "loop", 4) == 0)
                {
                    ac.AsmCodeType() = ACT_LOOP;
                }
                else if (ac.CondCode() == C_NONE)
                {
                    if (_stricmp(cr_ccentries[i].name, "call") == 0)
                        ac.AsmCodeType() = ACT_CALL;
                    else
                        ac.AsmCodeType() = ACT_JMP;
                }
                else
                    ac.AsmCodeType() = ACT_JCC;

                p++;
                OPERAND opr;
                opr.Text() = p;
                ParseOperand(opr, 32, true);
                if (opr.OperandType() == OT_MEMIMM)
                {
                    ADDR64 addr = opr.Value64();
                    DWORD rva = RVAFromVA64(addr);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        opr.SetAPI(symbol->pszName);
                }
                else if (ac.AsmCodeType() == ACT_JMP && opr.OperandType() == OT_IMM)
                {
                    ADDR64 addr = opr.Value64();
                    DWORD rva = RVAFromVA64(addr);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        opr.SetAPI(symbol->pszName);
                }
                ac.Operands().clear();
                ac.Operands().push_back(opr);
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL)
    {
        ac.Name() = q;
        return;
    }

    if (_strnicmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    ac.Name() = q;
    if (_stricmp(q, "push") == 0 || _stricmp(q, "pop") == 0 ||
        _stricmp(q, "enter") == 0 || _stricmp(q, "leave") == 0)
    {
        ac.AsmCodeType() = ACT_STACKOP;
    }

    ac.Operands().clear();
    p = strtok(p + 1, ",");
    if (p)
    {
        OPERAND opr;
        opr.Text() = p;
        ac.Operands().push_back(opr);
        p = strtok(NULL, ",");
        if (p)
        {
            if (_stricmp(p, "esp") == 0)
            {
                ac.AsmCodeType() = ACT_STACKOP;
            }
            opr.Text() = p;
            ac.Operands().push_back(opr);
            p = strtok(NULL, ",");
            if (p)
            {
                if (_stricmp(p, "esp") == 0)
                {
                    ac.AsmCodeType() = ACT_STACKOP;
                }
                opr.Text() = p;
                ac.Operands().push_back(opr);
                ParseOperand(*ac.Operand(2), 32);
            }
            ParseOperand(*ac.Operand(1), 32);
        }
        ParseOperand(*ac.Operand(0), 32);
    }
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE::ParseOperand

VOID PEMODULE::ParseOperand(OPERAND& opr, INT bits, bool jump/* = false*/)
{
    char buf[64];
    strcpy(buf, opr.Text().c_str());
    char *p = buf;

    DWORD size = cr_reg_get_size(p, bits);
    if (size != 0)
    {
        opr.OperandType() = OT_REG;
        opr.Size() = size;
        return;
    }

    if (_strnicmp(p, "byte ", 5) == 0)
    {
        p += 5;
        opr.Size() = 1;
    }
    else if (_strnicmp(p, "word ", 5) == 0)
    {
        p += 5;
        opr.Size() = 2;
    }
    else if (_strnicmp(p, "dword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 4;
    }
    else if (_strnicmp(p, "qword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 8;
    }
    else if (_strnicmp(p, "tword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 10;
    }
    else if (_strnicmp(p, "oword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 16;
    }
    else if (_strnicmp(p, "yword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 32;
    }
    else if (_strnicmp(p, "short ", 6) == 0)
    {
        p += 6;
        opr.Size() = 1;
    }
    else if (_strnicmp(p, "near ", 5) == 0)
    {
        p += 5;
        opr.Size() = 2;
    }

    // near or far
    if (_strnicmp(p, "near ", 5) == 0)
        p += 5;
    else if (_strnicmp(p, "far ", 4) == 0)
        p += 4;

    if (p[0] == '+' || p[0] == '-')
    {
        char *endptr;
        LONGLONG value = _strtoi64(p, &endptr, 16);
        opr.SetImm64(value, true);
    }
    else if (p[0] == '0' && p[1] == 'x')
    {
        char *endptr;
        ULONGLONG value = _strtoui64(p, &endptr, 16);
        opr.Value64() = value;

        if (jump)
        {
            if (bits == 64)
                sprintf(buf, "L%08lX%08lX", HILONG(value), LOLONG(value));
            else if (bits == 32)
                sprintf(buf, "L%08lX", LOLONG(value));
            else
                sprintf(buf, "L%04X", (WORD)value);
            opr.Value64() = value;
            opr.SetLabel(buf);
        }
        else
            opr.SetImm64(value, false);
    }
    else if (p[0] == '[')
    {
        p++;
        *strchr(p, ']') = '\0';

        DWORD size;
        if (_strnicmp(p, "word ", 5) == 0)
        {
            p += 5;
        }
        else if (_strnicmp(p, "dword ", 6) == 0)
        {
            p += 6;
        }
        else if (_strnicmp(p, "rel ", 4) == 0)
        {
            p += 4;
        }
        else if (_strnicmp(p, "qword ", 6) == 0)
        {
            p += 6;
        }
        else if ((size = cr_reg_get_size(p, bits)) != 0)
        {
            opr.OperandType() = OT_MEMREG;
            return;
        }

        ADDR64 addr;
        char *endptr;
        if (isdigit(*p))
        {
            addr = _strtoui64(p, &endptr, 16);
            opr.SetMemImm(addr);
        }
        else
        {
            opr.SetMemExp(p);
        }
    }
}

////////////////////////////////////////////////////////////////////////////
// decompiling

BOOL PEMODULE::DecompileAddr32(DECOMPSTATUS32& status, ADDR32 va)
{
    return FALSE;
}

BOOL PEMODULE::DecompileAddr64(DECOMPSTATUS64& status, ADDR64 va)
{
    return FALSE;
}

BOOL PEMODULE::Decompile32(DECOMPSTATUS32& status)
{
    return FALSE;
}

BOOL PEMODULE::Decompile64(DECOMPSTATUS64& status)
{
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
