////////////////////////////////////////////////////////////////////////////
// Module.cpp
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////
// CR_Symbol

CR_Symbol::CR_Symbol()
{
}

CR_Symbol::CR_Symbol(const CR_Symbol& s)
{
    Copy(s);
}

void CR_Symbol::operator=(const CR_Symbol& s)
{
    Copy(s);
}

/*virtual*/ CR_Symbol::~CR_Symbol()
{
}

void CR_Symbol::Copy(const CR_Symbol& s)
{
    Name() = s.Name();
    RVA() = s.RVA();
}

void CR_Symbol::clear()
{
    Name().clear();
    RVA() = 0;
}

CR_ImportSymbol *CR_SymbolInfo::GetImportSymbolFromRVA(DWORD RVA)
{
    for (auto& p : MapRVAToImportSymbol())
    {
        if (p.first == RVA)
            return &p.second;
    }
    return NULL;
}

CR_ImportSymbol *CR_SymbolInfo::GetImportSymbolFromName(const char *name)
{
    for (auto& p : MapNameToImportSymbol())
    {
        if (p.first == name)
            return &p.second;
    }
    return NULL;
}

CR_ExportSymbol *CR_SymbolInfo::GetExportSymbolFromRVA(DWORD RVA)
{
    for (auto& p : MapRVAToExportSymbol())
    {
        if (p.first == RVA)
            return &p.second;
    }
    return NULL;
}

CR_ExportSymbol *CR_SymbolInfo::GetExportSymbolFromName(const char *name)
{
    for (auto& p : MapNameToExportSymbol())
    {
        if (p.first == name)
            return &p.second;
    }
    return NULL;
}

CR_Symbol *CR_SymbolInfo::GetSymbolFromRVA(DWORD RVA)
{
    for (auto& p : MapRVAToSymbol())
    {
        if (p.first == RVA)
            return &p.second;
    }
    return NULL;
}

CR_Symbol *CR_SymbolInfo::GetSymbolFromName(const char *name)
{
    for (auto& p : MapNameToSymbol())
    {
        if (p.first == name)
            return &p.second;

    }
    return NULL;
}

const CR_ImportSymbol *CR_SymbolInfo::GetImportSymbolFromRVA(DWORD RVA) const
{
    for (auto& p : MapRVAToImportSymbol())
    {
        if (p.first == RVA)
            return &p.second;
    }
    return NULL;
}

const CR_ImportSymbol *CR_SymbolInfo::GetImportSymbolFromName(const char *name) const
{
    for (auto& p : MapNameToImportSymbol())
    {
        if (p.first == name)
            return &p.second;
    }
    return NULL;
}

const CR_ExportSymbol *CR_SymbolInfo::GetExportSymbolFromRVA(DWORD RVA) const
{
    for (auto& p : MapRVAToExportSymbol())
    {
        if (p.first == RVA)
            return &p.second;
    }
    return NULL;
}

const CR_ExportSymbol *CR_SymbolInfo::GetExportSymbolFromName(const char *name) const
{
    for (auto& p : MapNameToExportSymbol())
    {
        if (p.first == name)
            return &p.second;
    }
    return NULL;
}

const CR_Symbol *CR_SymbolInfo::GetSymbolFromRVA(DWORD RVA) const
{
    for (auto& p : MapRVAToSymbol())
    {
        if (p.first == RVA)
            return &p.second;
    }
    return NULL;
}

const CR_Symbol *CR_SymbolInfo::GetSymbolFromName(const char *name) const
{
    for (auto& p : MapNameToSymbol())
    {
        if (p.first == name)
            return &p.second;
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// CR_SymbolInfo

CR_SymbolInfo::CR_SymbolInfo()
{
}

CR_SymbolInfo::CR_SymbolInfo(const CR_SymbolInfo& info)
{
    Copy(info);
}

void CR_SymbolInfo::operator=(const CR_SymbolInfo& info)
{
    Copy(info);
}

/*virtual*/ CR_SymbolInfo::~CR_SymbolInfo()
{
}

void CR_SymbolInfo::Copy(const CR_SymbolInfo& info)
{
    GetImportDllNames() = info.GetImportDllNames();
    GetImportSymbols() = info.GetImportSymbols();
    MapRVAToImportSymbol() = info.MapRVAToImportSymbol();
    MapNameToImportSymbol() = info.MapNameToImportSymbol();
    GetExportSymbols() = info.GetExportSymbols();
    MapRVAToExportSymbol() = info.MapRVAToExportSymbol();
    MapNameToExportSymbol() = info.MapNameToExportSymbol();
    MapRVAToSymbol() = info.MapRVAToSymbol();
    MapNameToSymbol() = info.MapNameToSymbol();
}

void CR_SymbolInfo::clear()
{
    GetImportDllNames().clear();
    GetImportSymbols().clear();
    MapRVAToImportSymbol().clear();
    MapNameToImportSymbol().clear();
    GetExportSymbols().clear();
    MapRVAToExportSymbol().clear();
    MapNameToExportSymbol().clear();
    MapRVAToSymbol().clear();
    MapNameToSymbol().clear();
}

void CR_SymbolInfo::AddImportDllName(const char *name)
{
    GetImportDllNames().insert(name);
}

void CR_SymbolInfo::AddSymbol(DWORD rva, const char *name)
{
    CR_Symbol s;
    s.RVA() = rva;
    if (name)
        s.Name() = name;
    MapRVAToSymbol().insert(std::make_pair(rva, s));
    if (name)
        MapNameToSymbol().insert(std::make_pair(name, s));
}

void CR_SymbolInfo::AddSymbol(const CR_Symbol& s)
{
    AddSymbol(s.RVA(), s.Name().c_str());
}

void CR_SymbolInfo::AddImportSymbol(const CR_ImportSymbol& is)
{
    GetImportSymbols().insert(is);
    MapRVAToImportSymbol().insert(std::make_pair(is.dwRVA, is));
    if (is.Name.wImportByName)
    {
        MapNameToImportSymbol().insert(std::make_pair(is.pszName, is));
        AddSymbol(is.dwRVA, is.pszName);
    }
}

void CR_SymbolInfo::AddExportSymbol(const CR_ExportSymbol& es)
{
    GetExportSymbols().insert(es);
    MapRVAToExportSymbol().insert(std::make_pair(es.dwRVA, es));
    if (es.pszName)
    {
        MapNameToExportSymbol().insert(std::make_pair(es.pszName, es));
        AddSymbol(es.dwRVA, es.pszName);
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Module

CR_Module::CR_Module() :
    m_pszFileName(NULL),
    m_hFile(INVALID_HANDLE_VALUE),
    m_hFileMapping(NULL),
    m_pFileImage(NULL),
    m_dwFileSize(0),
    m_dwLastError(ERROR_SUCCESS),
    m_bModuleLoaded(FALSE),
    m_bDisAsmed(FALSE),
    m_bDecompiled(FALSE),
    m_pDOSHeader(NULL),
    m_pNTHeaders(NULL),
    m_pFileHeader(NULL),
    m_pOptional32(NULL),
    m_pOptional64(NULL),
    m_pLoadedImage(NULL),
    m_dwHeaderSum(0),
    m_dwCheckSum(0),
    m_dwSizeOfOptionalHeader(0),
    m_dwAddressOfEntryPoint(0),
    m_dwBaseOfCode(0),
    m_dwSizeOfHeaders(0),
    m_pSectionHeaders(NULL),
    m_pCodeSectionHeader(NULL),
    m_pDataDirectories(NULL)
{
}

CR_Module::CR_Module(LPCTSTR FileName) :
    m_pszFileName(NULL),
    m_hFile(INVALID_HANDLE_VALUE),
    m_hFileMapping(NULL),
    m_pFileImage(NULL),
    m_dwFileSize(0),
    m_dwLastError(ERROR_SUCCESS),
    m_bModuleLoaded(FALSE),
    m_bDisAsmed(FALSE),
    m_bDecompiled(FALSE),
    m_pDOSHeader(NULL),
    m_pNTHeaders(NULL),
    m_pFileHeader(NULL),
    m_pOptional32(NULL),
    m_pOptional64(NULL),
    m_pLoadedImage(NULL),
    m_dwHeaderSum(0),
    m_dwCheckSum(0),
    m_dwSizeOfOptionalHeader(0),
    m_dwAddressOfEntryPoint(0),
    m_dwBaseOfCode(0),
    m_dwSizeOfHeaders(0),
    m_pSectionHeaders(NULL),
    m_pCodeSectionHeader(NULL),
    m_pDataDirectories(NULL)
{
    LoadModule(FileName);
}

/*virtual*/ CR_Module::~CR_Module()
{
    if (IsModuleLoaded())
        UnloadModule();
}

void CR_Module::UnloadModule()
{
    if (m_pLoadedImage != NULL)
    {
        VirtualFree(m_pLoadedImage, 0, MEM_RELEASE);
        m_pLoadedImage = NULL;
    }
    if (m_pFileImage != NULL)
    {
        UnmapViewOfFile(m_pFileImage);
        m_pFileImage = NULL;
    }
    if (m_hFileMapping != NULL)
    {
        CloseHandle(m_hFileMapping);
        m_hFileMapping = NULL;
    }
    if (m_hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
    m_pszFileName = NULL;
    m_dwFileSize = 0;
    m_bModuleLoaded = FALSE;
    m_pDOSHeader = NULL;
    m_pNTHeaders = NULL;
    m_pFileHeader = NULL;
    m_pOptional32 = NULL;
    m_pOptional64 = NULL;
    m_dwHeaderSum = 0;
    m_dwCheckSum = 0;
    m_dwSizeOfOptionalHeader = 0;
    m_dwAddressOfEntryPoint = 0;
    m_dwBaseOfCode = 0;
    m_dwSizeOfHeaders = 0;
    m_pSectionHeaders = NULL;
    m_pCodeSectionHeader = NULL;
    m_pDataDirectories = NULL;

    m_SymbolInfo.clear();

    m_bDisAsmed = FALSE;
    m_bDecompiled = FALSE;

    m_vImgDelayDescrs.clear();
}

LPBYTE CR_Module::DirEntryData(DWORD index)
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

BOOL CR_Module::AddressInCode32(CR_Addr32 va) const
{
    if (!Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    const CR_Addr32 begin = OptionalHeader32()->ImageBase + pCode->RVA;
    const CR_Addr32 end = begin + pCode->Misc.VirtualSize;
    return begin <= va && va < end;
}

BOOL CR_Module::AddressInCode64(CR_Addr64 va) const
{
    if (!Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    const CR_Addr64 begin = OptionalHeader64()->ImageBase + pCode->RVA;
    const CR_Addr64 end = begin + pCode->Misc.VirtualSize;
    return begin <= va && va < end;
}

PREAL_IMAGE_SECTION_HEADER CR_Module::CodeSectionHeader()
{
    if (m_pCodeSectionHeader)
        return m_pCodeSectionHeader;

    assert(SectionHeaders());
    const DWORD size = NumberOfSections();
    for (DWORD i = 0; i < size; i++)
    {
        PREAL_IMAGE_SECTION_HEADER pHeader = SectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            m_pCodeSectionHeader = pHeader;
            return pHeader;
        }
    }
    return NULL;
}

const PREAL_IMAGE_SECTION_HEADER CR_Module::CodeSectionHeader() const
{
    if (m_pCodeSectionHeader)
        return m_pCodeSectionHeader;

    assert(SectionHeaders());
    const DWORD size = NumberOfSections();
    for (DWORD i = 0; i < size; i++)
    {
        PREAL_IMAGE_SECTION_HEADER pHeader = SectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
        {
            m_pCodeSectionHeader = pHeader;
            return pHeader;
        }
    }
    return NULL;
}

////////////////////////////////////////////////////////////////////////////
// CR_Module loading

BOOL CR_Module::_LoadImage(LPVOID Data)
{
    PIMAGE_DOS_HEADER pDOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Data);
    PIMAGE_NT_HEADERS pNTHeaders;

    if (pDOSHeader->e_magic == IMAGE_DOS_SIGNATURE && pDOSHeader->e_lfanew)  // "MZ"
    {
        pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<LPBYTE>(Data) + pDOSHeader->e_lfanew);
    }
    else
    {
        pDOSHeader = NULL;
        pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(Data);
    }
    DOSHeader() = pDOSHeader;

    if (pNTHeaders->Signature == IMAGE_NT_SIGNATURE) // "PE\0\0"
    {
        if (_LoadNTHeaders(pNTHeaders))
        {
            LoadedImage() = reinterpret_cast<LPBYTE>(
                VirtualAlloc(NULL, GetSizeOfImage() + 16,
                             MEM_COMMIT, PAGE_READWRITE));
            assert(LoadedImage());
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

BOOL CR_Module::_LoadNTHeaders(LPVOID Data)
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
    NTHeaders() = reinterpret_cast<PIMAGE_NT_HEADERS>(Data);
    pFileHeader = &NTHeaders()->FileHeader;

    LPBYTE pb;
    switch (pFileHeader->SizeOfOptionalHeader)
    {
    case IMAGE_SIZEOF_NT_OPTIONAL32_HEADER:
        FileHeader() = pFileHeader;
        OptionalHeader32() = pOptional32 = &NTHeaders32()->OptionalHeader;;
        if (pOptional32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return FALSE;

        pb = reinterpret_cast<LPBYTE>(pOptional32) + pFileHeader->SizeOfOptionalHeader;
        SectionHeaders() = reinterpret_cast<PREAL_IMAGE_SECTION_HEADER>(pb);
        DataDirectories() =
            reinterpret_cast<PREAL_IMAGE_DATA_DIRECTORY>(pOptional32->DataDirectory);
        break;

    case IMAGE_SIZEOF_NT_OPTIONAL64_HEADER:
        FileHeader() = pFileHeader;
        OptionalHeader64() = pOptional64 = &NTHeaders64()->OptionalHeader;
        if (pOptional64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return FALSE;

        pb = reinterpret_cast<LPBYTE>(pOptional64) + pFileHeader->SizeOfOptionalHeader;
        SectionHeaders() = reinterpret_cast<PREAL_IMAGE_SECTION_HEADER>(pb);
        DataDirectories() =
            reinterpret_cast<PREAL_IMAGE_DATA_DIRECTORY>(pOptional64->DataDirectory);
        break;

    default:
        FileHeader() = NULL;
        NTHeaders() = NULL;
        OptionalHeader32() = NULL;
        OptionalHeader64() = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL CR_Module::LoadModule(LPCTSTR pszFileName)
{
    File() = CreateFile(pszFileName, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (File() == INVALID_HANDLE_VALUE)
    {
        LastError() = GetLastError();
        return FALSE;
    }

    FileSize() = ::GetFileSize(File(), NULL);
    if (FileSize() == 0xFFFFFFFF)
    {
        LastError() = GetLastError();
        CloseHandle(File());
        return FALSE;
    }

    FileMapping() = CreateFileMappingA(
        File(), NULL, PAGE_READONLY, 0, 0, NULL);
    if (FileMapping() != NULL)
    {
        FileImage() = reinterpret_cast<LPBYTE>(
            MapViewOfFile(
                FileMapping(), FILE_MAP_READ, 0, 0, FileSize()));
        if (FileImage() != NULL)
        {
#ifndef NO_CHECKSUM
            CheckSumMappedFile(FileImage(), FileSize(),
                &m_dwHeaderSum, &m_dwCheckSum);
#endif
            if (_LoadImage(FileImage()))
            {
                LoadImportTables();
                LoadExportTable();
                ModuleLoaded() = TRUE;
                FileName() = pszFileName;
                return TRUE;
            }
            LastError() = ERROR_INVALID_DATA;
        }
        else
        {
            LastError() = GetLastError();
        }
        CloseHandle(FileMapping());
        FileMapping() = NULL;
    }
    else
    {
        LastError() = GetLastError();
    }

    CloseHandle(File());
    File() = INVALID_HANDLE_VALUE;

    return FALSE;
}

BOOL CR_Module::LoadImportTables()
{
    if (!_GetImportDllNames(ImportDllNames()))
        return FALSE;

    const DWORD size = (DWORD)ImportDllNames().size();
    for (DWORD i = 0; i < size; i++)
    {
        CR_DeqSet<CR_ImportSymbol> symbols;
        if (_GetImportSymbols(i, symbols))
        {
            for (DWORD j = 0; j < symbols.size(); j++)
            {
                SymbolInfo().AddImportSymbol(symbols[j]);
            }
        }
    }
    return TRUE;
}

BOOL CR_Module::LoadExportTable()
{
    CR_DeqSet<CR_ExportSymbol> symbols;
    CR_Symbol symbol;

    if (!_GetExportSymbols(SymbolInfo().GetExportSymbols()))
        return FALSE;

    DWORD siz = static_cast<DWORD>(symbols.size());
    for (DWORD i = 0; i < siz; i++)
    {
        if (symbols[i].dwRVA == 0 || symbols[i].pszForwarded)
            continue;

        SymbolInfo().AddExportSymbol(symbols[i]);
    }

    return TRUE;
}

BOOL CR_Module::LoadDelayLoad()
{
    if (!IsModuleLoaded())
        return FALSE;

    PREAL_IMAGE_DATA_DIRECTORY pDir =
        DataDirectory(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

    CR_DeqSet<ImgDelayDescr> Descrs;
    ImgDelayDescr *pDescrs =
        reinterpret_cast<ImgDelayDescr *>(LoadedImage() + pDir->RVA);

    std::size_t i = 0;
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

BOOL CR_Module::_GetImportDllNames(CR_StringSet& names)
{
    PIMAGE_IMPORT_DESCRIPTOR descs = ImportDescriptors();
    names.clear();

    if (descs == NULL)
        return FALSE;

    for (DWORD i = 0; descs[i].FirstThunk != 0; i++)
        names.insert(reinterpret_cast<char *>(GetData(descs[i].Name)));

    return TRUE;
}

BOOL CR_Module::_GetImportSymbols(DWORD dll_index, CR_DeqSet<CR_ImportSymbol>& symbols)
{
    DWORD i, j;
    CR_ImportSymbol symbol;
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
                            symbol.Name.wOrdinal = WORD(IMAGE_ORDINAL64(pINT64[j]));
                        }
                        else
                        {
                            pIBN = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
                                GetData(DWORD(pINT64[j])));
                            symbol.wHint = pIBN->Hint;
                            symbol.pszName = reinterpret_cast<char *>(pIBN->Name);
                        }
                        symbols.insert(symbol);
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
                            symbol.Name.wOrdinal = WORD(IMAGE_ORDINAL32(pINT[j]));
                        }
                        else
                        {
                            pIBN = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(GetData(pINT[j]));
                            symbol.wHint = pIBN->Hint;
                            symbol.pszName = reinterpret_cast<char *>(pIBN->Name);
                        }
                        symbols.insert(symbol);
                    }
                }
            }
            break;
        }
    }

    return TRUE;
}

BOOL CR_Module::_GetExportSymbols(CR_DeqSet<CR_ExportSymbol>& symbols)
{
    CR_ExportSymbol symbol;
    PIMAGE_EXPORT_DIRECTORY pDir = ExportDirectory();

    symbols.clear();

    if (pDir == NULL)
        return FALSE;

    // export address table (EAT)
    LPDWORD pEAT = reinterpret_cast<LPDWORD>(GetData(pDir->AddressOfFunctions));
    // export name pointer table (ENPT)
    LPDWORD pENPT = reinterpret_cast<LPDWORD>(GetData(pDir->AddressOfNames));
    // export ordinal table (EOT)
    LPWORD pEOT = reinterpret_cast<LPWORD>(GetData(pDir->AddressOfNameOrdinals));

    DWORD i, j;
    WORD wOrdinal;
    for (i = 0; i < pDir->NumberOfNames; i++)
    {
        wOrdinal = pEOT[i];
        symbol.dwRVA = pEAT[wOrdinal];
        symbol.pszName = reinterpret_cast<char *>(GetData(pENPT[i]));
        symbol.dwOrdinal = pDir->Base + wOrdinal;
        symbol.pszForwarded = NULL;
        symbols.insert(symbol);
    }

    for (i = 0; i < pDir->NumberOfFunctions; i++)
    {
        for (j = 0; j < pDir->NumberOfNames; j++)
        {
            if (static_cast<DWORD>(pEOT[j]) == i)
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
            symbol.pszForwarded = reinterpret_cast<char *>(GetData(dw));
        }
        else
        {
            symbol.dwRVA = dw;
            symbol.pszForwarded = NULL;
        }
        symbol.dwOrdinal = pDir->Base + i;
        symbols.insert(symbol);
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// finding

const CR_ImportSymbol *CR_Module::FindImportSymbolByRVA(DWORD rva) const
{
    return SymbolInfo().GetImportSymbolFromRVA(rva);
}

const CR_ImportSymbol *CR_Module::FindImportSymbolByName(const char *Name) const
{
    return SymbolInfo().GetImportSymbolFromName(Name);
}

const CR_ExportSymbol *CR_Module::FindExportSymbolByRVA(DWORD rva) const
{
    return SymbolInfo().GetExportSymbolFromRVA(rva);
}

const CR_ExportSymbol *CR_Module::FindExportSymbolByName(const char *Name) const
{
    return SymbolInfo().GetExportSymbolFromName(Name);
}

const CR_Symbol *CR_Module::FindSymbolByRVA(DWORD rva) const
{
    return SymbolInfo().GetSymbolFromRVA(rva);
}

const CR_Symbol *CR_Module::FindSymbolByName(const char *Name) const
{
    return SymbolInfo().GetSymbolFromName(Name);
}

const CR_Symbol *CR_Module::FindSymbolByAddr32(CR_Addr32 addr) const
{
    if (OptionalHeader32())
        return FindSymbolByRVA(RVAFromVA32(addr));
    else
        return NULL;
}

const CR_Symbol *CR_Module::FindSymbolByAddr64(CR_Addr64 addr) const
{
    if (OptionalHeader64())
        return FindSymbolByRVA(RVAFromVA64(addr));
    else
        return NULL;
}

const char *CR_Module::GetSymbolNameFromRVA(DWORD rva) const
{
    const CR_Symbol *symbol = FindSymbolByRVA(rva);
    return symbol ? symbol->Name().c_str() : NULL;
}

const char *CR_Module::GetSymbolNameFromAddr32(CR_Addr32 addr) const
{
    const CR_Symbol *symbol = FindSymbolByAddr32(addr);
    return symbol ? symbol->Name().c_str() : NULL;
}

const char *CR_Module::GetSymbolNameFromAddr64(CR_Addr64 addr) const
{
    const CR_Symbol *symbol = FindSymbolByAddr64(addr);
    return symbol ? symbol->Name().c_str() : NULL;
}

////////////////////////////////////////////////////////////////////////////
// disasm

extern "C"
int32_t disasm(uint8_t *data, char *output, int outbufsize, int segsize,
               int64_t offset, int autosync, uint32_t prefer);

BOOL CR_Module::DisAsmAddr32(CR_DisAsmInfo32& info, CR_Addr32 func, CR_Addr32 va)
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    DWORD rva = RVAFromVA32(va);
    LPBYTE input = LoadedImage() + rva;
    int lendis;
    CHAR outbuf[256];
    CR_Addr32 addr;

    CR_CodeFunc32 *cf = info.MapAddrToCodeFunc()[func].get();
    if (cf == NULL)
    {
        cf = new CR_CodeFunc32;
        info.MapAddrToCodeFunc()[func] = CR_SharedCodeFunc32(cf);
    }
    if (func == va)
        cf->Addr() = func;

    const PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    assert(pCode);

    LPBYTE iend = LoadedImage() + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend)
    {
        CR_CodeInsn32 *ac = info.MapAddrToAsmCode()[va].get();
        if (ac == NULL)
        {
            ac = new CR_CodeInsn32;
            info.MapAddrToAsmCode()[va] = CR_SharedCodeInsn32(ac);
        }
        if (ac->FuncAddrs().Contains(func))
            break;

        ac->Addr() = va;
        ac->FuncAddrs().Insert(func);

        if (ac->FuncAddrs().size() > 1)
        {
            cf->Flags() |= FF_FUNCINFUNC;
        }

        // disasm
        lendis = disasm(input, outbuf, sizeof(outbuf), 32, va, false, 0);

        // parse insn
        if (!lendis || input + lendis > iend)
        {
            lendis = 1;
            ac->Name() = "???";
            ac->CodeInsnType() = CIT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf->Flags() |= FF_DONTDECOMPBUTDISASM;
        }
        else
            ac->ParseText(outbuf);

        // add asm codes
        if (ac->Codes().empty())
        {
            for (int i = 0; i < lendis; i++)
                ac->Codes().push_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (ac->CodeInsnType())
        {
        case CIT_JCC:
            // conditional jump
            switch (ac->Operand(0)->OperandType())
            {
            case OT_IMM: case OT_FUNCNAME:
                addr = ac->Operand(0)->Value32();
                cf->Jumpers().Insert(va);
                cf->Jumpees().Insert(addr);
                break;

            default: break;
            }
            break;

        case CIT_JMP:
            switch (ac->Operand(0)->OperandType())
            {
            case OT_IMM:
                if (func == va)
                {
                    // func is jumper
                    cf->FuncType() = FT_JUMPERFUNC;

                    addr = ac->Operand(0)->Value32();
                    info.Entrances().Insert(addr);
                    cf->Callers().Insert(va);

                    CR_CodeFunc32 *newcf;
                    newcf = info.MapAddrToCodeFunc()[addr].get();
                    if (newcf == NULL)
                    {
                        newcf = new CR_CodeFunc32;
                        info.MapAddrToCodeFunc()[addr] =
                            CR_SharedCodeFunc32(newcf);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().Insert(func);
                }
                else
                {
                    addr = ac->Operand(0)->Value32();
                    cf->Jumpers().Insert(va);
                    cf->Jumpees().Insert(addr);
                }
                break;

            case OT_FUNCNAME:
                if (func == va)
                {
                    // func is jumper
                    cf->FuncType() = FT_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            case OT_MEMIMM:
                if (func == va)
                {
                    // func is jumper
                    cf->FuncType() = FT_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case CIT_CALL:
            switch (ac->Operand(0)->OperandType())
            {
            case OT_IMM:
                // function call
                addr = ac->Operand(0)->Value32();
                info.Entrances().Insert(addr);
                cf->Callers().Insert(va);
                {
                    CR_CodeFunc32 *newcf = info.MapAddrToCodeFunc()[addr].get();
                    if (newcf == NULL)
                    {
                        newcf = new CR_CodeFunc32;
                        info.MapAddrToCodeFunc()[addr] =
                            CR_SharedCodeFunc32(newcf);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().Insert(func);
                }
                break;

            default:
                break;
            }
            break;

        case CIT_RETURN:
            if (!ac->Operands().empty() && ac->Operand(0)->OperandType() == OT_IMM)
            {
                // func is __stdcall
                cf->FuncType() = FT_STDCALL;
                cf->SizeOfStackArgs() = (int)ac->Operand(0)->Value32();
            }
            else
            {
                // func is not __stdcall
                cf->Flags() |= FF_NOTSTDCALL;
            }
            bBreak = TRUE;
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
} // CR_Module::DisAsmAddr32

BOOL CR_Module::DisAsmAddr64(CR_DisAsmInfo64& info, CR_Addr64 func, CR_Addr64 va)
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // calculate
    DWORD rva = RVAFromVA64(va);
    LPBYTE input = LoadedImage() + rva;
    int lendis;
    CHAR outbuf[256];
    CR_Addr64 addr;

    CR_CodeFunc64 *cf = info.MapAddrToCodeFunc()[func].get();
    if (cf == NULL)
    {
        cf = new CR_CodeFunc64;
        info.MapAddrToCodeFunc()[func] = CR_SharedCodeFunc64(cf);
    }
    if (func == va)
        cf->Addr() = func;

    const PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    assert(pCode);

    LPBYTE iend = LoadedImage() + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend)
    {
        CR_CodeInsn64 *ac = info.MapAddrToAsmCode()[va].get();
        if (ac == NULL)
        {
            ac = new CR_CodeInsn64;
            info.MapAddrToAsmCode()[va] = CR_SharedCodeInsn64(ac);
        }
        if (ac->FuncAddrs().Contains(func))
            break;

        ac->Addr() = va;
        ac->FuncAddrs().Insert(func);

        if (ac->FuncAddrs().size() > 1)
        {
            cf->Flags() |= FF_FUNCINFUNC;
        }

        // disasm
        lendis = disasm(input, outbuf, sizeof(outbuf), 64, va, false, 0);

        // parse insn
        if (!lendis || input + lendis > iend)
        {
            lendis = 1;
            ac->Name() = "???";
            ac->CodeInsnType() = CIT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf->Flags() |= FF_DONTDECOMPBUTDISASM;
        }
        else
            ac->ParseText(outbuf);

        // add asm codes
        if (ac->Codes().empty())
        {
            for (int i = 0; i < lendis; i++)
                ac->Codes().push_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (ac->CodeInsnType())
        {
        case CIT_JCC:
            // conditional jump
            switch (ac->Operand(0)->OperandType())
            {
            case OT_IMM:
                addr = ac->Operand(0)->Value64();
                cf->Jumpers().Insert(va);
                cf->Jumpees().Insert(addr);
                break;

            default:
                break;
            }
            break;

        case CIT_JMP:
            switch (ac->Operand(0)->OperandType())
            {
            case OT_IMM:
                if (func == va)
                {
                    // func is jumper
                    cf->FuncType() = FT_JUMPERFUNC;

                    addr = ac->Operand(0)->Value64();
                    info.Entrances().Insert(addr);
                    cf->Callers().Insert(va);

                    CR_CodeFunc64 *newcf = info.MapAddrToCodeFunc()[addr].get();
                    if (newcf == NULL)
                    {
                        newcf = new CR_CodeFunc64;
                        info.MapAddrToCodeFunc()[addr] =
                            CR_SharedCodeFunc64(newcf);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().Insert(func);
                }
                else
                {
                    addr = ac->Operand(0)->Value64();
                    cf->Jumpers().Insert(va);
                    cf->Jumpees().Insert(addr);
                }
                break;

            case OT_FUNCNAME:
                if (func == va)
                {
                    // func is jumper
                    cf->FuncType() = FT_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            case OT_MEMIMM:
                if (func == va)
                {
                    // func is jumper
                    cf->FuncType() = FT_JUMPERFUNC;

                    bBreak = TRUE;
                }
                break;

            default:
                break;
            }
            bBreak = TRUE;
            break;

        case CIT_CALL:
            switch (ac->Operand(0)->OperandType())
            {
            case OT_IMM:
                // function call
                addr = ac->Operand(0)->Value64();
                info.Entrances().Insert(addr);
                cf->Callers().Insert(va);
                {
                    CR_CodeFunc64 *newcf = info.MapAddrToCodeFunc()[addr].get();
                    if (newcf == NULL)
                    {
                        newcf = new CR_CodeFunc64;
                        info.MapAddrToCodeFunc()[addr] =
                            CR_SharedCodeFunc64(newcf);
                    }
                    newcf->Addr() = addr;
                    newcf->Callees().Insert(func);
                }
                break;

            default:
                break;
            }
            break;

        case CIT_RETURN:
            if (!ac->Operands().empty() && ac->Operand(0)->OperandType() == OT_IMM)
            {
                // func is __stdcall
                cf->FuncType() = FT_STDCALL;
                cf->SizeOfStackArgs() = (int)ac->Operand(0)->Value64();
            }
            else
            {
                // func is not __stdcall
                cf->Flags() |= FF_NOTSTDCALL;
            }
            bBreak = TRUE;
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
} // CR_Module::DisAsmAddr64

BOOL CR_Module::DisAsm32(CR_DisAsmInfo32& info)
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    // register entrances
    CR_Addr32 va;
    va = VA32FromRVA(RVAOfEntryPoint());
    info.Entrances().Insert(va);
    {
        CR_Symbol symbol;
        symbol.RVA() = RVAOfEntryPoint();
        symbol.Name() = "EntryPoint";
        SymbolInfo().AddSymbol(symbol);
    }

    {
        CR_CodeFunc32 *codefunc = new CR_CodeFunc32;
        codefunc->Addr() = va;
        codefunc->Name() = "EntryPoint";
        codefunc->SizeOfStackArgs() = 0;
        codefunc->Flags() = FF_NOTSTDCALL;
        codefunc->FuncType() = FT_CDECL;
        info.MapAddrToCodeFunc()[va] = CR_SharedCodeFunc32(codefunc);
    }

    for (auto& e_symbol : ExportSymbols())
    {
        va = VA32FromRVA(e_symbol.dwRVA);

        if (AddressInCode32(va))
        {
            CR_Symbol symbol;
            symbol.RVA() = e_symbol.dwRVA;
            symbol.Name() = e_symbol.pszName;
            SymbolInfo().AddSymbol(symbol);
        }

        info.Entrances().Insert(va);

        CR_CodeFunc32 *func = info.MapAddrToCodeFunc()[va].get();
        if (func == NULL)
        {
            func = new CR_CodeFunc32;
            info.MapAddrToCodeFunc()[va] = CR_SharedCodeFunc32(func);
        }
        func->Addr() = va;
        func->Name() = e_symbol.pszName;
    }

    // disasm entrances
    {
        std::size_t i = 0, size, size2;
        CR_Addr32Set addrset;
        do
        {
            addrset = info.Entrances();
            size = addrset.size();

            for ( ; i < size; i++)
            {
                CR_CodeFunc32 *cf =
                    info.MapAddrToCodeFunc()[addrset[i]].get();
                assert(cf);

                DisAsmAddr32(info, addrset[i], addrset[i]);

                CR_Addr32Set jumpees;
                do
                {
                    jumpees = cf->Jumpees();
                    size2 = jumpees.size();
                    for (std::size_t j = 0; j < size2; j++)
                    {
                        DisAsmAddr32(info, addrset[i], jumpees[j]);
                    }
                    // cf->Jumpees() may grow in DisAsmAddr32
                } while (jumpees.size() < cf->Jumpees().size());
            }

            // info.Entrances() may grow in DisAsmAddr32
        } while(size < info.Entrances().size());
    }

    return TRUE;
}

BOOL CR_Module::DisAsm64(CR_DisAsmInfo64& info)
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // register entrances
    CR_Addr64 va;
    va = VA64FromRVA(RVAOfEntryPoint());
    info.Entrances().Insert(va);
    {
        CR_Symbol symbol;
        symbol.RVA() = RVAOfEntryPoint();
        symbol.Name() = "EntryPoint";
        SymbolInfo().AddSymbol(symbol);
    }

    {
        CR_CodeFunc64 *codefunc = new CR_CodeFunc64;
        codefunc->Addr() = va;
        codefunc->Name() = "EntryPoint";
        codefunc->SizeOfStackArgs() = 0;
        codefunc->Flags() = FF_NOTSTDCALL;
        codefunc->FuncType() = FT_CDECL;
        info.MapAddrToCodeFunc()[va] = CR_SharedCodeFunc64(codefunc);
    }

    for (auto& e_symbol : ExportSymbols())
    {
        va = VA64FromRVA(e_symbol.dwRVA);

        if (AddressInCode64(va))
        {
            CR_Symbol symbol;
            symbol.RVA() = e_symbol.dwRVA;
            symbol.Name() = e_symbol.pszName;
            SymbolInfo().AddSymbol(symbol);
        }

        info.Entrances().Insert(va);
        CR_CodeFunc64 *func = info.MapAddrToCodeFunc()[va].get();
        if (func == NULL)
        {
            func = new CR_CodeFunc64;
            info.MapAddrToCodeFunc()[va] = CR_SharedCodeFunc64(func);
        }
        func->Addr() = va;
        func->Name() = e_symbol.pszName;
    }

    // disasm entrances
    {
        std::size_t i = 0, size, size2;
        CR_Addr64Set addrset;
        do
        {
            addrset = info.Entrances();
            size = addrset.size();

            for ( ; i < size; i++)
            {
                CR_CodeFunc64 *cf =
                    info.MapAddrToCodeFunc()[addrset[i]].get();
                assert(cf);

                DisAsmAddr64(info, addrset[i], addrset[i]);

                CR_Addr64Set jumpees;
                do
                {
                    jumpees = cf->Jumpees();
                    size2 = jumpees.size();
                    for (std::size_t j = 0; j < size2; j++)
                    {
                        DisAsmAddr64(info, addrset[i], jumpees[j]);
                    }
                    // cf->Jumpees() may grow in DisAsmAddr64
                } while (jumpees.size() < cf->Jumpees().size());
            }

            // info.Entrances() may grow in DisAsmAddr64
        } while(size < info.Entrances().size());
    }

    return TRUE;
}

BOOL CR_Module::FixupAsm32(CR_DisAsmInfo32& info)
{
    CHAR buf[64];
    for (auto it : info.MapAddrToAsmCode())
    {
        auto& operands = it.second.get()->Operands();
        for (auto& opr : operands)
        {
            if (opr.OperandType() == OT_MEMIMM)
            {
                CR_Addr32 addr = opr.Value32();
                if (AddressInData32(addr))
                {
                    sprintf(buf, "M%08lX", addr);
                    opr.Text() = buf;
                }
                else if (AddressInCode32(addr))
                {
                    auto symbol = SymbolInfo().GetSymbolFromRVA(RVAFromVA32(addr));
                    if (symbol)
                    {
                        opr.SetFuncName(symbol->Name().c_str());
                    }
                    else
                    {
                        sprintf(buf, "L%08lX", addr);
                        opr.Text() = buf;
                    }
                }
            }
        }

        switch (it.second->CodeInsnType())
        {
        case CIT_JMP:
        case CIT_LOOP:
        case CIT_JCC:
        case CIT_CALL:
            if (operands[0].OperandType() == OT_MEMIMM)
            {
                CR_Addr32 addr = operands[0].Value32();
                const char *pName = GetSymbolNameFromAddr32(addr);
                if (pName)
                    operands[0].SetFuncName(pName);
            }
            else if (operands[0].OperandType() == OT_IMM)
            {
                CR_Addr32 addr = operands[0].Value32();
                const char *pName = GetSymbolNameFromAddr32(addr);
                if (pName)
                {
                    operands[0].SetFuncName(pName);
                }
                else if (AddressInCode32(addr))
                {
                    sprintf(buf, "L%08lX", addr);
                    operands[0].Text() = buf;
                }
            }
            break;

        case CIT_MISC:
            if (it.second->Name() == "mov" ||
                it.second->Name() == "cmp" ||
                it.second->Name() == "test" ||
                it.second->Name() == "and" ||
                it.second->Name() == "sub" ||
                it.second->Name().find("cmov") == 0)
            {
                if (operands[0].Size() == 0)
                    operands[0].Size() = operands[1].Size();
                else if (operands[1].Size() == 0)
                    operands[1].Size() = operands[0].Size();
            }
            else if (it.second->Name() == "lea")
            {
                CR_Addr32 addr = operands[1].Value32();
                if (AddressInData32(addr))
                {
                    sprintf(buf, "offset M%08lX", addr);
                    operands[1].Text() = buf;
                }
                else if (AddressInCode32(addr))
                {
                    sprintf(buf, "offset L%08lX", addr);
                    operands[1].Text() = buf;
                }
            }
            break;

        default:
            break;
        }
    }
    return TRUE;
}

BOOL CR_Module::FixupAsm64(CR_DisAsmInfo64& info)
{
    CHAR buf[64];
    for (auto it : info.MapAddrToAsmCode())
    {
        auto& operands = it.second.get()->Operands();
        for (auto& opr : operands)
        {
            if (opr.OperandType() == OT_MEMIMM)
            {
                CR_Addr64 addr = opr.Value64();
                if (AddressInData64(addr))
                {
                    sprintf(buf, "M%08lX%08lX", HILONG(addr), LOLONG(addr));
                    opr.Text() = buf;
                }
                else if (AddressInCode64(addr))
                {
                    auto symbol = SymbolInfo().GetSymbolFromRVA(RVAFromVA64(addr));
                    if (symbol)
                    {
                        opr.SetFuncName(symbol->Name().c_str());
                    }
                    else
                    {
                        sprintf(buf, "L%08lX%08lX", HILONG(addr), LOLONG(addr));
                        opr.Text() = buf;
                    }
                }
            }
        }

        switch (it.second->CodeInsnType())
        {
        case CIT_JMP:
        case CIT_LOOP:
        case CIT_JCC:
        case CIT_CALL:
            if (operands[0].OperandType() == OT_MEMIMM)
            {
                CR_Addr64 addr = operands[0].Value64();
                const char *pName = GetSymbolNameFromAddr64(addr);
                if (pName)
                    operands[0].SetFuncName(pName);
            }
            else if (operands[0].OperandType() == OT_IMM)
            {
                CR_Addr64 addr = operands[0].Value64();
                const char *pName = GetSymbolNameFromAddr64(addr);
                if (pName)
                {
                    operands[0].SetFuncName(pName);
                }
                else if (AddressInCode64(addr))
                {
                    sprintf(buf, "L%08lX%08lX", HILONG(addr), LOLONG(addr));
                    operands[0].Text() = buf;
                }
            }
            break;

        case CIT_MISC:
            if (it.second->Name() == "mov" ||
                it.second->Name() == "cmp" ||
                it.second->Name() == "test" ||
                it.second->Name() == "and" ||
                it.second->Name() == "sub" ||
                it.second->Name().find("cmov") == 0)
            {
                if (operands[0].Size() == 0)
                    operands[0].Size() = operands[1].Size();
                else if (operands[1].Size() == 0)
                    operands[1].Size() = operands[0].Size();
            }
            else if (it.second->Name() == "lea")
            {
                CR_Addr64 addr = operands[1].Value64();
                if (AddressInData64(addr))
                {
                    sprintf(buf, "offset M%08lX%08lX", HILONG(addr), LOLONG(addr));
                    operands[1].Text() = buf;
                }
                else if (AddressInCode64(addr))
                {
                    sprintf(buf, "offset L%08lX%08lX", HILONG(addr), LOLONG(addr));
                    operands[1].Text() = buf;
                }
            }
            break;

        default:
            break;
        }
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
    DWORD size = SizeofResource(hModule, hRsrc);
    printf("        Data size: 0x%08lX (%lu) Bytes\n", size, size);

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

const char * const cr_res_types[] =
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
        UINT nType = static_cast<UINT>(reinterpret_cast<UINT_PTR>(lpszType));
        UINT size = static_cast<UINT>(sizeof(cr_res_types) / sizeof(cr_res_types[0]));
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

void CR_Module::DumpResource()
{
    HINSTANCE hInst;
    hInst = LoadLibraryEx(GetFileName(), NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hInst == NULL)
        return;

    printf("\n### RESOURCE ###\n");
    if (!EnumResourceTypes(hInst, EnumResTypeProc, 0))
        printf("  No resource data\n");
    FreeLibrary(hInst);

    printf("\n");
}

////////////////////////////////////////////////////////////////////////////
// decompiling

BOOL CR_Module::DecompileAddr32(CR_DisAsmInfo32& info, CR_Addr32 va)
{
    return FALSE;
}

BOOL CR_Module::DecompileAddr64(CR_DisAsmInfo64& info, CR_Addr64 va)
{
    return FALSE;
}

BOOL CR_Module::Decompile32(CR_DisAsmInfo32& info)
{
    return FALSE;
}

BOOL CR_Module::Decompile64(CR_DisAsmInfo64& info)
{
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
