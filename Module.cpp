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

CR_Symbol& CR_Symbol::operator=(const CR_Symbol& s)
{
    Copy(s);
    return *this;
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

CR_SymbolInfo& CR_SymbolInfo::operator=(const CR_SymbolInfo& info)
{
    Copy(info);
    return *this;
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
    MapRVAToSymbol().insert(make_pair(rva, s));
    if (name)
        MapNameToSymbol().insert(make_pair(name, s));
}

void CR_SymbolInfo::AddSymbol(const CR_Symbol& s)
{
    AddSymbol(s.RVA(), s.Name().c_str());
}

void CR_SymbolInfo::AddImportSymbol(const CR_ImportSymbol& is)
{
    GetImportSymbols().insert(is);
    MapRVAToImportSymbol().insert(make_pair(is.dwRVA, is));
    if (is.Name.wImportByName)
    {
        MapNameToImportSymbol().insert(make_pair(is.pszName, is));
        AddSymbol(is.dwRVA, is.pszName);
    }
}

void CR_SymbolInfo::AddExportSymbol(const CR_ExportSymbol& es)
{
    GetExportSymbols().insert(es);
    MapRVAToExportSymbol().insert(make_pair(es.dwRVA, es));
    if (es.pszName)
    {
        MapNameToExportSymbol().insert(make_pair(es.pszName, es));
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
        CR_VecSet<CR_ImportSymbol> symbols;
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
    CR_VecSet<CR_ExportSymbol> symbols;
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

    vector<ImgDelayDescr> Descrs;
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

BOOL CR_Module::_GetImportDllNames(CR_VecSet<string>& names)
{
    PIMAGE_IMPORT_DESCRIPTOR descs = ImportDescriptors();
    names.clear();

    if (descs == NULL)
        return FALSE;

    for (DWORD i = 0; descs[i].FirstThunk != 0; i++)
        names.insert(reinterpret_cast<char *>(GetData(descs[i].Name)));

    return TRUE;
}

BOOL CR_Module::_GetImportSymbols(DWORD dll_index, CR_VecSet<CR_ImportSymbol>& symbols)
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

BOOL CR_Module::_GetExportSymbols(CR_VecSet<CR_ExportSymbol>& symbols)
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

BOOL CR_Module::DisAsmAddr32(CR_DecompStatus32& status, CR_Addr32 func, CR_Addr32 va)
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    DWORD rva = RVAFromVA32(va);
    LPBYTE input = LoadedImage() + rva;
    INT lendis;
    CHAR outbuf[256];
    CR_Addr32 addr;

    CR_CodeFunc32& cf = status.MapAddrToCodeFunc()[func];
    if (func == va)
        cf.Addr() = func;

    const PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    assert(pCode);

    LPBYTE iend = LoadedImage() + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend)
    {
        CR_CodeInsn32& ac = status.MapAddrToAsmCode()[va];
        if (ac.FuncAddrs().Find(func))
            break;

        ac.Addr() = va;
        ac.FuncAddrs().insertIfNotFound(func);

        if (ac.FuncAddrs().size() > 1)
        {
            cf.Flags() |= FF_FUNCINFUNC;
        }

        // disasm
        lendis = disasm(input, outbuf, sizeof(outbuf), 32, va, false, 0);

        // parse insn
        if (!lendis || input + lendis > iend)
        {
            lendis = 1;
            ac.Name() = "???";
            ac.CodeInsnType() = CIT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf.Flags() |= FF_DONTDECOMPBUTDISASM;
        }
        else
            _ParseInsn32(ac, va, outbuf);

        // add asm codes
        if (ac.Codes().empty())
        {
            for (INT i = 0; i < lendis; i++)
                ac.Codes().push_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (ac.CodeInsnType())
        {
        case CIT_JCC:
            // conditional jump
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM: case OT_API:
                cf.Jumpers().insertIfNotFound(va);
                addr = ac.Operand(0)->Value32();
                cf.Jumpees().insertIfNotFound(addr);
                break;

            default: break;
            }
            break;

        case CIT_JMP:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM:
                if (func == va)
                {
                    // func is jumper
                    cf.FuncType() = FT_JUMPER;

                    addr = ac.Operand(0)->Value32();
                    status.Entrances().insertIfNotFound(addr);
                    status.MapAddrToCodeFunc()[addr].Addr() = addr;
                    cf.Callers().insertIfNotFound(va);
                    status.MapAddrToCodeFunc()[addr].Callees().insertIfNotFound(func);
                }
                else
                {
                    cf.Jumpers().insertIfNotFound(va);
                    addr = ac.Operand(0)->Value32();
                    cf.Jumpees().insertIfNotFound(addr);
                }
                break;

            case OT_API: case OT_MEMIMM:
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

        case CIT_CALL:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM:
                // function call
                addr = ac.Operand(0)->Value32();
                status.Entrances().insertIfNotFound(addr);
                status.MapAddrToCodeFunc()[addr].Addr() = addr;
                cf.Callers().insertIfNotFound(va);
                status.MapAddrToCodeFunc()[addr].Callees().insertIfNotFound(func);
                break;

            default:
                break;
            }
            break;

        case CIT_RETURN:
            if (!ac.Operands().empty() && ac.Operand(0)->OperandType() == OT_IMM)
            {
                // func is __stdcall
                cf.FuncType() = FT_STDCALL;
                cf.SizeOfStackArgs() = (INT)ac.Operand(0)->Value32();
            }
            else
            {
                // func is not __stdcall
                cf.Flags() |= FF_NOTSTDCALL;
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
}

BOOL CR_Module::DisAsmAddr64(CR_DecompStatus64& status, CR_Addr64 func, CR_Addr64 va)
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // calculate
    DWORD rva = RVAFromVA64(va);
    LPBYTE input = LoadedImage() + rva;
    INT lendis;
    CHAR outbuf[256];
    CR_Addr64 addr;

    CR_CodeFunc64& cf = status.MapAddrToCodeFunc()[func];
    if (func == va)
        cf.Addr() = func;

    const PREAL_IMAGE_SECTION_HEADER pCode = CodeSectionHeader();
    assert(pCode);

    LPBYTE iend = LoadedImage() + pCode->RVA + pCode->SizeOfRawData;
    while (input < iend)
    {
        CR_CodeInsn64& ac = status.MapAddrToAsmCode()[va];
        if (ac.FuncAddrs().Find(func))
            break;

        ac.Addr() = va;
        ac.FuncAddrs().insertIfNotFound(func);

        if (ac.FuncAddrs().size() > 1)
        {
            cf.Flags() |= FF_FUNCINFUNC;
        }

        // disasm
        lendis = disasm(input, outbuf, sizeof(outbuf), 64, va, false, 0);

        // parse insn
        if (!lendis || input + lendis > iend)
        {
            lendis = 1;
            ac.Name() = "???";
            ac.CodeInsnType() = CIT_UNKNOWN;
            // don't decompile if any unknown instruction.
            cf.Flags() |= FF_DONTDECOMPBUTDISASM;
        }
        else
            _ParseInsn64(ac, va, outbuf);

        // add asm codes
        if (ac.Codes().empty())
        {
            for (INT i = 0; i < lendis; i++)
                ac.Codes().push_back(input[i]);
        }

        BOOL bBreak = FALSE;
        switch (ac.CodeInsnType())
        {
        case CIT_JCC:
            // conditional jump
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM:
                cf.Jumpers().insertIfNotFound(va);
                addr = ac.Operand(0)->Value64();
                cf.Jumpees().insertIfNotFound(addr);
                break;

            default:
                break;
            }
            break;

        case CIT_JMP:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM:
                if (func == va)
                {
                    // func is jumper
                    cf.FuncType() = FT_JUMPER;

                    addr = ac.Operand(0)->Value64();
                    status.Entrances().insertIfNotFound(addr);
                    status.MapAddrToCodeFunc()[addr].Addr() = addr;
                    cf.Callers().insertIfNotFound(va);
                    status.MapAddrToCodeFunc()[addr].Callees().insertIfNotFound(func);
                }
                else
                {
                    cf.Jumpers().insertIfNotFound(va);
                    addr = ac.Operand(0)->Value64();
                    cf.Jumpees().insertIfNotFound(addr);
                }
                break;

            case OT_API: case OT_MEMIMM:
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

        case CIT_CALL:
            switch (ac.Operand(0)->OperandType())
            {
            case OT_IMM:
                // function call
                addr = ac.Operand(0)->Value64();
                status.Entrances().insertIfNotFound(addr);
                status.MapAddrToCodeFunc()[addr].Addr() = addr;
                cf.Callers().insertIfNotFound(va);
                status.MapAddrToCodeFunc()[addr].Callees().insertIfNotFound(func);
                break;

            default:
                break;
            }
            break;

        case CIT_RETURN:
            if (!ac.Operands().empty() && ac.Operand(0)->OperandType() == OT_IMM)
            {
                // func is __stdcall
                cf.FuncType() = FT_STDCALL;
                cf.SizeOfStackArgs() = (INT)ac.Operand(0)->Value64();
            }
            else
            {
                // func is not __stdcall
                cf.Flags() |= FF_NOTSTDCALL;
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
}

BOOL CR_Module::DisAsm32(CR_DecompStatus32& status)
{
    if (!IsModuleLoaded() || !Is32Bit())
        return FALSE;

    // void WINAPI WinMainCRTStartup(void);
    // BOOL WINAPI _DllMainCRTStartup(HANDLE, DWORD, LPVOID);
    const char *pszEntryPointName;
    if (IsDLL())
        pszEntryPointName = "_DllMainCRTStartup";
    else
        pszEntryPointName = "WinMainCRTStartup";

    {
        CR_Symbol symbol;
        symbol.RVA() = RVAOfEntryPoint();
        symbol.Name() = pszEntryPointName;
        SymbolInfo().AddSymbol(symbol);
    }

    // register entrances
    CR_Addr32 va;
    va = VA32FromRVA(RVAOfEntryPoint());
    status.Entrances().insertIfNotFound(va);

    status.MapAddrToCodeFunc()[va].Addr() = va;
    status.MapAddrToCodeFunc()[va].Name() = pszEntryPointName;
    if (IsDLL())
    {
        status.MapAddrToCodeFunc()[va].SizeOfStackArgs() = 3 * sizeof(CR_Addr32);

        status.MapAddrToCodeFunc()[va].Args().clear();

        OPERAND opr;
        opr.DataType() = "HANDLE";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().insert(opr);
        opr.DataType() = "DWORD";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().insert(opr);
        opr.DataType() = "LPVOID";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().insert(opr);
        status.MapAddrToCodeFunc()[va].ReturnDataType() = "BOOL";
    }
    else
        status.MapAddrToCodeFunc()[va].SizeOfStackArgs() = 0;

    {
        for (std::size_t i = 0; i < ExportSymbols().size(); i++)
        {
            va = VA32FromRVA(ExportSymbols()[i].dwRVA);

            if (AddressInCode32(va))
            {
                CR_Symbol symbol;
                symbol.RVA() = ExportSymbols()[i].dwRVA;
                symbol.Name() = ExportSymbols()[i].pszName;
                SymbolInfo().AddSymbol(symbol);
            }

            status.Entrances().insertIfNotFound(va);

            status.MapAddrToCodeFunc()[va].Addr() = va;
            status.MapAddrToCodeFunc()[va].Name() = ExportSymbols()[i].pszName;
        }
    }

    // disasm entrances
    {
        std::size_t i = 0, size;
        CR_Addr32Set addrset;
        do
        {
            addrset = status.Entrances();
            size = addrset.size();

            for ( ; i < size; i++)
            {
                DisAsmAddr32(status, addrset[i], addrset[i]);

                CR_CodeFunc32& cf = status.MapAddrToCodeFunc()[addrset[i]];
                for (std::size_t j = 0; j < cf.Jumpees().size(); j++)
                {
                    DisAsmAddr32(status, addrset[i], cf.Jumpees()[j]);
                }
            }

            // status.Entrances() may grow in DisAsmAddr32
        } while(size < status.Entrances().size());
    }

    return TRUE;
}

BOOL CR_Module::DisAsm64(CR_DecompStatus64& status)
{
    if (!IsModuleLoaded() || !Is64Bit())
        return FALSE;

    // void WINAPI WinMainCRTStartup(void);
    // BOOL WINAPI _DllMainCRTStartup(HANDLE, DWORD, LPVOID);
    const char *pszEntryPointName;
    if (IsDLL())
        pszEntryPointName = "_DllMainCRTStartup";
    else
        pszEntryPointName = "WinMainCRTStartup";

    // register entrypoint
    {
        CR_Symbol symbol;
        symbol.RVA() = RVAOfEntryPoint();
        symbol.Name() = pszEntryPointName;
        SymbolInfo().AddSymbol(symbol);
    }

    // register entrances
    CR_Addr64 va;
    va = VA64FromRVA(RVAOfEntryPoint());
    status.Entrances().insertIfNotFound(va);

    status.MapAddrToCodeFunc()[va].Addr() = va;
    status.MapAddrToCodeFunc()[va].Name() = pszEntryPointName;
    if (IsDLL())
    {
        status.MapAddrToCodeFunc()[va].SizeOfStackArgs() = 3 * sizeof(CR_Addr64);

        OPERAND opr;
        opr.DataType() = "HANDLE";
        opr.Size() = 8;
        status.MapAddrToCodeFunc()[va].Args().insert(opr);
        opr.DataType() = "DWORD";
        opr.Size() = 4;
        status.MapAddrToCodeFunc()[va].Args().insert(opr);
        opr.DataType() = "LPVOID";
        opr.Size() = 8;
        status.MapAddrToCodeFunc()[va].Args().insert(opr);
        status.MapAddrToCodeFunc()[va].ReturnDataType() = "BOOL";
    }
    else
        status.MapAddrToCodeFunc()[va].SizeOfStackArgs() = 0;

    {
        for (std::size_t i = 0; i < ExportSymbols().size(); i++)
        {
            va = VA64FromRVA(ExportSymbols()[i].dwRVA);

            if (AddressInCode64(va))
            {
                CR_Symbol symbol;
                symbol.RVA() = ExportSymbols()[i].dwRVA;
                symbol.Name() = ExportSymbols()[i].pszName;
                SymbolInfo().AddSymbol(symbol);
            }

            status.Entrances().insertIfNotFound(va);
            status.MapAddrToCodeFunc()[va].Addr() = va;
            status.MapAddrToCodeFunc()[va].Name() = ExportSymbols()[i].pszName;
        }
    }

    // disasm entrances
    {
        std::size_t i = 0, size;
        CR_Addr64Set addrset;
        do
        {
            addrset = status.Entrances();
            size = addrset.size();

            for ( ; i < size; i++)
            {
                DisAsmAddr64(status, addrset[i], addrset[i]);

                CR_CodeFunc64& cf = status.MapAddrToCodeFunc()[addrset[i]];
                for (std::size_t j = 0; j < cf.Jumpees().size(); j++)
                {
                    DisAsmAddr64(status, addrset[i], cf.Jumpees()[j]);
                }
            }

            // status.Entrances() may grow in DisAsmAddr64
        } while(size < status.Entrances().size());
    }

    return TRUE;
}

BOOL CR_Module::FixUpAsm32(CR_DecompStatus32& status)
{
    CHAR buf[64];
    auto end = status.MapAddrToAsmCode().end();
    for (auto it = status.MapAddrToAsmCode().begin(); it != end; it++)
    {
        OPERANDSET& operands =  it->second.Operands();
        std::size_t i, size = operands.size();
        for (i = 0; i < size; i++)
        {
            if (operands[i].OperandType() == OT_MEMIMM)
            {
                OPERAND& opr = operands[i];
                CR_Addr32 addr = opr.Value32();
                if (AddressInData32(addr))
                {
                    sprintf(buf, "M%08lX", addr);
                    opr.Text() = buf;
                }
                else if (AddressInCode32(addr))
                {
                    sprintf(buf, "L%08lX", addr);
                    opr.Text() = buf;
                }
            }
        }

        switch (it->second.CodeInsnType())
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
                    operands[0].SetAPI(pName);
            }
            else if (operands[0].OperandType() == OT_IMM)
            {
                CR_Addr32 addr = operands[0].Value32();
                const char *pName = GetSymbolNameFromAddr32(addr);
                if (pName)
                    operands[0].SetAPI(pName);
                else if (AddressInCode32(addr))
                {
                    sprintf(buf, "L%08lX", addr);
                    operands[0].Text() = buf;
                }
            }
            break;

        case CIT_MISC:
            if (it->second.Name() == "mov" ||
                it->second.Name() == "cmp" ||
                it->second.Name() == "test" ||
                it->second.Name() == "and" ||
                it->second.Name() == "sub" ||
                it->second.Name().find("cmov") == 0)
            {
                if (operands[0].Size() == 0)
                    operands[0].Size() = operands[1].Size();
                else if (operands[1].Size() == 0)
                    operands[1].Size() = operands[0].Size();
            }
            else if (it->second.Name() == "lea")
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

BOOL CR_Module::FixUpAsm64(CR_DecompStatus64& status)
{
    CHAR buf[64];
    auto end = status.MapAddrToAsmCode().end();
    for (auto it = status.MapAddrToAsmCode().begin(); it != end; it++)
    {
        OPERANDSET& operands =  it->second.Operands();
        std::size_t i, size = operands.size();
        for (i = 0; i < size; i++)
        {
            if (operands[i].OperandType() == OT_MEMIMM)
            {
                OPERAND& opr = operands[i];
                CR_Addr64 addr = opr.Value64();
                if (AddressInData64(addr))
                {
                    sprintf(buf, "M%08lX%08lX", HILONG(addr), LOLONG(addr));
                    opr.Text() = buf;
                }
                else if (AddressInCode64(addr))
                {
                    sprintf(buf, "L%08lX%08lX", HILONG(addr), LOLONG(addr));
                    opr.Text() = buf;
                }
            }
        }

        switch (it->second.CodeInsnType())
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
                    operands[0].SetAPI(pName);
            }
            else if (operands[0].OperandType() == OT_IMM)
            {
                CR_Addr64 addr = operands[0].Value64();
                const char *pName = GetSymbolNameFromAddr64(addr);
                if (pName)
                    operands[0].SetAPI(pName);
                else if (AddressInCode64(addr))
                {
                    sprintf(buf, "L%08lX%08lX", HILONG(addr), LOLONG(addr));
                    operands[0].Text() = buf;
                }
            }
            break;

        case CIT_MISC:
            if (it->second.Name() == "mov" ||
                it->second.Name() == "cmp" ||
                it->second.Name() == "test" ||
                it->second.Name() == "and" ||
                it->second.Name() == "sub" ||
                it->second.Name().find("cmov") == 0)
            {
                if (operands[0].Size() == 0)
                    operands[0].Size() = operands[1].Size();
                else if (operands[1].Size() == 0)
                    operands[1].Size() = operands[0].Size();
            }
            else if (it->second.Name() == "lea")
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

    printf("### RESOURCE ###\n");
    if (!EnumResourceTypes(hInst, EnumResTypeProc, 0))
        printf("  No resource data\n");
    FreeLibrary(hInst);

    printf("\n");
}

////////////////////////////////////////////////////////////////////////////
// CR_Module::_ParseInsn32, CR_Module::_ParseInsn64

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
    CR_CondCode cc;
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

void CR_Module::_ParseInsn32(CR_CodeInsn32& ac, CR_Addr32 offset, const char *insn)
{
    char buf[128];
    strcpy(buf, insn);

    char *q = buf;

    if (strncmp(q, "cs ", 3) == 0 ||
        strncmp(q, "ss ", 3) == 0 ||
        strncmp(q, "ds ", 3) == 0 ||
        strncmp(q, "es ", 3) == 0 ||
        strncmp(q, "fs ", 3) == 0 ||
        strncmp(q, "gs ", 3) == 0)
    {
        q += 3;
    }

    if (strncmp(q, "a16 ", 4) == 0 ||
        strncmp(q, "o16 ", 4) == 0 ||
        strncmp(q, "o32 ", 4) == 0 ||
        strncmp(q, "o64 ", 4) == 0)
    {
        q += 4;
    }

    if (q[0] == 'r' && q[1] == 'e')
    {
        const std::size_t size = sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (std::size_t i = 0; i < size; i++)
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
                ac.Operands().insert(opr);
                return;
            }
        }
    }

    if (strncmp(q, "rep ", 4) == 0)
        q += 4;
    if (strncmp(q, "repne ", 6) == 0)
        q += 6;

    if (strncmp(q, "ret", 3) == 0 || strncmp(q, "iret", 4) == 0)
    {
        char *p = strchr(q, ' ');
        if (p)
        {
            *p = '\0';
            OPERAND opr;
            opr.Text() = p + 1;
            ac.Operands().clear();
            ParseOperand(opr, 32);
            ac.Operands().insert(opr);
        }
        ac.Name() = q;
        ac.CodeInsnType() = CIT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j')
    {
        const std::size_t size = sizeof(cr_ccentries) / sizeof(cr_ccentries[0]);
        for (std::size_t i = 0; i < size; i++)
        {
            if (strncmp(q, cr_ccentries[i].name, strlen(cr_ccentries[i].name)) == 0)
            {
                char *p = strchr(q, ' ');
                *p = '\0';
                ac.Name() = cr_ccentries[i].name;
                ac.CondCode() = cr_ccentries[i].cc;

                if (strncmp(cr_ccentries[i].name, "loop", 4) == 0)
                {
                    ac.CodeInsnType() = CIT_LOOP;
                }
                else if (ac.CondCode() == C_NONE)
                {
                    if (_stricmp(cr_ccentries[i].name, "call") == 0)
                        ac.CodeInsnType() = CIT_CALL;
                    else
                        ac.CodeInsnType() = CIT_JMP;
                }
                else
                    ac.CodeInsnType() = CIT_JCC;

                p++;
                OPERAND opr;
                opr.Text() = p;
                ParseOperand(opr, 32);
                ac.Operands().clear();
                ac.Operands().insert(opr);
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

    if (strncmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    ac.Name() = q;
    if (_stricmp(q, "push") == 0 || _stricmp(q, "pop") == 0 ||
        _stricmp(q, "enter") == 0 || _stricmp(q, "leave") == 0)
    {
        ac.CodeInsnType() = CIT_STACKOP;
    }

    ac.Operands().clear();
    p = strtok(p + 1, ",");
    if (p)
    {
        OPERAND opr;
        opr.Text() = p;
        ac.Operands().insert(opr);
        p = strtok(NULL, ",");
        if (p)
        {
            opr.Text() = p;
            ac.Operands().insert(opr);
            p = strtok(NULL, ",");
            if (p)
            {
                opr.Text() = p;
                ac.Operands().insert(opr);
                ParseOperand(*ac.Operand(2), 32);
            }
            ParseOperand(*ac.Operand(1), 32);
        }
        ParseOperand(*ac.Operand(0), 32);
    }
}

void CR_Module::_ParseInsn64(CR_CodeInsn64& ac, CR_Addr64 offset, const char *insn)
{
    char buf[128];
    strcpy(buf, insn);
    char *q = buf;
    if (strncmp(q, "a16 ", 4) == 0 ||
        strncmp(q, "o16 ", 4) == 0 ||
        strncmp(q, "o32 ", 4) == 0 ||
        strncmp(q, "o64 ", 4) == 0)
    {
        q += 4;
    }

    if (q[0] == 'r' && q[1] == 'e')
    {
        const std::size_t size = sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (std::size_t i = 0; i < size; i++)
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
                ac.Operands().insert(opr);
                return;
            }
        }
    }

    if (strncmp(q, "ret", 3) == 0 || strncmp(q, "iret", 4) == 0)
    {
        char *p = strchr(q, ' ');
        if (p)
        {
            *p = '\0';
            OPERAND opr;
            opr.Text() = p + 1;
            ac.Operands().clear();
            ParseOperand(opr, 64);
            ac.Operands().insert(opr);
        }
        ac.Name() = q;
        ac.CodeInsnType() = CIT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j')
    {
        const std::size_t size = sizeof(cr_ccentries) / sizeof(cr_ccentries[0]);
        for (std::size_t i = 0; i < size; i++)
        {
            if (strncmp(q, cr_ccentries[i].name, strlen(cr_ccentries[i].name)) == 0)
            {
                char *p = strchr(q, ' ');
                *p = '\0';
                ac.Name() = cr_ccentries[i].name;
                ac.CondCode() = cr_ccentries[i].cc;

                if (strncmp(cr_ccentries[i].name, "loop", 4) == 0)
                {
                    ac.CodeInsnType() = CIT_LOOP;
                }
                else if (ac.CondCode() == C_NONE)
                {
                    if (_stricmp(cr_ccentries[i].name, "call") == 0)
                        ac.CodeInsnType() = CIT_CALL;
                    else
                        ac.CodeInsnType() = CIT_JMP;
                }
                else
                    ac.CodeInsnType() = CIT_JCC;

                p++;
                OPERAND opr;
                opr.Text() = p;
                ParseOperand(opr, 64);
                ac.Operands().clear();
                ac.Operands().insert(opr);
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

    if (strncmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    ac.Name() = q;
    if (_stricmp(q, "push") == 0 || _stricmp(q, "pop") == 0 ||
        _stricmp(q, "enter") == 0 || _stricmp(q, "leave") == 0)
    {
        ac.CodeInsnType() = CIT_STACKOP;
    }

    ac.Operands().clear();
    p = strtok(p + 1, ",");
    if (p)
    {
        OPERAND opr;
        opr.Text() = p;
        ac.Operands().insert(opr);
        p = strtok(NULL, ",");
        if (p)
        {
            opr.Text() = p;
            ac.Operands().insert(opr);
            p = strtok(NULL, ",");
            if (p)
            {
                opr.Text() = p;
                ac.Operands().insert(opr);
                ParseOperand(*ac.Operand(2), 64);
            }
            ParseOperand(*ac.Operand(1), 64);
        }
        ParseOperand(*ac.Operand(0), 64);
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Module::ParseOperand

void CR_Module::ParseOperand(OPERAND& opr, INT bits)
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

    if (strncmp(p, "byte ", 5) == 0)
    {
        p += 5;
        opr.Size() = 1;
    }
    else if (strncmp(p, "word ", 5) == 0)
    {
        p += 5;
        opr.Size() = 2;
    }
    else if (strncmp(p, "dword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 4;
    }
    else if (strncmp(p, "qword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 8;
    }
    else if (strncmp(p, "tword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 10;
    }
    else if (strncmp(p, "oword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 16;
    }
    else if (strncmp(p, "yword ", 6) == 0)
    {
        p += 6;
        opr.Size() = 32;
    }
    else if (strncmp(p, "short ", 6) == 0)
    {
        p += 6;
        opr.Size() = 1;
    }
    else if (strncmp(p, "near ", 5) == 0)
    {
        p += 5;
        opr.Size() = 2;
    }

    // near or far
    if (strncmp(p, "near ", 5) == 0)
        p += 5;
    else if (strncmp(p, "far ", 4) == 0)
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
        opr.SetImm64(value, false);
    }
    else if (p[0] == '[')
    {
        p++;
        *strchr(p, ']') = '\0';

        if (strncmp(p, "word ", 5) == 0)
        {
            p += 5;
        }
        else if (strncmp(p, "dword ", 6) == 0)
        {
            p += 6;
        }
        else if (strncmp(p, "qword ", 6) == 0)
        {
            p += 6;
        }

        if (strncmp(p, "rel ", 4) == 0)
        {
            p += 4;
        }

        DWORD size;
        if ((size = cr_reg_get_size(p, bits)) != 0)
        {
            opr.OperandType() = OT_MEMREG;
            return;
        }

        CR_Addr64 addr;
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

BOOL CR_Module::DecompileAddr32(CR_DecompStatus32& status, CR_Addr32 va)
{
    return FALSE;
}

BOOL CR_Module::DecompileAddr64(CR_DecompStatus64& status, CR_Addr64 va)
{
    return FALSE;
}

BOOL CR_Module::Decompile32(CR_DecompStatus32& status)
{
    return FALSE;
}

BOOL CR_Module::Decompile64(CR_DecompStatus64& status)
{
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
