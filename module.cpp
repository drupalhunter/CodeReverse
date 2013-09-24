// module.cpp
// Copyright (C) 2013 Katayama Hirofumi MZ.  All rights reserved.

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

PEModule::PEModule() :
    m_pszFileName(NULL),
    m_hFile(INVALID_HANDLE_VALUE),
    m_hFileMapping(NULL),
    m_pFileImage(NULL),
    m_dwFileSize(0),
    m_dwLastError(ERROR_SUCCESS),
    m_bModuleLoaded(FALSE),
    m_bDisAsmed(FALSE),
    m_pDosHeader(NULL),
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
    m_dwSizeOfImage(0),
    m_dwSizeOfHeaders(0),
    m_dwNumberOfSections(0),
    m_pSectionHeaders(NULL),
    m_pDataDirectories(NULL)
{
}

PEModule::PEModule(LPCTSTR FileName) :
    m_pszFileName(NULL),
    m_hFile(INVALID_HANDLE_VALUE),
    m_hFileMapping(NULL),
    m_pFileImage(NULL),
    m_dwFileSize(0),
    m_dwLastError(ERROR_SUCCESS),
    m_bModuleLoaded(FALSE),
    m_bDisAsmed(FALSE),
    m_pDosHeader(NULL),
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
    m_dwSizeOfImage(0),
    m_dwSizeOfHeaders(0),
    m_dwNumberOfSections(0),
    m_pSectionHeaders(NULL),
    m_pDataDirectories(NULL)
{
    LoadModule(FileName);
}

PEModule::~PEModule()
{
    if (m_bModuleLoaded)
        UnloadModule();
}

VOID PEModule::UnloadModule()
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
    m_pDosHeader = NULL;
    m_pNTHeaders = NULL;
    m_pFileHeader = NULL;
    m_pOptional32 = NULL;
    m_pOptional64 = NULL;
    m_dwHeaderSum = 0;
    m_dwCheckSum = 0;
    m_dwSizeOfOptionalHeader = 0;
    m_dwAddressOfEntryPoint = 0;
    m_dwBaseOfCode = 0;
    m_dwSizeOfImage = 0;
    m_dwSizeOfHeaders = 0;
    m_dwNumberOfSections = 0;
    m_pSectionHeaders = NULL;
    m_pDataDirectories = NULL;

    m_vImportDllNames.clear();
    m_vExportSymbols.clear();
    m_mRVAToImportSymbol.clear();
    m_mNameToImportSymbol.clear();
    m_mRVAToExportSymbol.clear();
    m_mNameToExportSymbol.clear();
    m_mRVAToSymbol.clear();
    m_mNameToSymbol.clear();

    m_mapAddrToCodePoint32.clear();
    m_mapAddrToCodePoint64.clear();
    m_bDisAsmed = FALSE;
}

BOOL PEModule::_LoadImage(LPVOID Data)
{
    m_pDosHeader = (PIMAGE_DOS_HEADER)Data;
    if (m_pDosHeader->e_magic == IMAGE_DOS_SIGNATURE && m_pDosHeader->e_lfanew)  // "MZ"
    {
        m_pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)Data + m_pDosHeader->e_lfanew);
    }
    else
    {
        m_pDosHeader = NULL;
        m_pNTHeaders = (PIMAGE_NT_HEADERS)Data;
    }

    if (m_pNTHeaders->Signature == IMAGE_NT_SIGNATURE) // "PE\0\0"
    {
        if (_LoadNTHeaders(m_pNTHeaders))
        {
            if (m_pOptional32)
            {
                m_pLoadedImage = (LPBYTE)VirtualAlloc(
                    NULL,
                    m_pOptional32->SizeOfImage + 16,
                    MEM_COMMIT,
                    PAGE_READWRITE
                );
            }
            else if (m_pOptional64)
            {
                m_pLoadedImage = (LPBYTE)VirtualAlloc(
                    NULL,
                    m_pOptional64->SizeOfImage + 16,
                    MEM_COMMIT,
                    PAGE_READWRITE
                );
            }

            if (m_pLoadedImage != NULL)
            {
                CopyMemory(m_pLoadedImage, m_pFileImage, m_dwSizeOfHeaders);

                for (DWORD i = 0; i < m_dwNumberOfSections; i++)
                {
                    CopyMemory(
                        &m_pLoadedImage[m_pSectionHeaders[i].VirtualAddress],
                        &m_pFileImage[m_pSectionHeaders[i].PointerToRawData],
                        m_pSectionHeaders[i].SizeOfRawData
                    );
                }

                return TRUE;
            }
        }
    }

    m_pNTHeaders = NULL;
    return FALSE;
}

BOOL PEModule::_LoadNTHeaders(LPVOID Data)
{
    m_pNTHeaders = (PIMAGE_NT_HEADERS)Data;
    m_pFileHeader = &m_pNTHeaders->FileHeader;

    m_dwSizeOfOptionalHeader = m_pFileHeader->SizeOfOptionalHeader;
    m_dwNumberOfSections = m_pFileHeader->NumberOfSections;

    switch(m_dwSizeOfOptionalHeader)
    {
#ifndef IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
    #define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER sizeof(IMAGE_OPTIONAL_HEADER32)
#endif
    case IMAGE_SIZEOF_NT_OPTIONAL32_HEADER:
        m_pOptional32 = (PIMAGE_OPTIONAL_HEADER32)&m_pNTHeaders->OptionalHeader;
        if (m_pOptional32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return FALSE;

        m_dwAddressOfEntryPoint = m_pOptional32->AddressOfEntryPoint;
        m_dwBaseOfCode = m_pOptional32->BaseOfCode;
        m_dwSizeOfImage = m_pOptional32->SizeOfImage;
        m_dwSizeOfHeaders = m_pOptional32->SizeOfHeaders;
        m_pSectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)m_pOptional32 + m_dwSizeOfOptionalHeader);
        m_pDataDirectories = m_pOptional32->DataDirectory;
        break;

#ifndef IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
    #define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER sizeof(IMAGE_OPTIONAL_HEADER64)
#endif
    case IMAGE_SIZEOF_NT_OPTIONAL64_HEADER:
        m_pOptional64 = (PIMAGE_OPTIONAL_HEADER64)&m_pNTHeaders->OptionalHeader;
        if (m_pOptional64->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return FALSE;

        m_dwAddressOfEntryPoint = m_pOptional64->AddressOfEntryPoint;
        m_dwBaseOfCode = m_pOptional64->BaseOfCode;
        m_dwSizeOfImage = m_pOptional64->SizeOfImage;
        m_dwSizeOfHeaders = m_pOptional64->SizeOfHeaders;
        m_pSectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)m_pOptional64 + m_dwSizeOfOptionalHeader);
        m_pDataDirectories = m_pOptional64->DataDirectory;
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

BOOL PEModule::LoadModule(LPCTSTR FileName)
{
    m_hFile = CreateFile(FileName, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (m_hFile == INVALID_HANDLE_VALUE)
    {
        m_dwLastError = GetLastError();
        return FALSE;
    }

    m_dwFileSize = ::GetFileSize(m_hFile, NULL);
    if (m_dwFileSize == 0xFFFFFFFF)
    {
        m_dwLastError = GetLastError();
        CloseHandle(m_hFile);
        return FALSE;
    }

    m_hFileMapping = CreateFileMappingA(
        m_hFile, NULL, PAGE_READONLY,
        0, 0, NULL
    );
    if (m_hFileMapping != NULL)
    {
        m_pFileImage = (LPBYTE)MapViewOfFile(
            m_hFileMapping,
            FILE_MAP_READ,
            0, 0,
            m_dwFileSize
        );
        if (m_pFileImage != NULL)
        {
#ifndef NO_CHECKSUM
            CheckSumMappedFile(
                m_pFileImage, m_dwFileSize,
                &m_dwHeaderSum, &m_dwCheckSum);
#endif
            if (_LoadImage(m_pFileImage))
            {
                LoadImportTables();
                LoadExportTable();
                m_bModuleLoaded = TRUE;
                m_pszFileName = FileName;
                return TRUE;
            }
            m_dwLastError = ERROR_INVALID_DATA;
        }
        else
        {
            m_dwLastError = GetLastError();
        }
        CloseHandle(m_hFileMapping);
        m_hFileMapping = NULL;
    }
    else
    {
        m_dwLastError = GetLastError();
    }

    CloseHandle(m_hFile);
    m_hFile = INVALID_HANDLE_VALUE;

    return FALSE;
}

VOID PEModule::DumpHeaders()
{
    if (!ModuleLoaded())
        return;

#ifdef _UNICODE
    printf("FileName: %ls, FileSize: 0x%08lX (%lu)\n", m_pszFileName, m_dwFileSize, m_dwFileSize);
#else
    printf("FileName: %s, FileSize: 0x%08lX (%lu)\n", m_pszFileName, m_dwFileSize, m_dwFileSize);
#endif

    if (m_pDosHeader)
    {
        DumpDosHeader(m_pDosHeader);
    }
    if (m_pFileHeader)
    {
        DumpFileHeader(m_pFileHeader);
    }
    if (m_pOptional32)
    {
        DumpOptionalHeader32(m_pOptional32, m_dwCheckSum);
    }
    else if (m_pOptional64)
    {
        DumpOptionalHeader64(m_pOptional64, m_dwCheckSum);
    }
    if (m_pSectionHeaders)
    {
        for (DWORD i = 0; i < m_dwNumberOfSections; i++)
        {
            printf("\n### Section #%lu ###\n", i);
            DumpSectionHeader(&m_pSectionHeaders[i]);
        }
    }
}

VOID PEModule::DumpImportSymbols()
{
    PIMAGE_IMPORT_DESCRIPTOR descs;
    vector<string> dll_names;
    vector<IMPORT_SYMBOL> symbols;

    descs = GetImportDescriptors();
    if (descs == NULL)
        return;

    printf("\n### IMPORT ###\n");
    printf("  Characteristics: 0x%08lX\n", descs->Characteristics);
    printf("  TimeDateStamp: 0x%08lX (%s)\n", descs->TimeDateStamp, GetTimeStampString(descs->TimeDateStamp));
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
                        ULONGLONG dwl = m_pOptional64->ImageBase + symbols[j].dwRVA;
                        printf("    %08lX %08lX%08lX ", symbols[j].dwRVA,
                            (DWORD)(dwl >> 32), (DWORD)dwl);
                    }
                    else
                        printf("    %08lX %08lX ", symbols[j].dwRVA,
                            m_pOptional32->ImageBase + symbols[j].dwRVA);
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

LPBYTE PEModule::GetDirEntryData(DWORD index)
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
        if (m_pDataDirectories[index].VirtualAddress != 0 &&
            m_pDataDirectories[index].Size != 0)
        {
            return m_pLoadedImage + m_pDataDirectories[index].VirtualAddress;
        }
    }
    return NULL;
}

BOOL PEModule::_GetImportDllNames(vector<string>& names)
{
    PIMAGE_IMPORT_DESCRIPTOR descs = GetImportDescriptors();
    names.clear();

    if (descs == NULL)
        return FALSE;

    for (DWORD i = 0; descs[i].FirstThunk != 0; i++)
        names.push_back((LPSTR)GetData(descs[i].Name));

    return TRUE;
}

BOOL PEModule::_GetImportSymbols(DWORD dll_index, vector<IMPORT_SYMBOL>& symbols)
{
    DWORD i, j;
    IMPORT_SYMBOL symbol;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PIMAGE_IMPORT_DESCRIPTOR descs = GetImportDescriptors();

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
                    if (pINT64[j] < m_dwSizeOfImage)
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
                    if (pINT[j] < m_dwSizeOfImage)
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

BOOL PEModule::_GetExportSymbols(vector<EXPORT_SYMBOL>& symbols)
{
    EXPORT_SYMBOL symbol;
    PIMAGE_EXPORT_DIRECTORY pDir = GetExportDirectory();

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

VOID PEModule::DumpExportSymbols()
{
    PIMAGE_EXPORT_DIRECTORY pDir = GetExportDirectory();

    if (pDir == NULL)
        return;

    //DWORD dwNumberOfNames = pDir->NumberOfNames;
    //DWORD dwAddressOfFunctions = pDir->AddressOfFunctions;
    //DWORD dwAddressOfNames = pDir->AddressOfNames;
    //DWORD dwAddressOfOrdinals = pDir->AddressOfNameOrdinals;
    //LPDWORD pEAT = (LPDWORD)GetData(dwAddressOfFunctions);
    //LPDWORD pENPT = (LPDWORD)GetData(dwAddressOfNames);
    //LPWORD pOT = (LPWORD)GetData(dwAddressOfOrdinals);

    printf("\n### EXPORT ###\n");
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

    printf("  %-50s %-5s ; %s\n", "FUNCTION NAME", "ORDI.", "RVA");

    for (DWORD i = 0; i < m_vExportSymbols.size(); i++)
    {
        EXPORT_SYMBOL& symbol = m_vExportSymbols[i];
        if (symbol.dwRVA)
        {
            if (symbol.pszName)
                printf("  %-50s @%-4lu ; 0x%08lX\n", 
                    symbol.pszName, symbol.dwOrdinal, symbol.dwRVA);
            else
                printf("  %-50s @%-4lu ; 0x%08lX\n", 
                    "(No Name)", symbol.dwOrdinal, symbol.dwRVA);
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

////////////////////////////////////////////////////////////////////////////

BOOL PEModule::LoadImportTables()
{
    vector<IMPORT_SYMBOL> symbols;
    SYMBOL symbol;

    if (!_GetImportDllNames(m_vImportDllNames))
        return FALSE;

    for (DWORD i = 0; i < m_vImportDllNames.size(); i++)
    {
        if (_GetImportSymbols(i, symbols))
        {
            for (DWORD j = 0; j < symbols.size(); j++)
            {
                symbol.dwRVA = symbols[j].dwRVA;
                symbol.pszName = symbols[j].pszName;
                m_mRVAToSymbol.insert(make_pair(symbol.dwRVA, symbol));
                m_mRVAToImportSymbol.insert(make_pair(symbols[j].dwRVA, symbols[j]));
                if (symbols[j].Name.wImportByName)
                {
                    m_mNameToImportSymbol.insert(make_pair(symbols[j].pszName, symbols[j]));
                    m_mNameToSymbol.insert(make_pair(symbol.pszName, symbol));
                }
            }
        }
    }
    return TRUE;
}

BOOL PEModule::LoadExportTable()
{
    vector<EXPORT_SYMBOL> symbols;
    SYMBOL symbol;

    m_vExportSymbols.clear();

    if (!_GetExportSymbols(symbols))
        return FALSE;

    m_vExportSymbols = symbols;

    for (DWORD i = 0; i < (DWORD)symbols.size(); i++)
    {
        if (symbols[i].dwRVA == 0 || symbols[i].pszForwarded)
            continue;

        if (symbols[i].dwRVA)
            m_mRVAToExportSymbol.insert(make_pair(symbols[i].dwRVA, symbols[i]));
        if (symbols[i].pszName)
            m_mNameToExportSymbol.insert(make_pair(symbols[i].pszName, symbols[i]));

        symbol.dwRVA = symbols[i].dwRVA;
        symbol.pszName = symbols[i].pszName;
        if (symbol.dwRVA)
            m_mRVAToSymbol.insert(make_pair(symbol.dwRVA, symbol));
        if (symbol.pszName)
            m_mNameToSymbol.insert(make_pair(symbol.pszName, symbol));
    }

    return TRUE;
}

const IMPORT_SYMBOL *PEModule::FindImportSymbolByRVA(DWORD RVA) const
{
    map<DWORD, IMPORT_SYMBOL>::const_iterator it;
    it = m_mRVAToImportSymbol.find(RVA);
    if (it != m_mRVAToImportSymbol.end())
        return &it->second;
    return NULL;
}

const IMPORT_SYMBOL *PEModule::FindImportSymbolByName(LPCSTR Name) const
{
    map<string, IMPORT_SYMBOL>::const_iterator it;
    it = m_mNameToImportSymbol.find(Name);
    if (it != m_mNameToImportSymbol.end())
        return &it->second;
    return NULL;
}

const EXPORT_SYMBOL *PEModule::FindExportSymbolByRVA(DWORD RVA) const
{
    map<DWORD, EXPORT_SYMBOL>::const_iterator it;
    it = m_mRVAToExportSymbol.find(RVA);
    if (it != m_mRVAToExportSymbol.end())
        return &it->second;
    return NULL;
}

const EXPORT_SYMBOL *PEModule::FindExportSymbolByName(LPCSTR Name) const
{
    map<string, EXPORT_SYMBOL>::const_iterator it;
    it = m_mNameToExportSymbol.find(Name);
    if (it != m_mNameToExportSymbol.end())
        return &it->second;
    return NULL;
}

const SYMBOL *PEModule::FindSymbolByRVA(DWORD RVA) const
{
    map<DWORD, SYMBOL>::const_iterator it;
    it = m_mRVAToSymbol.find(RVA);
    if (it != m_mRVAToSymbol.end())
        return &it->second;
    return NULL;
}

const SYMBOL *PEModule::FindSymbolByName(LPCSTR Name) const
{
    map<string, SYMBOL>::const_iterator it;
    it = m_mNameToSymbol.find(Name);
    if (it != m_mNameToSymbol.end())
        return &it->second;
    return NULL;
}

PREAL_IMAGE_SECTION_HEADER PEModule::GetCodeSectionHeader() const
{
    if (m_pSectionHeaders == NULL)
        return NULL;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    for (DWORD i = 0; i < m_dwNumberOfSections; i++)
    {
        pHeader = GetSectionHeader(i);
        if (pHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            return pHeader;
    }
    return NULL;
}

BOOL PEModule::AddressInCode32(ADDRESS32 VA) const
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    DWORD RVA = (DWORD)(DWORD_PTR)(VA - m_pOptional32->ImageBase);

    return (pCode->RVA <= RVA && RVA < pCode->RVA + pCode->Misc.VirtualSize);
}

BOOL PEModule::AddressInData32(ADDRESS32 VA) const
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    DWORD RVA;

    const DWORD dwFlags = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
    for (DWORD i = 0; i < m_dwNumberOfSections; i++)
    {
        if (m_pSectionHeaders[i].Characteristics & dwFlags)
            continue;

        RVA = VA - m_pOptional32->ImageBase;

        pHeader = GetSectionHeader(i);
        if (pHeader->RVA <= RVA && RVA < pHeader->RVA + pHeader->Misc.VirtualSize)
            return TRUE;
    }
    return FALSE;
}

BOOL PEModule::AddressInCode64(ADDRESS64 VA) const
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    DWORD RVA = (DWORD)(DWORD_PTR)(VA - m_pOptional64->ImageBase);

    return (pCode->RVA <= RVA && RVA < pCode->RVA + pCode->Misc.VirtualSize);
}

BOOL PEModule::AddressInData64(ADDRESS64 VA) const
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    DWORD RVA;

    const DWORD dwFlags = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
    for (DWORD i = 0; i < m_dwNumberOfSections; i++)
    {
        if (m_pSectionHeaders[i].Characteristics & dwFlags)
            continue;

        RVA = (DWORD)(DWORD_PTR)(VA - m_pOptional64->ImageBase);

        pHeader = GetSectionHeader(i);
        if (pHeader->RVA <= RVA && RVA < pHeader->RVA + pHeader->Misc.VirtualSize)
            return TRUE;
    }
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int32_t disasm(uint8_t *data, char *output, int outbufsize, int segsize,
               int64_t offset, int autosync, uint32_t prefer);

BOOL PEModule::DisAsm32()
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    LPBYTE input = m_pFileImage + pCode->PointerToRawData;
    ADDRESS32 offset = m_pOptional32->ImageBase + pCode->RVA;
    DWORD size = pCode->SizeOfRawData;

    CODEPOINT32 cp;
    INT lendis;
    LPBYTE p = input, end = input + size;
    CHAR outbuf[256];

    while (p < end)
    {
        lendis = disasm(p, outbuf, sizeof(outbuf), 32, offset, false, 0);

        cp.Clear();

        if (!lendis || p + lendis > end)
        {
            lendis = 1;
            cp.name = "???";
        }
        else
            _ParseInsn32(cp, offset, outbuf);

        for (INT i = 0; i < lendis; i++)
            cp.codes.push_back(p[i]);

        cp.addr = offset;
        m_mapAddrToCodePoint32.insert(make_pair(offset, cp));

        p += lendis;
        offset += lendis;
    }

    m_bDisAsmed = TRUE;
    return TRUE;
}

BOOL PEModule::DisAsm64()
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    LPBYTE input = m_pFileImage + pCode->PointerToRawData;
    ADDRESS64 offset = m_pOptional64->ImageBase + pCode->RVA;
    DWORD size = pCode->SizeOfRawData;

    CODEPOINT64 cp;
    INT lendis;
    LPBYTE p = input, end = input + size;
    CHAR outbuf[256];

    while (p < end)
    {
        lendis = disasm(p, outbuf, sizeof(outbuf), 64, offset, false, 0);

        cp.Clear();

        if (!lendis || p + lendis > end)
        {
            lendis = 1;
            cp.name = "???";
        }
        else
            _ParseInsn64(cp, offset, outbuf);

        for (INT i = 0; i < lendis; i++)
            cp.codes.push_back(p[i]);

        cp.addr = offset;
        m_mapAddrToCodePoint64.insert(make_pair(offset, cp));

        p += lendis;
        offset += lendis;
    }

    m_bDisAsmed = TRUE;
    return TRUE;
}

////////////////////////////////////////////////////////////////////////////

void dump_codes(const vector<BYTE>& codes, int bits)
{
    size_t codesperline;

    if (bits == 64)
        codesperline = 16;
    else if (bits == 32)
        codesperline = 12;
    else
        codesperline = 9;

    for (size_t i = 0; i < codesperline; i++)
    {
        if (i < codes.size())
        {
            if (i == codesperline - 1)
                printf("%02X+", codes[i]);
            else
                printf("%02X ", codes[i]);
        }
        else
            printf("   ");
    }
}

BOOL PEModule::DumpDisAsm()
{
    if (!m_bDisAsmed && !DisAsm())
        return FALSE;

    printf("### DISASSEMBLY ###\n");

    if (Is64Bit())
    {
        map<ULONGLONG, CODEPOINT64>::iterator it, end = m_mapAddrToCodePoint64.end();
        for (it = m_mapAddrToCodePoint64.begin(); it != end; it++)
        {
            CODEPOINT64& cp = it->second;
            printf("L%08lX%08lX: ", HILONG(cp.addr), LOLONG(cp.addr));
            dump_codes(cp.codes, 64);
            if (cp.operand3.type != OT_NONE)
            {
                printf("%s %s,%s,%s\n", cp.name.c_str(),
                    cp.operand1.text.c_str(), cp.operand2.text.c_str(),
                    cp.operand3.text.c_str());
            }
            else if (cp.operand2.type != OT_NONE)
            {
                printf("%s %s,%s\n", cp.name.c_str(),
                    cp.operand1.text.c_str(), cp.operand2.text.c_str());
            }
            else if (cp.operand1.type != OT_NONE)
            {
                printf("%s %s\n", cp.name.c_str(),
                    cp.operand1.text.c_str());
            }
            else
            {
                printf("%s\n", cp.name.c_str());
            }
        }
    }
    else if (Is32Bit())
    {
        map<DWORD, CODEPOINT32>::iterator it, end = m_mapAddrToCodePoint32.end();
        for (it = m_mapAddrToCodePoint32.begin(); it != end; it++)
        {
            CODEPOINT32& cp = it->second;
            printf("L%08lX: ", cp.addr);
            dump_codes(cp.codes, 32);
            if (cp.operand3.type != OT_NONE)
            {
                printf("%s %s,%s,%s\n", cp.name.c_str(),
                    cp.operand1.text.c_str(), cp.operand2.text.c_str(),
                    cp.operand3.text.c_str());
            }
            else if (cp.operand2.type != OT_NONE)
            {
                printf("%s %s,%s\n", cp.name.c_str(),
                    cp.operand1.text.c_str(), cp.operand2.text.c_str());
            }
            else if (cp.operand1.type != OT_NONE)
            {
                printf("%s %s\n", cp.name.c_str(),
                    cp.operand1.text.c_str());
            }
            else
            {
                printf("%s\n", cp.name.c_str());
            }
        }
    }
    else
    {
        ;
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////

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

static const LPCSTR s_apszResTypes[] =
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
        if (nType < sizeof(s_apszResTypes) / sizeof(s_apszResTypes[0]) &&
            s_apszResTypes[nType])
        {
            printf("  Resource Type: %s\n", s_apszResTypes[nType]);
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

VOID PEModule::DumpResource()
{
    HINSTANCE hInst;
    hInst = LoadLibraryEx(m_pszFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hInst == NULL)
        return;

    printf("### RESOURCE ###\n");
    EnumResourceTypes(hInst, EnumResTypeProc, 0);
    FreeLibrary(hInst);

    printf("\n");
}

////////////////////////////////////////////////////////////////////////////

static const char * const s_rep_insns[] =
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
    CCODE cc;
};

static const CCENTRY s_ccentries[] =
{
    { "call", C_none },

    { "loop", C_none },
    { "loope", C_E },
    { "loopne", C_NE },

    { "jmp", C_none },

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

VOID PEModule::_ParseInsn32(CODEPOINT32& cp, ADDRESS32 offset, const char *insn)
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

    cp.Clear();

    if (q[0] == 'r' && q[1] == 'e')
    {
        for (size_t i = 0; i < sizeof(s_rep_insns) / sizeof(s_rep_insns[0]); i++)
        {
            if (_stricmp(q, s_rep_insns[i]) == 0)
            {
                cp.name = q;
                char *p = q + strlen(q) - 1;
                if (*p == 'b')
                    cp.operand1.size = 1;
                else if (*p == 'w')
                    cp.operand1.size = 2;
                else if (*p == 'd')
                    cp.operand1.size = 4;

                if (q[3] == 'e')
                    cp.cc = C_E;
                else if (q[3] == 'n')
                    cp.cc = C_NE;
                else
                    cp.cc = C_none;
                return;
            }
        }
    }

    if (_strnicmp(q, "rep ", 4) == 0)
        q += 4;
    if (_strnicmp(q, "repne ", 6) == 0)
        q += 6;

    if (_stricmp(q, "ret") == 0 || _stricmp(q, "iret") == 0)
    {
        cp.name = q;
        cp.bt = BT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j')
    {
        for (size_t i = 0; i < sizeof(s_ccentries) / sizeof(s_ccentries[0]); i++)
        {
            if (strncmp(q, s_ccentries[i].name, strlen(s_ccentries[i].name)) == 0)
            {
                char *p = strchr(q, ' ');
                *p = '\0';
                cp.name = s_ccentries[i].name;
                cp.cc = s_ccentries[i].cc;

                if (_strnicmp(s_ccentries[i].name, "loop", 4) == 0)
                {
                    cp.bt = BT_LOOP;
                }
                else if (cp.cc == C_none)
                {
                    if (_stricmp(s_ccentries[i].name, "call") == 0)
                        cp.bt = BT_CALL;
                    else
                        cp.bt = BT_JMP;
                }
                else
                    cp.bt = BT_JCC;

                p++;
                cp.operand1.text = p;
                parse_operand(cp.operand1, 32, true);
                if (cp.operand1.type == OT_MEMIMM)
                {
                    ADDRESS32 addr = (ADDRESS32)cp.operand1.value;
                    DWORD RVA = addr - m_pOptional32->ImageBase;
                    const SYMBOL *symbol = FindSymbolByRVA(RVA);
                    if (symbol)
                        cp.operand1.SetAPI(symbol->pszName);
                }
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL)
    {
        cp.name = q;
        return;
    }

    if (_strnicmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    cp.name = q;
    p = strtok(p + 1, ",");
    if (p)
    {
        cp.operand1.text = p;
        p = strtok(NULL, ",");
        if (p)
        {
            cp.operand2.text = p;
            p = strtok(NULL, ",");
            if (p)
            {
                cp.operand3.text = p;
                parse_operand(cp.operand3, 32);
            }
            parse_operand(cp.operand2, 32);
        }
        parse_operand(cp.operand1, 32);
    }
}

VOID PEModule::_ParseInsn64(CODEPOINT64& cp, ADDRESS64 offset, const char *insn)
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

    cp.Clear();

    if (q[0] == 'r' && q[1] == 'e')
    {
        for (size_t i = 0; i < sizeof(s_rep_insns) / sizeof(s_rep_insns[0]); i++)
        {
            if (_stricmp(q, s_rep_insns[i]) == 0)
            {
                cp.name = q;
                char *p = q + strlen(q) - 1;
                if (*p == 'b')
                    cp.operand1.size = 1;
                else if (*p == 'w')
                    cp.operand1.size = 2;
                else if (*p == 'd')
                    cp.operand1.size = 4;
                else if (*p == 'q')
                    cp.operand1.size = 8;

                if (q[3] == 'e')
                    cp.cc = C_E;
                else if (q[3] == 'n')
                    cp.cc = C_NE;
                else
                    cp.cc = C_none;
                return;
            }
        }
    }

    if (_stricmp(q, "ret") == 0 || _stricmp(q, "iret") == 0)
    {
        cp.name = q;
        cp.bt = BT_RETURN;
        return;
    }

    if (q[0] == 'c' || q[0] == 'l' || q[0] == 'j')
    {
        for (size_t i = 0; i < sizeof(s_ccentries) / sizeof(s_ccentries[0]); i++)
        {
            if (strncmp(q, s_ccentries[i].name, strlen(s_ccentries[i].name)) == 0)
            {
                char *p = strchr(q, ' ');
                *p = '\0';
                cp.name = s_ccentries[i].name;
                cp.cc = s_ccentries[i].cc;

                if (_strnicmp(s_ccentries[i].name, "loop", 4) == 0)
                {
                    cp.bt = BT_LOOP;
                }
                else if (cp.cc == C_none)
                {
                    if (_stricmp(s_ccentries[i].name, "call") == 0)
                        cp.bt = BT_CALL;
                    else
                        cp.bt = BT_JMP;
                }
                else
                    cp.bt = BT_JCC;

                p++;
                cp.operand1.text = p;
                parse_operand(cp.operand1, 64, true);
                if (cp.operand1.type == OT_MEMIMM)
                {
                    ADDRESS64 addr = cp.operand1.value;
                    DWORD RVA = (DWORD)(addr - m_pOptional64->ImageBase);
                    const SYMBOL *symbol = FindSymbolByRVA(RVA);
                    if (symbol)
                        cp.operand1.SetAPI(symbol->pszName);
                }
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL)
    {
        cp.name = q;
        return;
    }

    if (_strnicmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    cp.name = q;
    p = strtok(p + 1, ",");
    if (p)
    {
        cp.operand1.text = p;
        p = strtok(NULL, ",");
        if (p)
        {
            cp.operand2.text = p;
            p = strtok(NULL, ",");
            if (p)
            {
                cp.operand3.text = p;
                parse_operand(cp.operand3, 64);
            }
            parse_operand(cp.operand2, 64);
        }
        parse_operand(cp.operand1, 64);
    }
}

////////////////////////////////////////////////////////////////////////////
