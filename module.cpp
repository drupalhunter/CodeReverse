
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
// along with CodeReverse.  If not, see <http://www.gnu.org/licenses/>.
////////////////////////////////////////////////////////////////////////////

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
    m_bDecompiled(FALSE),
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
    m_bDecompiled(FALSE),
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

    m_mAddrToAsmCode32.clear();
    m_mAddrToAsmCode64.clear();
    m_bDisAsmed = FALSE;
    m_bDecompiled = FALSE;

    m_sEntrances32.clear();
    m_sEntrances64.clear();

    m_vImgDelayDescrs.clear();

    m_mAddrToCF32.clear();
    m_mAddrToCF64.clear();
}

////////////////////////////////////////////////////////////////////////////
// loading

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
        m_pDataDirectories = (PREAL_IMAGE_DATA_DIRECTORY)m_pOptional32->DataDirectory;
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
        m_pDataDirectories = (PREAL_IMAGE_DATA_DIRECTORY)m_pOptional64->DataDirectory;
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

BOOL PEModule::LoadDelayLoad()
{
    if (!ModuleLoaded())
        return FALSE;

    PREAL_IMAGE_DATA_DIRECTORY pDir =
        &m_pDataDirectories[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

    vector<ImgDelayDescr> Descrs;
    ImgDelayDescr *pDescrs;
    pDescrs = (ImgDelayDescr *)(m_pLoadedImage + pDir->RVA);

    size_t i = 0;
    while (pDescrs[i].rvaHmod)
    {
        Descrs.push_back(pDescrs[i]);
        i++;
    }

    m_vImgDelayDescrs = Descrs;

    // TODO: load IAT and INT

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// dumping

VOID PEModule::DumpHeaders()
{
    if (!ModuleLoaded())
        return;

#ifdef _UNICODE
    printf("FileName: %ls, FileSize: 0x%08lX (%lu)\n",
        m_pszFileName, m_dwFileSize, m_dwFileSize);
#else
    printf("FileName: %s, FileSize: 0x%08lX (%lu)\n",
        m_pszFileName, m_dwFileSize, m_dwFileSize);
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

    for (DWORD i = 0; i < m_vExportSymbols.size(); i++)
    {
        EXPORT_SYMBOL& symbol = m_vExportSymbols[i];
        if (symbol.dwRVA)
        {
            if (Is64Bit())
            {
                ADDR64 va = m_pOptional64->ImageBase + symbol.dwRVA;
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
                ADDR32 va = m_pOptional32->ImageBase + symbol.dwRVA;
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

VOID PEModule::DumpDelayLoad()
{
    if (m_vImgDelayDescrs.empty())
    {
        LoadDelayLoad();
        if (m_vImgDelayDescrs.empty())
            return;
    }

    printf("### DELAY LOAD ###\n");
    size_t i, size = m_vImgDelayDescrs.size();
    DWORD rva;
    if (Is64Bit())
    {
        ADDR64 addr;
        for (i = 0; i < size; i++)
        {
            printf("  ### Descr #%u ###\n", (INT)i);
            printf("    NAME       %-8s %-8s\n", "RVA", "VA");

            rva = m_vImgDelayDescrs[i].grAttrs;
            addr = m_pOptional64->ImageBase + rva;
            printf("    Attrs:     %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = m_vImgDelayDescrs[i].rvaDLLName;
            addr = m_pOptional64->ImageBase + rva;
            printf("    DLL Name:  %s\n", (LPCSTR)(m_pLoadedImage + rva));
            printf("            :  %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = m_vImgDelayDescrs[i].rvaHmod;
            addr = m_pOptional64->ImageBase + rva;
            printf("    Module:    %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = m_vImgDelayDescrs[i].rvaIAT;
            addr = m_pOptional64->ImageBase + rva;
            printf("    IAT:       %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = m_vImgDelayDescrs[i].rvaINT;
            addr = m_pOptional64->ImageBase + rva;
            printf("    INT:       %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = m_vImgDelayDescrs[i].rvaBoundIAT;
            addr = m_pOptional64->ImageBase + rva;
            printf("    BoundIAT:  %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            rva = m_vImgDelayDescrs[i].rvaUnloadIAT;
            addr = m_pOptional64->ImageBase + rva;
            printf("    UnloadIAT: %08lX %08lX%08lX\n", rva, HILONG(addr), LOLONG(addr));

            LPCSTR pszTime = GetTimeStampString(m_vImgDelayDescrs[i].dwTimeStamp);
            printf("    dwTimeStamp:  0x%08lX (%s)",
                m_vImgDelayDescrs[i].dwTimeStamp, pszTime);
        }
    }
    else if (Is32Bit())
    {
        ADDR32 addr;
        for (i = 0; i < size; i++)
        {
            printf("  ### Descr #%u ###\n", (INT)i);
            printf("    NAME       %-8s %-8s\n", "RVA", "VA");

            rva = m_vImgDelayDescrs[i].grAttrs;
            addr = m_pOptional32->ImageBase + rva;
            printf("    Attrs:     %08lX %08lX\n", rva, addr);

            rva = m_vImgDelayDescrs[i].rvaDLLName;
            addr = m_pOptional32->ImageBase + rva;
            printf("    DLL Name:  %s\n", (LPCSTR)(m_pLoadedImage + rva));
            printf("            :  %08lX %08lX\n", rva, addr);

            rva = m_vImgDelayDescrs[i].rvaHmod;
            addr = m_pOptional32->ImageBase + rva;
            printf("    Module:    %08lX %08lX\n", rva, addr);

            rva = m_vImgDelayDescrs[i].rvaIAT;
            addr = m_pOptional32->ImageBase + rva;
            printf("    IAT:       %08lX %08lX\n", rva, addr);

            rva = m_vImgDelayDescrs[i].rvaINT;
            addr = m_pOptional32->ImageBase + rva;
            printf("    INT:       %08lX %08lX\n", rva, addr);

            rva = m_vImgDelayDescrs[i].rvaBoundIAT;
            addr = m_pOptional32->ImageBase + rva;
            printf("    BoundIAT:  %08lX %08lX\n", rva, addr);

            rva = m_vImgDelayDescrs[i].rvaUnloadIAT;
            addr = m_pOptional32->ImageBase + rva;
            printf("    UnloadIAT: %08lX %08lX\n", rva, addr);

            LPCSTR pszTime = GetTimeStampString(m_vImgDelayDescrs[i].dwTimeStamp);
            printf("    dwTimeStamp:  0x%08lX (%s)",
                m_vImgDelayDescrs[i].dwTimeStamp, pszTime);
        }
    }

    printf("\n\n");
}

////////////////////////////////////////////////////////////////////////////
// getting

LPBYTE PEModule::GetDirEntryData(DWORD index)
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
    {
        if (m_pDataDirectories[index].RVA != 0 &&
            m_pDataDirectories[index].Size != 0)
        {
            return m_pLoadedImage + m_pDataDirectories[index].RVA;
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

////////////////////////////////////////////////////////////////////////////
// finding

const IMPORT_SYMBOL *PEModule::FindImportSymbolByRVA(DWORD rva) const
{
    map<DWORD, IMPORT_SYMBOL>::const_iterator it;
    it = m_mRVAToImportSymbol.find(rva);
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

const EXPORT_SYMBOL *PEModule::FindExportSymbolByRVA(DWORD rva) const
{
    map<DWORD, EXPORT_SYMBOL>::const_iterator it;
    it = m_mRVAToExportSymbol.find(rva);
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

const SYMBOL *PEModule::FindSymbolByRVA(DWORD rva) const
{
    map<DWORD, SYMBOL>::const_iterator it;
    it = m_mRVAToSymbol.find(rva);
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

const SYMBOL *PEModule::FindSymbolByAddr32(ADDR32 addr) const
{
    if (m_pOptional32)
        return FindSymbolByRVA(addr - m_pOptional32->ImageBase);
    else
        return NULL;
}

const SYMBOL *PEModule::FindSymbolByAddr64(ADDR64 addr) const
{
    if (m_pOptional64)
        return FindSymbolByRVA((DWORD)(addr - m_pOptional64->ImageBase));
    else
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

////////////////////////////////////////////////////////////////////////////
// verifying

BOOL PEModule::AddressInCode32(ADDR32 va) const
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    DWORD rva = (DWORD)(DWORD_PTR)(va - m_pOptional32->ImageBase);

    return (pCode->RVA <= rva && rva < pCode->RVA + pCode->Misc.VirtualSize);
}

BOOL PEModule::AddressInData32(ADDR32 va) const
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    DWORD rva;

    const DWORD dwFlags = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
    for (DWORD i = 0; i < m_dwNumberOfSections; i++)
    {
        if (m_pSectionHeaders[i].Characteristics & dwFlags)
            continue;

        rva = va - m_pOptional32->ImageBase;

        pHeader = GetSectionHeader(i);
        if (pHeader->RVA <= rva && rva < pHeader->RVA + pHeader->Misc.VirtualSize)
            return TRUE;
    }
    return FALSE;
}

BOOL PEModule::AddressInCode64(ADDR64 va) const
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    DWORD rva = (DWORD)(DWORD_PTR)(va - m_pOptional64->ImageBase);

    return (pCode->RVA <= rva && rva < pCode->RVA + pCode->Misc.VirtualSize);
}

BOOL PEModule::AddressInData64(ADDR64 va) const
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pHeader;
    DWORD rva;

    const DWORD dwFlags = (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE);
    for (DWORD i = 0; i < m_dwNumberOfSections; i++)
    {
        if (m_pSectionHeaders[i].Characteristics & dwFlags)
            continue;

        rva = (DWORD)(DWORD_PTR)(va - m_pOptional64->ImageBase);

        pHeader = GetSectionHeader(i);
        if (pHeader->RVA <= rva && rva < pHeader->RVA + pHeader->Misc.VirtualSize)
            return TRUE;
    }
    return FALSE;
}

////////////////////////////////////////////////////////////////////////////
// disasm

extern "C"
int32_t disasm(uint8_t *data, char *output, int outbufsize, int segsize,
               int64_t offset, int autosync, uint32_t prefer);

BOOL PEModule::DisAsmAddr32(ADDR32 func, ADDR32 va)
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    // get code section
    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    // check boundary
    ADDR32 CodeVA = m_pOptional32->ImageBase + pCode->RVA;
    if (!(CodeVA <= va && va < CodeVA + pCode->SizeOfRawData))
        return FALSE;

    // calculate
    DWORD rva = va - m_pOptional32->ImageBase;
    LPBYTE input = m_pLoadedImage + rva;
    ADDR32 offset = va;

    ASMCODE32 ac;
    INT lendis;
    LPBYTE p = input;
    CHAR outbuf[256];
    vector<ADDR32> jump_entries, call_entries;

    // insert code function
    if (m_mAddrToCF32.find(func) == m_mAddrToCF32.end())
    {
        CODEFUNC cf;
        cf.Addr32 = func;
        const SYMBOL * pSymbol = FindSymbolByAddr32(func);
        if (pSymbol)
        {
            cf.Name = pSymbol->pszName;
        }
        else
        {
            CHAR buf[64];
            sprintf(buf, "L%08lX", func);
            cf.Name = buf;
        }
        m_mAddrToCF32[func] = cf;
    }

    LPBYTE iend = m_pLoadedImage + pCode->RVA + pCode->SizeOfRawData;
    while (p < iend)
    {
        map<ADDR32, ASMCODE32>::iterator it, end;
        it = m_mAddrToAsmCode32.find(offset);
        end = m_mAddrToAsmCode32.end();
        if (it != end)
            break;

        // disasm
        lendis = disasm(p, outbuf, sizeof(outbuf), 32, offset, false, 0);

        // parse insn
        ac.Clear();
        if (!lendis || p + lendis > iend)
        {
            lendis = 1;
            ac.name = "???";
        }
        else
            _ParseInsn32(ac, offset, outbuf);

        // set codes
        for (INT i = 0; i < lendis; i++)
            ac.codes.push_back(p[i]);

        ac.addr = offset;
        ac.func = func;

        bool bBreak = false;
        switch (ac.bt)
        {
        case BT_JCC:
            // conditional jump
            switch (ac.operand1.type)
            {
            case OT_IMM: case OT_LABEL: case OT_API:
                if (func == offset)
                {
                    // func is jumper
                    m_mAddrToCF64[func].Type = FT_JUMPER;
                    m_mAddrToCF64[func].SizeOfArgs = 0;
                    bBreak = true;
                }
                else
                    jump_entries.push_back((ADDR32)ac.operand1.value);
                break;

            default: break;
            }
            break;

        case BT_JMP:
            switch (ac.operand1.type)
            {
            case OT_IMM: case OT_LABEL:
                if (func == offset)
                {
                    // func is jumper
                    m_mAddrToCF32[func].Type = FT_JUMPER;
                }
                else
                    jump_entries.push_back(ac.operand1.value);
                break;

            case OT_API:
                if (func == offset)
                {
                    // func is jumper
                    m_mAddrToCF32[func].Type = FT_JUMPER;
                    m_mAddrToCF32[func].Name = "__imp";
                    m_mAddrToCF32[func].Name += ac.operand1.text;
                }
                break;

            default: break;
            }
            bBreak = true;
            break;

        case BT_CALL:
            switch (ac.operand1.type)
            {
            case OT_IMM: case OT_LABEL:
                // function call
                call_entries.push_back((ADDR32)ac.operand1.value);
                break;

            default: break;
            }
            break;

        case BT_RETURN:
            if (ac.operand1.type == OT_IMM)
            {
                // func is __stdcall
                m_mAddrToCF32[func].Type = FT_STDCALL;
                m_mAddrToCF32[func].SizeOfArgs = ac.operand1.value;
            }
            else
            {
                // func is not __stdcall
                m_mAddrToCF32[func].Flags |= FF_NOTSTDCALL;
            }
            bBreak = true;
            break;

        default:
            // check stack frame
            if (ac.name == "enter")
            {
                m_mAddrToCF32[func].Flags |= FF_HASSTACKFRAME;
            }
            else if (ac.name == "leave")
            {
                m_mAddrToCF32[func].Flags |= FF_HASSTACKFRAME;
            }
            else if (ac.name == "sub")
            {
                if (ac.operand1.text == "esp")
                {
                    m_mAddrToCF32[func].Flags |= FF_HASSTACKFRAME;
                }
            }
            break;
        }

        // add asm code
        m_mAddrToAsmCode32.insert(make_pair(offset, ac));

        if (bBreak)
            break;

        // move to next position
        p += lendis;
        offset += lendis;
    }

    {
        vector<ADDR32>::iterator it, end;
        // recurse
        end = jump_entries.end();
        for (it = jump_entries.begin(); it != end; it++)
        {
            DisAsmAddr32(func, *it);
        }
        // add entrances
        end = call_entries.end();
        for (it = call_entries.begin(); it != end; it++)
        {
            m_sEntrances32.insert(*it);
        }
    }

    return TRUE;
}

BOOL PEModule::DisAsmAddr64(ADDR64 func, ADDR64 va)
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    // get code section
    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    // check boundary
    ADDR64 CodeVA = m_pOptional64->ImageBase + pCode->RVA;
    if (!(CodeVA <= va && va < CodeVA + pCode->SizeOfRawData))
        return FALSE;

    // calculate
    DWORD rva = (DWORD)(va - m_pOptional64->ImageBase);
    LPBYTE input = m_pLoadedImage + rva;
    ADDR64 offset = va;

    ASMCODE64 ac;
    INT lendis;
    LPBYTE p = input;
    CHAR outbuf[256];
    vector<ADDR64> jump_entries, call_entries;

    // insert code function
    if (m_mAddrToCF64.find(func) == m_mAddrToCF64.end())
    {
        CODEFUNC cf;
        cf.Addr64 = func;
        const SYMBOL * pSymbol = FindSymbolByAddr64(func);
        if (pSymbol)
        {
            cf.Name = pSymbol->pszName;
        }
        else
        {
            CHAR buf[64];
            sprintf(buf, "L%08lX%08lX", HILONG(func), LOLONG(func));
            cf.Name = buf;
        }
        m_mAddrToCF64[func] = cf;
    }

    LPBYTE iend = m_pLoadedImage + pCode->RVA + pCode->SizeOfRawData;
    while (p < iend)
    {
        map<ADDR64, ASMCODE64>::iterator it, end;
        it = m_mAddrToAsmCode64.find(offset);
        end = m_mAddrToAsmCode64.end();
        if (it != end)
            break;

        // disasm
        lendis = disasm(p, outbuf, sizeof(outbuf), 64, offset, false, 0);

        // parse insn
        ac.Clear();
        if (!lendis || p + lendis > iend)
        {
            lendis = 1;
            ac.name = "???";
        }
        else
            _ParseInsn64(ac, offset, outbuf);

        // add asm codes
        for (INT i = 0; i < lendis; i++)
            ac.codes.push_back(p[i]);

        ac.func = func;
        ac.addr = offset;

        bool bBreak = false;
        switch (ac.bt)
        {
        case BT_JCC:
            // conditional jump
            switch (ac.operand1.type)
            {
            case OT_IMM: case OT_LABEL:
                if (func == offset)
                {
                    // func is jumper
                    m_mAddrToCF64[func].Type = FT_JUMPER;
                    bBreak = true;
                }
                else
                    jump_entries.push_back(ac.operand1.value);
                break;

            default: break;
            }
            break;

        case BT_JMP:
            switch (ac.operand1.type)
            {
            case OT_IMM: case OT_LABEL:
                if (func == offset)
                {
                    // func is jumper
                    m_mAddrToCF64[func].Type = FT_JUMPER;
                }
                else
                    jump_entries.push_back(ac.operand1.value);
                break;

            case OT_API:
                if (func == offset)
                {
                    // func is jumper
                    m_mAddrToCF64[func].Type = FT_JUMPER;
                    m_mAddrToCF64[func].Name = "__imp";
                    m_mAddrToCF64[func].Name += ac.operand1.text;
                }
                break;

            default: break;
            }
            bBreak = true;
            break;

        case BT_CALL:
            switch (ac.operand1.type)
            {
            case OT_IMM: case OT_LABEL:
                // function call
                call_entries.push_back(ac.operand1.value);
                break;

            default: break;
            }
            break;

        case BT_RETURN:
            if (ac.operand1.type == OT_IMM)
            {
                // func is __stdcall
                m_mAddrToCF64[func].Type = FT_STDCALL;
                m_mAddrToCF64[func].SizeOfArgs = ac.operand1.value;
            }
            else
            {
                // func is not __stdcall
                m_mAddrToCF64[func].Flags |= FF_NOTSTDCALL;
            }
            bBreak = true;
            break;

        default:
            // check stack frame
            if (ac.name == "enter")
            {
                m_mAddrToCF64[func].Flags |= FF_HASSTACKFRAME;
            }
            else if (ac.name == "leave")
            {
                m_mAddrToCF64[func].Flags |= FF_HASSTACKFRAME;
            }
            else if (ac.name == "sub")
            {
                if (ac.operand1.text == "rsp")
                {
                    m_mAddrToCF64[func].Flags |= FF_HASSTACKFRAME;
                }
            }
            break;
        }

        // add asm code
        m_mAddrToAsmCode64.insert(make_pair(offset, ac));

        if (bBreak)
            break;

        // move to next position
        p += lendis;
        offset += lendis;
    }

    {
        vector<ADDR64>::iterator it, end;
        // recurse
        end = jump_entries.end();
        for (it = jump_entries.begin(); it != end; it++)
        {
            DisAsmAddr64(func, *it);
        }
        // add entrances
        end = call_entries.end();
        for (it = call_entries.begin(); it != end; it++)
        {
            m_sEntrances64.insert(*it);
        }
    }

    return TRUE;
}

BOOL PEModule::DisAsm32()
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    // register entrypoint
    SYMBOL symbol;
    symbol.dwRVA = m_dwAddressOfEntryPoint;
    symbol.pszName = "EntryPoint";
    m_mRVAToSymbol.insert(make_pair(m_dwAddressOfEntryPoint, symbol));
    string name = symbol.pszName;
    m_mNameToSymbol.insert(make_pair(name, symbol));

    // register entrances
    ADDR32 va;
    va = m_pOptional32->ImageBase + m_dwAddressOfEntryPoint;
    m_sEntrances32.insert(va);

    m_mAddrToCF32[va].Addr32 = va;
    m_mAddrToCF32[va].Name = "EntryPoint";

    {
        vector<EXPORT_SYMBOL>::const_iterator it, end;
        end = m_vExportSymbols.end();
        for (it = m_vExportSymbols.begin(); it != end; it++)
        {
            va = m_pOptional32->ImageBase + it->dwRVA;
            m_sEntrances32.insert(va);

            m_mAddrToCF32[va].Addr32 = va;
            m_mAddrToCF32[va].Name = it->pszName;
        }
    }

    // disasm entrances
    {
        set<ADDR32> s;
        size_t size;
        do
        {
            s = m_sEntrances32;
            size = s.size();

            set<ADDR32>::iterator it, end = s.end();
            for (it = s.begin(); it != end; it++)
            {
                ADDR32 addr = *it;
                DisAsmAddr32(addr, addr);
            }

            // m_sEntrances32 may grow in DisAsmAddr64
        } while(size != m_sEntrances32.size());
    }

    return TRUE;
}

BOOL PEModule::DisAsm64()
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    // register entrypoint
    SYMBOL symbol;
    symbol.dwRVA = m_dwAddressOfEntryPoint;
    symbol.pszName = "EntryPoint";
    m_mRVAToSymbol.insert(make_pair(m_dwAddressOfEntryPoint, symbol));
    string name = symbol.pszName;
    m_mNameToSymbol.insert(make_pair(name, symbol));

    // register entrances
    ADDR64 va;
    va = m_pOptional64->ImageBase + m_dwAddressOfEntryPoint;
    m_sEntrances64.insert(va);

    m_mAddrToCF64[va].Addr64 = va;
    m_mAddrToCF64[va].Name = "EntryPoint";

    {
        vector<EXPORT_SYMBOL>::const_iterator it, end;
        end = m_vExportSymbols.end();
        for (it = m_vExportSymbols.begin(); it != end; it++)
        {
            va = m_pOptional64->ImageBase + it->dwRVA;
            m_sEntrances64.insert(va);
            m_mAddrToCF64[va].Addr64 = va;
            m_mAddrToCF64[va].Name = it->pszName;
        }
    }

    // disasm entrances
    {
        set<ADDR64> s;
        size_t size;
        do
        {
            s = m_sEntrances64;
            size = s.size();

            set<ADDR64>::iterator it, end = s.end();
            for (it = s.begin(); it != end; it++)
            {
                ADDR64 addr = *it;
                DisAsmAddr64(addr, addr);
            }

            // m_sEntrances64 may grow in DisAsmAddr64
        } while(size != m_sEntrances64.size());
    }

    return TRUE;
}

BOOL PEModule::DumpDisAsmFunc32(ADDR32 func)
{
    if (!m_bDisAsmed && !DisAsm())
        return FALSE;

    if (!Is32Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    map<ADDR32, ASMCODE32>::iterator it, end;
    end = m_mAddrToAsmCode32.end();
    for (it = m_mAddrToAsmCode32.begin(); it != end; it++)
    {
        ASMCODE32& ac = it->second;

        if (func != 0 && ac.func != func)
            continue;

        printf("L%08lX: ", ac.addr);
        
        DumpCodes(ac.codes, 32);

        if (ac.operand3.type != OT_NONE)
        {
            printf("%s %s,%s,%s\n", ac.name.c_str(),
                ac.operand1.text.c_str(), ac.operand2.text.c_str(),
                ac.operand3.text.c_str());
        }
        else if (ac.operand2.type != OT_NONE)
        {
            printf("%s %s,%s\n", ac.name.c_str(),
                ac.operand1.text.c_str(), ac.operand2.text.c_str());
        }
        else if (ac.operand1.type != OT_NONE)
        {
            printf("%s %s\n", ac.name.c_str(),
                ac.operand1.text.c_str());
        }
        else
        {
            printf("%s\n", ac.name.c_str());
        }
    }

    return TRUE;
}

BOOL PEModule::DumpDisAsmFunc64(ADDR64 func)
{
    if (!m_bDisAsmed && !DisAsm())
        return FALSE;

    if (!Is64Bit())
        return FALSE;

    PREAL_IMAGE_SECTION_HEADER pCode = GetCodeSectionHeader();
    if (pCode == NULL)
        return FALSE;

    map<ADDR64, ASMCODE64>::iterator it, end;
    end = m_mAddrToAsmCode64.end();
    for (it = m_mAddrToAsmCode64.begin(); it != end; it++)
    {
        ASMCODE64& ac = it->second;

        if (func != 0 && ac.func != func)
            continue;

        printf("L%08lX%08lX: ", HILONG(ac.addr), LOLONG(ac.addr));

        DumpCodes(ac.codes, 64);

        if (ac.operand3.type != OT_NONE)
        {
            printf("%s %s,%s,%s\n", ac.name.c_str(),
                ac.operand1.text.c_str(), ac.operand2.text.c_str(),
                ac.operand3.text.c_str());
        }
        else if (ac.operand2.type != OT_NONE)
        {
            printf("%s %s,%s\n", ac.name.c_str(),
                ac.operand1.text.c_str(), ac.operand2.text.c_str());
        }
        else if (ac.operand1.type != OT_NONE)
        {
            printf("%s %s\n", ac.name.c_str(),
                ac.operand1.text.c_str());
        }
        else
        {
            printf("%s\n", ac.name.c_str());
        }
    }

    return TRUE;
}

BOOL PEModule::DumpDisAsm()
{
    if (!ModuleLoaded())
        return FALSE;

    if (!m_bDisAsmed && !DisAsm())
        return FALSE;

    printf("### DISASSEMBLY ###\n\n");

    if (Is64Bit())
    {
        set<ADDR64>::iterator it, end;
        end = m_sEntrances64.end();
        for (it = m_sEntrances64.begin(); it != end; it++)
        {
            CODEFUNC& cf = m_mAddrToCF64[*it];
            if (cf.Flags & FF_IGNORE)
                continue;

            printf(";; Function %s @ L%08lX%08lX\n", cf.Name.c_str(),
                HILONG(cf.Addr64), LOLONG(cf.Addr64));
            if (cf.Type == FT_JUMPER)
            {
                printf("Type = FT_JUMPER, ");
            }
            else if (cf.Type == FT_APIIMP)
            {
                printf("Type = FT_APIIMP, ");
            }
            else
            {
                printf("Type = normal, ");
            }
            if (cf.Flags & FF_HASSTACKFRAME)
            {
                printf("HasStackFrame, ");
            }
            printf("SizeOfArgs == %d\n", cf.SizeOfArgs);
            DumpDisAsmFunc64(*it);

            printf(";; End of Function %s @ L%08lX%08lX\n\n", cf.Name.c_str(),
                HILONG(cf.Addr64), LOLONG(cf.Addr64));
        }
    }
    else if (Is32Bit())
    {
        set<ADDR32>::iterator it, end;
        end = m_sEntrances32.end();
        for (it = m_sEntrances32.begin(); it != end; it++)
        {
            CODEFUNC& cf = m_mAddrToCF32[*it];
            if (cf.Flags & FF_IGNORE)
                continue;

            printf(";; Function %s @ L%08lX\n", cf.Name.c_str(), cf.Addr32);
            if (cf.Type == FT_STDCALL)
            {
                printf("Type = FT_STDCALL, ");
            }
            else if (cf.Type == FT_JUMPER)
            {
                printf("Type = FT_JUMPER, ");
            }
            else if (cf.Type == FT_APIIMP)
            {
                printf("Type = FT_APIIMP, ");
            }
            else if (cf.Flags & FF_NOTSTDCALL)
            {
                printf("Type = not __stdcall, ");
            }
            else
            {
                printf("Type = unknown, ");
            }
            if (cf.Flags & FF_HASSTACKFRAME)
            {
                printf("HasStackFrame, ");
            }
            printf("SizeOfArgs == %d\n", cf.SizeOfArgs);
            DumpDisAsmFunc32(*it);

            printf(";; End of Function %s @ L%08lX\n\n", cf.Name.c_str(), cf.Addr32);
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

VOID PEModule::DumpResource()
{
    HINSTANCE hInst;
    hInst = LoadLibraryEx(m_pszFileName, NULL, LOAD_LIBRARY_AS_DATAFILE);
    if (hInst == NULL)
        return;

    printf("### RESOURCE ###\n");
    if (!EnumResourceTypes(hInst, EnumResTypeProc, 0))
        printf("  No resource data\n");
    FreeLibrary(hInst);

    printf("\n");
}

////////////////////////////////////////////////////////////////////////////
// PEModule::_ParseInsn32, PEModule::_ParseInsn64

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
    CCODE cc;
};

const CCENTRY cr_ccentries[] =
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

VOID PEModule::_ParseInsn32(ASMCODE32& ac, ADDR32 offset, const char *insn)
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

    ac.Clear();

    if (q[0] == 'r' && q[1] == 'e')
    {
        const size_t size = sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (size_t i = 0; i < size; i++)
        {
            if (_stricmp(q, cr_rep_insns[i]) == 0)
            {
                ac.name = q;
                char *p = q + strlen(q) - 1;
                if (*p == 'b')
                    ac.operand1.size = 1;
                else if (*p == 'w')
                    ac.operand1.size = 2;
                else if (*p == 'd')
                    ac.operand1.size = 4;

                if (q[3] == 'e')
                    ac.cc = C_E;
                else if (q[3] == 'n')
                    ac.cc = C_NE;
                else
                    ac.cc = C_none;
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
            ac.operand1.text = p + 1;
            ParseOperand(ac.operand1, 32, false);
        }
        ac.name = q;
        ac.bt = BT_RETURN;
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
                ac.name = cr_ccentries[i].name;
                ac.cc = cr_ccentries[i].cc;

                if (_strnicmp(cr_ccentries[i].name, "loop", 4) == 0)
                {
                    ac.bt = BT_LOOP;
                }
                else if (ac.cc == C_none)
                {
                    if (_stricmp(cr_ccentries[i].name, "call") == 0)
                        ac.bt = BT_CALL;
                    else
                        ac.bt = BT_JMP;
                }
                else
                    ac.bt = BT_JCC;

                p++;
                ac.operand1.text = p;
                ParseOperand(ac.operand1, 32, true);
                if (ac.operand1.type == OT_MEMIMM)
                {
                    ADDR32 addr = (ADDR32)ac.operand1.value;
                    DWORD rva = addr - m_pOptional32->ImageBase;
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        ac.operand1.SetAPI(symbol->pszName);
                }
                else if (ac.bt == BT_JMP && ac.operand1.type == OT_IMM)
                {
                    ADDR32 addr = ac.operand1.value;
                    DWORD rva = (DWORD)(addr - m_pOptional32->ImageBase);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        ac.operand1.SetAPI(symbol->pszName);
                }
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL)
    {
        ac.name = q;
        return;
    }

    if (_strnicmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    ac.name = q;
    p = strtok(p + 1, ",");
    if (p)
    {
        ac.operand1.text = p;
        p = strtok(NULL, ",");
        if (p)
        {
            ac.operand2.text = p;
            p = strtok(NULL, ",");
            if (p)
            {
                ac.operand3.text = p;
                ParseOperand(ac.operand3, 32);
            }
            ParseOperand(ac.operand2, 32);
        }
        ParseOperand(ac.operand1, 32);
    }
}

VOID PEModule::_ParseInsn64(ASMCODE64& ac, ADDR64 offset, const char *insn)
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

    ac.Clear();

    if (q[0] == 'r' && q[1] == 'e')
    {
        const size_t size = sizeof(cr_rep_insns) / sizeof(cr_rep_insns[0]);
        for (size_t i = 0; i < size; i++)
        {
            if (_stricmp(q, cr_rep_insns[i]) == 0)
            {
                ac.name = q;
                char *p = q + strlen(q) - 1;
                if (*p == 'b')
                    ac.operand1.size = 1;
                else if (*p == 'w')
                    ac.operand1.size = 2;
                else if (*p == 'd')
                    ac.operand1.size = 4;
                else if (*p == 'q')
                    ac.operand1.size = 8;

                if (q[3] == 'e')
                    ac.cc = C_E;
                else if (q[3] == 'n')
                    ac.cc = C_NE;
                else
                    ac.cc = C_none;
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
            ac.operand1.text = p + 1;
            ParseOperand(ac.operand1, 32, false);
        }
        ac.name = q;
        ac.bt = BT_RETURN;
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
                ac.name = cr_ccentries[i].name;
                ac.cc = cr_ccentries[i].cc;

                if (_strnicmp(cr_ccentries[i].name, "loop", 4) == 0)
                {
                    ac.bt = BT_LOOP;
                }
                else if (ac.cc == C_none)
                {
                    if (_stricmp(cr_ccentries[i].name, "call") == 0)
                        ac.bt = BT_CALL;
                    else
                        ac.bt = BT_JMP;
                }
                else
                    ac.bt = BT_JCC;

                p++;
                ac.operand1.text = p;
                ParseOperand(ac.operand1, 64, true);
                if (ac.operand1.type == OT_MEMIMM)
                {
                    ADDR64 addr = ac.operand1.value;
                    DWORD rva = (DWORD)(addr - m_pOptional64->ImageBase);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        ac.operand1.SetAPI(symbol->pszName);
                }
                else if (ac.bt == BT_JMP && ac.operand1.type == OT_IMM)
                {
                    ADDR64 addr = ac.operand1.value;
                    DWORD rva = (DWORD)(addr - m_pOptional64->ImageBase);
                    const SYMBOL *symbol = FindSymbolByRVA(rva);
                    if (symbol)
                        ac.operand1.SetAPI(symbol->pszName);
                }
                return;
            }
        }
    }

    char *p = strchr(q, ' ');
    if (p == NULL)
    {
        ac.name = q;
        return;
    }

    if (_strnicmp(q, "lock ", 5) == 0)
        p = strchr(p + 1, ' ');

    *p = '\0';
    ac.name = q;
    p = strtok(p + 1, ",");
    if (p)
    {
        ac.operand1.text = p;
        p = strtok(NULL, ",");
        if (p)
        {
            ac.operand2.text = p;
            p = strtok(NULL, ",");
            if (p)
            {
                ac.operand3.text = p;
                ParseOperand(ac.operand3, 64);
            }
            ParseOperand(ac.operand2, 64);
        }
        ParseOperand(ac.operand1, 64);
    }
}

////////////////////////////////////////////////////////////////////////////
// PEModule::ParseOperand

VOID PEModule::ParseOperand(OPERAND& opr, INT bits, bool jump/* = false*/)
{
    char buf[64];
    strcpy(buf, opr.text.c_str());
    char *p = buf;

    DWORD size = cr_reg_get_size(p, bits);
    if (size != 0)
    {
        opr.type = OT_REG;
        opr.size = size;
        return;
    }

    if (_strnicmp(p, "byte ", 5) == 0)
    {
        p += 5;
        opr.size = 1;
    }
    else if (_strnicmp(p, "word ", 5) == 0)
    {
        p += 5;
        opr.size = 2;
    }
    else if (_strnicmp(p, "dword ", 6) == 0)
    {
        p += 6;
        opr.size = 4;
    }
    else if (_strnicmp(p, "qword ", 6) == 0)
    {
        p += 6;
        opr.size = 8;
    }
    else if (_strnicmp(p, "tword ", 6) == 0)
    {
        p += 6;
        opr.size = 10;
    }
    else if (_strnicmp(p, "oword ", 6) == 0)
    {
        p += 6;
        opr.size = 16;
    }
    else if (_strnicmp(p, "yword ", 6) == 0)
    {
        p += 6;
        opr.size = 32;
    }
    else if (_strnicmp(p, "short ", 6) == 0)
    {
        p += 6;
        opr.size = 1;
    }
    else if (_strnicmp(p, "near ", 5) == 0)
    {
        p += 5;
        opr.size = 2;
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
        opr.SetImm(value, true);
    }
    else if (p[0] == '0' && p[1] == 'x')
    {
        char *endptr;
        ULONGLONG value = _strtoui64(p, &endptr, 16);
        opr.value = value;

        if (jump)
        {
            if (bits == 64)
                sprintf(buf, "L%08lX%08lX", HILONG(value), LOLONG(value));
            else if (bits == 32)
                sprintf(buf, "L%08lX", LOLONG(value));
            else
                sprintf(buf, "L%04X", (WORD)value);
            opr.value = value;
            opr.SetLabel(buf);
        }
        else
            opr.SetImm(value, false);
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
            opr.type = OT_MEMREG;
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

BOOL PEModule::DecompileAddr32(ADDR32 va)
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    if (m_sEntrances32.count(va) == 0)
    {
        m_sEntrances32.insert(va);
        DisAsmAddr32(va, va);
    }

    if (m_mAddrToCF32.find(va) != m_mAddrToCF32.end())
        return TRUE;

    return TRUE;
}

BOOL PEModule::DecompileAddr64(ADDR64 va)
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    if (m_sEntrances64.count(va) == 0)
    {
        m_sEntrances64.insert(va);
        DisAsmAddr64(va, va);
    }

    if (m_mAddrToCF64.find(va) != m_mAddrToCF64.end())
        return TRUE;

    return TRUE;
}

BOOL PEModule::Decompile32()
{
    if (!ModuleLoaded() || !Is32Bit())
        return FALSE;

    set<ADDR32> s(m_sEntrances32);
    size_t size = s.size();

    set<ADDR32>::iterator it, end = s.end();
    for (it = s.begin(); it != end; it++)
    {
        DecompileAddr32(*it);
    }
    while (size != m_sEntrances32.size())
    {
        s = m_sEntrances32;
        end = s.end();
        for (it = s.begin(); it != end; it++)
        {
            DecompileAddr32(*it);
        }
        size = s.size();
    }

    m_bDecompiled = TRUE;
    return TRUE;
}

BOOL PEModule::Decompile64()
{
    if (!ModuleLoaded() || !Is64Bit())
        return FALSE;

    set<ADDR64> s(m_sEntrances64);
    size_t size = s.size();

    set<ADDR64>::iterator it, end = s.end();
    for (it = s.begin(); it != end; it++)
    {
        DecompileAddr64(*it);
    }
    while (size != m_sEntrances64.size())
    {
        s = m_sEntrances64;
        end = s.end();
        for (it = s.begin(); it != end; it++)
        {
            DecompileAddr64(*it);
        }
        size = s.size();
    }

    m_bDecompiled = TRUE;
    return TRUE;
}

BOOL PEModule::Decompile()
{
    if (!ModuleLoaded())
        return FALSE;

    if (!m_bDisAsmed)
        DisAsm();

    if (Is64Bit())
        return Decompile64();
    else if (Is32Bit())
        return Decompile32();
    else
        return FALSE;
}

BOOL PEModule::DumpDecompile()
{
    if (!ModuleLoaded())
        return FALSE;

    if (!m_bDecompiled)
        Decompile();

    printf("### DECOMPILATION ###\n");

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
