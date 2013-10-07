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
    BYTE        Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;
    DWORD       RVA;    // Not VirtualAddress!
    DWORD       SizeOfRawData;
    DWORD       PointerToRawData;
    DWORD       PointerToRelocations;
    DWORD       PointerToLinenumbers;
    WORD        NumberOfRelocations;
    WORD        NumberOfLinenumbers;
    DWORD       Characteristics;
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
// PEMODULE

class PEMODULE
{
public:
    PEMODULE();
    PEMODULE(LPCTSTR FileName);
    virtual ~PEMODULE();

    BOOL LoadModule(LPCTSTR FileName);
    VOID UnloadModule();
    BOOL IsModuleLoaded() const;

    // dumpers
    VOID DumpHeaders();
    VOID DumpImportSymbols();
    VOID DumpExportSymbols();
    VOID DumpResource();
    VOID DumpDelayLoad();

public:
    // attributes
    BOOL    Is32Bit() const;
    BOOL    Is64Bit() const;
    DWORD   GetFileSize() const;
    LPCTSTR GetFileName() const;
    BOOL    IsDLL() const;
    BOOL    IsCUIExe() const;
    BOOL    IsGUIExe() const;
    DWORD   HeaderSum() const;
    BOOL    RVAInDirEntry(DWORD rva, DWORD index) const;
    BOOL    IsValidAddress(ULONGLONG Address) const;
    DWORD   GetBaseOfCode() const;
    DWORD   GetSizeOfHeaders() const;
    DWORD   GetSizeOfImage() const;
    DWORD   GetSizeOfOptionalHeader() const;
    LPBYTE  GetData(DWORD rva);
    LPBYTE  DirEntryData(DWORD index);
    DWORD   DirEntryDataSize(DWORD index) const;
    BOOL    AddressInCode32(ADDR32 va) const;
    BOOL    AddressInData32(ADDR32 va) const;
    BOOL    AddressInCode64(ADDR64 va) const;
    BOOL    AddressInData64(ADDR64 va) const;
    DWORD   RVAOfEntryPoint() const;
    DWORD   RVAFromVA32(ADDR32 va) const;
    DWORD   RVAFromVA64(ADDR64 va) const;
    ADDR32  VA32FromRVA(DWORD rva) const;
    ADDR64  VA64FromRVA(DWORD rva) const;
    DWORD   CheckSum() const;
    
public:
    // accessors
    WORD&                       NumberOfSections();
    DWORD&                      LastError();
    LPBYTE&                     LoadedImage();
    LPBYTE&                     FileImage();
    PIMAGE_DOS_HEADER           DOSHeader();
    PIMAGE_NT_HEADERS           NTHeaders();
    PIMAGE_NT_HEADERS32         NTHeaders32();
    PIMAGE_NT_HEADERS64         NTHeaders64();
    PIMAGE_OPTIONAL_HEADER32&   OptionalHeader32();
    PIMAGE_OPTIONAL_HEADER64&   OptionalHeader64();
	PIMAGE_FILE_HEADER          FileHeader();
    PREAL_IMAGE_DATA_DIRECTORY  DataDirectory(DWORD index);
    PREAL_IMAGE_DATA_DIRECTORY& DataDirectories();
    PREAL_IMAGE_SECTION_HEADER& SectionHeaders();
    PREAL_IMAGE_SECTION_HEADER  SectionHeader(DWORD index);
    PREAL_IMAGE_SECTION_HEADER  CodeSectionHeader();
    PIMAGE_IMPORT_DESCRIPTOR    ImportDescriptors();
    PIMAGE_EXPORT_DIRECTORY     ExportDirectory();
    PIMAGE_RESOURCE_DIRECTORY   ResourceDirectory();
    vector<string>&             ImportDllNames();
    vector<EXPORT_SYMBOL>&      ExportSymbols();
	vector<ImgDelayDescr>&      DelayLoadDescriptors();
    // const accessors
    const WORD&                       NumberOfSections() const;
    const DWORD&                      LastError() const;
    const LPBYTE&                     LoadedImage() const;
    const LPBYTE&                     FileImage() const;
    const PIMAGE_DOS_HEADER           DOSHeader() const;
    const PIMAGE_NT_HEADERS32         NTHeaders32() const;
    const PIMAGE_NT_HEADERS64         NTHeaders64() const;
    const PIMAGE_OPTIONAL_HEADER32&   OptionalHeader32() const;
    const PIMAGE_OPTIONAL_HEADER64&   OptionalHeader64() const;
	const PIMAGE_FILE_HEADER          FileHeader() const;
    const PREAL_IMAGE_DATA_DIRECTORY  DataDirectory(DWORD index) const;
    const PREAL_IMAGE_DATA_DIRECTORY& DataDirectories() const;
    const PREAL_IMAGE_SECTION_HEADER& SectionHeaders() const;
    const PREAL_IMAGE_SECTION_HEADER  SectionHeader(DWORD index) const;
    const PREAL_IMAGE_SECTION_HEADER  CodeSectionHeader() const;
    const PIMAGE_IMPORT_DESCRIPTOR    ImportDescriptors() const;
    const PIMAGE_EXPORT_DIRECTORY     ExportDirectory() const;
    const PIMAGE_RESOURCE_DIRECTORY   ResourceDirectory() const;
    const vector<string>&             ImportDllNames() const;
    const vector<EXPORT_SYMBOL>&      ExportSymbols() const;
	const vector<ImgDelayDescr>&      DelayLoadDescriptors() const;

public:
    // loading
    BOOL LoadImportTables();
    BOOL LoadExportTable();
    BOOL LoadDelayLoad();

public:
    // finding
    const IMPORT_SYMBOL *FindImportSymbolByRVA(DWORD rva) const;
    const IMPORT_SYMBOL *FindImportSymbolByName(LPCSTR Name) const;
    const EXPORT_SYMBOL *FindExportSymbolByRVA(DWORD rva) const;
    const EXPORT_SYMBOL *FindExportSymbolByName(LPCSTR Name) const;
    const SYMBOL *FindSymbolByRVA(DWORD rva) const;
    const SYMBOL *FindSymbolByName(LPCSTR Name) const;
    const SYMBOL *FindSymbolByAddr32(ADDR32 addr) const;
    const SYMBOL *FindSymbolByAddr64(ADDR64 addr) const;

public:
    VOID AddMapNameToSymbol(const string& name, const SYMBOL& symbol);
    VOID AddMapNameToImportSymbol(const string& name, const IMPORT_SYMBOL& symbol);
    VOID AddMapNameToExportSymbol(const string& name, const EXPORT_SYMBOL& symbol);
    VOID AddMapRVAToSymbol(DWORD rva, const SYMBOL& symbol);
    VOID AddMapRVAToImportSymbol(DWORD rva, const IMPORT_SYMBOL& symbol);
    VOID AddMapRVAToExportSymbol(DWORD rva, const EXPORT_SYMBOL& symbol);

    BOOL DisAsmAddr32(DECOMPSTATUS32& status, ADDR32 func, ADDR32 va);
    BOOL DisAsmAddr64(DECOMPSTATUS64& status, ADDR64 func, ADDR64 va);
    BOOL DisAsm32(DECOMPSTATUS32& status);
    BOOL DisAsm64(DECOMPSTATUS64& status);

    BOOL DecompileAddr32(DECOMPSTATUS32& status, ADDR32 va);
    BOOL DecompileAddr64(DECOMPSTATUS64& status, ADDR64 va);
    BOOL Decompile32(DECOMPSTATUS32& status);
    BOOL Decompile64(DECOMPSTATUS64& status);
    BOOL Decompile();

    VOID ParseOperand(OPERAND& opr, INT bits, bool jump = false);

protected:
    BOOL _LoadImage(LPVOID Data);
    BOOL _LoadNTHeaders(LPVOID Data);

    BOOL _GetImportDllNames(vector<string>& names);
    BOOL _GetImportSymbols(DWORD dll_index, vector<IMPORT_SYMBOL>& symbols);
    BOOL _GetExportSymbols(vector<EXPORT_SYMBOL>& symbols);

    VOID _ParseInsn32(ASMCODE32& ac, ADDR32 offset, const char *insn);
    VOID _ParseInsn64(ASMCODE64& ac, ADDR64 offset, const char *insn);

protected:
    struct PEMODULEIMPL;
    PEMODULEIMPL *m_pImpl;
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
VOID DumpDOSHeader(LPVOID Data);
VOID DumpFileHeader(LPVOID Data);
VOID DumpOptionalHeader32(LPVOID Data, DWORD CheckSum);
VOID DumpOptionalHeader64(LPVOID Data, DWORD CheckSum);
VOID DumpSectionHeader(LPVOID Data);
VOID DumpCodes(const vector<BYTE>& codes, INT bits);

////////////////////////////////////////////////////////////////////////////
