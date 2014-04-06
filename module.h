////////////////////////////////////////////////////////////////////////////
// module.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
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

class SYMBOL
{
public:
    SYMBOL();
    SYMBOL(const SYMBOL& s);
    SYMBOL& operator=(const SYMBOL& s);
    virtual ~SYMBOL();
    VOID Copy(const SYMBOL& s);
    VOID clear();

public: // accessors
    DWORD&          RVA();
    string&         Name();
    const DWORD&    RVA() const;
    const string&   Name() const;

protected:
    DWORD           m_rva;
    string          m_name;
};
typedef SYMBOL *LPSYMBOL;

////////////////////////////////////////////////////////////////////////////
// SYMBOLINFO

class SYMBOLINFO
{
public:
    SYMBOLINFO();
    SYMBOLINFO(const SYMBOLINFO& info);
    SYMBOLINFO& operator=(const SYMBOLINFO& info);
    virtual ~SYMBOLINFO();
    VOID Copy(const SYMBOLINFO& info);
    VOID clear();

public:
    VOID AddImportDllName(LPCSTR name);
    VOID AddSymbol(DWORD rva, LPCSTR name);
    VOID AddSymbol(const SYMBOL& s);
    VOID AddImportSymbol(const IMPORT_SYMBOL& is);
    VOID AddExportSymbol(const EXPORT_SYMBOL& es);

public: // accessors
    VECSET<string>&                     GetImportDllNames();
    VECSET<IMPORT_SYMBOL>&              GetImportSymbols();
    VECSET<EXPORT_SYMBOL>&              GetExportSymbols();
    IMPORT_SYMBOL *                     GetImportSymbolFromRVA(DWORD RVA);
    IMPORT_SYMBOL *                     GetImportSymbolFromName(LPCSTR name);
    EXPORT_SYMBOL *                     GetExportSymbolFromRVA(DWORD RVA);
    EXPORT_SYMBOL *                     GetExportSymbolFromName(LPCSTR name);
    SYMBOL *                            GetSymbolFromRVA(DWORD RVA);
    SYMBOL *                            GetSymbolFromName(LPCSTR name);
    map<DWORD, IMPORT_SYMBOL>&          MapRVAToImportSymbol();
    map<string, IMPORT_SYMBOL>&         MapNameToImportSymbol();
    map<DWORD, EXPORT_SYMBOL>&          MapRVAToExportSymbol();
    map<string, EXPORT_SYMBOL>&         MapNameToExportSymbol();
    map<DWORD, SYMBOL>&                 MapRVAToSymbol();
    map<string, SYMBOL>&                MapNameToSymbol();

public: // const accessors
    const VECSET<string>&               GetImportDllNames() const;
    const VECSET<IMPORT_SYMBOL>&        GetImportSymbols() const;
    const VECSET<EXPORT_SYMBOL>&        GetExportSymbols() const;
    const IMPORT_SYMBOL *               GetImportSymbolFromRVA(DWORD RVA) const;
    const IMPORT_SYMBOL *               GetImportSymbolFromName(LPCSTR name) const;
    const EXPORT_SYMBOL *               GetExportSymbolFromRVA(DWORD RVA) const;
    const EXPORT_SYMBOL *               GetExportSymbolFromName(LPCSTR name) const;
    const SYMBOL *                      GetSymbolFromRVA(DWORD RVA) const;
    const SYMBOL *                      GetSymbolFromName(LPCSTR name) const;
    const map<DWORD, IMPORT_SYMBOL>&    MapRVAToImportSymbol() const;
    const map<string, IMPORT_SYMBOL>&   MapNameToImportSymbol() const;
    const map<DWORD, EXPORT_SYMBOL>&    MapRVAToExportSymbol() const;
    const map<string, EXPORT_SYMBOL>&   MapNameToExportSymbol() const;
    const map<DWORD, SYMBOL>&           MapRVAToSymbol() const;
    const map<string, SYMBOL>&          MapNameToSymbol() const;

protected:
    // import symbols
    VECSET<string>                      m_vImportDllNames;
    VECSET<IMPORT_SYMBOL>               m_vImportSymbols;
    map<DWORD, IMPORT_SYMBOL>           m_mRVAToImportSymbol;
    map<string, IMPORT_SYMBOL>          m_mNameToImportSymbol;

    // export symbols
    VECSET<EXPORT_SYMBOL>               m_vExportSymbols;
    map<DWORD, EXPORT_SYMBOL>           m_mRVAToExportSymbol;
    map<string, EXPORT_SYMBOL>          m_mNameToExportSymbol;

    // symbols
    map<DWORD, SYMBOL>                  m_mRVAToSymbol;
    map<string, SYMBOL>                 m_mNameToSymbol;
};

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
    BOOL    IsValidAddr32(ADDR32 addr) const;
    BOOL    IsValidAddr64(ADDR64 addr) const;
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
    WORD&                               NumberOfSections();
    DWORD&                              LastError();
    LPBYTE&                             LoadedImage();
    LPBYTE&                             FileImage();
    PIMAGE_DOS_HEADER&                  DOSHeader();
    PIMAGE_NT_HEADERS&                  NTHeaders();
    PIMAGE_NT_HEADERS32&                NTHeaders32();
    PIMAGE_NT_HEADERS64&                NTHeaders64();
    PIMAGE_OPTIONAL_HEADER32&           OptionalHeader32();
    PIMAGE_OPTIONAL_HEADER64&           OptionalHeader64();
    PIMAGE_FILE_HEADER&                 FileHeader();
    PREAL_IMAGE_DATA_DIRECTORY          DataDirectory(DWORD index);
    PREAL_IMAGE_DATA_DIRECTORY&         DataDirectories();
    PREAL_IMAGE_SECTION_HEADER&         SectionHeaders();
    PREAL_IMAGE_SECTION_HEADER          SectionHeader(DWORD index);
    PREAL_IMAGE_SECTION_HEADER          CodeSectionHeader();
    PIMAGE_IMPORT_DESCRIPTOR            ImportDescriptors();
    PIMAGE_EXPORT_DIRECTORY             ExportDirectory();
    PIMAGE_RESOURCE_DIRECTORY           ResourceDirectory();
    vector<ImgDelayDescr>&              DelayLoadDescriptors();
    VECSET<string>&                     ImportDllNames();
    VECSET<IMPORT_SYMBOL>&              ImportSymbols();
    VECSET<EXPORT_SYMBOL>&              ExportSymbols();
    SYMBOLINFO&                         SymbolInfo();
    HANDLE&                             File();
    LPCTSTR&                            FileName();
    DWORD&                              FileSize();
    HANDLE&                             FileMapping();
    BOOL&                               ModuleLoaded();
    // const accessors
    const WORD&                         NumberOfSections() const;
    const DWORD&                        LastError() const;
    const LPBYTE&                       LoadedImage() const;
    const LPBYTE&                       FileImage() const;
    const PIMAGE_DOS_HEADER&            DOSHeader() const;
    const PIMAGE_NT_HEADERS&            NTHeaders() const;
    const PIMAGE_NT_HEADERS32&          NTHeaders32() const;
    const PIMAGE_NT_HEADERS64&          NTHeaders64() const;
    const PIMAGE_OPTIONAL_HEADER32&     OptionalHeader32() const;
    const PIMAGE_OPTIONAL_HEADER64&     OptionalHeader64() const;
    const PIMAGE_FILE_HEADER&           FileHeader() const;
    const PREAL_IMAGE_DATA_DIRECTORY    DataDirectory(DWORD index) const;
    const PREAL_IMAGE_DATA_DIRECTORY&   DataDirectories() const;
    const PREAL_IMAGE_SECTION_HEADER&   SectionHeaders() const;
    const PREAL_IMAGE_SECTION_HEADER    SectionHeader(DWORD index) const;
    const PREAL_IMAGE_SECTION_HEADER    CodeSectionHeader() const;
    const PIMAGE_IMPORT_DESCRIPTOR      ImportDescriptors() const;
    const PIMAGE_EXPORT_DIRECTORY       ExportDirectory() const;
    const PIMAGE_RESOURCE_DIRECTORY     ResourceDirectory() const;
    const vector<ImgDelayDescr>&        DelayLoadDescriptors() const;
    const VECSET<string>&               ImportDllNames() const;
    const VECSET<IMPORT_SYMBOL>&        ImportSymbols() const;
    const VECSET<EXPORT_SYMBOL>&        ExportSymbols() const;
    const SYMBOLINFO&                   SymbolInfo() const;
    HANDLE&                             File() const;
    LPCTSTR&                            FileName() const;
    const DWORD&                        FileSize() const;
    HANDLE&                             FileMapping() const;
    const BOOL&                         ModuleLoaded() const;

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
    LPCSTR GetSymbolNameFromRVA(DWORD rva) const;
    LPCSTR GetSymbolNameFromAddr32(ADDR32 addr) const;
    LPCSTR GetSymbolNameFromAddr64(ADDR64 addr) const;

public:
    BOOL DisAsmAddr32(DECOMPSTATUS32& status, ADDR32 func, ADDR32 va);
    BOOL DisAsmAddr64(DECOMPSTATUS64& status, ADDR64 func, ADDR64 va);
    BOOL DisAsm32(DECOMPSTATUS32& status);
    BOOL DisAsm64(DECOMPSTATUS64& status);

    BOOL FixUpAsm32(DECOMPSTATUS32& status);
    BOOL FixUpAsm64(DECOMPSTATUS64& status);

    BOOL DumpDisAsm32(DECOMPSTATUS32& status);
    BOOL DumpDisAsmFunc32(DECOMPSTATUS32& status, ADDR32 func);

    BOOL DumpDisAsm64(DECOMPSTATUS64& status);
    BOOL DumpDisAsmFunc64(DECOMPSTATUS64& status, ADDR64 func);

    BOOL DecompileAddr32(DECOMPSTATUS32& status, ADDR32 va);
    BOOL DecompileAddr64(DECOMPSTATUS64& status, ADDR64 va);
    BOOL Decompile32(DECOMPSTATUS32& status);
    BOOL Decompile64(DECOMPSTATUS64& status);
    BOOL Decompile();

    VOID ParseOperand(OPERAND& opr, INT bits);

protected:
    BOOL _LoadImage(LPVOID Data);
    BOOL _LoadNTHeaders(LPVOID Data);

    BOOL _GetImportDllNames(VECSET<string>& names);
    BOOL _GetImportSymbols(DWORD dll_index, VECSET<IMPORT_SYMBOL>& symbols);
    BOOL _GetExportSymbols(VECSET<EXPORT_SYMBOL>& symbols);

    VOID _ParseInsn32(ASMCODE32& ac, ADDR32 offset, const char *insn);
    VOID _ParseInsn64(ASMCODE64& ac, ADDR64 offset, const char *insn);

protected:
    LPCTSTR                     m_pszFileName;
    HANDLE                      m_hFile;
    HANDLE                      m_hFileMapping;
    LPBYTE                      m_pFileImage;
    DWORD                       m_dwFileSize;
    DWORD                       m_dwLastError;
    BOOL                        m_bModuleLoaded;
    BOOL                        m_bDisAsmed;
    BOOL                        m_bDecompiled;

    PIMAGE_DOS_HEADER           m_pDOSHeader;
    union
    {
        PIMAGE_NT_HEADERS       m_pNTHeaders;
        PIMAGE_NT_HEADERS32     m_pNTHeaders32;
        PIMAGE_NT_HEADERS64     m_pNTHeaders64;
    };
    PIMAGE_FILE_HEADER          m_pFileHeader;
    PIMAGE_OPTIONAL_HEADER32    m_pOptional32;
    PIMAGE_OPTIONAL_HEADER64    m_pOptional64;

    LPBYTE                      m_pLoadedImage;
    DWORD                       m_dwHeaderSum;
    DWORD                       m_dwCheckSum;
    DWORD                       m_dwSizeOfOptionalHeader;
    DWORD                       m_dwAddressOfEntryPoint;
    DWORD                       m_dwBaseOfCode;
    DWORD                       m_dwSizeOfHeaders;

    PREAL_IMAGE_SECTION_HEADER  m_pSectionHeaders;
    mutable
    PREAL_IMAGE_SECTION_HEADER  m_pCodeSectionHeader;
    PREAL_IMAGE_DATA_DIRECTORY  m_pDataDirectories;

    SYMBOLINFO                  m_SymbolInfo;

    // delay loading
    vector<ImgDelayDescr>       m_vImgDelayDescrs;

private:
    // Don't copy it
    PEMODULE(const PEMODULE&);
    PEMODULE& operator=(const PEMODULE&);
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
