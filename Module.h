#ifndef MODULE_H_
#define MODULE_H_

////////////////////////////////////////////////////////////////////////////
// Module.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// REAL_IMAGE_SECTION_HEADER, REAL_IMAGE_DATA_DIRECTORY

#include <pshpack1.h>
typedef struct _REAL_IMAGE_SECTION_HEADER {
    BYTE        Name[IMAGE_SIZEOF_SHORT_NAME];
    union
    {
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
// CR_ImportSymbol

struct CR_ImportSymbol
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
        const char *pszName;
    };
};

////////////////////////////////////////////////////////////////////////////
// CR_ExportSymbol

struct CR_ExportSymbol
{
    DWORD   dwRVA;
    DWORD   dwOrdinal;
    const char * pszName;
    const char * pszForwarded;
};
typedef CR_ExportSymbol *LPEXPORT_SYMBOL;

////////////////////////////////////////////////////////////////////////////
// CR_Symbol

class CR_Symbol
{
public:
    CR_Symbol();
    CR_Symbol(const CR_Symbol& s);
    void operator=(const CR_Symbol& s);
    virtual ~CR_Symbol();
    void Copy(const CR_Symbol& s);
    void clear();

public: // accessors
    DWORD&              RVA();
    CR_String&        Name();
    const DWORD&        RVA() const;
    const CR_String&  Name() const;

protected:
    DWORD               m_rva;
    CR_String         m_name;
};
typedef CR_Symbol *LPSYMBOL;

////////////////////////////////////////////////////////////////////////////
// CR_SymbolInfo

class CR_SymbolInfo
{
public:
    CR_SymbolInfo();
    CR_SymbolInfo(const CR_SymbolInfo& info);
    void operator=(const CR_SymbolInfo& info);
    virtual ~CR_SymbolInfo();
    void Copy(const CR_SymbolInfo& info);
    void clear();

public:
    void AddImportDllName(const char *name);
    void AddSymbol(DWORD rva, const char *name);
    void AddSymbol(const CR_Symbol& s);
    void AddImportSymbol(const CR_ImportSymbol& is);
    void AddExportSymbol(const CR_ExportSymbol& es);

public: // accessors
    CR_StringSet&                               GetImportDllNames();
    CR_DeqSet<CR_ImportSymbol>&                 GetImportSymbols();
    CR_DeqSet<CR_ExportSymbol>&                 GetExportSymbols();
    CR_ImportSymbol *                           GetImportSymbolFromRVA(DWORD RVA);
    CR_ImportSymbol *                           GetImportSymbolFromName(const char *name);
    CR_ExportSymbol *                           GetExportSymbolFromRVA(DWORD RVA);
    CR_ExportSymbol *                           GetExportSymbolFromName(const char *name);
    CR_Symbol *                                 GetSymbolFromRVA(DWORD RVA);
    CR_Symbol *                                 GetSymbolFromName(const char *name);
    CR_Map<DWORD, CR_ImportSymbol>&             MapRVAToImportSymbol();
    CR_Map<CR_String, CR_ImportSymbol>&         MapNameToImportSymbol();
    CR_Map<DWORD, CR_ExportSymbol>&             MapRVAToExportSymbol();
    CR_Map<CR_String, CR_ExportSymbol>&         MapNameToExportSymbol();
    CR_Map<DWORD, CR_Symbol>&                   MapRVAToSymbol();
    CR_Map<CR_String, CR_Symbol>&               MapNameToSymbol();

public: // const accessors
    const CR_StringSet&                         GetImportDllNames() const;
    const CR_DeqSet<CR_ImportSymbol>&           GetImportSymbols() const;
    const CR_DeqSet<CR_ExportSymbol>&           GetExportSymbols() const;
    const CR_ImportSymbol *                     GetImportSymbolFromRVA(DWORD RVA) const;
    const CR_ImportSymbol *                     GetImportSymbolFromName(const char *name) const;
    const CR_ExportSymbol *                     GetExportSymbolFromRVA(DWORD RVA) const;
    const CR_ExportSymbol *                     GetExportSymbolFromName(const char *name) const;
    const CR_Symbol *                           GetSymbolFromRVA(DWORD RVA) const;
    const CR_Symbol *                           GetSymbolFromName(const char *name) const;
    const CR_Map<DWORD, CR_ImportSymbol>&       MapRVAToImportSymbol() const;
    const CR_Map<CR_String, CR_ImportSymbol>&   MapNameToImportSymbol() const;
    const CR_Map<DWORD, CR_ExportSymbol>&       MapRVAToExportSymbol() const;
    const CR_Map<CR_String, CR_ExportSymbol>&   MapNameToExportSymbol() const;
    const CR_Map<DWORD, CR_Symbol>&             MapRVAToSymbol() const;
    const CR_Map<CR_String, CR_Symbol>&         MapNameToSymbol() const;

protected:
    // import symbols
    CR_StringSet                                m_vImportDllNames;
    CR_DeqSet<CR_ImportSymbol>                  m_vImportSymbols;
    CR_Map<DWORD, CR_ImportSymbol>              m_mRVAToImportSymbol;
    CR_Map<CR_String, CR_ImportSymbol>          m_mNameToImportSymbol;

    // export symbols
    CR_DeqSet<CR_ExportSymbol>                  m_vExportSymbols;
    CR_Map<DWORD, CR_ExportSymbol>              m_mRVAToExportSymbol;
    CR_Map<CR_String, CR_ExportSymbol>          m_mNameToExportSymbol;

    // symbols
    CR_Map<DWORD, CR_Symbol>                    m_mRVAToSymbol;
    CR_Map<CR_String, CR_Symbol>                m_mNameToSymbol;
};

////////////////////////////////////////////////////////////////////////////
// CR_Module

class CR_Module
{
public:
    CR_Module();
    CR_Module(LPCTSTR FileName);
    virtual ~CR_Module();

    BOOL LoadModule(LPCTSTR pszFileName);
    void UnloadModule();
    BOOL IsModuleLoaded() const;

    // dumpers
    void DumpHeaders();
    void DumpImportSymbols();
    void DumpExportSymbols();
    void DumpResource();
    void DumpDelayLoad();

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
    BOOL    IsValidAddr32(CR_Addr32 addr) const;
    BOOL    IsValidAddr64(CR_Addr64 addr) const;
    DWORD   GetBaseOfCode() const;
    DWORD   GetSizeOfHeaders() const;
    DWORD   GetSizeOfImage() const;
    DWORD   GetSizeOfOptionalHeader() const;
    LPBYTE  GetData(DWORD rva);
    LPBYTE  DirEntryData(DWORD index);
    DWORD   DirEntryDataSize(DWORD index) const;
    BOOL    AddressInCode32(CR_Addr32 va) const;
    BOOL    AddressInData32(CR_Addr32 va) const;
    BOOL    AddressInCode64(CR_Addr64 va) const;
    BOOL    AddressInData64(CR_Addr64 va) const;
    DWORD   RVAOfEntryPoint() const;
    DWORD   RVAFromVA32(CR_Addr32 va) const;
    DWORD   RVAFromVA64(CR_Addr64 va) const;
    CR_Addr32  VA32FromRVA(DWORD rva) const;
    CR_Addr64  VA64FromRVA(DWORD rva) const;
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
    CR_DeqSet<ImgDelayDescr>&           DelayLoadDescriptors();
    CR_StringSet&                       ImportDllNames();
    CR_DeqSet<CR_ImportSymbol>&         ImportSymbols();
    CR_DeqSet<CR_ExportSymbol>&         ExportSymbols();
    CR_SymbolInfo&                      SymbolInfo();
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
    const CR_DeqSet<ImgDelayDescr>&     DelayLoadDescriptors() const;
    const CR_StringSet&                 ImportDllNames() const;
    const CR_DeqSet<CR_ImportSymbol>&   ImportSymbols() const;
    const CR_DeqSet<CR_ExportSymbol>&   ExportSymbols() const;
    const CR_SymbolInfo&                SymbolInfo() const;
    HANDLE&                             File() const;
    const LPCTSTR&                      FileName() const;
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
    const CR_ImportSymbol *FindImportSymbolByRVA(DWORD rva) const;
    const CR_ImportSymbol *FindImportSymbolByName(const char *Name) const;
    const CR_ExportSymbol *FindExportSymbolByRVA(DWORD rva) const;
    const CR_ExportSymbol *FindExportSymbolByName(const char *Name) const;
    const CR_Symbol *FindSymbolByRVA(DWORD rva) const;
    const CR_Symbol *FindSymbolByName(const char *Name) const;
    const CR_Symbol *FindSymbolByAddr32(CR_Addr32 addr) const;
    const CR_Symbol *FindSymbolByAddr64(CR_Addr64 addr) const;
    const char *GetSymbolNameFromRVA(DWORD rva) const;
    const char *GetSymbolNameFromAddr32(CR_Addr32 addr) const;
    const char *GetSymbolNameFromAddr64(CR_Addr64 addr) const;

public:
    BOOL DisAsmAddr32(CR_DecompStatus32& status, CR_Addr32 func, CR_Addr32 va);
    BOOL DisAsmAddr64(CR_DecompStatus64& status, CR_Addr64 func, CR_Addr64 va);
    BOOL DisAsm32(CR_DecompStatus32& status);
    BOOL DisAsm64(CR_DecompStatus64& status);

    BOOL FixUpAsm32(CR_DecompStatus32& status);
    BOOL FixUpAsm64(CR_DecompStatus64& status);

    BOOL DumpDisAsm32(CR_DecompStatus32& status);
    BOOL DumpDisAsmFunc32(CR_DecompStatus32& status, CR_Addr32 func);

    BOOL DumpDisAsm64(CR_DecompStatus64& status);
    BOOL DumpDisAsmFunc64(CR_DecompStatus64& status, CR_Addr64 func);

    BOOL DecompileAddr32(CR_DecompStatus32& status, CR_Addr32 va);
    BOOL DecompileAddr64(CR_DecompStatus64& status, CR_Addr64 va);
    BOOL Decompile32(CR_DecompStatus32& status);
    BOOL Decompile64(CR_DecompStatus64& status);
    BOOL Decompile();

protected:
    BOOL _LoadImage(LPVOID Data);
    BOOL _LoadNTHeaders(LPVOID Data);

    BOOL _GetImportDllNames(CR_StringSet& names);
    BOOL _GetImportSymbols(DWORD dll_index, CR_DeqSet<CR_ImportSymbol>& symbols);
    BOOL _GetExportSymbols(CR_DeqSet<CR_ExportSymbol>& symbols);

    void _ParseInsn32(CR_CodeInsn32& ac, CR_Addr32 offset, const char *insn);
    void _ParseInsn64(CR_CodeInsn64& ac, CR_Addr64 offset, const char *insn);

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

    CR_SymbolInfo               m_SymbolInfo;

    // delay loading
    CR_DeqSet<ImgDelayDescr>    m_vImgDelayDescrs;

private:
    // Don't copy it
    CR_Module(const CR_Module&);
    CR_Module& operator=(const CR_Module&);
};

////////////////////////////////////////////////////////////////////////////
// Dumping.cpp

const char *CrGetTimeStampString(DWORD TimeStamp);
const char *CrGetMachineString(WORD Machine);
const char *CrGetFileCharacteristicsString(WORD w);
const char *CrGetSectionFlagsString(DWORD dw);
const char *CrGetDllCharacteristicsString(WORD w);
const char *CrGetSubsystemString(WORD w);
void CrDumpDataDirectory(LPVOID Data, DWORD index);
void CrDumpDOSHeader(LPVOID Data);
void CrDumpFileHeader(LPVOID Data);
void CrDumpOptionalHeader32(LPVOID Data, DWORD CheckSum);
void CrDumpOptionalHeader64(LPVOID Data, DWORD CheckSum);
void CrDumpSectionHeader(LPVOID Data);
void CrDumpCodes(const CR_Binary& codes, int bits);

////////////////////////////////////////////////////////////////////////////

// inline functions
#include "Module_inl.h"

#endif  // ndef MODULE_H_
