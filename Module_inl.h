////////////////////////////////////////////////////////////////////////////
// Module_inl.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// CR_Symbol accessors

inline DWORD& CR_Symbol::RVA()
{
    return m_rva;
}

inline CR_String& CR_Symbol::Name()
{
    return m_name;
}

inline const DWORD& CR_Symbol::RVA() const
{
    return m_rva;
}

inline const CR_String& CR_Symbol::Name() const
{
    return m_name;
}

////////////////////////////////////////////////////////////////////////////
// CR_SymbolInfo accessors

inline CR_StringSet& CR_SymbolInfo::GetImportDllNames()
{
    return m_vImportDllNames;
}

inline CR_DeqSet<CR_ImportSymbol>& CR_SymbolInfo::GetImportSymbols()
{
    return m_vImportSymbols;
}

inline CR_DeqSet<CR_ExportSymbol>& CR_SymbolInfo::GetExportSymbols()
{
    return m_vExportSymbols;
}

inline CR_Map<DWORD, CR_ImportSymbol>& CR_SymbolInfo::MapRVAToImportSymbol()
{
    return m_mRVAToImportSymbol;
}

inline CR_Map<CR_String, CR_ImportSymbol>& CR_SymbolInfo::MapNameToImportSymbol()
{
    return m_mNameToImportSymbol;
}

inline CR_Map<DWORD, CR_ExportSymbol>& CR_SymbolInfo::MapRVAToExportSymbol()
{
    return m_mRVAToExportSymbol;
}

inline CR_Map<CR_String, CR_ExportSymbol>& CR_SymbolInfo::MapNameToExportSymbol()
{
    return m_mNameToExportSymbol;
}

inline CR_Map<DWORD, CR_Symbol>& CR_SymbolInfo::MapRVAToSymbol()
{
    return m_mRVAToSymbol;
}

inline CR_Map<CR_String, CR_Symbol>& CR_SymbolInfo::MapNameToSymbol()
{
    return m_mNameToSymbol;
}

////////////////////////////////////////////////////////////////////////////
// CR_SymbolInfo const accessors

inline const CR_StringSet& CR_SymbolInfo::GetImportDllNames() const
{
    return m_vImportDllNames;
}

inline const CR_DeqSet<CR_ImportSymbol>& CR_SymbolInfo::GetImportSymbols() const
{
    return m_vImportSymbols;
}

inline const CR_DeqSet<CR_ExportSymbol>& CR_SymbolInfo::GetExportSymbols() const
{
    return m_vExportSymbols;
}

inline const CR_Map<DWORD, CR_ImportSymbol>& CR_SymbolInfo::MapRVAToImportSymbol() const
{
    return m_mRVAToImportSymbol;
}

inline const CR_Map<CR_String, CR_ImportSymbol>& CR_SymbolInfo::MapNameToImportSymbol() const
{
    return m_mNameToImportSymbol;
}

inline const CR_Map<DWORD, CR_ExportSymbol>& CR_SymbolInfo::MapRVAToExportSymbol() const
{
    return m_mRVAToExportSymbol;
}

inline const CR_Map<CR_String, CR_ExportSymbol>& CR_SymbolInfo::MapNameToExportSymbol() const
{
    return m_mNameToExportSymbol;
}

inline const CR_Map<DWORD, CR_Symbol>& CR_SymbolInfo::MapRVAToSymbol() const
{
    return m_mRVAToSymbol;
}

inline const CR_Map<CR_String, CR_Symbol>& CR_SymbolInfo::MapNameToSymbol() const
{
    return m_mNameToSymbol;
}

////////////////////////////////////////////////////////////////////////////
// CR_Module attributes

inline BOOL CR_Module::IsDLL() const
{
    if (!IsModuleLoaded())
        return FALSE;

    return (FileHeader()->Characteristics & IMAGE_FILE_DLL) != 0;
}

inline BOOL CR_Module::IsCUIExe() const
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

inline BOOL CR_Module::IsGUIExe() const
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

inline DWORD CR_Module::GetFileSize() const
{
    return m_dwFileSize;
}

inline LPCTSTR CR_Module::GetFileName() const
{
    return m_pszFileName;
}

inline BOOL CR_Module::Is32Bit() const
{
    return OptionalHeader32() != NULL;
}

inline BOOL CR_Module::Is64Bit() const
{
    return OptionalHeader64() != NULL;
}

inline BOOL CR_Module::IsModuleLoaded() const
{
    return m_bModuleLoaded;
}

inline BOOL CR_Module::RVAInDirEntry(DWORD rva, DWORD index) const
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        DataDirectories()[index].RVA <= rva &&
        rva < DataDirectories()[index].RVA + DataDirectories()[index].Size)
    {
        return TRUE;
    }
    return FALSE;
}

inline BOOL CR_Module::IsValidAddr32(CR_Addr32 addr) const
{
    if (!Is32Bit())
        return FALSE;

    const CR_Addr32 begin = OptionalHeader32()->ImageBase;
    const CR_Addr32 end = begin + OptionalHeader32()->SizeOfImage;
    return begin <= addr && addr < end;
}

inline BOOL CR_Module::IsValidAddr64(CR_Addr64 addr) const
{
    if (!Is64Bit())
        return FALSE;

    const CR_Addr64 begin = OptionalHeader64()->ImageBase;
    const CR_Addr64 end = begin + OptionalHeader64()->SizeOfImage;
    return begin <= addr && addr < end;
}

inline DWORD CR_Module::GetBaseOfCode() const
{
    if (Is64Bit())
        return OptionalHeader64()->BaseOfCode;
    else if (Is32Bit())
        return OptionalHeader32()->BaseOfCode;
    else
        return 0;
}

inline DWORD CR_Module::GetSizeOfHeaders() const
{
    if (Is64Bit())
        return OptionalHeader64()->SizeOfHeaders;
    else if (Is32Bit())
        return OptionalHeader32()->SizeOfHeaders;
    else
        return 0;
}

inline DWORD CR_Module::GetSizeOfImage() const
{
    if (Is64Bit())
        return OptionalHeader64()->SizeOfImage;
    else if (Is32Bit())
        return OptionalHeader32()->SizeOfImage;
    else
        return 0;
}

inline PIMAGE_IMPORT_DESCRIPTOR CR_Module::ImportDescriptors()
{
    return reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_IMPORT));
}

inline PIMAGE_EXPORT_DIRECTORY CR_Module::ExportDirectory()
{
    return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_EXPORT));
}

inline PIMAGE_RESOURCE_DIRECTORY CR_Module::ResourceDirectory()
{
    return reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_RESOURCE));
}

inline LPBYTE CR_Module::GetData(DWORD rva)
{
    return (LoadedImage() ? LoadedImage() + rva : NULL);
}

inline LPBYTE& CR_Module::LoadedImage()
{
    return m_pLoadedImage;
}

inline LPBYTE& CR_Module::FileImage()
{
    return m_pFileImage;
}

inline DWORD CR_Module::GetSizeOfOptionalHeader() const
{
    if (FileHeader())
        return FileHeader()->SizeOfOptionalHeader;
    else
        return 0;
}

inline DWORD CR_Module::DirEntryDataSize(DWORD index) const
{
    return (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ?
        DataDirectories()[index].Size : 0);
}

inline BOOL CR_Module::AddressInData32(CR_Addr32 va) const
{
    return (Is32Bit() && IsValidAddr32(va) && !AddressInCode32(va));
}

inline BOOL CR_Module::AddressInData64(CR_Addr64 va) const
{
    return (Is64Bit() && IsValidAddr64(va) && !AddressInCode64(va));
}

inline DWORD CR_Module::RVAOfEntryPoint() const
{
    if (Is64Bit())
        return OptionalHeader64()->AddressOfEntryPoint;
    else if (Is32Bit())
        return OptionalHeader32()->AddressOfEntryPoint;
    else
        return 0;
}

inline DWORD CR_Module::RVAFromVA32(CR_Addr32 va) const
{
    assert(OptionalHeader32());
    return va - OptionalHeader32()->ImageBase;
}

inline DWORD CR_Module::RVAFromVA64(CR_Addr64 va) const
{
    assert(OptionalHeader64());
    return (DWORD)(va - OptionalHeader64()->ImageBase);
}

inline CR_Addr32 CR_Module::VA32FromRVA(DWORD rva) const
{
    assert(OptionalHeader32());
    return OptionalHeader32()->ImageBase + rva;
}

inline CR_Addr64 CR_Module::VA64FromRVA(DWORD rva) const
{
    assert(OptionalHeader64());
    return OptionalHeader64()->ImageBase + rva;
}

inline DWORD CR_Module::CheckSum() const
{
    return m_dwCheckSum;
}

////////////////////////////////////////////////////////////////////////////
// CR_Module accessors

inline WORD& CR_Module::NumberOfSections()
{
    assert(FileHeader());
    return FileHeader()->NumberOfSections;
}

inline DWORD& CR_Module::LastError()
{
    return m_dwLastError;
}

inline PIMAGE_DOS_HEADER& CR_Module::DOSHeader()
{
    return m_pDOSHeader;
}

inline PIMAGE_NT_HEADERS& CR_Module::NTHeaders()
{
    return m_pNTHeaders;
}

inline PIMAGE_NT_HEADERS32& CR_Module::NTHeaders32()
{
    return m_pNTHeaders32;
}

inline PIMAGE_NT_HEADERS64& CR_Module::NTHeaders64()
{
    return m_pNTHeaders64;
}

inline PIMAGE_FILE_HEADER& CR_Module::FileHeader()
{
    return m_pFileHeader;
}

inline PIMAGE_OPTIONAL_HEADER32& CR_Module::OptionalHeader32()
{
    return m_pOptional32;
}

inline PIMAGE_OPTIONAL_HEADER64& CR_Module::OptionalHeader64()
{
    return m_pOptional64;
}

inline PREAL_IMAGE_DATA_DIRECTORY& CR_Module::DataDirectories()
{
    return m_pDataDirectories;
}

inline PREAL_IMAGE_DATA_DIRECTORY CR_Module::DataDirectory(DWORD index)
{
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return &m_pDataDirectories[index];
    return NULL;
}

inline PREAL_IMAGE_SECTION_HEADER& CR_Module::SectionHeaders()
{
    return m_pSectionHeaders;
}

inline PREAL_IMAGE_SECTION_HEADER CR_Module::SectionHeader(DWORD index)
{
    assert(m_pSectionHeaders);
    if (index < NumberOfSections())
        return &m_pSectionHeaders[index];
    return NULL;
}

inline CR_DeqSet<ImgDelayDescr>& CR_Module::DelayLoadDescriptors()
{
    return m_vImgDelayDescrs;
}

inline CR_StringSet& CR_Module::ImportDllNames()
{
    return SymbolInfo().GetImportDllNames();
}

inline CR_DeqSet<CR_ImportSymbol>& CR_Module::ImportSymbols()
{
    return SymbolInfo().GetImportSymbols();
}

inline CR_DeqSet<CR_ExportSymbol>& CR_Module::ExportSymbols()
{
    return SymbolInfo().GetExportSymbols();
}

inline CR_SymbolInfo& CR_Module::SymbolInfo()
{
    return m_SymbolInfo;
}

inline HANDLE& CR_Module::File()
{
    return m_hFile;
}

inline LPCTSTR& CR_Module::FileName()
{
    return m_pszFileName;
}

inline DWORD& CR_Module::FileSize()
{
    return m_dwFileSize;
}

inline HANDLE& CR_Module::FileMapping()
{
    return m_hFileMapping;
}

inline BOOL& CR_Module::ModuleLoaded()
{
    return m_bModuleLoaded;
}

////////////////////////////////////////////////////////////////////////////
// CR_Module const accessors

inline const WORD& CR_Module::NumberOfSections() const
{
    return FileHeader()->NumberOfSections;
}

inline const DWORD& CR_Module::LastError() const
{
    return m_dwLastError;
}

inline const PIMAGE_DOS_HEADER& CR_Module::DOSHeader() const
{
    return m_pDOSHeader;
}

inline const PIMAGE_NT_HEADERS& CR_Module::NTHeaders() const
{
    return m_pNTHeaders;
}

inline const PIMAGE_NT_HEADERS32& CR_Module::NTHeaders32() const
{
    return m_pNTHeaders32;
}

inline const PIMAGE_NT_HEADERS64& CR_Module::NTHeaders64() const
{
    return m_pNTHeaders64;
}

inline const PIMAGE_FILE_HEADER& CR_Module::FileHeader() const
{
    return m_pFileHeader;
}

inline const PIMAGE_OPTIONAL_HEADER32& CR_Module::OptionalHeader32() const
{
    return m_pOptional32;
}

inline const PIMAGE_OPTIONAL_HEADER64& CR_Module::OptionalHeader64() const
{
    return m_pOptional64;
}

inline const PREAL_IMAGE_DATA_DIRECTORY& CR_Module::DataDirectories() const
{
    return m_pDataDirectories;
}

inline const PREAL_IMAGE_DATA_DIRECTORY CR_Module::DataDirectory(DWORD index) const
{
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    return &m_pDataDirectories[index];
}

inline const PREAL_IMAGE_SECTION_HEADER& CR_Module::SectionHeaders() const
{
    return m_pSectionHeaders;
}

inline const PREAL_IMAGE_SECTION_HEADER CR_Module::SectionHeader(DWORD index) const
{
    assert(m_pSectionHeaders);
    assert(index < NumberOfSections());
    if (index < NumberOfSections())
        return &m_pSectionHeaders[index];
    return NULL;
}

inline const CR_DeqSet<ImgDelayDescr>& CR_Module::DelayLoadDescriptors() const
{
    return m_vImgDelayDescrs;
}

inline const CR_StringSet& CR_Module::ImportDllNames() const
{
    return SymbolInfo().GetImportDllNames();
}

inline const CR_DeqSet<CR_ImportSymbol>& CR_Module::ImportSymbols() const
{
    return SymbolInfo().GetImportSymbols();
}

inline const CR_DeqSet<CR_ExportSymbol>& CR_Module::ExportSymbols() const
{
    return SymbolInfo().GetExportSymbols();
}

inline const CR_SymbolInfo& CR_Module::SymbolInfo() const
{
    return m_SymbolInfo;
}

inline HANDLE& CR_Module::File() const
{
    return const_cast<HANDLE&>(m_hFile);
}

inline const LPCTSTR& CR_Module::FileName() const
{
    return m_pszFileName;
}

inline const DWORD& CR_Module::FileSize() const
{
    return m_dwFileSize;
}

inline HANDLE& CR_Module::FileMapping() const
{
    return const_cast<HANDLE&>(m_hFileMapping);
}

inline const BOOL& CR_Module::ModuleLoaded() const
{
    return m_bModuleLoaded;
}
