////////////////////////////////////////////////////////////////////////////
// SYMBOL accessors

inline DWORD& SYMBOL::RVA()
{
    return m_rva;
}

inline string& SYMBOL::Name()
{
    return m_name;
}

inline const DWORD& SYMBOL::RVA() const
{
    return m_rva;
}

inline const string& SYMBOL::Name() const
{
    return m_name;
}

////////////////////////////////////////////////////////////////////////////
// SYMBOLINFO accessors

inline VECSET<string>& SYMBOLINFO::GetImportDllNames()
{
    return m_vImportDllNames;
}

inline VECSET<IMPORT_SYMBOL>& SYMBOLINFO::GetImportSymbols()
{
    return m_vImportSymbols;
}

inline VECSET<EXPORT_SYMBOL>& SYMBOLINFO::GetExportSymbols()
{
    return m_vExportSymbols;
}

inline map<DWORD, IMPORT_SYMBOL>& SYMBOLINFO::MapRVAToImportSymbol()
{
    return m_mRVAToImportSymbol;
}

inline map<string, IMPORT_SYMBOL>& SYMBOLINFO::MapNameToImportSymbol()
{
    return m_mNameToImportSymbol;
}

inline map<DWORD, EXPORT_SYMBOL>& SYMBOLINFO::MapRVAToExportSymbol()
{
    return m_mRVAToExportSymbol;
}

inline map<string, EXPORT_SYMBOL>& SYMBOLINFO::MapNameToExportSymbol()
{
    return m_mNameToExportSymbol;
}

inline map<DWORD, SYMBOL>& SYMBOLINFO::MapRVAToSymbol()
{
    return m_mRVAToSymbol;
}

inline map<string, SYMBOL>& SYMBOLINFO::MapNameToSymbol()
{
    return m_mNameToSymbol;
}

////////////////////////////////////////////////////////////////////////////
// SYMBOLINFO const accessors

inline const VECSET<string>& SYMBOLINFO::GetImportDllNames() const
{
    return m_vImportDllNames;
}

inline const VECSET<IMPORT_SYMBOL>& SYMBOLINFO::GetImportSymbols() const
{
    return m_vImportSymbols;
}

inline const VECSET<EXPORT_SYMBOL>& SYMBOLINFO::GetExportSymbols() const
{
    return m_vExportSymbols;
}

inline const map<DWORD, IMPORT_SYMBOL>& SYMBOLINFO::MapRVAToImportSymbol() const
{
    return m_mRVAToImportSymbol;
}

inline const map<string, IMPORT_SYMBOL>& SYMBOLINFO::MapNameToImportSymbol() const
{
    return m_mNameToImportSymbol;
}

inline const map<DWORD, EXPORT_SYMBOL>& SYMBOLINFO::MapRVAToExportSymbol() const
{
    return m_mRVAToExportSymbol;
}

inline const map<string, EXPORT_SYMBOL>& SYMBOLINFO::MapNameToExportSymbol() const
{
    return m_mNameToExportSymbol;
}

inline const map<DWORD, SYMBOL>& SYMBOLINFO::MapRVAToSymbol() const
{
    return m_mRVAToSymbol;
}

inline const map<string, SYMBOL>& SYMBOLINFO::MapNameToSymbol() const
{
    return m_mNameToSymbol;
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE attributes

inline BOOL PEMODULE::IsDLL() const
{
    if (!IsModuleLoaded())
        return FALSE;

    return (FileHeader()->Characteristics & IMAGE_FILE_DLL) != 0;
}

inline BOOL PEMODULE::IsCUIExe() const
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

inline BOOL PEMODULE::IsGUIExe() const
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

inline DWORD PEMODULE::GetFileSize() const
{
    return m_dwFileSize;
}

inline LPCTSTR PEMODULE::GetFileName() const
{
    return m_pszFileName;
}

inline BOOL PEMODULE::Is32Bit() const
{
    return OptionalHeader32() != NULL;
}

inline BOOL PEMODULE::Is64Bit() const
{
    return OptionalHeader64() != NULL;
}

inline BOOL PEMODULE::IsModuleLoaded() const
{
    return m_bModuleLoaded;
}

inline BOOL PEMODULE::RVAInDirEntry(DWORD rva, DWORD index) const
{
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES &&
        DataDirectories()[index].RVA <= rva &&
        rva < DataDirectories()[index].RVA + DataDirectories()[index].Size)
    {
        return TRUE;
    }
    return FALSE;
}

inline BOOL PEMODULE::IsValidAddr32(ADDR32 addr) const
{
    if (!Is32Bit())
        return FALSE;

    const ADDR32 begin = OptionalHeader32()->ImageBase;
    const ADDR32 end = begin + OptionalHeader32()->SizeOfImage;
    return begin <= addr && addr < end;
}

inline BOOL PEMODULE::IsValidAddr64(ADDR64 addr) const
{
    if (!Is64Bit())
        return FALSE;

    const ADDR64 begin = OptionalHeader64()->ImageBase;
    const ADDR64 end = begin + OptionalHeader64()->SizeOfImage;
    return begin <= addr && addr < end;
}

inline DWORD PEMODULE::GetBaseOfCode() const
{
    if (Is64Bit())
        return OptionalHeader64()->BaseOfCode;
    else if (Is32Bit())
        return OptionalHeader32()->BaseOfCode;
    else
        return 0;
}

inline DWORD PEMODULE::GetSizeOfHeaders() const
{
    if (Is64Bit())
        return OptionalHeader64()->SizeOfHeaders;
    else if (Is32Bit())
        return OptionalHeader32()->SizeOfHeaders;
    else
        return 0;
}

inline DWORD PEMODULE::GetSizeOfImage() const
{
    if (Is64Bit())
        return OptionalHeader64()->SizeOfImage;
    else if (Is32Bit())
        return OptionalHeader32()->SizeOfImage;
    else
        return 0;
}

inline PIMAGE_IMPORT_DESCRIPTOR PEMODULE::ImportDescriptors()
{
    return reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_IMPORT));
}

inline PIMAGE_EXPORT_DIRECTORY PEMODULE::ExportDirectory()
{
    return reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_EXPORT));
}

inline PIMAGE_RESOURCE_DIRECTORY PEMODULE::ResourceDirectory()
{
    return reinterpret_cast<PIMAGE_RESOURCE_DIRECTORY>(
        DirEntryData(IMAGE_DIRECTORY_ENTRY_RESOURCE));
}

inline LPBYTE PEMODULE::GetData(DWORD rva)
{
    return (LoadedImage() ? LoadedImage() + rva : NULL);
}

inline LPBYTE& PEMODULE::LoadedImage()
{
    return m_pLoadedImage;
}

inline LPBYTE& PEMODULE::FileImage()
{
    return m_pFileImage;
}

inline DWORD PEMODULE::GetSizeOfOptionalHeader() const
{
    if (FileHeader())
        return FileHeader()->SizeOfOptionalHeader;
    else
        return 0;
}

inline DWORD PEMODULE::DirEntryDataSize(DWORD index) const
{
    return (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ?
        DataDirectories()[index].Size : 0);
}

inline BOOL PEMODULE::AddressInData32(ADDR32 va) const
{
    return (Is32Bit() && IsValidAddr32(va) && !AddressInCode32(va));
}

inline BOOL PEMODULE::AddressInData64(ADDR64 va) const
{
    return (Is64Bit() && IsValidAddr64(va) && !AddressInCode64(va));
}

inline DWORD PEMODULE::RVAOfEntryPoint() const
{
    if (Is64Bit())
        return OptionalHeader64()->AddressOfEntryPoint;
    else if (Is32Bit())
        return OptionalHeader32()->AddressOfEntryPoint;
    else
        return 0;
}

inline DWORD PEMODULE::RVAFromVA32(ADDR32 va) const
{
    assert(OptionalHeader32());
    return va - OptionalHeader32()->ImageBase;
}

inline DWORD PEMODULE::RVAFromVA64(ADDR64 va) const
{
    assert(OptionalHeader64());
    return (DWORD)(va - OptionalHeader64()->ImageBase);
}

inline ADDR32 PEMODULE::VA32FromRVA(DWORD rva) const
{
    assert(OptionalHeader32());
    return OptionalHeader32()->ImageBase + rva;
}

inline ADDR64 PEMODULE::VA64FromRVA(DWORD rva) const
{
    assert(OptionalHeader64());
    return OptionalHeader64()->ImageBase + rva;
}

inline DWORD PEMODULE::CheckSum() const
{
    return m_dwCheckSum;
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE accessors

inline WORD& PEMODULE::NumberOfSections()
{
    assert(FileHeader());
    return FileHeader()->NumberOfSections;
}

inline DWORD& PEMODULE::LastError()
{
    return m_dwLastError;
}

inline PIMAGE_DOS_HEADER& PEMODULE::DOSHeader()
{
    return m_pDOSHeader;
}

inline PIMAGE_NT_HEADERS& PEMODULE::NTHeaders()
{
    return m_pNTHeaders;
}

inline PIMAGE_NT_HEADERS32& PEMODULE::NTHeaders32()
{
    return m_pNTHeaders32;
}

inline PIMAGE_NT_HEADERS64& PEMODULE::NTHeaders64()
{
    return m_pNTHeaders64;
}

inline PIMAGE_FILE_HEADER& PEMODULE::FileHeader()
{
    return m_pFileHeader;
}

inline PIMAGE_OPTIONAL_HEADER32& PEMODULE::OptionalHeader32()
{
    return m_pOptional32;
}

inline PIMAGE_OPTIONAL_HEADER64& PEMODULE::OptionalHeader64()
{
    return m_pOptional64;
}

inline PREAL_IMAGE_DATA_DIRECTORY& PEMODULE::DataDirectories()
{
    return m_pDataDirectories;
}

inline PREAL_IMAGE_DATA_DIRECTORY PEMODULE::DataDirectory(DWORD index)
{
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    if (index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return &m_pDataDirectories[index];
    return NULL;
}

inline PREAL_IMAGE_SECTION_HEADER& PEMODULE::SectionHeaders()
{
    return m_pSectionHeaders;
}

inline PREAL_IMAGE_SECTION_HEADER PEMODULE::SectionHeader(DWORD index)
{
    assert(m_pSectionHeaders);
    if (index < NumberOfSections())
        return &m_pSectionHeaders[index];
    return NULL;
}

inline vector<ImgDelayDescr>& PEMODULE::DelayLoadDescriptors()
{
    return m_vImgDelayDescrs;
}

inline VECSET<string>& PEMODULE::ImportDllNames()
{
    return SymbolInfo().GetImportDllNames();
}

inline VECSET<IMPORT_SYMBOL>& PEMODULE::ImportSymbols()
{
    return SymbolInfo().GetImportSymbols();
}

inline VECSET<EXPORT_SYMBOL>& PEMODULE::ExportSymbols()
{
    return SymbolInfo().GetExportSymbols();
}

inline SYMBOLINFO& PEMODULE::SymbolInfo()
{
    return m_SymbolInfo;
}

inline HANDLE& PEMODULE::File()
{
    return m_hFile;
}

inline LPCTSTR& PEMODULE::FileName()
{
    return m_pszFileName;
}

inline DWORD& PEMODULE::FileSize()
{
    return m_dwFileSize;
}

inline HANDLE& PEMODULE::FileMapping()
{
    return m_hFileMapping;
}

inline BOOL& PEMODULE::ModuleLoaded()
{
    return m_bModuleLoaded;
}

////////////////////////////////////////////////////////////////////////////
// PEMODULE const accessors

inline const WORD& PEMODULE::NumberOfSections() const
{
    return FileHeader()->NumberOfSections;
}

inline const DWORD& PEMODULE::LastError() const
{
    return m_dwLastError;
}

inline const PIMAGE_DOS_HEADER& PEMODULE::DOSHeader() const
{
    return m_pDOSHeader;
}

inline const PIMAGE_NT_HEADERS& PEMODULE::NTHeaders() const
{
    return m_pNTHeaders;
}

inline const PIMAGE_NT_HEADERS32& PEMODULE::NTHeaders32() const
{
    return m_pNTHeaders32;
}

inline const PIMAGE_NT_HEADERS64& PEMODULE::NTHeaders64() const
{
    return m_pNTHeaders64;
}

inline const PIMAGE_FILE_HEADER& PEMODULE::FileHeader() const
{
    return m_pFileHeader;
}

inline const PIMAGE_OPTIONAL_HEADER32& PEMODULE::OptionalHeader32() const
{
    return m_pOptional32;
}

inline const PIMAGE_OPTIONAL_HEADER64& PEMODULE::OptionalHeader64() const
{
    return m_pOptional64;
}

inline const PREAL_IMAGE_DATA_DIRECTORY& PEMODULE::DataDirectories() const
{
    return m_pDataDirectories;
}

inline const PREAL_IMAGE_DATA_DIRECTORY PEMODULE::DataDirectory(DWORD index) const
{
    assert(index < IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
    return &m_pDataDirectories[index];
}

inline const PREAL_IMAGE_SECTION_HEADER& PEMODULE::SectionHeaders() const
{
    return m_pSectionHeaders;
}

inline const PREAL_IMAGE_SECTION_HEADER PEMODULE::SectionHeader(DWORD index) const
{
    assert(m_pSectionHeaders);
    assert(index < NumberOfSections());
    if (index < NumberOfSections())
        return &m_pSectionHeaders[index];
    return NULL;
}

inline const vector<ImgDelayDescr>& PEMODULE::DelayLoadDescriptors() const
{
    return m_vImgDelayDescrs;
}

inline const VECSET<string>& PEMODULE::ImportDllNames() const
{
    return SymbolInfo().GetImportDllNames();
}

inline const VECSET<IMPORT_SYMBOL>& PEMODULE::ImportSymbols() const
{
    return SymbolInfo().GetImportSymbols();
}

inline const VECSET<EXPORT_SYMBOL>& PEMODULE::ExportSymbols() const
{
    return SymbolInfo().GetExportSymbols();
}

inline const SYMBOLINFO& PEMODULE::SymbolInfo() const
{
    return m_SymbolInfo;
}

inline HANDLE& PEMODULE::File() const
{
    return const_cast<HANDLE&>(m_hFile);
}

inline const LPCTSTR& PEMODULE::FileName() const
{
    return m_pszFileName;
}

inline const DWORD& PEMODULE::FileSize() const
{
    return m_dwFileSize;
}

inline HANDLE& PEMODULE::FileMapping() const
{
    return const_cast<HANDLE&>(m_hFileMapping);
}

inline const BOOL& PEMODULE::ModuleLoaded() const
{
    return m_bModuleLoaded;
}
