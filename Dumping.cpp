////////////////////////////////////////////////////////////////////////////
// Dumping.cpp
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"

////////////////////////////////////////////////////////////////////////////

const char *CrGetTimeStampString(DWORD TimeStamp)
{
    std::time_t t;
    char *p;
    std::size_t len;
    if (TimeStamp == 0)
        return "NULL";

    t = static_cast<time_t>(TimeStamp);
    p = std::asctime(std::gmtime(&t));
    len = std::strlen(p);
    if (len > 0 && p[len - 1] == '\n')
        p[len - 1] = '\0';
    return p;
}

const char *CrGetMachineString(WORD Machine)
{
#ifndef IMAGE_FILE_MACHINE_SH3DSP
    #define IMAGE_FILE_MACHINE_SH3DSP 0x01A3
#endif
#ifndef IMAGE_FILE_MACHINE_SH5
    #define IMAGE_FILE_MACHINE_SH5 0x01A8
#endif
#ifndef IMAGE_FILE_MACHINE_ARMV7
    #define IMAGE_FILE_MACHINE_ARMV7 0x01C4
#endif
#ifndef IMAGE_FILE_MACHINE_AM33
    #define IMAGE_FILE_MACHINE_AM33 0x01D3
#endif
#ifndef IMAGE_FILE_MACHINE_POWERPCFP
    #define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#endif
#ifndef IMAGE_FILE_MACHINE_TRICORE
    #define IMAGE_FILE_MACHINE_TRICORE 0x0520
#endif
#ifndef IMAGE_FILE_MACHINE_CEF
    #define IMAGE_FILE_MACHINE_CEF 0x0CEF
#endif
#ifndef IMAGE_FILE_MACHINE_EBC
    #define IMAGE_FILE_MACHINE_EBC 0x0EBC
#endif
#ifndef IMAGE_FILE_MACHINE_AMD64
    #define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_M32R
    #define IMAGE_FILE_MACHINE_M32R 0x9041
#endif
#ifndef IMAGE_FILE_MACHINE_CEE
    #define IMAGE_FILE_MACHINE_CEE 0xC0EE
#endif
    switch(Machine)
    {
    case IMAGE_FILE_MACHINE_UNKNOWN: return "IMAGE_FILE_MACHINE_UNKNOWN";
    case IMAGE_FILE_MACHINE_I386: return "IMAGE_FILE_MACHINE_I386";
    case IMAGE_FILE_MACHINE_R3000: return "IMAGE_FILE_MACHINE_R3000";
    case IMAGE_FILE_MACHINE_R4000: return "IMAGE_FILE_MACHINE_R4000";
    case IMAGE_FILE_MACHINE_R10000: return "IMAGE_FILE_MACHINE_R10000";
    case IMAGE_FILE_MACHINE_WCEMIPSV2: return "IMAGE_FILE_MACHINE_WCEMIPSV2";
    case IMAGE_FILE_MACHINE_ALPHA: return "IMAGE_FILE_MACHINE_ALPHA";
    case IMAGE_FILE_MACHINE_SH3: return "IMAGE_FILE_MACHINE_SH3";
    case IMAGE_FILE_MACHINE_SH3DSP: return "IMAGE_FILE_MACHINE_SH3DSP";
    case IMAGE_FILE_MACHINE_SH3E: return "IMAGE_FILE_MACHINE_SH3E";
    case IMAGE_FILE_MACHINE_SH4: return "IMAGE_FILE_MACHINE_SH4";
    case IMAGE_FILE_MACHINE_SH5: return "IMAGE_FILE_MACHINE_SH5";
    case IMAGE_FILE_MACHINE_ARM: return "IMAGE_FILE_MACHINE_ARM";
    case IMAGE_FILE_MACHINE_ARMV7: return "IMAGE_FILE_MACHINE_ARMV7";
    case IMAGE_FILE_MACHINE_THUMB: return "IMAGE_FILE_MACHINE_THUMB";
    case IMAGE_FILE_MACHINE_AM33: return "IMAGE_FILE_MACHINE_AM33";
    case IMAGE_FILE_MACHINE_POWERPC: return "IMAGE_FILE_MACHINE_POWERPC";
    case IMAGE_FILE_MACHINE_POWERPCFP: return "IMAGE_FILE_MACHINE_POWERPCFP";
    case IMAGE_FILE_MACHINE_IA64: return "IMAGE_FILE_MACHINE_IA64";
    case IMAGE_FILE_MACHINE_MIPS16: return "IMAGE_FILE_MACHINE_MIPS16";
    case IMAGE_FILE_MACHINE_ALPHA64: return "IMAGE_FILE_MACHINE_ALPHA64";
    case IMAGE_FILE_MACHINE_MIPSFPU: return "IMAGE_FILE_MACHINE_MIPSFPU";
    case IMAGE_FILE_MACHINE_MIPSFPU16: return "IMAGE_FILE_MACHINE_MIPSFPU16";
    case IMAGE_FILE_MACHINE_TRICORE: return "IMAGE_FILE_MACHINE_TRICORE";
    case IMAGE_FILE_MACHINE_CEF: return "IMAGE_FILE_MACHINE_CEF";
    case IMAGE_FILE_MACHINE_EBC: return "IMAGE_FILE_MACHINE_EBC";
    case IMAGE_FILE_MACHINE_AMD64: return "IMAGE_FILE_MACHINE_AMD64";
    case IMAGE_FILE_MACHINE_M32R: return "IMAGE_FILE_MACHINE_M32R";
    case IMAGE_FILE_MACHINE_CEE: return "IMAGE_FILE_MACHINE_CEE";
    default: return "Unknown Machine";
    }
}

const char *CrGetFileCharacteristicsString(WORD w)
{
    static char buf[512];
    buf[0] = 0;
    if (IMAGE_FILE_RELOCS_STRIPPED & w) strcat(buf, "IMAGE_FILE_RELOCS_STRIPPED ");
    if (IMAGE_FILE_EXECUTABLE_IMAGE & w) strcat(buf, "IMAGE_FILE_EXECUTABLE_IMAGE ");
    if (IMAGE_FILE_LINE_NUMS_STRIPPED & w) strcat(buf, "IMAGE_FILE_LINE_NUMS_STRIPPED ");
    if (IMAGE_FILE_LOCAL_SYMS_STRIPPED & w) strcat(buf, "IMAGE_FILE_LOCAL_SYMS_STRIPPED ");
    if (IMAGE_FILE_AGGRESIVE_WS_TRIM & w) strcat(buf, "IMAGE_FILE_AGGRESIVE_WS_TRIM ");
    if (IMAGE_FILE_LARGE_ADDRESS_AWARE & w) strcat(buf, "IMAGE_FILE_LARGE_ADDRESS_AWARE ");
    if (IMAGE_FILE_BYTES_REVERSED_LO & w) strcat(buf, "IMAGE_FILE_BYTES_REVERSED_LO ");
    if (IMAGE_FILE_32BIT_MACHINE & w) strcat(buf, "IMAGE_FILE_32BIT_MACHINE ");
    if (IMAGE_FILE_DEBUG_STRIPPED & w) strcat(buf, "IMAGE_FILE_DEBUG_STRIPPED ");
    if (IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP & w) strcat(buf, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP ");
    if (IMAGE_FILE_NET_RUN_FROM_SWAP & w) strcat(buf, "IMAGE_FILE_NET_RUN_FROM_SWAP ");
    if (IMAGE_FILE_SYSTEM & w) strcat(buf, "IMAGE_FILE_SYSTEM ");
    if (IMAGE_FILE_DLL & w) strcat(buf, "IMAGE_FILE_DLL ");
    if (IMAGE_FILE_UP_SYSTEM_ONLY & w) strcat(buf, "IMAGE_FILE_UP_SYSTEM_ONLY ");
    if (IMAGE_FILE_BYTES_REVERSED_HI & w) strcat(buf, "IMAGE_FILE_BYTES_REVERSED_HI ");
    if (buf[0])
        buf[strlen(buf) - 1] = 0;
    return buf;
}

const char *CrGetSectionFlagsString(DWORD dw)
{
#ifndef IMAGE_SCN_TYPE_DSECT
    #define IMAGE_SCN_TYPE_DSECT 0x00000001
#endif
#ifndef IMAGE_SCN_TYPE_NOLOAD
    #define IMAGE_SCN_TYPE_NOLOAD 0x00000002
#endif
#ifndef IMAGE_SCN_TYPE_GROUP
    #define IMAGE_SCN_TYPE_GROUP 0x00000004
#endif
#ifndef IMAGE_SCN_TYPE_NO_PAD
    #define IMAGE_SCN_TYPE_NO_PAD 0x00000008
#endif
#ifndef IMAGE_SCN_TYPE_COPY
    #define IMAGE_SCN_TYPE_COPY 0x00000010
#endif
#ifndef IMAGE_SCN_CNT_CODE
    #define IMAGE_SCN_CNT_CODE 0x00000020
#endif
#ifndef IMAGE_SCN_CNT_INITIALIZED_DATA
    #define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#endif
#ifndef IMAGE_SCN_CNT_UNINITIALIZED_DATA
    #define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#endif
#ifndef IMAGE_SCN_LNK_OTHER
    #define IMAGE_SCN_LNK_OTHER 0x00000100
#endif
#ifndef IMAGE_SCN_LNK_INFO
    #define IMAGE_SCN_LNK_INFO 0x00000200
#endif
#ifndef IMAGE_SCN_TYPE_OVER
    #define IMAGE_SCN_TYPE_OVER 0x00000400
#endif
#ifndef IMAGE_SCN_LNK_REMOVE
    #define IMAGE_SCN_LNK_REMOVE 0x00000800
#endif
#ifndef IMAGE_SCN_LNK_COMDAT
    #define IMAGE_SCN_LNK_COMDAT 0x00001000
#endif
#ifndef IMAGE_SCN_MEM_PROTECTED
    #define IMAGE_SCN_MEM_PROTECTED 0x00004000
#endif
#ifndef IMAGE_SCN_NO_DEFER_SPEC_EXC
    #define IMAGE_SCN_NO_DEFER_SPEC_EXC 0x00004000
#endif
#ifndef IMAGE_SCN_GPREL
    #define IMAGE_SCN_GPREL 0x00008000
#endif
#ifndef IMAGE_SCN_MEM_FARDATA
    #define IMAGE_SCN_MEM_FARDATA 0x00008000
#endif
#ifndef IMAGE_SCN_MEM_SYSHEAP
    #define IMAGE_SCN_MEM_SYSHEAP 0x00010000
#endif
#ifndef IMAGE_SCN_MEM_PURGEABLE
    #define IMAGE_SCN_MEM_PURGEABLE 0x00020000
#endif
#ifndef IMAGE_SCN_MEM_16BIT
    #define IMAGE_SCN_MEM_16BIT 0x00020000
#endif
#ifndef IMAGE_SCN_MEM_LOCKED
    #define IMAGE_SCN_MEM_LOCKED 0x00040000
#endif
#ifndef IMAGE_SCN_MEM_PRELOAD
    #define IMAGE_SCN_MEM_PRELOAD 0x00080000
#endif
#ifndef IMAGE_SCN_ALIGN_1BYTES
    #define IMAGE_SCN_ALIGN_1BYTES 0x00100000
#endif
#ifndef IMAGE_SCN_ALIGN_2BYTES
    #define IMAGE_SCN_ALIGN_2BYTES 0x00200000
#endif
#ifndef IMAGE_SCN_ALIGN_4BYTES
    #define IMAGE_SCN_ALIGN_4BYTES 0x00300000
#endif
#ifndef IMAGE_SCN_ALIGN_8BYTES
    #define IMAGE_SCN_ALIGN_8BYTES 0x00400000
#endif
#ifndef IMAGE_SCN_ALIGN_16BYTES
    #define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#endif
#ifndef IMAGE_SCN_ALIGN_32BYTES
    #define IMAGE_SCN_ALIGN_32BYTES 0x00600000
#endif
#ifndef IMAGE_SCN_ALIGN_64BYTES
    #define IMAGE_SCN_ALIGN_64BYTES 0x00700000
#endif
#ifndef IMAGE_SCN_ALIGN_128BYTES
    #define IMAGE_SCN_ALIGN_128BYTES 0x00800000
#endif
#ifndef IMAGE_SCN_ALIGN_256BYTES
    #define IMAGE_SCN_ALIGN_256BYTES 0x00900000
#endif
#ifndef IMAGE_SCN_ALIGN_512BYTES
    #define IMAGE_SCN_ALIGN_512BYTES 0x00A00000
#endif
#ifndef IMAGE_SCN_ALIGN_1024BYTES
    #define IMAGE_SCN_ALIGN_1024BYTES 0x00B00000
#endif
#ifndef IMAGE_SCN_ALIGN_2048BYTES
    #define IMAGE_SCN_ALIGN_2048BYTES 0x00C00000
#endif
#ifndef IMAGE_SCN_ALIGN_4096BYTES
    #define IMAGE_SCN_ALIGN_4096BYTES 0x00D00000
#endif
#ifndef IMAGE_SCN_ALIGN_8192BYTES
    #define IMAGE_SCN_ALIGN_8192BYTES 0x00E00000
#endif
#ifndef IMAGE_SCN_LNK_NRELOC_OVFL
    #define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
#endif
#ifndef IMAGE_SCN_MEM_DISCARDABLE
    #define IMAGE_SCN_MEM_DISCARDABLE 0x02000000
#endif
#ifndef IMAGE_SCN_MEM_NOT_CACHED
    #define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#endif
#ifndef IMAGE_SCN_MEM_NOT_PAGED
    #define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#endif
#ifndef IMAGE_SCN_MEM_SHARED
    #define IMAGE_SCN_MEM_SHARED 0x10000000
#endif
#ifndef IMAGE_SCN_MEM_EXECUTE
    #define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif
#ifndef IMAGE_SCN_MEM_READ
    #define IMAGE_SCN_MEM_READ 0x40000000
#endif
#ifndef IMAGE_SCN_MEM_WRITE
    #define IMAGE_SCN_MEM_WRITE 0x80000000
#endif

    static char buf[512];
    buf[0] = 0;

    if (IMAGE_SCN_TYPE_DSECT & dw) strcat(buf, "IMAGE_SCN_TYPE_DSECT ");
    if (IMAGE_SCN_TYPE_NOLOAD & dw) strcat(buf, "IMAGE_SCN_TYPE_NOLOAD ");
    if (IMAGE_SCN_TYPE_GROUP & dw) strcat(buf, "IMAGE_SCN_TYPE_GROUP ");
    if (IMAGE_SCN_TYPE_NO_PAD & dw) strcat(buf, "IMAGE_SCN_TYPE_NO_PAD ");
    if (IMAGE_SCN_TYPE_COPY & dw) strcat(buf, "IMAGE_SCN_TYPE_COPY ");
    if (IMAGE_SCN_CNT_CODE & dw) strcat(buf, "IMAGE_SCN_CNT_CODE ");
    if (IMAGE_SCN_CNT_INITIALIZED_DATA & dw) strcat(buf, "IMAGE_SCN_CNT_INITIALIZED_DATA ");
    if (IMAGE_SCN_CNT_UNINITIALIZED_DATA & dw) strcat(buf, "IMAGE_SCN_CNT_UNINITIALIZED_DATA ");
    if (IMAGE_SCN_LNK_OTHER & dw) strcat(buf, "IMAGE_SCN_LNK_OTHER ");
    if (IMAGE_SCN_LNK_INFO & dw) strcat(buf, "IMAGE_SCN_LNK_INFO ");
    if (IMAGE_SCN_TYPE_OVER & dw) strcat(buf, "IMAGE_SCN_TYPE_OVER ");
    if (IMAGE_SCN_LNK_REMOVE & dw) strcat(buf, "IMAGE_SCN_LNK_REMOVE ");
    if (IMAGE_SCN_LNK_COMDAT & dw) strcat(buf, "IMAGE_SCN_LNK_COMDAT ");
    if (IMAGE_SCN_MEM_PROTECTED & dw) strcat(buf, "IMAGE_SCN_MEM_PROTECTED ");
    if (IMAGE_SCN_NO_DEFER_SPEC_EXC & dw) strcat(buf, "IMAGE_SCN_NO_DEFER_SPEC_EXC ");
    if (IMAGE_SCN_GPREL & dw) strcat(buf, "IMAGE_SCN_GPREL ");
    if (IMAGE_SCN_MEM_FARDATA & dw) strcat(buf, "IMAGE_SCN_MEM_FARDATA ");
    if (IMAGE_SCN_MEM_SYSHEAP & dw) strcat(buf, "IMAGE_SCN_MEM_SYSHEAP ");
    if (IMAGE_SCN_MEM_PURGEABLE & dw) strcat(buf, "IMAGE_SCN_MEM_PURGEABLE ");
    if (IMAGE_SCN_MEM_16BIT & dw) strcat(buf, "IMAGE_SCN_MEM_16BIT ");
    if (IMAGE_SCN_MEM_LOCKED & dw) strcat(buf, "IMAGE_SCN_MEM_LOCKED ");
    if (IMAGE_SCN_MEM_PRELOAD & dw) strcat(buf, "IMAGE_SCN_MEM_PRELOAD ");
    if (IMAGE_SCN_ALIGN_1BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_1BYTES ");
    if (IMAGE_SCN_ALIGN_2BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_2BYTES ");
    if (IMAGE_SCN_ALIGN_4BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_4BYTES ");
    if (IMAGE_SCN_ALIGN_8BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_8BYTES ");
    if (IMAGE_SCN_ALIGN_16BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_16BYTES ");
    if (IMAGE_SCN_ALIGN_32BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_32BYTES ");
    if (IMAGE_SCN_ALIGN_64BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_64BYTES ");
    if (IMAGE_SCN_ALIGN_128BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_128BYTES ");
    if (IMAGE_SCN_ALIGN_256BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_256BYTES ");
    if (IMAGE_SCN_ALIGN_512BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_512BYTES ");
    if (IMAGE_SCN_ALIGN_1024BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_1024BYTES ");
    if (IMAGE_SCN_ALIGN_2048BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_2048BYTES ");
    if (IMAGE_SCN_ALIGN_4096BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_4096BYTES ");
    if (IMAGE_SCN_ALIGN_8192BYTES == (dw & IMAGE_SCN_ALIGN_MASK)) strcat(buf, "IMAGE_SCN_ALIGN_8192BYTES ");
    if (IMAGE_SCN_LNK_NRELOC_OVFL & dw) strcat(buf, "IMAGE_SCN_LNK_NRELOC_OVFL ");
    if (IMAGE_SCN_MEM_DISCARDABLE & dw) strcat(buf, "IMAGE_SCN_MEM_DISCARDABLE ");
    if (IMAGE_SCN_MEM_NOT_CACHED & dw) strcat(buf, "IMAGE_SCN_MEM_NOT_CACHED ");
    if (IMAGE_SCN_MEM_NOT_PAGED & dw) strcat(buf, "IMAGE_SCN_MEM_NOT_PAGED ");
    if (IMAGE_SCN_MEM_SHARED & dw) strcat(buf, "IMAGE_SCN_MEM_SHARED ");
    if (IMAGE_SCN_MEM_EXECUTE & dw) strcat(buf, "IMAGE_SCN_MEM_EXECUTE ");
    if (IMAGE_SCN_MEM_READ & dw) strcat(buf, "IMAGE_SCN_MEM_READ ");
    if (IMAGE_SCN_MEM_WRITE & dw) strcat(buf, "IMAGE_SCN_MEM_WRITE ");
    if (buf[0])
        buf[strlen(buf) - 1] = 0;
    return buf;
}

const char *CrGetDllCharacteristicsString(WORD w)
{
#ifndef IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    #define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
    #define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    #define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
    #define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_SEH
    #define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_NO_BIND
    #define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
    #define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#endif
#ifndef IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
    #define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000
#endif

    static char buf[512];
    buf[0] = 0;
    if (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ");
    if (IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ");
    if (IMAGE_DLLCHARACTERISTICS_NX_COMPAT & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT ");
    if (IMAGE_DLLCHARACTERISTICS_NO_ISOLATION & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION ");
    if (IMAGE_DLLCHARACTERISTICS_NO_SEH & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NO_SEH ");
    if (IMAGE_DLLCHARACTERISTICS_NO_BIND & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_NO_BIND ");
    if (IMAGE_DLLCHARACTERISTICS_WDM_DRIVER & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ");
    if (IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE & w) strcat(buf, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE ");
    if (buf[0])
        buf[strlen(buf) - 1] = 0;
    return buf;
}

const char *CrGetSubsystemString(WORD w)
{
#ifndef IMAGE_SUBSYSTEM_UNKNOWN
    #define IMAGE_SUBSYSTEM_UNKNOWN 0
#endif
#ifndef IMAGE_SUBSYSTEM_NATIVE
    #define IMAGE_SUBSYSTEM_NATIVE 1
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_GUI
    #define IMAGE_SUBSYSTEM_WINDOWS_GUI 2
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_CUI
    #define IMAGE_SUBSYSTEM_WINDOWS_CUI 3
#endif
#ifndef IMAGE_SUBSYSTEM_OS2_CUI
    #define IMAGE_SUBSYSTEM_OS2_CUI 5
#endif
#ifndef IMAGE_SUBSYSTEM_POSIX_CUI
    #define IMAGE_SUBSYSTEM_POSIX_CUI 7
#endif
#ifndef IMAGE_SUBSYSTEM_NATIVE_WINDOWS
    #define IMAGE_SUBSYSTEM_NATIVE_WINDOWS 8
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_CE_GUI
    #define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI 9
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_APPLICATION
    #define IMAGE_SUBSYSTEM_EFI_APPLICATION 10
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER
    #define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER 11
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER
    #define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER 12
#endif
#ifndef IMAGE_SUBSYSTEM_EFI_ROM
    #define IMAGE_SUBSYSTEM_EFI_ROM 13
#endif
#ifndef IMAGE_SUBSYSTEM_XBOX
    #define IMAGE_SUBSYSTEM_XBOX 14
#endif
#ifndef IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION
    #define IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION 16
#endif

    switch(w)
    {
    case IMAGE_SUBSYSTEM_UNKNOWN: return "IMAGE_SUBSYSTEM_UNKNOWN";
    case IMAGE_SUBSYSTEM_NATIVE: return "IMAGE_SUBSYSTEM_NATIVE";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "IMAGE_SUBSYSTEM_WINDOWS_CUI";
    case IMAGE_SUBSYSTEM_OS2_CUI: return "IMAGE_SUBSYSTEM_OS2_CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return "IMAGE_SUBSYSTEM_POSIX_CUI";
    case IMAGE_SUBSYSTEM_NATIVE_WINDOWS: return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "IMAGE_SUBSYSTEM_EFI_APPLICATION";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER";
    case IMAGE_SUBSYSTEM_EFI_ROM: return "IMAGE_SUBSYSTEM_EFI_ROM";
    case IMAGE_SUBSYSTEM_XBOX: return "IMAGE_SUBSYSTEM_XBOX";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION";
    default: return "(Unknown)";
    }
}

void CrDumpDataDirectory(LPVOID Data, DWORD index)
{
#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
    #define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_IMPORT
    #define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_RESOURCE
    #define IMAGE_DIRECTORY_ENTRY_RESOURCE 2
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_EXCEPTION
    #define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_SECURITY
    #define IMAGE_DIRECTORY_ENTRY_SECURITY 4
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_BASERELOC
    #define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_DEBUG
    #define IMAGE_DIRECTORY_ENTRY_DEBUG 6
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_ARCHITECTURE
    #define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_GLOBALPTR
    #define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_TLS
    #define IMAGE_DIRECTORY_ENTRY_TLS 9
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
    #define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
    #define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_IAT
    #define IMAGE_DIRECTORY_ENTRY_IAT 12
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
    #define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
    #define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14
#endif

    PIMAGE_DATA_DIRECTORY Directory = (PIMAGE_DATA_DIRECTORY)Data;
    printf("    ");
    switch(index)
    {
    case IMAGE_DIRECTORY_ENTRY_EXPORT: printf("IMAGE_DIRECTORY_ENTRY_EXPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_IMPORT: printf("IMAGE_DIRECTORY_ENTRY_IMPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_RESOURCE: printf("IMAGE_DIRECTORY_ENTRY_RESOURCE"); break;
    case IMAGE_DIRECTORY_ENTRY_EXCEPTION: printf("IMAGE_DIRECTORY_ENTRY_EXCEPTION"); break;
    case IMAGE_DIRECTORY_ENTRY_SECURITY: printf("IMAGE_DIRECTORY_ENTRY_SECURITY"); break;
    case IMAGE_DIRECTORY_ENTRY_BASERELOC: printf("IMAGE_DIRECTORY_ENTRY_BASERELOC"); break;
    case IMAGE_DIRECTORY_ENTRY_DEBUG: printf("IMAGE_DIRECTORY_ENTRY_DEBUG"); break;
    case IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: printf("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE"); break;
    case IMAGE_DIRECTORY_ENTRY_GLOBALPTR: printf("IMAGE_DIRECTORY_ENTRY_GLOBALPTR"); break;
    case IMAGE_DIRECTORY_ENTRY_TLS: printf("IMAGE_DIRECTORY_ENTRY_TLS"); break;
    case IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: printf("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"); break;
    case IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: printf("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_IAT: printf("IMAGE_DIRECTORY_ENTRY_IAT"); break;
    case IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: printf("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"); break;
    case IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: printf("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"); break;
    }
    printf(" (%lu): V.A.: 0x%08lX, Size: 0x%08lX (%lu)\n", index, Directory->VirtualAddress, Directory->Size, Directory->Size);
}

void CrDumpDOSHeader(LPVOID Data)
{
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)Data;
    printf("\n### DOS Header ###\n");
    printf("  e_magic: 0x%04X\n", DOSHeader->e_magic);
    printf("  e_cblp: 0x%04X\n", DOSHeader->e_cblp);
    printf("  e_cp: 0x%04X\n", DOSHeader->e_cp);
    printf("  e_crlc: 0x%04X\n", DOSHeader->e_crlc);
    printf("  e_cparhdr: 0x%04X\n", DOSHeader->e_cparhdr);
    printf("  e_minalloc: 0x%04X\n", DOSHeader->e_minalloc);
    printf("  e_maxalloc: 0x%04X\n", DOSHeader->e_maxalloc);
    printf("  e_ss: 0x%04X\n", DOSHeader->e_ss);
    printf("  e_sp: 0x%04X\n", DOSHeader->e_sp);
    printf("  e_csum: 0x%04X\n", DOSHeader->e_csum);
    printf("  e_ip: 0x%04X\n", DOSHeader->e_ip);
    printf("  e_cs: 0x%04X\n", DOSHeader->e_cs);
    printf("  e_lfarlc: 0x%04X\n", DOSHeader->e_lfarlc);
    printf("  e_ovno: 0x%04X\n", DOSHeader->e_ovno);
    printf("  e_res[0]: 0x%04X\n", DOSHeader->e_res[0]);
    printf("  e_res[1]: 0x%04X\n", DOSHeader->e_res[1]);
    printf("  e_res[2]: 0x%04X\n", DOSHeader->e_res[2]);
    printf("  e_res[3]: 0x%04X\n", DOSHeader->e_res[3]);
    printf("  e_oemid: 0x%04X\n", DOSHeader->e_oemid);
    printf("  e_oeminfo: 0x%04X\n", DOSHeader->e_oeminfo);
    printf("  e_res2[0]: 0x%04X\n", DOSHeader->e_res2[0]);
    printf("  e_res2[1]: 0x%04X\n", DOSHeader->e_res2[1]);
    printf("  e_res2[2]: 0x%04X\n", DOSHeader->e_res2[2]);
    printf("  e_res2[3]: 0x%04X\n", DOSHeader->e_res2[3]);
    printf("  e_res2[4]: 0x%04X\n", DOSHeader->e_res2[4]);
    printf("  e_res2[5]: 0x%04X\n", DOSHeader->e_res2[5]);
    printf("  e_res2[6]: 0x%04X\n", DOSHeader->e_res2[6]);
    printf("  e_res2[7]: 0x%04X\n", DOSHeader->e_res2[7]);
    printf("  e_res2[8]: 0x%04X\n", DOSHeader->e_res2[8]);
    printf("  e_res2[9]: 0x%04X\n", DOSHeader->e_res2[9]);
    printf("  e_lfanew: 0x%08lX\n", DOSHeader->e_lfanew);
}

void CrDumpFileHeader(LPVOID Data)
{
    PIMAGE_FILE_HEADER FileHeader = (PIMAGE_FILE_HEADER)Data;
    printf("\n### IMAGE_FILE_HEADER ###\n");
    printf("  Machine: 0x%04X (%s)\n", FileHeader->Machine, CrGetMachineString(FileHeader->Machine));
    printf("  NumberOfSections: 0x%04X (%u)\n", FileHeader->NumberOfSections, FileHeader->NumberOfSections);
    printf("  TimeDateStamp: 0x%08lX (%s)\n", FileHeader->TimeDateStamp, CrGetTimeStampString(FileHeader->TimeDateStamp));
    printf("  PointerToSymbolTable: 0x%08lX\n", FileHeader->PointerToSymbolTable);
    printf("  NumberOfSymbols: 0x%08lX (%lu)\n", FileHeader->NumberOfSymbols, FileHeader->NumberOfSymbols);
    printf("  SizeOfOptionalHeader: 0x%04X (%u)\n", FileHeader->SizeOfOptionalHeader, FileHeader->SizeOfOptionalHeader);
    printf("  Characteristics: 0x%04X (%s)\n", FileHeader->Characteristics, CrGetFileCharacteristicsString(FileHeader->Characteristics));
}

void CrDumpOptionalHeader32(LPVOID Data, DWORD CheckSum)
{
    DWORD i;
    PIMAGE_OPTIONAL_HEADER32 Optional32 = (PIMAGE_OPTIONAL_HEADER32)Data;
    PIMAGE_DATA_DIRECTORY DataDirectories, DataDirectory;

    printf("\n### IMAGE_OPTIONAL_HEADER32 ###\n");
    printf("  Magic: 0x%04X\n", Optional32->Magic);
    printf("  LinkerVersion: %u.%u\n", Optional32->MajorLinkerVersion, Optional32->MinorLinkerVersion);
    printf("  SizeOfCode: 0x%08lX (%lu)\n", Optional32->SizeOfCode, Optional32->SizeOfCode);
    printf("  SizeOfInitializedData: 0x%08lX (%lu)\n", Optional32->SizeOfInitializedData, Optional32->SizeOfInitializedData);
    printf("  SizeOfUninitializedData: 0x%08lX (%lu)\n", Optional32->SizeOfUninitializedData, Optional32->SizeOfUninitializedData);
    printf("  AddressOfEntryPoint: 0x%08lX\n", Optional32->AddressOfEntryPoint);
    printf("  BaseOfCode: 0x%08lX\n", Optional32->BaseOfCode);
    printf("  BaseOfData: 0x%08lX\n", Optional32->BaseOfData);
    printf("  ImageBase: 0x%08lX\n", Optional32->ImageBase);
    printf("  SectionAlignment: 0x%08lX\n", Optional32->SectionAlignment);
    printf("  FileAlignment: 0x%08lX\n", Optional32->FileAlignment);
    printf("  OperatingSystemVersion: %u.%u\n", Optional32->MajorOperatingSystemVersion, Optional32->MinorOperatingSystemVersion);
    printf("  ImageVersion: %u.%u\n", Optional32->MajorImageVersion, Optional32->MinorImageVersion);
    printf("  SubsystemVersion: %u.%u\n", Optional32->MajorSubsystemVersion, Optional32->MinorSubsystemVersion);
    printf("  Win32VersionValue: 0x%08lX\n", Optional32->Win32VersionValue);
    printf("  SizeOfImage: 0x%08lX (%lu)\n", Optional32->SizeOfImage, Optional32->SizeOfImage);
    printf("  SizeOfHeaders: 0x%08lX (%lu)\n", Optional32->SizeOfHeaders, Optional32->SizeOfHeaders);
#ifndef NO_CHECKSUM
    printf("  CheckSum: 0x%08lX (%s)\n", Optional32->CheckSum, (Optional32->CheckSum == 0 || Optional32->CheckSum == CheckSum ? "valid" : "invalid"));
#else
    printf("  CheckSum: 0x%08lX\n", Optional32->CheckSum);
#endif
    printf("  Subsystem: 0x%04X (%s)\n", Optional32->Subsystem, CrGetSubsystemString(Optional32->Subsystem));
    printf("  DllCharacteristics: 0x%04X (%s)\n", Optional32->DllCharacteristics, CrGetDllCharacteristicsString(Optional32->DllCharacteristics));
    printf("  SizeOfStackReserve: 0x%08lX (%lu)\n", Optional32->SizeOfStackReserve, Optional32->SizeOfStackReserve);
    printf("  SizeOfStackCommit: 0x%08lX (%lu)\n", Optional32->SizeOfStackCommit, Optional32->SizeOfStackCommit);
    printf("  SizeOfHeapReserve: 0x%08lX (%lu)\n", Optional32->SizeOfHeapReserve, Optional32->SizeOfHeapReserve);
    printf("  SizeOfHeapCommit: 0x%08lX (%lu)\n", Optional32->SizeOfHeapCommit, Optional32->SizeOfHeapCommit);
    printf("  LoaderFlags: 0x%08lX\n", Optional32->LoaderFlags);
    printf("  NumberOfRvaAndSizes: 0x%08lX (%lu)\n", Optional32->NumberOfRvaAndSizes, Optional32->NumberOfRvaAndSizes);

    printf("\n  ### Directory Entries ###\n");
    DataDirectories = Optional32->DataDirectory;
    for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        DataDirectory = &DataDirectories[i];
        if (DataDirectory->VirtualAddress != 0 || DataDirectory->Size != 0)
        {
            CrDumpDataDirectory(DataDirectory, i);
        }
    }
}

void CrDumpOptionalHeader64(LPVOID Data, DWORD CheckSum)
{
    DWORD i;
    PIMAGE_OPTIONAL_HEADER64 Optional64 = (PIMAGE_OPTIONAL_HEADER64)Data;
    PIMAGE_DATA_DIRECTORY DataDirectories, DataDirectory;

    printf("\n### IMAGE_OPTIONAL_HEADER64 ###\n");
    printf("  Magic: 0x%04X\n", Optional64->Magic);
    printf("  LinkerVersion: %u.%u\n", Optional64->MajorLinkerVersion, Optional64->MinorLinkerVersion);
    printf("  SizeOfCode: 0x%08lX (%lu)\n", Optional64->SizeOfCode, Optional64->SizeOfCode);
    printf("  SizeOfInitializedData: 0x%08lX (%lu)\n", Optional64->SizeOfInitializedData, Optional64->SizeOfInitializedData);
    printf("  SizeOfUninitializedData: 0x%08lX (%lu)\n", Optional64->SizeOfUninitializedData, Optional64->SizeOfUninitializedData);
    printf("  AddressOfEntryPoint: 0x%08lX\n", Optional64->AddressOfEntryPoint);
    printf("  BaseOfCode: 0x%08lX\n", Optional64->BaseOfCode);
    printf("  ImageBase: 0x%08lX%08lX\n", HILONG(Optional64->ImageBase), LOLONG(Optional64->ImageBase));
    printf("  SectionAlignment: 0x%08lX\n", Optional64->SectionAlignment);
    printf("  FileAlignment: 0x%08lX\n", Optional64->FileAlignment);
    printf("  OperatingSystemVersion: %u.%u\n", Optional64->MajorOperatingSystemVersion, Optional64->MinorOperatingSystemVersion);
    printf("  ImageVersion: %u.%u\n", Optional64->MajorImageVersion, Optional64->MinorImageVersion);
    printf("  SubsystemVersion: %u.%u\n", Optional64->MajorSubsystemVersion, Optional64->MinorSubsystemVersion);
    printf("  Win32VersionValue: 0x%08lX\n", Optional64->Win32VersionValue);
    printf("  SizeOfImage: 0x%08lX (%lu)\n", Optional64->SizeOfImage, Optional64->SizeOfImage);
    printf("  SizeOfHeaders: 0x%08lX (%lu)\n", Optional64->SizeOfHeaders, Optional64->SizeOfHeaders);
#ifndef NO_CHECKSUM
    printf("  CheckSum: 0x%08lX (%s)\n", Optional64->CheckSum, (Optional64->CheckSum == 0 || Optional64->CheckSum == CheckSum ? "valid" : "invalid"));
#else
    printf("  CheckSum: 0x%08lX\n", Optional64->CheckSum);
#endif
    printf("  Subsystem: 0x%04X (%s)\n", Optional64->Subsystem, CrGetSubsystemString(Optional64->Subsystem));
    printf("  DllCharacteristics: 0x%04X (%s)\n", Optional64->DllCharacteristics, CrGetDllCharacteristicsString(Optional64->DllCharacteristics));

    char a[64];
    _i64toa(Optional64->SizeOfStackReserve, a, 10);
    printf("  SizeOfStackReserve: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfStackReserve), LOLONG(Optional64->SizeOfStackReserve), a);
    _i64toa(Optional64->SizeOfStackCommit, a, 10);
    printf("  SizeOfStackCommit: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfStackCommit), LOLONG(Optional64->SizeOfStackCommit), a);
    _i64toa(Optional64->SizeOfHeapReserve, a, 10);
    printf("  SizeOfHeapReserve: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfHeapReserve), LOLONG(Optional64->SizeOfHeapReserve), a);
    _i64toa(Optional64->SizeOfHeapCommit, a, 10);
    printf("  SizeOfHeapCommit: 0x%08lX%08lX (%s)\n", HILONG(Optional64->SizeOfHeapCommit), LOLONG(Optional64->SizeOfHeapCommit), a);

    printf("  LoaderFlags: 0x%08lX\n", Optional64->LoaderFlags);
    printf("  NumberOfRvaAndSizes: 0x%08lX (%lu)\n", Optional64->NumberOfRvaAndSizes, Optional64->NumberOfRvaAndSizes);

    printf("\n  ### Directory Entries ###\n");
    DataDirectories = Optional64->DataDirectory;
    for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        DataDirectory = &DataDirectories[i];
        if (DataDirectory->VirtualAddress != 0 || DataDirectory->Size != 0)
        {
            CrDumpDataDirectory(DataDirectory, i);
        }
    }
}

void CrDumpSectionHeader(LPVOID Data)
{
    PREAL_IMAGE_SECTION_HEADER SectionHeader;
    DWORD i;

    SectionHeader = (PREAL_IMAGE_SECTION_HEADER)Data;
    printf("  Name: ");
    for (i = 0; i < 8 && SectionHeader->Name[i] != 0; i++)
        printf("%c", SectionHeader->Name[i]);
    printf("\n");

    printf("  VirtualSize: 0x%08lX (%lu)\n", SectionHeader->Misc.VirtualSize, SectionHeader->Misc.VirtualSize);
    printf("  RVA: 0x%08lX\n", SectionHeader->RVA);
    printf("  SizeOfRawData: 0x%08lX (%lu)\n", SectionHeader->SizeOfRawData, SectionHeader->SizeOfRawData);
    printf("  PointerToRawData: 0x%08lX\n", SectionHeader->PointerToRawData);
    printf("  PointerToRelocations: 0x%08lX\n", SectionHeader->PointerToRelocations);
    printf("  PointerToLinenumbers: 0x%08lX\n", SectionHeader->PointerToLinenumbers);
    printf("  NumberOfRelocations: 0x%08X (%u)\n", SectionHeader->NumberOfRelocations, SectionHeader->NumberOfRelocations);
    printf("  NumberOfLinenumbers: 0x%08X (%u)\n", SectionHeader->NumberOfLinenumbers, SectionHeader->NumberOfLinenumbers);
    printf("  Characteristics: 0x%08lX (%s)\n", SectionHeader->Characteristics, CrGetSectionFlagsString(SectionHeader->Characteristics));
}

void CrDumpCodes(const CR_Binary& codes, INT bits)
{
    std::size_t codesperline;

    if (bits == 64)
        codesperline = 16;
    else if (bits == 32)
        codesperline = 12;
    else
        codesperline = 9;

    std::size_t i;
    for (i = 0; i < codesperline; i++)
    {
        if (i < codes.size())
        {
            printf("%02X ", codes[i]);
        }
        else
            printf("   ");
    }

    for (; i < codes.size(); i++)
    {
        printf("%02X ", codes[i]);
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Module dumping

void CR_Module::DumpHeaders()
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
        CrDumpDOSHeader(DOSHeader());
    }
    if (FileHeader())
    {
        CrDumpFileHeader(FileHeader());
    }
    if (OptionalHeader32())
    {
        CrDumpOptionalHeader32(OptionalHeader32(), CheckSum());
    }
    else if (OptionalHeader64())
    {
        CrDumpOptionalHeader64(OptionalHeader64(), CheckSum());
    }
    if (SectionHeaders())
    {
        DWORD size = NumberOfSections();
        for (DWORD i = 0; i < size; i++)
        {
            printf("\n### Section #%lu ###\n", i);
            CrDumpSectionHeader(SectionHeader(i));
        }
    }
}

void CR_Module::DumpImportSymbols()
{
    PIMAGE_IMPORT_DESCRIPTOR descs;
    CR_StringSet dll_names;
    CR_DeqSet<CR_ImportSymbol> symbols;

    descs = ImportDescriptors();
    if (descs == NULL)
        return;

    printf("\n### IMPORTS ###\n");
    printf("  Characteristics: 0x%08lX\n", descs->Characteristics);
    printf("  TimeDateStamp: 0x%08lX (%s)\n", descs->TimeDateStamp,
        CrGetTimeStampString(descs->TimeDateStamp));
    printf("  ForwarderChain: 0x%08lX\n", descs->ForwarderChain);
    printf("  Name: 0x%08lX (%s)\n", descs->Name, reinterpret_cast<char *>(GetData(descs->Name)));
    printf("  \n");

    if (!_GetImportDllNames(dll_names))
        return;

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
                    CR_Addr64 addr = VA64FromRVA(symbols[j].dwRVA);
                    printf("    %08lX %08lX%08lX ", symbols[j].dwRVA,
                        HILONG(addr), LOLONG(addr));
                }
                else if (Is32Bit())
                {
                    CR_Addr32 addr = VA32FromRVA(symbols[j].dwRVA);
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

void CR_Module::DumpExportSymbols()
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
    printf("  TimeDateStamp: 0x%08lX (%s)\n", pDir->TimeDateStamp, CrGetTimeStampString(pDir->TimeDateStamp));
    printf("  Version: %u.%u\n", pDir->MajorVersion, pDir->MinorVersion);
    printf("  Name: 0x%08lX (%s)\n", pDir->Name, reinterpret_cast<char *>(GetData(pDir->Name)));
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
        CR_ExportSymbol& symbol = ExportSymbols()[i];
        if (symbol.dwRVA)
        {
            if (Is64Bit())
            {
                CR_Addr64 va = VA64FromRVA(symbol.dwRVA);
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
                CR_Addr32 va = VA32FromRVA(symbol.dwRVA);
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

void CR_Module::DumpDelayLoad()
{
    if (DelayLoadDescriptors().empty())
    {
        LoadDelayLoad();
        if (DelayLoadDescriptors().empty())
            return;
    }

    printf("### DELAY LOAD ###\n");
    const std::size_t size = DelayLoadDescriptors().size();
    DWORD rva;
    if (Is64Bit())
    {
        CR_Addr64 addr;
        for (std::size_t i = 0; i < size; i++)
        {
            printf("  ### Descr #%u ###\n", static_cast<int>(i));
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

            const char *pszTime = CrGetTimeStampString(DelayLoadDescriptors()[i].dwTimeStamp);
            printf("    dwTimeStamp:  0x%08lX (%s)",
                DelayLoadDescriptors()[i].dwTimeStamp, pszTime);
        }
    }
    else if (Is32Bit())
    {
        CR_Addr32 addr;
        for (std::size_t i = 0; i < size; i++)
        {
            printf("  ### Descr #%u ###\n", static_cast<int>(i));
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

            const char *pszTime = CrGetTimeStampString(DelayLoadDescriptors()[i].dwTimeStamp);
            printf("    dwTimeStamp:  0x%08lX (%s)",
                DelayLoadDescriptors()[i].dwTimeStamp, pszTime);
        }
    }

    printf("\n\n");
}

////////////////////////////////////////////////////////////////////////////
// CR_Module::DumpDisAsm32

BOOL CR_Module::DumpDisAsm32(CR_DecompStatus32& status)
{
    printf("### DISASSEMBLY ###\n\n");

    status.Entrances().sort();
    status.Entrances().unique();
    const std::size_t size = status.Entrances().size();
    for (std::size_t i = 0; i < size; i++)
    {
        const CR_CodeFunc32& cf = status.MapAddrToCodeFunc()[status.Entrances()[i]];
        if (cf.Flags() & FF_IGNORE)
            continue;

        const char *pszName = GetSymbolNameFromAddr32(cf.Addr());
        if (pszName)
            printf(";; Function %s @ L%08lX\n", pszName, cf.Addr());
        else
            printf(";; Function L%08lX\n", cf.Addr());

        switch (cf.FuncType())
        {
        case FT_JUMPERFUNC:
            printf("ft = FT_JUMPERFUNC, ");
            break;

        case FT_CDECL:
            printf("ft = FT_CDECL, ");
            break;

        case FT_STDCALL:
            printf("ft = FT_STDCALL, ");
            break;

        case FT_FASTCALL:
            printf("ft = FT_FASTCALL, ");
            break;

        default:
            printf("ft = FT_UNKNOWN, ");
            break;
        }
        printf("SizeOfStackArgs == %d\n", cf.SizeOfStackArgs());
        DumpDisAsmFunc32(status, status.Entrances()[i]);

        if (pszName)
            printf(";; End of Function %s @ L%08lX\n\n", pszName, cf.Addr());
        else
            printf(";; End of Function L%08lX\n\n", cf.Addr());
    }
    return TRUE;
}

BOOL CR_Module::DumpDisAsmFunc32(CR_DecompStatus32& status, CR_Addr32 func)
{
    auto end = status.MapAddrToAsmCode().end();
    for (auto it = status.MapAddrToAsmCode().begin(); it != end; it++)
    {
        const CR_CodeInsn32& ac = it->second;

        if (func != 0 && !ac.FuncAddrs().Contains(func))
            continue;

        printf("L%08lX: ", ac.Addr());

        CrDumpCodes(ac.Codes(), 32);

        switch (ac.Operands().size())
        {
        case 3:
            printf("%s %s,%s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str(),
                ac.Operand(2)->Text().c_str());
            break;

        case 2:
            printf("%s %s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str());
            break;

        case 1:
            printf("%s %s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str());
            break;

        case 0:
            printf("%s\n", ac.Name().c_str());
            break;
        }
    }

    return TRUE;
}

////////////////////////////////////////////////////////////////////////////
// CR_Module::DumpDisAsm64

BOOL CR_Module::DumpDisAsm64(CR_DecompStatus64& status)
{
    printf("### DISASSEMBLY ###\n\n");

    status.Entrances().sort();
    status.Entrances().unique();
    const std::size_t size = status.Entrances().size();
    for (std::size_t i = 0; i < size; i++)
    {
        const CR_CodeFunc64& cf = status.MapAddrToCodeFunc()[status.Entrances()[i]];
        if (cf.Flags() & FF_IGNORE)
            continue;

        const char *pszName = GetSymbolNameFromAddr64(cf.Addr());
        if (pszName)
            printf(";; Function %s @ L%08lX%08lX\n", pszName,
                HILONG(cf.Addr()), LOLONG(cf.Addr()));
        else
            printf(";; Function L%08lX%08lX\n", HILONG(cf.Addr()), LOLONG(cf.Addr()));
        if (cf.FuncType() == FT_JUMPERFUNC)
        {
            printf("ft = FT_JUMPERFUNC, ");
        }
        else
        {
            printf("ft = FT_64BITFUNC, ");
        }
        printf("SizeOfStackArgs == %d\n", cf.SizeOfStackArgs());
        DumpDisAsmFunc64(status, status.Entrances()[i]);

        if (pszName)
            printf(";; End of Function %s @ L%08lX%08lX\n\n", pszName,
                HILONG(cf.Addr()), LOLONG(cf.Addr()));
        else
            printf(";; End of Function L%08lX%08lX\n\n",
                HILONG(cf.Addr()), LOLONG(cf.Addr()));
    }
    return TRUE;
}

BOOL CR_Module::DumpDisAsmFunc64(CR_DecompStatus64& status, CR_Addr64 func)
{
    auto end = status.MapAddrToAsmCode().end();
    for (auto it = status.MapAddrToAsmCode().begin(); it != end; it++)
    {
        const CR_CodeInsn64& ac = it->second;

        if (func != 0 && !ac.FuncAddrs().Contains(func))
            continue;

        printf("L%08lX%08lX: ", HILONG(ac.Addr()), LOLONG(ac.Addr()));

        CrDumpCodes(ac.Codes(), 64);

        switch (ac.Operands().size())
        {
        case 3:
            printf("%s %s,%s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str(),
                ac.Operand(2)->Text().c_str());
            break;

        case 2:
            printf("%s %s,%s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str(), ac.Operand(1)->Text().c_str());
            break;

        case 1:
            printf("%s %s\n", ac.Name().c_str(),
                ac.Operand(0)->Text().c_str());
            break;

        case 0:
            printf("%s\n", ac.Name().c_str());
            break;
        }
    }

    return TRUE;
}
