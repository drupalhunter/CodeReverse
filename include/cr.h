////////////////////////////////////////////////////////////////////////////
// cr.h - the CodeReverse header file for decompilation
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
// CodeReverse primitive types

typedef INT         XINT;
typedef CHAR        XCHAR;
typedef SHORT       XSHORT;
typedef LONG        XLONG;
typedef INT_PTR     XINT_PTR;
typedef LONG_PTR    XLONG_PTR;

typedef INT_PTR     INTEGER;
typedef UINT_PTR    UINTEGER;
typedef XINT_PTR    XINTEGER;

typedef signed      SIGNED;
typedef unsigned    UNSIGNED;
typedef signed      XSIGNED;

////////////////////////////////////////////////////////////////////////////
// LOLONG, HILONG, MAKELONGLONG

#ifndef LOLONG
    #define LOLONG(dwl) ((DWORD)(dwl))
#endif
#ifndef HILONG
    #define HILONG(dwl) ((DWORD)(((dwl) >> 32) & 0xFFFFFFFF))
#endif
#ifndef MAKELONGLONG
    #define MAKELONGLONG(lo,hi) (((DWORDLONG)(hi) << 32) | (DWORD)(lo))
#endif

////////////////////////////////////////////////////////////////////////////
