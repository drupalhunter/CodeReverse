////////////////////////////////////////////////////////////////////////////
// cr.h - the CodeReverse header file for decompilation
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
