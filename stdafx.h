////////////////////////////////////////////////////////////////////////////
// stdafx.h
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

//#define NO_CHECKSUM    /* Don't check the checksum */
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>
#include <delayimp.h>   // ImgDelayDescr
#include <imagehlp.h>   // CheckSumMappedFile

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <stack>
#include <algorithm>
#include <stdint.h>
using namespace std;

#include "codereverse.h"
#include "module.h"
#include "mzc2mini.h"

#if !defined(NO_CHECKSUM) && defined(_MSC_VER)
    #pragma comment(lib, "imagehlp.lib")
#endif
