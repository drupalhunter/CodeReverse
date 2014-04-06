////////////////////////////////////////////////////////////////////////////
// stdafx.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
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
