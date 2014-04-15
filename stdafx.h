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

#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <cassert>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <stack>
#include <algorithm>
#include <cstdint>
using namespace std;

#include "CodeReverse.h"
#include "Module.h"
#include "mzc2mini.h"
#include "Contents.h"

#if !defined(NO_CHECKSUM) && defined(_MSC_VER)
    #pragma comment(lib, "imagehlp.lib")
#endif
