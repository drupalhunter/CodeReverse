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
#include <delayimp.h>       // ImgDelayDescr
#include <imagehlp.h>       // CheckSumMappedFile

#include <cstdlib>          // standard library
#include <cstdio>           // standard IO
#include <cstring>          // C string
#include <cassert>          // for assert
#include <ctime>            // for std::time_t, std::asctime, std::gmtime
#include <cstdint>

#include <vector>           // for std::vector
#include <string>           // for std::string
#include <set>              // for std::set
#include <map>              // for std::map
#include <unordered_map>    // for std::unordered_map
#include <stack>            // for std::stack
#include <deque>            // for std::deque
#include <algorithm>        // for std::sort, std::unique

#include <memory>
using std::shared_ptr;
using std::dynamic_pointer_cast;
using std::static_pointer_cast;
using std::make_shared;

#include "Location.h"       // CR_Location
#include "CodeReverse.h"
#include "TypeSystem.h"
#include "Coding.h"
#include "Module.h"
#include "mzc2mini.h"

#if !defined(NO_CHECKSUM) && defined(_MSC_VER)
    #pragma comment(lib, "imagehlp.lib")
#endif
