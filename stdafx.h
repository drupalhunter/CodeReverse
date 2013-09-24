#define NO_CHECKSUM    /* Don't check the checksum */
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <algorithm>
#include <stdint.h>
using namespace std;

#include "codereverse.h"
#include "module.h"

#ifndef NO_CHECKSUM
    #pragma comment(lib, "imagehlp.lib")
#endif
