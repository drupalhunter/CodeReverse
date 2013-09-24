/*
 * snprintf()
 *
 * Implement snprintf() in terms of vsnprintf()
 */

#define _CRT_SECURE_NO_WARNINGS

#include "..\compiler.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "..\nasmlib.h"

int snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int rv;

    va_start(ap, format);
    rv = vsnprintf(str, size, format, ap);
    va_end(ap);

    return rv;
}
