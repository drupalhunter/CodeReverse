/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 2013 Katayama Hirofumi MZ.  All rights reserved.
 *   Copyright 1996-2009 The NASM Authors - All Rights Reserved
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following
 *   conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *     
 *     THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 *     CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *     INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *     MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *     DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 *     CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *     SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *     NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *     LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *     HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *     CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *     OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 *     EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ----------------------------------------------------------------------- */

/*
 * h-ndisasm.c   Hacked NDISASM main module
 */

#include "compiler.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include "pri.h"

#include "insns.h"
#include "nasm.h"
#include "nasmlib.h"
#include "disasm.h"

#define BPL 11            /* bytes per line of hex dump */

void output_ins32(uint32_t offset, uint8_t *data,
                  int datalen, char *insn)
{
    int bytes;
    fprintf(stdout, "%08"PRIX32": ", offset);

    bytes = 0;
    while (datalen > 0 && bytes < BPL) {
        fprintf(stdout, "%02X", *data++);
        bytes++;
        datalen--;
    }

    fprintf(stdout, "%*s%s\n", (BPL + 1 - bytes) * 2, "", insn);

    while (datalen > 0) {
        fprintf(stdout, "         -");
        bytes = 0;
        while (datalen > 0 && bytes < BPL) {
            fprintf(stdout, "%02X", *data++);
            bytes++;
            datalen--;
        }
        fprintf(stdout, "\n");
    }
}

void output_ins64(uint64_t offset, uint8_t *data,
                  int datalen, char *insn)
{
    int bytes;
    fprintf(stdout, "%016"PRIX64": ", offset);

    bytes = 0;
    while (datalen > 0 && bytes < BPL) {
        fprintf(stdout, "%02X", *data++);
        bytes++;
        datalen--;
    }

    fprintf(stdout, "%*s%s\n", (BPL + 1 - bytes) * 2, "", insn);

    while (datalen > 0) {
        fprintf(stdout, "         -");
        bytes = 0;
        while (datalen > 0 && bytes < BPL) {
            fprintf(stdout, "%02X", *data++);
            bytes++;
            datalen--;
        }
        fprintf(stdout, "\n");
    }
}

void
do_disasm32(void *input, uint32_t size, int offset)
{
    int32_t lendis;
    char *p = (char *)input, *end = (char *)input + size;
    char outbuf[256];

    while (p < end)
    {
        lendis = disasm((uint8_t *) p, outbuf, sizeof(outbuf), 32,
                        offset, false, 0);

        if (!lendis || p + lendis > end)
            lendis = eatbyte((uint8_t *) p, outbuf, sizeof(outbuf), 32);

        output_ins32(offset, (uint8_t *) p, lendis, outbuf);

        p += lendis;
        offset += lendis;
    }
}

void
do_disasm64(void *input, uint32_t size, uint64_t offset)
{
    int32_t lendis;
    char *p = (char *)input, *end = (char *)input + size;
    char outbuf[256];

    while (p < end)
    {
        lendis = disasm((uint8_t *) p, outbuf, sizeof(outbuf), 64,
                        offset, false, 0);

        if (!lendis || p + lendis > end)
            lendis = eatbyte((uint8_t *) p, outbuf, sizeof(outbuf), 64);

        output_ins64(offset, (uint8_t *) p, lendis, outbuf);

        p += lendis;
        offset += lendis;
    }
}

#if 0
char buffer[0x10000];

int main(int argc, char **argv)
{
    FILE *fp;
    int lenread;
    int bits;
    int32_t offset;

    if (argc != 2)
    {
        fprintf(stderr, "invalid arguments\n");
    }

    tolower_init();
    nasm_init_malloc_error();

    bits = 32;
    offset = 0x100;

    fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        fprintf(stderr, "Cannot read %s file.\n", argv[1]);
        return 1;
    }
    lenread = fread(buffer, 1, 0x10000, fp);
    fclose(fp);

    do_disasm32(buffer, lenread, bits, offset);

    return 0;
}
#endif
