/* ----------------------------------------------------------------------- *
 *   
 *   Copyright 1996-2012 The NASM Authors - All Rights Reserved
 *   See the file AUTHORS included with the NASM distribution for
 *   the specific copyright holders.
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
 * nasm.h   main header file for the Netwide Assembler: inter-module interface
 */

#ifndef NASM_NASM_H
#define NASM_NASM_H

#include "compiler.h"

#include <stdio.h>
#include <stdint.h>
#include "nasmlib.h"
#include "insnsi.h"     /* For enum opcode */
#include "opflags.h"
#include "regs.h"

#define NO_SEG -1L              /* null segment value */
#define SEG_ABS 0x40000000L     /* mask for far-absolute segments */

#ifndef FILENAME_MAX
#define FILENAME_MAX 256
#endif

#ifndef PREFIX_MAX
#define PREFIX_MAX 10
#endif

#ifndef POSTFIX_MAX
#define POSTFIX_MAX 10
#endif

#define IDLEN_MAX 4096

/*
 * Name pollution problems: <time.h> on Digital UNIX pulls in some
 * strange hardware header file which sees fit to define R_SP. We
 * undefine it here so as not to break the enum below.
 */
#ifdef R_SP
#undef R_SP
#endif

/*
 * We must declare the existence of this structure type up here,
 * since we have to reference it before we define it...
 */
struct ofmt;

/*
 * Values for the `type' parameter to an output function.
 *
 * Exceptions are OUT_RELxADR, which denote an x-byte relocation
 * which will be a relative jump. For this we need to know the
 * distance in bytes from the start of the relocated record until
 * the end of the containing instruction. _This_ is what is stored
 * in the size part of the parameter, in this case.
 *
 * Also OUT_RESERVE denotes reservation of N bytes of BSS space,
 * and the contents of the "data" parameter is irrelevant.
 *
 * The "data" parameter for the output function points to a "int32_t",
 * containing the address in question, unless the type is
 * OUT_RAWDATA, in which case it points to an "uint8_t"
 * array.
 */
enum out_type {
    OUT_RAWDATA,    /* Plain bytes */
    OUT_ADDRESS,    /* An address (symbol value) */
    OUT_RESERVE,    /* Reserved bytes (RESB et al) */
    OUT_REL1ADR,    /* 1-byte relative address */
    OUT_REL2ADR,    /* 2-byte relative address */
    OUT_REL4ADR,    /* 4-byte relative address */
    OUT_REL8ADR     /* 8-byte relative address */
};

/*
 * A label-lookup function.
 */
typedef bool (*lfunc)(char *label, int32_t *segment, int64_t *offset);

/*
 * And a label-definition function. The boolean parameter
 * `is_norm' states whether the label is a `normal' label (which
 * should affect the local-label system), or something odder like
 * an EQU or a segment-base symbol, which shouldn't.
 */
typedef void (*ldfunc)(char *label, int32_t segment, int64_t offset,
                       char *special, bool is_norm, bool isextrn);

void define_label(char *label, int32_t segment, int64_t offset,
                  char *special, bool is_norm, bool isextrn);

/*
 * List-file generators should look like this:
 */
typedef struct {
    /*
     * Called to initialize the listing file generator. Before this
     * is called, the other routines will silently do nothing when
     * called. The `char *' parameter is the file name to write the
     * listing to.
     */
    void (*init)(char *fname, efunc error);

    /*
     * Called to clear stuff up and close the listing file.
     */
    void (*cleanup)(void);

    /*
     * Called to output binary data. Parameters are: the offset;
     * the data; the data type. Data types are similar to the
     * output-format interface, only OUT_ADDRESS will _always_ be
     * displayed as if it's relocatable, so ensure that any non-
     * relocatable address has been converted to OUT_RAWDATA by
     * then. Note that OUT_RAWDATA,0 is a valid data type, and is a
     * dummy call used to give the listing generator an offset to
     * work with when doing things like uplevel(LIST_TIMES) or
     * uplevel(LIST_INCBIN).
     */
    void (*output)(int32_t offset, const void *data, enum out_type type, uint64_t size);

    /*
     * Called to send a text line to the listing generator. The
     * `int' parameter is LIST_READ or LIST_MACRO depending on
     * whether the line came directly from an input file or is the
     * result of a multi-line macro expansion.
     */
    void (*line)(int type, char *line);

    /*
     * Called to change one of the various levelled mechanisms in
     * the listing generator. LIST_INCLUDE and LIST_MACRO can be
     * used to increase the nesting level of include files and
     * macro expansions; LIST_TIMES and LIST_INCBIN switch on the
     * two binary-output-suppression mechanisms for large-scale
     * pseudo-instructions.
     *
     * LIST_MACRO_NOLIST is synonymous with LIST_MACRO except that
     * it indicates the beginning of the expansion of a `nolist'
     * macro, so anything under that level won't be expanded unless
     * it includes another file.
     */
    void (*uplevel)(int type);

    /*
     * Reverse the effects of uplevel.
     */
    void (*downlevel)(int type);

    /*
     * Called on a warning or error, with the error message.
     */
    void (*error)(int severity, const char *pfx, const char *msg);
} ListGen;

/*
 * Token types returned by the scanner, in addition to ordinary
 * ASCII character values, and zero for end-of-string.
 */
enum token_type { /* token types, other than chars */
    TOKEN_INVALID = -1, /* a placeholder value */
    TOKEN_EOS = 0,      /* end of string */
    TOKEN_EQ = '=',
    TOKEN_GT = '>',
    TOKEN_LT = '<',     /* aliases */
    TOKEN_ID = 256,     /* identifier */
    TOKEN_NUM,          /* numeric constant */
    TOKEN_ERRNUM,       /* malformed numeric constant */
    TOKEN_STR,          /* string constant */
    TOKEN_ERRSTR,       /* unterminated string constant */
    TOKEN_FLOAT,        /* floating-point constant */
    TOKEN_REG,          /* register name */
    TOKEN_INSN,         /* instruction name */
    TOKEN_HERE,         /* $ */
    TOKEN_BASE,         /* $$ */
    TOKEN_SPECIAL,      /* BYTE, WORD, DWORD, QWORD, FAR, NEAR, etc */
    TOKEN_PREFIX,       /* A32, O16, LOCK, REPNZ, TIMES, etc */
    TOKEN_SHL,          /* << */
    TOKEN_SHR,          /* >> */
    TOKEN_SDIV,         /* // */
    TOKEN_SMOD,         /* %% */
    TOKEN_GE,           /* >= */
    TOKEN_LE,           /* <= */
    TOKEN_NE,           /* <> (!= is same as <>) */
    TOKEN_DBL_AND,      /* && */
    TOKEN_DBL_OR,       /* || */
    TOKEN_DBL_XOR,      /* ^^ */
    TOKEN_SEG,          /* SEG */
    TOKEN_WRT,          /* WRT */
    TOKEN_FLOATIZE,     /* __floatX__ */
    TOKEN_STRFUNC,      /* __utf16*__, __utf32*__ */
    TOKEN_IFUNC         /* __ilog2*__ */
};

enum floatize {
    FLOAT_8,
    FLOAT_16,
    FLOAT_32,
    FLOAT_64,
    FLOAT_80M,
    FLOAT_80E,
    FLOAT_128L,
    FLOAT_128H
};

/* Must match the list in string_transform(), in strfunc.c */
enum strfunc {
    STRFUNC_UTF16,
    STRFUNC_UTF16LE,
    STRFUNC_UTF16BE,
    STRFUNC_UTF32,
    STRFUNC_UTF32LE,
    STRFUNC_UTF32BE
};

enum ifunc {
    IFUNC_ILOG2E,
    IFUNC_ILOG2W,
    IFUNC_ILOG2F,
    IFUNC_ILOG2C
};

size_t string_transform(char *, size_t, char **, enum strfunc);

/*
 * The expression evaluator must be passed a scanner function; a
 * standard scanner is provided as part of nasmlib.c. The
 * preprocessor will use a different one. Scanners, and the
 * token-value structures they return, look like this.
 *
 * The return value from the scanner is always a copy of the
 * `t_type' field in the structure.
 */
struct tokenval {
    char                *t_charptr;
    int64_t             t_integer;
    int64_t             t_inttwo;
    enum token_type     t_type;
};
typedef int (*scanner)(void *private_data, struct tokenval *tv);

struct location {
    int64_t offset;
    int32_t segment;
    int     known;
};

/*
 * Expression-evaluator datatype. Expressions, within the
 * evaluator, are stored as an array of these beasts, terminated by
 * a record with type==0. Mostly, it's a vector type: each type
 * denotes some kind of a component, and the value denotes the
 * multiple of that component present in the expression. The
 * exception is the WRT type, whose `value' field denotes the
 * segment to which the expression is relative. These segments will
 * be segment-base types, i.e. either odd segment values or SEG_ABS
 * types. So it is still valid to assume that anything with a
 * `value' field of zero is insignificant.
 */
typedef struct {
    int32_t type;                  /* a register, or EXPR_xxx */
    int64_t value;                 /* must be >= 32 bits */
} expr;

/*
 * Library routines to manipulate expression data types.
 */
int is_reloc(expr *vect);
int is_simple(expr *vect);
int is_really_simple(expr *vect);
int is_unknown(expr *vect);
int is_just_unknown(expr *vect);
int64_t reloc_value(expr *vect);
int32_t reloc_seg(expr *vect);
int32_t reloc_wrt(expr *vect);

/*
 * The evaluator can also return hints about which of two registers
 * used in an expression should be the base register. See also the
 * `operand' structure.
 */
struct eval_hints {
    int64_t base;
    int     type;
};

/*
 * The actual expression evaluator function looks like this. When
 * called, it expects the first token of its expression to already
 * be in `*tv'; if it is not, set tv->t_type to TOKEN_INVALID and
 * it will start by calling the scanner.
 *
 * If a forward reference happens during evaluation, the evaluator
 * must set `*fwref' to true if `fwref' is non-NULL.
 *
 * `critical' is non-zero if the expression may not contain forward
 * references. The evaluator will report its own error if this
 * occurs; if `critical' is 1, the error will be "symbol not
 * defined before use", whereas if `critical' is 2, the error will
 * be "symbol undefined".
 *
 * If `critical' has bit 8 set (in addition to its main value: 0x101
 * and 0x102 correspond to 1 and 2) then an extended expression
 * syntax is recognised, in which relational operators such as =, <
 * and >= are accepted, as well as low-precedence logical operators
 * &&, ^^ and ||.
 *
 * If `hints' is non-NULL, it gets filled in with some hints as to
 * the base register in complex effective addresses.
 */
#define CRITICAL 0x100
typedef expr *(*evalfunc)(scanner sc, void *scprivate,
                          struct tokenval *tv, int *fwref, int critical,
                          efunc error, struct eval_hints *hints);

/*
 * Special values for expr->type.
 * These come after EXPR_REG_END as defined in regs.h.
 */
#define EXPR_UNKNOWN    (EXPR_REG_END+1) /* forward references */
#define EXPR_SIMPLE     (EXPR_REG_END+2)
#define EXPR_WRT        (EXPR_REG_END+3)
#define EXPR_SEGBASE    (EXPR_REG_END+4)

/*
 * Linked list of strings
 */
typedef struct string_list {
    struct string_list  *next;
    char                str[1];
} StrList;

/*
 * Some lexical properties of the NASM source language, included
 * here because they are shared between the parser and preprocessor.
 */

/*
 * isidstart matches any character that may start an identifier, and isidchar
 * matches any character that may appear at places other than the start of an
 * identifier. E.g. a period may only appear at the start of an identifier
 * (for local labels), whereas a number may appear anywhere *but* at the
 * start.
 */

#define isidstart(c) (nasm_isalpha(c)   ||  \
                      (c) == '_'        ||  \
                      (c) == '.'        ||  \
                      (c) == '?'        ||  \
                      (c) == '@')

#define isidchar(c) (isidstart(c)       ||  \
                     nasm_isdigit(c)    ||  \
                     (c) == '$'         ||  \
                     (c) == '#'         ||  \
                     (c) == '~')

/* Ditto for numeric constants. */

#define isnumstart(c)  (nasm_isdigit(c) || (c) == '$')
#define isnumchar(c)   (nasm_isalnum(c) || (c) == '_')

/*
 * Data-type flags that get passed to listing-file routines.
 */
enum {
    LIST_READ,
    LIST_MACRO,
    LIST_MACRO_NOLIST,
    LIST_INCLUDE,
    LIST_INCBIN,
    LIST_TIMES
};

/*
 * -----------------------------------------------------------
 * Format of the `insn' structure returned from `parser.c' and
 * passed into `assemble.c'
 * -----------------------------------------------------------
 */

/* Verify value to be a valid register */
bool is_register(int reg);

enum ccode { /* condition code names */
    C_A, C_AE, C_B, C_BE, C_C, C_E, C_G, C_GE, C_L, C_LE, C_NA, C_NAE,
    C_NB, C_NBE, C_NC, C_NE, C_NG, C_NGE, C_NL, C_NLE, C_NO, C_NP,
    C_NS, C_NZ, C_O, C_P, C_PE, C_PO, C_S, C_Z,
    C_none = -1
};

/*
 * REX flags
 */
#define REX_REAL    0x4f    /* Actual REX prefix bits */
#define REX_B       0x01    /* ModRM r/m extension */
#define REX_X       0x02    /* SIB index extension */
#define REX_R       0x04    /* ModRM reg extension */
#define REX_W       0x08    /* 64-bit operand size */
#define REX_L       0x20    /* Use LOCK prefix instead of REX.R */
#define REX_P       0x40    /* REX prefix present/required */
#define REX_H       0x80    /* High register present, REX forbidden */
#define REX_V       0x0100  /* Instruction uses VEX/XOP instead of REX */
#define REX_NH      0x0200  /* Instruction which doesn't use high regs */

/*
 * REX_V "classes" (prefixes which behave like VEX)
 */
enum vex_class {
    RV_VEX      = 0,    /* C4/C5 */
    RV_XOP      = 1     /* 8F */
};

/*
 * Note that because segment registers may be used as instruction
 * prefixes, we must ensure the enumerations for prefixes and
 * register names do not overlap.
 */
enum prefixes { /* instruction prefixes */
    P_none = 0,
    PREFIX_ENUM_START = REG_ENUM_LIMIT,
    P_A16 = PREFIX_ENUM_START, P_A32, P_A64, P_ASP,
    P_LOCK, P_O16, P_O32, P_O64, P_OSP,
    P_REP, P_REPE, P_REPNE, P_REPNZ, P_REPZ, P_TIMES,
    P_WAIT, P_XACQUIRE, P_XRELEASE,
    PREFIX_ENUM_LIMIT
};

enum extop_type { /* extended operand types */
    EOT_NOTHING,
    EOT_DB_STRING,      /* Byte string */
    EOT_DB_STRING_FREE, /* Byte string which should be nasm_free'd*/
    EOT_DB_NUMBER       /* Integer */
};

enum ea_flags { /* special EA flags */
    EAF_BYTEOFFS    =  1,   /* force offset part to byte size */
    EAF_WORDOFFS    =  2,   /* force offset part to [d]word size */
    EAF_TIMESTWO    =  4,   /* really do EAX*2 not EAX+EAX */
    EAF_REL         =  8,   /* IP-relative addressing */
    EAF_ABS         = 16,   /* non-IP-relative addressing */
    EAF_FSGS        = 32    /* fs/gs segment override present */
};

enum eval_hint { /* values for `hinttype' */
    EAH_NOHINT   = 0,       /* no hint at all - our discretion */
    EAH_MAKEBASE = 1,       /* try to make given reg the base */
    EAH_NOTBASE  = 2        /* try _not_ to make reg the base */
};

typedef struct operand { /* operand to an instruction */
    opflags_t       type;       /* type of operand */
    int             disp_size;  /* 0 means default; 16; 32; 64 */
    enum reg_enum   basereg;
    enum reg_enum   indexreg;   /* address registers */
    int             scale;      /* index scale */
    int             hintbase;
    enum eval_hint  hinttype;   /* hint as to real base register */
    int32_t         segment;    /* immediate segment, if needed */
    int64_t         offset;     /* any immediate number */
    int32_t         wrt;        /* segment base it's relative to */
    int             eaflags;    /* special EA flags */
    int             opflags;    /* see OPFLAG_* defines below */
} operand;

#define OPFLAG_FORWARD      1   /* operand is a forward reference */
#define OPFLAG_EXTERN       2   /* operand is an external reference */
#define OPFLAG_UNKNOWN      4   /* operand is an unknown reference 
                                 * (always a forward reference also)
                                 */

typedef struct extop { /* extended operand */
    struct extop    *next;      /* linked list */
    char            *stringval; /* if it's a string, then here it is */
    size_t          stringlen;  /* ... and here's how long it is */
    int64_t         offset;     /* ... it's given here ... */
    int32_t         segment;    /* if it's a number/address, then... */
    int32_t         wrt;        /* ... and here */
    enum extop_type type;       /* defined above */
} extop;

enum ea_type {
    EA_INVALID,     /* Not a valid EA at all */
    EA_SCALAR,      /* Scalar EA */
    EA_XMMVSIB,     /* XMM vector EA */
    EA_YMMVSIB      /* XMM vector EA */
};

/*
 * Prefix positions: each type of prefix goes in a specific slot.
 * This affects the final ordering of the assembled output, which
 * shouldn't matter to the processor, but if you have stylistic
 * preferences, you can change this.  REX prefixes are handled
 * differently for the time being.
 *
 * LOCK and REP used to be one slot; this is no longer the case since
 * the introduction of HLE.
 */
enum prefix_pos {
    PPS_WAIT,   /* WAIT (technically not a prefix!) */
    PPS_REP,    /* REP/HLE prefix */
    PPS_LOCK,   /* LOCK prefix */
    PPS_SEG,    /* Segment override prefix */
    PPS_OSIZE,  /* Operand size prefix */
    PPS_ASIZE,  /* Address size prefix */
    MAXPREFIX   /* Total number of prefix slots */
};

/* If you need to change this, also change it in insns.pl */
#define MAX_OPERANDS 5

typedef struct insn { /* an instruction itself */
    char            *label;                 /* the label defined, or NULL */
    int             prefixes[MAXPREFIX];    /* instruction prefixes, if any */
    enum opcode     opcode;                 /* the opcode - not just the string */
    enum ccode      condition;              /* the condition code, if Jcc/SETcc */
    int             operands;               /* how many operands? 0-3 (more if db et al) */
    int             addr_size;              /* address size */
    operand         oprs[MAX_OPERANDS];     /* the operands, defined as above */
    extop           *eops;                  /* extended operands */
    int             eops_float;             /* true if DD and floating */
    int32_t         times;                  /* repeat count (TIMES prefix) */
    bool            forw_ref;               /* is there a forward reference? */
    int             rex;                    /* Special REX Prefix */
    int             vexreg;                 /* Register encoded in VEX prefix */
    int             vex_cm;                 /* Class and M field for VEX prefix */
    int             vex_wlp;                /* W, P and L information for VEX prefix */
} insn;

enum geninfo { GI_SWITCH };

/*
 * ------------------------------------------------------------
 * The data structure defining a debug format driver, and the
 * interfaces to the functions therein.
 * ------------------------------------------------------------
 */

struct dfmt {
    /*
     * This is a short (one-liner) description of the type of
     * output generated by the driver.
     */
    const char *fullname;

    /*
     * This is a single keyword used to select the driver.
     */
    const char *shortname;

    /*
     * init - called initially to set up local pointer to object format.
     */
    void (*init)(void);

    /*
     * linenum - called any time there is output with a change of
     * line number or file.
     */
    void (*linenum)(const char *filename, int32_t linenumber, int32_t segto);

    /*
     * debug_deflabel - called whenever a label is defined. Parameters
     * are the same as to 'symdef()' in the output format. This function
     * would be called before the output format version.
     */

    void (*debug_deflabel)(char *name, int32_t segment, int64_t offset,
                           int is_global, char *special);
    /*
     * debug_directive - called whenever a DEBUG directive other than 'LINE'
     * is encountered. 'directive' contains the first parameter to the
     * DEBUG directive, and params contains the rest. For example,
     * 'DEBUG VAR _somevar:int' would translate to a call to this
     * function with 'directive' equal to "VAR" and 'params' equal to
     * "_somevar:int".
     */
    void (*debug_directive)(const char *directive, const char *params);

    /*
     * typevalue - called whenever the assembler wishes to register a type
     * for the last defined label.  This routine MUST detect if a type was
     * already registered and not re-register it.
     */
    void (*debug_typevalue)(int32_t type);

    /*
     * debug_output - called whenever output is required
     * 'type' is the type of info required, and this is format-specific
     */
    void (*debug_output)(int type, void *param);

    /*
     * cleanup - called after processing of file is complete
     */
    void (*cleanup)(void);
};

extern const struct dfmt *dfmt;

/*
 * The type definition macros
 * for debugging
 *
 * low 3 bits: reserved
 * next 5 bits: type
 * next 24 bits: number of elements for arrays (0 for labels)
 */

#define TY_UNKNOWN 0x00
#define TY_LABEL   0x08
#define TY_BYTE    0x10
#define TY_WORD    0x18
#define TY_DWORD   0x20
#define TY_FLOAT   0x28
#define TY_QWORD   0x30
#define TY_TBYTE   0x38
#define TY_OWORD   0x40
#define TY_YWORD   0x48
#define TY_COMMON  0xE0
#define TY_SEG     0xE8
#define TY_EXTERN  0xF0
#define TY_EQU     0xF8

#define TYM_TYPE(x)     ((x) & 0xF8)
#define TYM_ELEMENTS(x) (((x) & 0xFFFFFF00) >> 8)

#define TYS_ELEMENTS(x) ((x) << 8)

enum special_tokens {
    SPECIAL_ENUM_START  = PREFIX_ENUM_LIMIT,
    S_ABS               = SPECIAL_ENUM_START,
    S_BYTE,
    S_DWORD,
    S_FAR,
    S_LONG,
    S_NEAR,
    S_NOSPLIT,
    S_OWORD,
    S_QWORD,
    S_REL,
    S_SHORT,
    S_STRICT,
    S_TO,
    S_TWORD,
    S_WORD,
    S_YWORD,
    SPECIAL_ENUM_LIMIT
};

/*
 * Global modes
 */

/*
 * This declaration passes the "pass" number to all other modules
 * "pass0" assumes the values: 0, 0, ..., 0, 1, 2
 * where 0 = optimizing pass
 *       1 = pass 1
 *       2 = pass 2
 */

extern int pass0;
extern int passn;               /* Actual pass number */

extern bool tasm_compatible_mode;
extern int optimizing;
extern int globalbits;          /* 16, 32 or 64-bit mode */
extern int globalrel;           /* default to relative addressing? */
extern int maxbits;             /* max bits supported by output */

/*
 * NASM version strings, defined in ver.c
 */
extern const char nasm_version[];
extern const char nasm_date[];
extern const char nasm_compile_options[];
extern const char nasm_comment[];
extern const char nasm_signature[];

#endif
