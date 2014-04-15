////////////////////////////////////////////////////////////////////////////
// Type.h
// Copyright (C) 2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#ifndef TYPE_H_
#define TYPE_H_

#include <string>   // for std::string
#include <deque>    // for std::deque
#include <cassert>  // for assert

////////////////////////////////////////////////////////////////////////////
// CR_TypeFlags

enum
{
    TF_VOID         = (1 << 0),
    TF_CHAR         = (1 << 1),
    TF_SHORT        = (1 << 2),
    TF_LONG         = (1 << 3),
    TF_LONGLONG     = (1 << 4),
    TF_INT          = (1 << 5),
    TF_VA_LIST      = (1 << 6),
    TF_FLOAT        = (1 << 7),
    TF_DOUBLE       = (1 << 8),
    TF_UNSIGNED     = (1 << 9),
    TF_STRUCT       = (1 << 10),
    TF_UNION        = (1 << 11),
    TF_ENUM         = (1 << 12),
    TF_POINTER      = (1 << 13),
    TF_ARRAY        = (1 << 14),
    TF_FUNCTION     = (1 << 15),
    TF_STDCALL      = (1 << 16),
    TF_FASTCALL     = (1 << 17),
    TF_CONST        = (1 << 18),
    TF_VOLATILE     = (1 << 19),
    TF_COMPLEX      = (1 << 20),
    TF_IMAGINARY    = (1 << 21),
    TF_ATOMIC       = (1 << 22),
    TF_EXTERN       = (1 << 23),
    TF_STATIC       = (1 << 24),
    TF_THREADLOCAL  = (1 << 25),
    TF_INLINE       = (1 << 26),
    TF_VARIABLE     = (1 << 27),
    TF_TYPE         = (1 << 28),
    TF_OFFSET       = (1 << 29),
    TF_PLUS1OFFSET  = TF_OFFSET * 1,
    TF_PLUS2OFFSET  = TF_OFFSET * 2,
    TF_PLUS4OFFSET  = TF_OFFSET * 4,
    TF_OFFSETMASK   = TF_OFFSET * 7
};
typedef unsigned long CR_TypeFlags;

////////////////////////////////////////////////////////////////////////////
// CrNormalizeTypeFlags

inline CR_TypeFlags CrNormalizeTypeFlags(CR_TypeFlags flags)
{
    if (flags & TF_INT)
    {
        if (flags & TF_SHORT)
            flags &= ~TF_INT;
        else if (flags & TF_LONG)
            flags &= ~TF_INT;
        else if (flags & TF_LONGLONG)
            flags &= ~TF_INT;
    }
    return flags;
}

////////////////////////////////////////////////////////////////////////////
// CR_LogFunc

struct CR_LogFunc
{
    bool                    m_ellipsis;
    std::deque<CR_TypeID>   m_type_list;
    std::deque<std::string> m_name_list;
    CR_TypeID               m_return_type;
    enum {
        FT_CDECL, FT_STDCALL, FT_FASTCALL
    } m_func_type;

    CR_LogFunc() :
        m_ellipsis(false),
        m_return_type(0),
        m_func_type(FT_CDECL)
    {
    }

    CR_LogFunc(const CR_LogFunc& lf) :
        m_ellipsis(lf.m_ellipsis),
        m_type_list(lf.m_type_list),
        m_name_list(lf.m_name_list),
        m_return_type(lf.m_return_type),
        m_func_type(lf.m_func_type)
    {
    }

    void operator=(const CR_LogFunc& lf)
    {
        m_ellipsis = lf.m_ellipsis;
        m_type_list = lf.m_type_list;
        m_name_list = lf.m_name_list;
        m_return_type = lf.m_return_type;
        m_func_type = lf.m_func_type;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogType

struct CR_LogType
{
    CR_TypeFlags m_flags;

    // For TF_POINTER:  the type ID (CR_TypeID)
    // For TF_ARRAY:    the type ID (CR_TypeID)
    // For TF_FUNCTION: the function ID (CR_FuncID)
    // For TF_STRUCT:   the struct ID (CR_StructID)
    // For TF_ENUM:     the enum ID (CR_EnumID)
    // For TF_UNION:    the union ID (CR_UnionID)
    CR_ID        m_id;

    int          m_count;   // for TF_ARRAY

    CR_LogType() : m_flags(0), m_id(0), m_count(0) { }

    CR_LogType(CR_TypeFlags flags) : m_flags(flags), m_id(0), m_count(0) { }

    bool operator==(const CR_LogType& type)
    {
        return m_flags == type.m_flags &&
               m_id == type.m_id &&
               m_count == type.m_count;
    }

    bool operator!=(const CR_LogType& type)
    {
        return m_flags != type.m_flags ||
               m_id != type.m_id ||
               m_count != type.m_count;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogStruct

struct CR_LogStruct
{
    bool                    m_ellipsis;
    std::deque<CR_TypeID>   m_type_list;
    std::deque<std::string> m_name_list;
    std::size_t             m_size;

    int FindName(const std::string& name) const
    {
        for (size_t i : m_name_list)
        {
            if (it == name)
                return i;
        }
        return -1;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogUnion

struct CR_LogUnion
{
    bool                    m_ellipsis;
    std::deque<CR_TypeID>   m_type_list;
    std::deque<std::string> m_name_list;
    std::size_t             m_size;

    int FindName(const std::string& name) const
    {
        for (size_t i : m_name_list)
        {
            if (it == name)
                return i;
        }
        return -1;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogEnum

struct CR_LogEnum
{
    std::unordered_map<std::string, int>  m_mNameToValue;
    std::unordered_map<int, std::string>  m_mValueToName;

    std::unordered_map<std::string, int>& MapNameToValue()
    { return m_mNameToValue; }

    std::unordered_map<int, std::string>& MapValueToName()
    { return m_mValueToName; }

    const std::unordered_map<std::string, int>& MapNameToValue() const
    { return m_mNameToValue; }

    const std::unordered_map<int, std::string>& MapValueToName() const
    { return m_mValueToName; }

    int MapNameToValue(const std::string& name) const
    {
        return m_mNameToValue[name];
    }

    std::string MapValueToName(int value) const
    {
        return m_mValueToName[value];
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogVar

struct CR_LogVar
{
    CR_TypeID       m_type_id;
    union
    {
        char        m_char_value;
        short       m_short_value;
        long        m_long_value;
        long long   m_long_long_value;
        int         m_int_value;
        float       m_float_value;
        double      m_double_value;
        long double m_long_double_value;
        void *      m_pointer_value;
    };
};

////////////////////////////////////////////////////////////////////////////
// CR_NameScope

struct CR_NameScope
{
    std::map<std::string, CR_TypeFlags>     m_mNameToTypeFlags;
    std::deque<CR_LogType>                  m_types;
    std::deque<CR_LogFunc>                  m_funcs;
    std::deque<CR_LogStruct>                m_structs;
    std::deque<CR_LogEnum>                  m_enums;
    std::deque<CR_LogUnion>                 m_unions;
    std::deque<CR_LogVar>                   m_vars;

    CR_NameScope()
    {
        Init();
    }

    void Init()
    {
        MapNameToTypeFlags("void", TF_VOID);

        MapNameToTypeFlags("char", TF_CHAR);
        MapNameToTypeFlags("short", TF_SHORT);
        MapNameToTypeFlags("long", TF_LONG);
        MapNameToTypeFlags("long long", TF_LONGLONG);
        MapNameToTypeFlags("int", TF_INT);

        MapNameToTypeFlags("unsigned char", TF_UNSIGNED | TF_CHAR);
        MapNameToTypeFlags("unsigned short", TF_UNSIGNED | TF_SHORT);
        MapNameToTypeFlags("unsigned long", TF_UNSIGNED | TF_LONG);
        MapNameToTypeFlags("unsigned long long", TF_UNSIGNED | TF_LONGLONG);
        MapNameToTypeFlags("unsigned int", TF_UNSIGNED | TF_INT);

        MapNameToTypeFlags("float", TF_FLOAT);
        MapNameToTypeFlags("double", TF_DOUBLE);
        MapNameToTypeFlags("long double", TF_LONG | TF_DOUBLE);

        MapNameToTypeFlags("va_list", TF_VA_LIST);
    }

    std::map<std::string, CR_TypeFlags>& MapNameToTypeFlags()
    { return m_mNameToTypeFlags; }

    const std::map<std::string, CR_TypeFlags>& MapNameToTypeFlags() const
    { return m_mNameToTypeFlags; }

    void MapNameToTypeFlags(const std::string& name, CR_TypeFlags flags)
    {
        m_mNameToTypeFlags[name] = flags;
        m_types.push_back(CR_LogType(flags));
    }

    CR_TypeFlags TypeFlagsFromName(const std::string& name) const
    {
        auto it = m_mNameToTypeFlags.find(name);
        return (it != m_mNameToTypeFlags.end() ? *it : 0);
    }

    CR_LogType& TypeFromTypeID(CR_TypeID tid)
    {
        assert(0 <= tid && tid < m_types.size());
        return m_types[tid];
    }

    const CR_LogType& TypeFromTypeID(CR_TypeID tid) const
    {
        assert(0 <= tid && tid < m_types.size());
        return m_types[tid];
    }

    CR_LogFunc& FuncFromFuncID(CR_FuncID fid)
    {
        assert(0 <= fid && fid < m_funcs.size());
        return m_funcs[fid];
    }

    const CR_LogFunc& FuncFromFuncID(CR_FuncID fid) const
    {
        assert(0 <= fid && fid < m_funcs.size());
        return m_funcs[fid];
    }

    CR_LogStruct& StructFromStructID(CR_StructID sid)
    {
        assert(0 <= sid && sid < m_structs.size());
        return m_structs[sid];
    }

    const CR_LogStruct& StructFromStructID(CR_StructID sid) const
    {
        assert(0 <= sid && sid < m_structs.size());
        return m_structs[sid];
    }

    CR_LogEnum& EnumFromEnumID(CR_EnumID eid)
    {
        assert(0 <= eid && eid < m_enums.size());
        return m_enums[eid];
    }

    const CR_LogEnum& EnumFromEnumID(CR_EnumID eid) const
    {
        assert(0 <= eid && eid < m_enums.size());
        return m_enums[eid];
    }

    CR_LogUnion& UnionFromUnionID(CR_UnionID uid)
    {
        assert(0 <= uid && uid < m_unions.size());
        return m_unions[uid];
    }

    const CR_LogUnion& UnionFromUnionID(CR_UnionID uid) const
    {
        assert(0 <= uid && uid < m_unions.size());
        return m_unions[uid];
    }

    CR_LogVar& VarFromVarID(CR_VarID vid)
    {
        assert(0 <= vid && vid < m_vars.size());
        return m_vars[vid];
    }

    const CR_LogVar& VarFromVarID(CR_VarID vid) const
    {
        assert(0 <= vid && vid < m_vars.size());
        return m_vars[vid];
    }
};

#endif  // ndef TYPE_H_
