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
    TF_SIGNED       = (1 << 9),
    TF_UNSIGNED     = (1 << 10),
    TF_STRUCT       = (1 << 11),
    TF_UNION        = (1 << 12),
    TF_ENUM         = (1 << 13),
    TF_POINTER      = (1 << 14),
    TF_ARRAY        = (1 << 15),
    TF_FUNCTION     = (1 << 16),
    TF_CDECL        = (1 << 17),
    TF_STDCALL      = (1 << 18),
    TF_FASTCALL     = (1 << 19),
    TF_CONST        = (1 << 20),
    TF_VOLATILE     = (1 << 21),
    TF_COMPLEX      = (1 << 22),
    TF_IMAGINARY    = (1 << 23),
    TF_ATOMIC       = (1 << 24),
    TF_EXTERN       = (1 << 25),
    TF_STATIC       = (1 << 26),
    TF_THREADLOCAL  = (1 << 27),
    TF_INLINE       = (1 << 28),
    TF_ALIAS        = (1 << 29)
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
// IDs

// CR_ID --- ID
typedef std::size_t CR_ID;

// CR_TypeID --- type ID
typedef CR_ID CR_TypeID;

// CR_FuncID --- function ID
typedef CR_ID CR_FuncID;

// CR_VarID --- variable ID
typedef CR_ID CR_VarID;

// CR_StructID --- struct or union ID
typedef CR_ID CR_StructID;

// CR_EnumID --- enum ID
typedef CR_ID CR_EnumID;

// cr_invalid_id --- invalid ID
#define cr_invalid_id   static_cast<CR_ID>(-1)

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
    // For TF_CONST:    the type ID (CR_TypeID)
    // For TF_FUNCTION: the function ID (CR_FuncID)
    // For TF_STRUCT:   the struct ID (CR_StructID)
    // For TF_ENUM:     the enum ID (CR_EnumID)
    // For TF_UNION:    the union ID (CR_UnionID)
    // otherwise: zero
    CR_ID        m_id;

    int          m_count;   // for TF_ARRAY

    CR_LogType() : m_flags(0), m_id(0), m_count(0) { }

    CR_LogType(CR_TypeFlags flags) : m_flags(flags), m_id(0), m_count(0) { }

    bool operator==(const CR_LogType& type) const
    {
        return m_flags == type.m_flags &&
               m_id == type.m_id &&
               m_count == type.m_count;
    }

    bool operator!=(const CR_LogType& type) const
    {
        return m_flags != type.m_flags ||
               m_id != type.m_id ||
               m_count != type.m_count;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogStruct -- logical structure or union

struct CR_LogStruct
{
    bool                    m_struct_or_union;
    std::deque<CR_TypeID>   m_type_list;
    std::deque<std::string> m_name_list;

    CR_LogStruct(bool struct_or_union = true) :
        m_struct_or_union(struct_or_union)
    {
    }

    CR_LogStruct(const CR_LogStruct& ls) :
        m_struct_or_union(ls.m_struct_or_union),
        m_type_list(ls.m_type_list),
        m_name_list(ls.m_name_list)
    {
    }

    void operator=(const CR_LogStruct& ls)
    {
        m_struct_or_union = ls.m_struct_or_union;
        m_type_list = ls.m_type_list;
        m_name_list = ls.m_name_list;
    }

    int FindName(const std::string& name) const
    {
        for (size_t i = 0; i < m_name_list.size(); i++)
        {
            if (m_name_list[i] == name)
                return i;
        }
        return -1;
    }

    bool operator==(const CR_LogStruct& ls) const
    {
        return m_struct_or_union == ls.m_struct_or_union &&
               m_type_list == ls.m_type_list &&
               m_name_list == ls.m_name_list;
    }

    bool operator!=(const CR_LogStruct& ls) const
    {
        return m_struct_or_union != ls.m_struct_or_union ||
               m_type_list != ls.m_type_list ||
               m_name_list != ls.m_name_list;
    }
};

////////////////////////////////////////////////////////////////////////////
// CR_LogEnum

struct CR_LogEnum
{
    std::unordered_map<std::string, int>  m_mNameToValue;
    std::unordered_map<int, std::string>  m_mValueToName;

    CR_LogEnum() { }

    CR_LogEnum(const CR_LogEnum& le) :
        m_mNameToValue(le.m_mNameToValue),
        m_mValueToName(le.m_mValueToName)
    {
    }

    void operator=(const CR_LogEnum& le)
    {
        m_mNameToValue = le.m_mNameToValue;
        m_mValueToName = le.m_mValueToName;
    }

    std::unordered_map<std::string, int>& MapNameToValue()
    { return m_mNameToValue; }

    std::unordered_map<int, std::string>& MapValueToName()
    { return m_mValueToName; }

    const std::unordered_map<std::string, int>& MapNameToValue() const
    { return m_mNameToValue; }

    const std::unordered_map<int, std::string>& MapValueToName() const
    { return m_mValueToName; }
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
    std::map<std::string, CR_TypeID>        m_mNameToTypeID;
    std::map<CR_TypeID, std::string>        m_mTypeIDToName;
    std::map<std::string, CR_VarID>         m_mNameToVarID;
    std::map<CR_VarID, std::string>         m_mVarIDToName;
    std::map<std::string, CR_TypeID>        m_mNameToFuncTypeID;
    CR_VecSet<CR_LogType>                   m_types;
    std::vector<CR_LogFunc>                 m_funcs;
    std::vector<CR_LogStruct>               m_structs_or_unions;
    std::vector<CR_LogEnum>                 m_enums;
    std::vector<CR_LogVar>                  m_vars;

    CR_NameScope()
    {
        Init();
    }

    CR_NameScope(const CR_NameScope& ns) :
        m_mNameToTypeID(ns.m_mNameToTypeID),
        m_mTypeIDToName(ns.m_mTypeIDToName),
        m_mNameToVarID(ns.m_mNameToVarID),
        m_mVarIDToName(ns.m_mVarIDToName),
        m_mNameToFuncTypeID(ns.m_mNameToFuncTypeID),
        m_types(ns.m_types),
        m_funcs(ns.m_funcs),
        m_structs_or_unions(ns.m_structs_or_unions),
        m_enums(ns.m_enums),
        m_vars(ns.m_vars)
    {
    }

    void operator=(const CR_NameScope& ns)
    {
        m_mNameToTypeID = ns.m_mNameToTypeID;
        m_mTypeIDToName = ns.m_mTypeIDToName;
        m_mNameToVarID = ns.m_mNameToVarID;
        m_mVarIDToName = ns.m_mVarIDToName;
        m_mNameToFuncTypeID = ns.m_mNameToFuncTypeID;
        m_types = ns.m_types;
        m_funcs = ns.m_funcs;
        m_structs_or_unions = ns.m_structs_or_unions;
        m_enums = ns.m_enums;
        m_vars = ns.m_vars;
    }

    void Init()
    {
        AddType("void", TF_VOID);

        AddType("char", TF_CHAR);
        AddType("short", TF_SHORT);
        AddType("long", TF_LONG);
        AddType("long long", TF_LONGLONG);
        AddType("int", TF_INT);

        AddType("unsigned char", TF_UNSIGNED | TF_CHAR);
        AddType("unsigned short", TF_UNSIGNED | TF_SHORT);
        AddType("unsigned long", TF_UNSIGNED | TF_LONG);
        AddType("unsigned long long", TF_UNSIGNED | TF_LONGLONG);
        AddType("unsigned int", TF_UNSIGNED | TF_INT);

        AddType("float", TF_FLOAT);
        AddType("double", TF_DOUBLE);
        AddType("long double", TF_LONG | TF_DOUBLE);

        AddType("va_list", TF_VA_LIST);
    }

    CR_TypeID TypeIDFromName(const std::string& name) const
    {
        auto it = m_mNameToTypeID.find(name);
        if (it != m_mNameToTypeID.end())
            return it->second;
        else
            return cr_invalid_id;
    }

    std::string NameFromTypeID(CR_TypeID tid) const
    {
        auto it = m_mTypeIDToName.find(tid);
        if (it != m_mTypeIDToName.end())
            return it->second;
        else
            return "";
    }

    CR_TypeID AddType(const std::string& name, const CR_LogType& lt)
    {
        CR_TypeID tid = m_types.Insert(lt);
        if (!name.empty())
        {
            m_mNameToTypeID[name] = tid;
            m_mTypeIDToName[tid] = name;
        }
        return tid;
    }

    CR_TypeID AddType(const std::string& name, CR_TypeFlags flags)
    {
        return AddType(name, CR_LogType(flags));
    }

    CR_TypeID AddAliasType(const std::string& name, CR_TypeID tid)
    {
        return AddType(name, TF_ALIAS);
    }

    CR_VarID AddVar(const std::string& name, CR_TypeID tid)
    {
        CR_LogVar var;
        var.m_type_id = tid;
        var.m_int_value = 0;
        m_vars.push_back(var);
        CR_VarID vid;
        vid = static_cast<CR_VarID>(m_vars.size()) - 1;;
        if (!name.empty())
        {
            m_mNameToVarID[name] = vid;
            m_mVarIDToName[vid] = name;
        }
        return vid;
    }

    CR_VarID AddVar(const std::string& name, const CR_LogType& lt)
    {
        CR_TypeID tid = m_types.Insert(lt);
        return AddVar(name, tid);
    }

    CR_TypeID AddConstType(CR_TypeID tid)
    {
        CR_LogType lt;
        lt.m_flags = TF_CONST;
        lt.m_id = tid;
        CR_TypeID newtid = m_types.Insert(lt);
        std::string name = NameFromTypeID(tid);
        if (!name.empty())
        {
            name = std::string("const ") + name;
            m_mNameToTypeID[name] = newtid;
            m_mTypeIDToName[newtid] = name;
        }
        return newtid;
    }

    CR_TypeID AddPtrType(CR_TypeID tid, CR_TypeFlags flags = 0)
    {
        CR_LogType lt;
        lt.m_flags = TF_POINTER | flags;
        lt.m_id = tid;
        CR_LogType type = m_types[tid];
        CR_TypeID newtid = m_types.Insert(lt);
        std::string name = NameFromTypeID(tid);
        if (!name.empty() && !(type.m_flags & TF_FUNCTION))
        {
            name += "*";
            m_mNameToTypeID[name] = newtid;
            m_mTypeIDToName[newtid] = name;
        }
        return newtid;
    }

    CR_TypeID AddArrayType(const std::string& name, CR_TypeID tid, int count)
    {
        CR_LogType lt;
        lt.m_flags = TF_ARRAY;
        lt.m_id = tid;
        lt.m_count = count;
        tid = m_types.Insert(lt);
        return tid;
    }

    CR_TypeID AddFuncType(const CR_LogFunc& lf)
    {
        m_funcs.push_back(lf);
        CR_FuncID fid = static_cast<CR_FuncID>(m_funcs.size()) - 1;
        CR_LogType lt;
        lt.m_flags = TF_FUNCTION;
        lt.m_id = fid;
        CR_TypeID tid = m_types.Insert(lt);
        return tid;
    }

    CR_TypeID AddFunc(const std::string& name, const CR_LogFunc& lf)
    {
        m_funcs.push_back(lf);
        CR_FuncID fid = static_cast<CR_FuncID>(m_funcs.size()) - 1;
        CR_LogType lt;
        lt.m_flags = TF_FUNCTION;
        lt.m_id = fid;
        CR_TypeID tid = m_types.Insert(lt);
        if (!name.empty())
            m_mNameToFuncTypeID[name] = tid;
        return tid;
    }

    CR_TypeID AddStructOrUnionType(const std::string& name, const CR_LogStruct& ls)
    {
        m_structs_or_unions.push_back(ls);
        CR_StructID sid = static_cast<CR_StructID>(m_structs_or_unions.size()) - 1;
        CR_LogType lt;
        lt.m_flags = (ls.m_struct_or_union ? TF_STRUCT : TF_UNION);
        lt.m_id = sid;
        CR_TypeID tid = m_types.Insert(lt);
        if (!name.empty())
        {
            if (ls.m_struct_or_union)
            {
                std::string newname(std::string("struct ") + name);
                m_mNameToTypeID[newname] = tid;
                m_mTypeIDToName[tid] = newname;
            }
            else
            {
                std::string newname(std::string("union ") + name);
                m_mNameToTypeID[newname] = tid;
                m_mTypeIDToName[tid] = newname;
            }
        }
        return tid;
    }

    CR_TypeID AddEnumType(const std::string& name, const CR_LogEnum& le)
    {
        m_enums.push_back(le);
        CR_EnumID eid = static_cast<CR_EnumID>(m_enums.size()) - 1;
        CR_LogType lt;
        lt.m_flags = TF_ENUM;
        lt.m_id = eid;
        CR_TypeID newtid = m_types.Insert(lt);
        if (!name.empty())
        {
            std::string newname(std::string("enum ") + name);
            m_mNameToTypeID[newname] = newtid;
            m_mTypeIDToName[newtid] = newname;
        }
        return newtid;
    }

    CR_LogType& TypeFromTypeID(CR_TypeID tid)
    {
        return m_types[tid];
    }

    const CR_LogType& TypeFromTypeID(CR_TypeID tid) const
    {
        return m_types[tid];
    }

    CR_LogFunc& FuncFromFuncID(CR_FuncID fid)
    {
        return m_funcs[fid];
    }

    const CR_LogFunc& FuncFromFuncID(CR_FuncID fid) const
    {
        return m_funcs[fid];
    }

    CR_LogStruct& StructOrUnionFromStructID(CR_StructID sid)
    {
        return m_structs_or_unions[sid];
    }

    const CR_LogStruct& StructOrUnionFromStructID(CR_StructID sid) const
    {
        return m_structs_or_unions[sid];
    }

    CR_LogEnum& EnumFromEnumID(CR_EnumID eid)
    {
        return m_enums[eid];
    }

    const CR_LogEnum& EnumFromEnumID(CR_EnumID eid) const
    {
        return m_enums[eid];
    }

    CR_LogVar& VarFromVarID(CR_VarID vid)
    {
        return m_vars[vid];
    }

    const CR_LogVar& VarFromVarID(CR_VarID vid) const
    {
        return m_vars[vid];
    }

    int GetSizeofStruct(CR_StructID sid) const
    {
        if (sid == cr_invalid_id)
            return 0;
        const CR_LogStruct& ls = m_structs_or_unions[sid];
        int size = 0;
        for (auto tid : ls.m_type_list)
        {
            size += GetSizeofType(tid);
        }
        return size;
    }

    int GetSizeofUnion(CR_StructID sid) const
    {
        if (sid == cr_invalid_id)
            return 0;

        const CR_LogStruct& ls = m_structs_or_unions[sid];
        int maxsize = 0, size;
        for (auto tid : ls.m_type_list)
        {
            size = GetSizeofType(tid);
            if (maxsize < size)
                maxsize = size;
        }
        return maxsize;
    }

    int GetSizeofType(CR_TypeID tid) const
    {
        if (tid == cr_invalid_id)
            return 0;
        const CR_LogType& lt = m_types[tid];
        if (lt.m_flags & TF_ALIAS)
            return GetSizeofType(lt.m_id);
        if (lt.m_flags & TF_POINTER)
            return GetSizeofType(lt.m_id);
        if (lt.m_flags & TF_ARRAY)
            return GetSizeofType(lt.m_id) * lt.m_count;
        if (lt.m_flags & TF_CONST)
            return GetSizeofType(lt.m_id);
        if (lt.m_flags & TF_FUNCTION)
            return sizeof(void *);
        if (lt.m_flags & TF_STRUCT)
            return GetSizeofStruct(lt.m_id);
        if (lt.m_flags & TF_UNION)
            return GetSizeofUnion(lt.m_id);
        if (lt.m_flags & TF_ENUM)
            return sizeof(int);
        if (lt.m_flags & TF_LONGLONG)
            return 8;
        if ((lt.m_flags & TF_LONG) && !(lt.m_flags & TF_DOUBLE))
            return sizeof(long);
        if ((lt.m_flags & TF_LONG) && (lt.m_flags & TF_DOUBLE))
            return sizeof(long double);
        if (lt.m_flags & TF_SHORT)
            return sizeof(short);
        if (lt.m_flags & TF_CHAR)
            return sizeof(char);
        if (lt.m_flags & TF_FLOAT)
            return sizeof(float);
        if (lt.m_flags & TF_DOUBLE)
            return sizeof(double);
        return 0;
    }

    std::string StringOfType(CR_TypeID tid, const std::string& content) const
    {
        if (tid == cr_invalid_id)
        {
            return "";
        }
        auto it = m_mTypeIDToName.find(tid);
        if (it != m_mTypeIDToName.end())
        {
            return it->second + " " + content;
        }
        const CR_LogType& type = m_types[tid];
        if (type.m_flags & TF_POINTER)
        {
            const CR_LogType& type2 = m_types[type.m_id];
            if ((type2.m_flags & TF_FUNCTION) || (type2.m_flags & TF_ARRAY) ||
                (type2.m_flags & TF_POINTER))
            {
                if (type2.m_flags & TF_FUNCTION)
                {
                    if (type.m_flags & TF_STDCALL)
                        return StringOfType(type.m_id, "(__stdcall *" + content + ")");
                    if (type.m_flags & TF_FASTCALL)
                        return StringOfType(type.m_id, "(__fastcall *" + content + ")");
                }
                return StringOfType(type.m_id, "(*" + content + ")");
            }
            else
                return StringOfType(type.m_id, "") + " *" + content;
        }
        if (type.m_flags & TF_ARRAY)
        {
            if (type.m_count)
            {
                char buf[64];
                std::sprintf(buf, "[%d]", type.m_count);
                return StringOfType(type.m_id, content + buf);
            }
            else
                return StringOfType(type.m_id, content + "[]");
        }
        if (type.m_flags & TF_CONST)
        {
            return std::string("const ") + StringOfType(type.m_id, content);
        }
        if (type.m_flags & TF_FUNCTION)
        {
            const CR_LogFunc& lf = m_funcs[type.m_id];
            std::string rettype = StringOfType(lf.m_return_type, "");
            std::string paramlist =
                StringOfParamList(lf.m_type_list, lf.m_name_list);
            if (lf.m_ellipsis)
                paramlist += ", ...";
            return rettype + " " + content + "(" + paramlist + ")";
        }
        return "";
    }

    std::string StringOfParamList(
        const std::deque<CR_TypeID>& type_list,
        const std::deque<std::string>& name_list) const
    {
        assert(type_list.size() == name_list.size());
        std::size_t i, size = type_list.size();
        std::string str;
        if (size > 0)
        {
            str += StringOfType(type_list[0], name_list[0]);
            for (i = 1; i < size; i++)
            {
                str += ", ";
                str += StringOfType(type_list[i], name_list[i]);
            }
        }
        return str;
    }

    int GetIntValueFromVarName(const std::string& name) const
    {
        CR_VarID vid;
        auto it = m_mNameToVarID.find(name);
        if (it == m_mNameToVarID.end())
            return 0;
        vid = it->second;
        const CR_LogVar& var = m_vars[vid];
        return var.m_int_value;
    }
};

#endif  // ndef TYPE_H_
