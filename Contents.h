#ifndef CONTENTS_H_
#define CONTENTS_H_

#include "Type.h"

////////////////////////////////////////////////////////////////////////////
// NAMESCOPE

struct NAMESCOPE
{
    typedef std::map<std::string, CR_TypeExpr> map_type;

public:
    NAMESCOPE() : m_next(NULL)
    {
    }

    NAMESCOPE(const NAMESCOPE& namescope) : m_next(NULL)
    {
        m_map1 = namescope.m_map1;
        m_map2 = namescope.m_map2;
        m_map3 = namescope.m_map3;
    }

    void operator=(const NAMESCOPE& namescope)
    {
        m_map1 = namescope.m_map1;
        m_map2 = namescope.m_map2;
        m_map3 = namescope.m_map3;
    }

          map_type& Map1()       { return m_map1; }
          map_type& Map2()       { return m_map2; }
          map_type& Map3()       { return m_map3; }
    const map_type& Map1() const { return m_map1; }
    const map_type& Map2() const { return m_map2; }
    const map_type& Map3() const { return m_map3; }

          NAMESCOPE *Up()       { return m_up; }
    const NAMESCOPE *Up() const { return m_up; }

    void add_type_name(const std::string& name, const CR_TypeExpr& te)
    {
        m_map1.insert(std::make_pair(name, te));
    }

    void add_tag_name(const std::string& name, const CR_TypeExpr& te)
    {
        m_map2.insert(std::make_pair(name, te));
    }

    void add_var_name(const std::string& name, const CR_TypeExpr& te)
    {
        m_map3.insert(std::make_pair(name, te));
    }

    CR_TypeExpr *find_type_name(const std::string& name)
    {
        map_type::iterator it;
        it = m_map1.find(name);
        if (it != m_map1.end())
            return &*it;
        if (Up())
            return Up()->find_type_name(name);
        return NULL;
    }

    const CR_TypeExpr *find_type_name(const std::string& name) const
    {
        map_type::const_iterator it;
        it = m_map1.find(name);
        if (it != m_map1.end())
            return &*it;
        if (Up())
            return Up()->find_type_name(name);
        return NULL;
    }

    CR_TypeExpr *find_tag_name(const std::string& name)
    {
        map_type::iterator it;
        it = m_map2.find(name);
        if (it != m_map2.end())
            return &*it;
        if (Up())
            return Up()->find_tag_name(name);
        return NULL;
    }

    const CR_TypeExpr *find_tag_name(const std::string& name) const
    {
        map_type::const_iterator it;
        it = m_map2.find(name);
        if (it != m_map2.end())
            return &*it;
        if (Up())
            return Up()->find_tag_name(name);
        return NULL;
    }

    CR_TypeExpr *find_var_name(const std::string& name)
    {
        map_type::iterator it;
        it = m_map3.find(name);
        if (it != m_map3.end())
            return &*it;
        if (Up())
            return Up()->find_var_name(name);
        return NULL;
    }

    const CR_TypeExpr *find_var_name(const std::string& name) const
    {
        map_type::const_iterator it;
        it = m_map3.find(name);
        if (it != m_map3.end())
            return &*it;
        if (Up())
            return Up()->find_var_name(name);
        return NULL;
    }

public:
    map_type   m_map1;  // type name mapping
    map_type   m_map2;  // tag name mapping
    map_type   m_map3;  // var name mapping
    NAMESCOPE *m_up;
};

////////////////////////////////////////////////////////////////////////////
// LOGFUNC - logical function

struct LOGFUNC : NAMESCOPE
{
    bool                        m_ellipsis;     // ...
    CR_TypeFlags                m_flags;        // flags
    CR_TypeExpr                 m_retval_type;  // return value type
    std::deque<CR_TypeExpr>     m_args;         // arguments

    LOGFUNC() : m_ellipsis(false), m_flags(0) { }

    LOGFUNC(const LOGFUNC& lf) :
        m_ellipsis(lf.m_ellipsis), m_flags(lf.m_flags),
        m_retval_type(lf.m_retval_type), m_args(lf.m_args)
    {
    }

    void operator=(const LOGFUNC& lf)
    {
        m_ellipsis = lf.m_ellipsis;
        m_flags = lf.m_flags;
        m_retval_type = lf.m_retval_type;
        m_args = lf.m_args;
    }
};

////////////////////////////////////////////////////////////////////////////
// SEMANTICCONTENTS --- semantic contents

struct SEMANTICCONTENTS
{
    NAMESCOPE               m_namescope;
    std::deque<LOGFUNC>     m_funcs;
};

////////////////////////////////////////////////////////////////////////////

#endif  // ndef CONTENTS_H_
