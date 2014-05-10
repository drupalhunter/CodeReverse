#ifndef CODEREVERSE_H_
#define CODEREVERSE_H_

////////////////////////////////////////////////////////////////////////////
// CodeReverse.h
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

// logo
extern const char * const cr_logo;

////////////////////////////////////////////////////////////////////////////
// LOLONG, HILONG, MAKELONGLONG

#ifndef LOLONG
    #define LOLONG(dwl) static_cast<DWORD>(dwl)
#endif
#ifndef HILONG
    #define HILONG(dwl) static_cast<DWORD>(((dwl) >> 32) & 0xFFFFFFFF)
#endif
#ifndef MAKELONGLONG
    #define MAKELONGLONG(lo,hi) \
        ((static_cast<DWORDLONG>(hi) << 32) | static_cast<DWORD>(lo))
#endif

////////////////////////////////////////////////////////////////////////////
// CR_Addr32, CR_Addr64 (virtual address)

typedef unsigned long       CR_Addr32;
typedef unsigned long long  CR_Addr64;

////////////////////////////////////////////////////////////////////////////
// CR_DataByte

typedef unsigned char CR_DataByte;

////////////////////////////////////////////////////////////////////////////
// CR_TriBool - tri-state logical value

class CR_TriBool
{
public:
    CR_TriBool();
    CR_TriBool(BOOL b);
    CR_TriBool(const CR_TriBool& tb);
    virtual ~CR_TriBool();
    void operator=(BOOL b);
    void operator=(const CR_TriBool& tb);
    bool operator==(const CR_TriBool& tb) const;
    bool operator!=(const CR_TriBool& tb) const;
    void clear();

    BOOL CanBeTrue() const;
    BOOL CanBeFalse() const;
    BOOL IsUnknown() const;

    CR_TriBool& IsFalse(const CR_TriBool& tb);
    CR_TriBool& IsTrue(const CR_TriBool& tb);
    CR_TriBool& LogicalAnd(const CR_TriBool& tb1, const CR_TriBool& tb2);
    CR_TriBool& LogicalOr(const CR_TriBool& tb1, const CR_TriBool& tb2);
    CR_TriBool& LogicalNot(const CR_TriBool& tb1);
    CR_TriBool& Equal(const CR_TriBool& tb1, const CR_TriBool& tb2);
    CR_TriBool& NotEqual(const CR_TriBool& tb1, const CR_TriBool& tb2);

public:
    enum {
        TB_UNKNOWN, TB_FALSE, TB_TRUE
    } m_value;
};

////////////////////////////////////////////////////////////////////////////
// CR_DeqSet<ITEM_T> -- deque and set

template <typename ITEM_T>
class CR_DeqSet : public std::deque<ITEM_T>
{
public:
    CR_DeqSet()
    {
    }

    CR_DeqSet(const CR_DeqSet<ITEM_T>& vs) : std::deque<ITEM_T>(vs)
    {
    }

    void operator=(const CR_DeqSet<ITEM_T>& vs)
    {
        this->assign(vs.begin(), vs.end());
    }

    virtual ~CR_DeqSet()
    {
    }

    void insert(const ITEM_T& item)
    {
        this->push_back(item);
    }

    bool Contains(const ITEM_T& item) const
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++)
        {
            if (this->at(i) == item)
                return true;
        }
        return false;
    }

    std::size_t Find(const ITEM_T& item) const
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++)
        {
            if (this->at(i) == item)
                return i;
        }
        return static_cast<std::size_t>(-1);
    }

    std::size_t Insert(const ITEM_T& item)
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; i++)
        {
            if (this->at(i) == item)
                return i;
        }
        this->push_back(item);
        return this->size() - 1;
    }

    std::size_t count(const ITEM_T& item) const
    {
        std::size_t count = 0;
        for (std::size_t i : *this)
        {
            if (this->at(i) == item)
                count++;
        }
        return count;
    }

    void sort()
    {
        std::sort(this->begin(), this->end());
    }

    void unique()
    {
        std::unique(this->begin(), this->end());
    }

    void erase(const ITEM_T& item)
    {
        std::size_t i, j;
        const std::size_t count = this->size();
        for (i = j = 0; i < count; i++)
        {
            if (this->at(i) != item)
            {
                this->at(j++) = this->at(i);
            }
        }
        if (i != j)
            this->resize(j);
    }
};

namespace std
{
    template <typename ITEM_T>
    inline void swap(CR_DeqSet<ITEM_T>& vs1, CR_DeqSet<ITEM_T>& vs2)
    {
        vs1.swap(vs2);
    }
}

////////////////////////////////////////////////////////////////////////////
// CR_Addr32Set, CR_Addr64Set

typedef CR_DeqSet<CR_Addr32> CR_Addr32Set;
typedef CR_DeqSet<CR_Addr64> CR_Addr64Set;

////////////////////////////////////////////////////////////////////////////
// CR_String

typedef std::string CR_String;

////////////////////////////////////////////////////////////////////////////
// CR_StringSet

typedef CR_DeqSet<CR_String> CR_StringSet;

////////////////////////////////////////////////////////////////////////////
// CR_Binary

typedef CR_DeqSet<CR_DataByte> CR_Binary;

////////////////////////////////////////////////////////////////////////////
// CR_Map<from, to>, CR_UnorderedMap<from, to>

#define CR_Map              std::map
#define CR_UnorderedMap     std::unordered_map

////////////////////////////////////////////////////////////////////////////

// inline functions
#include "CodeReverse_inl.h"

#endif  // ndef CODEREVERSE_H_
