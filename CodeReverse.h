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
// CR_TriBool - logical value of three states

class CR_TriBool
{
public:
    CR_TriBool();
    CR_TriBool(bool b);
    CR_TriBool(const CR_TriBool& tb);

    void operator=(bool b);
    void operator=(const CR_TriBool& tb);
    bool operator==(const CR_TriBool& tb) const;
    bool operator!=(const CR_TriBool& tb) const;
    void clear();

    bool CanBeTrue() const;
    bool CanBeFalse() const;
    bool CanBeUnknown() const;

    bool IsFalse() const;
    bool IsTrue() const;
    bool IsUnknown() const;

    void SetFalse();
    void SetTrue();
    void SetUnknown();
    void AssumeEqual(      CR_TriBool& tb);
    void AssumeEqual(const CR_TriBool& tb);

    void LogicalNot();
    void LogicalAnd(const CR_TriBool& tb);
    void LogicalOr(const CR_TriBool& tb);
    void LogicalAnd(const CR_TriBool& tb1, const CR_TriBool& tb2);
    void LogicalOr(const CR_TriBool& tb1, const CR_TriBool& tb2);

    void Equal(const CR_TriBool& tb);
    void NotEqual(const CR_TriBool& tb);
    void Equal(const CR_TriBool& tb1, const CR_TriBool& tb2);
    void NotEqual(const CR_TriBool& tb1, const CR_TriBool& tb2);

protected:
    static const char TB_UNKNOWN    = -1;
    static const char TB_FALSE      = 0;
    static const char TB_TRUE       = 1;
    char m_value;
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
        for (std::size_t i = 0; i < siz; ++i)
        {
            if (this->at(i) == item)
                return true;
        }
        return false;
    }

    std::size_t Find(const ITEM_T& item) const
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; ++i)
        {
            if (this->at(i) == item)
                return i;
        }
        return static_cast<std::size_t>(-1);
    }

    std::size_t Insert(const ITEM_T& item)
    {
        const std::size_t siz = this->size();
        for (std::size_t i = 0; i < siz; ++i)
        {
            if (this->at(i) == item)
                return i;
        }
        this->push_back(item);
        return this->size() - 1;
    }

    void AddHead(const ITEM_T& item)
    {
        this->push_front(item);
    }

    void AddTail(const ITEM_T& item)
    {
        this->push_back(item);
    }

    void AddHead(const CR_DeqSet<ITEM_T>& items)
    {
        std::deque<ITEM_T>::insert(
            std::deque<ITEM_T>::begin(), items.begin(), items.end());
    }

    void AddTail(const CR_DeqSet<ITEM_T>& items)
    {
        std::deque<ITEM_T>::insert(
            std::deque<ITEM_T>::end(), items.begin(), items.end());
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
        for (i = j = 0; i < count; ++i)
        {
            if (this->at(i) != item)
            {
                this->at(j++) = this->at(i);
            }
        }
        if (i != j)
            this->resize(j);
    }

    using std::deque<ITEM_T>::erase;
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
// CR_DataByte, CR_DataBytes

typedef unsigned char CR_DataByte;

typedef CR_DeqSet<CR_DataByte> CR_DataBytes;

////////////////////////////////////////////////////////////////////////////
// CR_Map<from, to>, CR_UnorderedMap<from, to>

#define CR_Map              std::map
#define CR_UnorderedMap     std::unordered_map

////////////////////////////////////////////////////////////////////////////

// inline functions
#include "CodeReverse_inl.h"

#endif  // ndef CODEREVERSE_H_
