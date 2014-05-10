////////////////////////////////////////////////////////////////////////////
// CR_TriBool - tri-state logical value

inline CR_TriBool::CR_TriBool()
{
    m_value = TB_UNKNOWN;
}

inline CR_TriBool::CR_TriBool(BOOL b)
{
    m_value = (b ? TB_TRUE : TB_FALSE);
}

inline CR_TriBool::CR_TriBool(const CR_TriBool& tb)
{
    m_value = tb.m_value;
}

inline /*virtual*/ CR_TriBool::~CR_TriBool()
{
}

inline void CR_TriBool::operator=(const CR_TriBool& tb)
{
    m_value = tb.m_value;
}

inline void CR_TriBool::operator=(BOOL b)
{
    m_value = (b ? TB_TRUE : TB_FALSE);
}

inline bool CR_TriBool::operator==(const CR_TriBool& tb) const
{
    return m_value == tb.m_value;
}

inline bool CR_TriBool::operator!=(const CR_TriBool& tb) const
{
    return m_value != tb.m_value;
}

inline void CR_TriBool::clear()
{
    m_value = TB_UNKNOWN;
}

inline BOOL CR_TriBool::CanBeTrue() const
{
    return m_value != TB_FALSE;
}

inline BOOL CR_TriBool::CanBeFalse() const
{
    return m_value != TB_TRUE;
}

inline BOOL CR_TriBool::IsUnknown() const
{
    return m_value == TB_UNKNOWN;
}

inline CR_TriBool& CR_TriBool::IsTrue(const CR_TriBool& tb)
{
    m_value = tb.m_value;
    return *this;
}

inline CR_TriBool& CR_TriBool::LogicalNot(const CR_TriBool& tb1)
{
    return IsFalse(tb1);
}

inline CR_TriBool&
CR_TriBool::NotEqual(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    CR_TriBool tb;
    tb.Equal(tb1, tb2);
    return LogicalNot(tb);
}

////////////////////////////////////////////////////////////////////////////
