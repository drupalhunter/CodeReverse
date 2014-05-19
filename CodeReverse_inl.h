////////////////////////////////////////////////////////////////////////////
// CR_TriBool - logical value of three states

inline CR_TriBool::CR_TriBool() : m_value(TB_UNKNOWN)
{
}

inline CR_TriBool::CR_TriBool(bool b) :
    m_value(b ? TB_TRUE : TB_FALSE)
{
}

inline CR_TriBool::CR_TriBool(const CR_TriBool& tb) : m_value(tb.m_value)
{
}

inline void CR_TriBool::operator=(const CR_TriBool& tb)
{
    m_value = tb.m_value;
}

inline void CR_TriBool::operator=(bool b)
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

inline bool CR_TriBool::CanBeTrue() const
{
    return m_value != TB_FALSE;
}

inline bool CR_TriBool::CanBeFalse() const
{
    return m_value != TB_TRUE;
}

inline bool CR_TriBool::IsTrue() const
{
    return m_value == TB_TRUE;
}

inline bool CR_TriBool::IsFalse() const
{
    return m_value == TB_FALSE;
}

inline bool CR_TriBool::IsUnknown() const
{
    return m_value == TB_UNKNOWN;
}

inline void CR_TriBool::SetFalse()
{
    m_value = TB_FALSE;
}

inline void CR_TriBool::SetTrue()
{
    m_value = TB_TRUE;
}

inline void CR_TriBool::SetUnknown()
{
    m_value = TB_UNKNOWN;
}

inline void CR_TriBool::LogicalNot()
{
    if (m_value == TB_TRUE)
        m_value = TB_FALSE;
    else if (m_value == TB_FALSE)
        m_value = TB_TRUE;
}

inline void CR_TriBool::LogicalAnd(const CR_TriBool& tb)
{
    if (tb.m_value == TB_FALSE)
        m_value = TB_FALSE;
    else if (tb.m_value == TB_UNKNOWN && m_value == TB_TRUE)
        m_value = TB_UNKNOWN;
}

inline void CR_TriBool::LogicalOr(const CR_TriBool& tb)
{
    if (tb.m_value == TB_TRUE)
        m_value = TB_TRUE;
    else if (tb.m_value == TB_UNKNOWN && m_value == TB_FALSE)
        m_value = TB_UNKNOWN;
}

inline void CR_TriBool::Equal(const CR_TriBool& tb)
{
    if (m_value == TB_TRUE)
        m_value = tb.m_value;
    else if (m_value != TB_FALSE)
        ;
    else if (tb.m_value == TB_FALSE)
        m_value = TB_TRUE;
    else if (tb.m_value == TB_TRUE)
        m_value = TB_FALSE;
    else if (tb.m_value == TB_UNKNOWN)
        m_value = TB_UNKNOWN;
}

inline void CR_TriBool::NotEqual(const CR_TriBool& tb)
{
    Equal(tb);
    LogicalNot();
}

inline void CR_TriBool::NotEqual(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    Equal(tb1, tb2);
    LogicalNot();
}

inline void CR_TriBool::AssumeEqual(CR_TriBool& tb)
{
    if (m_value == TB_UNKNOWN)
        m_value = tb.m_value;
    else if (tb.m_value == TB_UNKNOWN)
        tb.m_value = m_value;
}

inline void CR_TriBool::AssumeEqual(const CR_TriBool& tb)
{
    if (m_value == TB_UNKNOWN)
        m_value = tb.m_value;
}

////////////////////////////////////////////////////////////////////////////
