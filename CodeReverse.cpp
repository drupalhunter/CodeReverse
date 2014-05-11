////////////////////////////////////////////////////////////////////////////
// CodeReverse.cpp
// Copyright (C) 2013-2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "CParseHeader.h"

////////////////////////////////////////////////////////////////////////////

const char * const cr_logo =
    "///////////////////////////////////////////////\n"
#ifdef _WIN64
# ifdef __GNUC__
    "// CodeReverse 0.1.4 (64-bit) for gcc        //\n"
# elif defined(_MSC_VER)
    "// CodeReverse 0.1.4 (64-bit) for cl         //\n"
# endif
#else   // ndef _WIN64
# ifdef __GNUC__
    "// CodeReverse 0.1.4 (32-bit) for gcc        //\n"
# elif defined(_MSC_VER)
    "// CodeReverse 0.1.4 (32-bit) for cl         //\n"
# endif
#endif  // ndef _WIN64
    "// https://github.com/katahiromz/CodeReverse //\n"
    "// katayama.hirofumi.mz@gmail.com            //\n"
    "///////////////////////////////////////////////\n";


////////////////////////////////////////////////////////////////////////////
// CR_TriBool - logical value of three states

void CR_TriBool::LogicalAnd(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    if (tb1.m_value == TB_FALSE || tb2.m_value == TB_FALSE)
        m_value = TB_FALSE;
    else if (tb1.m_value == TB_TRUE)
        m_value = tb2.m_value;
    else if (tb2.m_value == TB_TRUE)
        m_value = tb1.m_value;
    else
        m_value = TB_UNKNOWN;
}

void CR_TriBool::LogicalOr(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    if (tb1.m_value == TB_TRUE || tb2.m_value == TB_TRUE)
        m_value = TB_TRUE;
    else if (tb1.m_value == TB_FALSE)
        m_value = tb2.m_value;
    else if (tb2.m_value == TB_FALSE)
        m_value = tb1.m_value;
    else
        m_value = TB_UNKNOWN;
}

void CR_TriBool::Equal(const CR_TriBool& tb1, const CR_TriBool& tb2)
{
    if (tb1.m_value == TB_UNKNOWN || tb2.m_value == TB_UNKNOWN)
    {
        m_value = TB_UNKNOWN;
        return;
    }
    m_value = (tb1.m_value == tb2.m_value ? TB_TRUE : TB_FALSE);
}

////////////////////////////////////////////////////////////////////////////

// temporary file
static char *cr_tmpfile = NULL;

void CrDeleteTempFileAtExit(void)
{
    ::DeleteFile(cr_tmpfile);
}

////////////////////////////////////////////////////////////////////////////

using namespace cparser;

////////////////////////////////////////////////////////////////////////////
// CrCalcConstInt...Expr functions

int CrCalcConstIntPrimExpr(CR_NameScope& namescope, PrimExpr *pe);
int CrCalcConstIntPostfixExpr(CR_NameScope& namescope, PostfixExpr *pe);
int CrCalcConstIntUnaryExpr(CR_NameScope& namescope, UnaryExpr *ue);
int CrCalcConstIntCastExpr(CR_NameScope& namescope, CastExpr *ce);
int CrCalcConstIntMulExpr(CR_NameScope& namescope, MulExpr *me);
int CrCalcConstIntAddExpr(CR_NameScope& namescope, AddExpr *ae);
int CrCalcConstIntShiftExpr(CR_NameScope& namescope, ShiftExpr *se);
int CrCalcConstIntRelExpr(CR_NameScope& namescope, RelExpr *re);
int CrCalcConstIntEqualExpr(CR_NameScope& namescope, EqualExpr *ee);
int CrCalcConstIntAndExpr(CR_NameScope& namescope, AndExpr *ae);
int CrCalcConstIntExclOrExpr(CR_NameScope& namescope, ExclOrExpr *eoe);
int CrCalcConstIntInclOrExpr(CR_NameScope& namescope, InclOrExpr *ioe);
int CrCalcConstIntLogAndExpr(CR_NameScope& namescope, LogAndExpr *lae);
int CrCalcConstIntLogOrExpr(CR_NameScope& namescope, LogOrExpr *loe);
int CrCalcConstIntAssignExpr(CR_NameScope& namescope, AssignExpr *ae);
int CrCalcConstIntExpr(CR_NameScope& namescope, Expr *e);
int CrCalcConstIntCondExpr(CR_NameScope& namescope, CondExpr *ce);

int CrCalcConstIntPrimExpr(CR_NameScope& namescope, PrimExpr *pe)
{
    int n;
    switch (pe->m_prim_type)
    {
    case PrimExpr::IDENTIFIER:
        n = namescope.GetIntValueFromVarName(pe->m_text);
        return n;

    case PrimExpr::F_CONSTANT:
        return 0;

    case PrimExpr::I_CONSTANT:
        n = std::atoi(pe->m_text.c_str());
        return n;

    case PrimExpr::STRING:
        return 1;

    case PrimExpr::PAREN:
        n = CrCalcConstIntExpr(namescope, pe->m_expr.get());
        return n;

    case PrimExpr::SELECTION:
        // TODO:
        break;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntPostfixExpr(CR_NameScope& namescope, PostfixExpr *pe)
{
    int n;
    switch (pe->m_postfix_type)
    {
    case PostfixExpr::SINGLE:
        n = CrCalcConstIntPrimExpr(namescope, pe->m_prim_expr.get());
        return n;

    case PostfixExpr::ARRAYITEM:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::FUNCCALL1:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::FUNCCALL2:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::DOT:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::ARROW:
        //pe->m_postfix_expr
        return 0;

    case PostfixExpr::INC:
        n = CrCalcConstIntPostfixExpr(namescope, pe->m_postfix_expr.get());
        return n;

    case PostfixExpr::DEC:
        n = CrCalcConstIntPostfixExpr(namescope, pe->m_postfix_expr.get());
        return n;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcSizeOfUnaryExpr(CR_NameScope& namescope, UnaryExpr *ue)
{
    return 0;
}

CR_TypeID CrAnalyseDeclSpecs(CR_NameScope& namescope, DeclSpecs *ds);

int CrCalcSizeOfTypeName(CR_NameScope& namescope, TypeName *tn)
{
    CR_TypeID tid = CrAnalyseDeclSpecs(namescope, tn->m_decl_specs.get());
    if (tn->m_declor)
    {
        switch (tn->m_declor->m_declor_type)
        {
        case Declor::POINTERS:
        case Declor::FUNCTION:
            return (namescope.Is64Bit() ? 8 : 4);

        case Declor::ARRAY:
            {
                int count = CrCalcConstIntCondExpr(
                    namescope, tn->m_declor->m_const_expr.get());
                return namescope.GetSizeofType(tid) * count;
            }

        case Declor::BITS:
            return 0;

        default:
            break;
        }
    }
    return namescope.GetSizeofType(tid);
}

int CrCalcConstIntUnaryExpr(CR_NameScope& namescope, UnaryExpr *ue)
{
    int n;
    switch (ue->m_unary_type)
    {
    case UnaryExpr::SINGLE:
        n = CrCalcConstIntPostfixExpr(namescope, ue->m_postfix_expr.get());
        return n;

    case UnaryExpr::INC:
        n = CrCalcConstIntUnaryExpr(namescope, ue->m_unary_expr.get());
        return ++n;

    case UnaryExpr::DEC:
        n = CrCalcConstIntUnaryExpr(namescope, ue->m_unary_expr.get());
        return --n;

    case UnaryExpr::AND:
        return 0;

    case UnaryExpr::ASTERISK:
        return 0;

    case UnaryExpr::PLUS:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return n;

    case UnaryExpr::MINUS:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return n;

    case UnaryExpr::BITWISE_NOT:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return ~n;

    case UnaryExpr::NOT:
        n = CrCalcConstIntCastExpr(namescope, ue->m_cast_expr.get());
        return !n;

    case UnaryExpr::SIZEOF1:
        n = CrCalcSizeOfUnaryExpr(namescope, ue->m_unary_expr.get());
        return n;

    case UnaryExpr::SIZEOF2:
        n = CrCalcSizeOfTypeName(namescope, ue->m_type_name.get());
        return n;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntCastExpr(CR_NameScope& namescope, CastExpr *ce)
{
    int n;
    switch (ce->m_cast_type)
    {
    case CastExpr::UNARY:
        n = CrCalcConstIntUnaryExpr(namescope, ce->m_unary_expr.get());
        return n;
    
    case CastExpr::INITERLIST:
        // TODO:
        //ce->m_type_name
        //ce->m_initer_list
        return 0;

    case CastExpr::CAST:
        //ce->m_type_name
        n = CrCalcConstIntCastExpr(namescope, ce->m_cast_expr.get());
        return n;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntMulExpr(CR_NameScope& namescope, MulExpr *me)
{
    int n1, n2;
    switch (me->m_mul_type)
    {
    case MulExpr::SINGLE:
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n2;

    case MulExpr::ASTERISK:
        n1 = CrCalcConstIntMulExpr(namescope, me->m_mul_expr.get());
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n1 * n2;

    case MulExpr::SLASH:
        n1 = CrCalcConstIntMulExpr(namescope, me->m_mul_expr.get());
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n1 / n2;

    case MulExpr::PERCENT:
        n1 = CrCalcConstIntMulExpr(namescope, me->m_mul_expr.get());
        n2 = CrCalcConstIntCastExpr(namescope, me->m_cast_expr.get());
        return n1 % n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntAddExpr(CR_NameScope& namescope, AddExpr *ae)
{
    int n1, n2;
    switch (ae->m_add_type)
    {
    case AddExpr::SINGLE:
        n2 = CrCalcConstIntMulExpr(namescope, ae->m_mul_expr.get());
        return n2;

    case AddExpr::PLUS:
        n1 = CrCalcConstIntAddExpr(namescope, ae->m_add_expr.get());
        n2 = CrCalcConstIntMulExpr(namescope, ae->m_mul_expr.get());
        return n1 + n2;

    case AddExpr::MINUS:
        n1 = CrCalcConstIntAddExpr(namescope, ae->m_add_expr.get());
        n2 = CrCalcConstIntMulExpr(namescope, ae->m_mul_expr.get());
        return n1 - n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntShiftExpr(CR_NameScope& namescope, ShiftExpr *se)
{
    int n1, n2;
    switch (se->m_shift_type)
    {
    case ShiftExpr::SINGLE:
        n2 = CrCalcConstIntAddExpr(namescope, se->m_add_expr.get());
        return n2;

    case ShiftExpr::L_SHIFT:
        n1 = CrCalcConstIntShiftExpr(namescope, se->m_shift_expr.get());
        n2 = CrCalcConstIntAddExpr(namescope, se->m_add_expr.get());
        return n1 << n2;

    case ShiftExpr::R_SHIFT:
        n1 = CrCalcConstIntShiftExpr(namescope, se->m_shift_expr.get());
        n2 = CrCalcConstIntAddExpr(namescope, se->m_add_expr.get());
        return n1 >> n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntRelExpr(CR_NameScope& namescope, RelExpr *re)
{
    int n1, n2;
    switch (re->m_rel_type)
    {
    case RelExpr::SINGLE:
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n2;

    case RelExpr::LT:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 < n2;

    case RelExpr::GT:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 > n2;

    case RelExpr::LE:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 <= n2;

    case RelExpr::GE:
        n1 = CrCalcConstIntRelExpr(namescope, re->m_rel_expr.get());
        n2 = CrCalcConstIntShiftExpr(namescope, re->m_shift_expr.get());
        return n1 >= n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntEqualExpr(CR_NameScope& namescope, EqualExpr *ee)
{
    int n1, n2;
    switch (ee->m_equal_type)
    {
    case EqualExpr::SINGLE:
        return CrCalcConstIntRelExpr(namescope, ee->m_rel_expr.get());

    case EqualExpr::EQUAL:
        n1 = CrCalcConstIntEqualExpr(namescope, ee->m_equal_expr.get());
        n2 = CrCalcConstIntRelExpr(namescope, ee->m_rel_expr.get());
        return n1 == n2;

    case EqualExpr::NE:
        n1 = CrCalcConstIntEqualExpr(namescope, ee->m_equal_expr.get());
        n2 = CrCalcConstIntRelExpr(namescope, ee->m_rel_expr.get());
        return n1 != n2;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntAndExpr(CR_NameScope& namescope, AndExpr *ae)
{
    int n = CrCalcConstIntEqualExpr(namescope, (*ae)[0].get());
    for (std::size_t i = 1; i < ae->size(); ++i)
    {
        n &= CrCalcConstIntEqualExpr(namescope, (*ae)[i].get());
    }
    return n;
}

int CrCalcConstIntExclOrExpr(CR_NameScope& namescope, ExclOrExpr *eoe)
{
    int n = 0;
    for (auto& ae : *eoe)
    {
        n ^= CrCalcConstIntAndExpr(namescope, ae.get());
    }
    return n;
}

int CrCalcConstIntInclOrExpr(CR_NameScope& namescope, InclOrExpr *ioe)
{
    int n = 0;
    for (auto& eoe : *ioe)
    {
        n |= CrCalcConstIntExclOrExpr(namescope, eoe.get());
    }
    return n;
}

int CrCalcConstIntLogAndExpr(CR_NameScope& namescope, LogAndExpr *lae)
{
    int n = 1;
    for (auto& ioe : *lae)
    {
        n = n && CrCalcConstIntInclOrExpr(namescope, ioe.get());
        if (n == 0)
            break;
    }
    return n;
}

int CrCalcConstIntLogOrExpr(CR_NameScope& namescope, LogOrExpr *loe)
{
    for (auto& lae : *loe)
    {
        if (CrCalcConstIntLogAndExpr(namescope, lae.get()))
            return 1;
    }
    return 0;
}

int CrCalcConstIntAssignExpr(CR_NameScope& namescope, AssignExpr *ae)
{
    int n1, n2;
    switch (ae->m_assign_type)
    {
    case AssignExpr::COND:
        n1 = CrCalcConstIntCondExpr(namescope, ae->m_cond_expr.get());
        return n1;

    case AssignExpr::SINGLE:
        n1 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        return n1;

    case AssignExpr::MUL:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 *= n2;
        return n1;

    case AssignExpr::DIV:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 /= n2;
        return n1;

    case AssignExpr::MOD:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 %= n2;
        return n1;

    case AssignExpr::ADD:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 += n2;
        return n1;

    case AssignExpr::SUB:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 -= n2;
        return n1;

    case AssignExpr::L_SHIFT:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 <<= n2;
        return n1;

    case AssignExpr::R_SHIFT:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 >>= n2;
        return n1;

    case AssignExpr::AND:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 &= n2;
        return n1;

    case AssignExpr::XOR:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 ^= n2;
        return n1;

    case AssignExpr::OR:
        n1 = CrCalcConstIntUnaryExpr(namescope, ae->m_unary_expr.get());
        n2 = CrCalcConstIntAssignExpr(namescope, ae->m_assign_expr.get());
        n1 |= n2;
        return n1;

    default:
        assert(0);
    }
    return 0;
}

int CrCalcConstIntExpr(CR_NameScope& namescope, Expr *e)
{
    int n = 0;
    for (auto& ae : *e)
    {
        n = CrCalcConstIntAssignExpr(namescope, ae.get());
    }
    return n;
}

int CrCalcConstIntCondExpr(CR_NameScope& namescope, CondExpr *ce)
{
    switch (ce->m_cond_type)
    {
    case CondExpr::SINGLE:
        return CrCalcConstIntLogOrExpr(namescope, ce->m_log_or_expr.get());

    case CondExpr::QUESTION:
        if (CrCalcConstIntLogOrExpr(namescope, ce->m_log_or_expr.get()))
        {
            return CrCalcConstIntExpr(namescope, ce->m_expr.get());
        }
        else
        {
            return CrCalcConstIntCondExpr(namescope, ce->m_cond_expr.get());
        }

    default:
        assert(0);
        break;
    }
    return 0;
}

////////////////////////////////////////////////////////////////////////////
// CrAnalyse... functions

CR_TypeID CrAnalysePointer(CR_NameScope& namescope, Pointers *pointers,
                           CR_TypeID tid);
void CrAnalyseTypedefDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                                DeclorList *dl);
void CrAnalyseDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                         DeclorList *dl);
void CrAnalyseStructDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                               DeclorList *dl, CR_LogStruct& ls);
void CrAnalyseDeclList(CR_NameScope& namescope, DeclList *dl);
void CrAnalyseParamList(CR_NameScope& namescope, CR_LogFunc& func,
                        ParamList *pl);
void CrAnalyseFunc(CR_NameScope& namescope, CR_TypeID return_type,
                   Declor *declor, DeclList *decl_list);
CR_TypeID CrAnalyseStructDeclList(CR_NameScope& namescope,
                                  const CR_String& name, DeclList *dl,
                                  int pack);
CR_TypeID CrAnalyseUnionDeclList(CR_NameScope& namescope,
                                 const CR_String& name, DeclList *dl);
CR_TypeID CrAnalyseEnumorList(CR_NameScope& namescope,
                              const CR_String& name, EnumorList *el);
CR_TypeID CrAnalyseAtomic(CR_NameScope& namescope, AtomicTypeSpec *ats);
CR_TypeID CrAnalyseDeclSpecs(CR_NameScope& namescope, DeclSpecs *ds);

////////////////////////////////////////////////////////////////////////////

CR_TypeID CrAnalysePointers(CR_NameScope& namescope, Pointers *pointers,
                            CR_TypeID tid)
{
    assert(pointers);
    for (auto& ac : *pointers)
    {
        assert(ac);
        tid = namescope.AddPtrType(tid, ac->m_flags);
    }
    return tid;
}

void CrAnalyseTypedefDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                                DeclorList *dl)
{
    assert(dl);
    for (auto& declor : *dl)
    {
        CR_TypeID tid2 = tid;

        int value;
        Declor *d = declor.get();
        while (d)
        {
            CR_String name;
            switch (d->m_declor_type)
            {
            case Declor::TYPEDEF_TAG:
                assert(!d->m_name.empty());
                name = d->m_name;
                #ifdef __GNUC__
                    if (name == "__builtin_va_list")
                        name = "va_list";
                #endif
                if (d->m_flags && namescope.IsFuncType(tid2))
                    namescope.AddTypeFlags(tid2, d->m_flags);
                namescope.AddAliasType(name, tid2);
                d = NULL;
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                continue;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType(tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    lf.m_return_type = tid2;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                continue;

            case Declor::BITS:
                // TODO:
                assert(0);
                d = NULL;
                break;

            default:
                assert(0);
                d = NULL;
                break;
            }
        }
    }
}

void CrAnalyseDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                         DeclorList *dl)
{
    assert(dl);
    for (auto& declor : *dl)
    {
        CR_TypeID tid2 = tid;

        int value;
        Declor *d = declor.get();
        while (d)
        {
            #ifdef DEEPDEBUG
                printf("DeclorList#%s\n", namescope.StringOfType(tid2, "").c_str());
            #endif

            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                if (d->m_flags && namescope.IsFuncType(tid2))
                    namescope.AddTypeFlags(tid2, d->m_flags);
                namescope.AddVar(d->m_name, tid2);
                #ifdef DEEPDEBUG
                    printf("#%s\n", namescope.StringOfType(tid2, d->m_name).c_str());
                #endif
                d = d->m_declor.get();
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                break;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType(tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    lf.m_return_type = tid2;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                break;

            default:
                assert(0);
                break;
            }
        }
    }
}

void CrAnalyseStructDeclorList(CR_NameScope& namescope, CR_TypeID tid,
                               DeclorList *dl, CR_LogStruct& ls)
{
    assert(dl);
    for (auto& declor : *dl)
    {
        CR_TypeID tid2 = tid;

        int value, bits = 0;
        CR_String name;
        Declor *d = declor.get();
        while (d)
        {
            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                if (d->m_flags && namescope.IsFuncType(tid2))
                    namescope.AddTypeFlags(tid2, d->m_flags);
                name = d->m_name;
                d = NULL;
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                continue;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType(tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                continue;

            case Declor::BITS:
                assert(ls.m_struct_or_union);   // must be struct
                assert(d->m_const_expr);
                bits = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                d = d->m_declor.get();
                continue;

            default:
                assert(0);
                d = NULL;
                break;
            }
        }
        ls.m_type_list.push_back(tid2);
        ls.m_name_list.push_back(name);
        ls.m_bitfield.push_back(bits);
    }
}

void CrAnalyseDeclList(CR_NameScope& namescope, DeclList *dl)
{
    assert(dl);
    for (auto& decl : *dl)
    {
        CR_TypeID tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
        switch (decl->m_decl_type)
        {
        case Decl::TYPEDEF:
            CrAnalyseTypedefDeclorList(namescope, tid, decl->m_declor_list.get());
            break;

        case Decl::DECLORLIST:
            CrAnalyseDeclorList(namescope, tid, decl->m_declor_list.get());
            break;

        case Decl::STATIC_ASSERT:
            {
                shared_ptr<CondExpr> const_expr =
                    decl->m_static_assert_decl->m_const_expr;
                if (CrCalcConstIntCondExpr(namescope, const_expr.get()) == 0)
                {
                    assert(0);
                }
            }
            break;

        default:
            break;
        }
    }
}

void CrAnalyseParamList(CR_NameScope& namescope, CR_LogFunc& func,
                        ParamList *pl)
{
    assert(pl);
    func.m_ellipsis = pl->m_ellipsis;
    for (auto& decl : *pl)
    {
        assert(decl->m_decl_type == Decl::PARAM);
        assert(decl->m_declor_list->size() <= 1);

        DeclorList *dl = decl->m_declor_list.get();
        Declor *d;
        if (decl->m_declor_list->size())
            d = (*dl)[0].get();
        else
            d = NULL;
        CR_TypeID tid;
        tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());

        #ifdef DEEPDEBUG
            printf("ParamList##%s\n", namescope.StringOfType(tid, "").c_str());
        #endif

        CR_TypeID tid2 = tid;
        int value;
        CR_String name;
        while (d)
        {
            switch (d->m_declor_type)
            {
            case Declor::IDENTIFIER:
                name = d->m_name;
                d = NULL;
                break;

            case Declor::POINTERS:
                tid2 = CrAnalysePointers(namescope, d->m_pointers.get(), tid2);
                d = d->m_declor.get();
                continue;

            case Declor::ARRAY:
                if (d->m_const_expr)
                    value = CrCalcConstIntCondExpr(namescope, d->m_const_expr.get());
                else
                    value = 0;
                tid2 = namescope.AddArrayType(tid2, value);
                d = d->m_declor.get();
                continue;

            case Declor::FUNCTION:
                {
                    CR_LogFunc lf;
                    lf.m_return_type = tid2;
                    if (d->m_param_list)
                    {
                        CrAnalyseParamList(namescope, lf, d->m_param_list.get());
                    }
                    tid2 = namescope.AddFuncType(lf);
                }
                d = d->m_declor.get();
                continue;

            case Declor::BITS:
                // TODO:
                d = NULL;
                break;

            default:
                assert(0);
                d = NULL;
            }
        }
        func.m_type_list.push_back(tid2);
        func.m_name_list.push_back(name);
    }
}

void CrAnalyseFunc(CR_NameScope& namescope, CR_TypeID return_type,
                   Declor *declor, DeclList *decl_list)
{
    CR_LogFunc func;
    assert(declor);

    if (declor->m_declor_type == Declor::FUNCTION)
    {
        if (!declor->m_name.empty())
        {
            if (decl_list)
            {
                CrAnalyseDeclList(namescope, decl_list);
                if (declor->m_param_list)
                {
                    CrAnalyseParamList(namescope, func, declor->m_param_list.get());
                    namescope.AddFuncType(func);
                }
                else
                {
                    assert(0);
                }
            }
            else
            {
                assert(declor->m_param_list);
                if (declor->m_param_list)
                {
                    CrAnalyseParamList(namescope, func, declor->m_param_list.get());
                    namescope.AddFuncType(func);
                }
            }
        }
    }
}

CR_TypeID CrAnalyseStructDeclList(CR_NameScope& namescope,
                                  const CR_String& name, DeclList *dl, int pack)
{
    CR_LogStruct ls;
    ls.m_struct_or_union = true;    // struct
    ls.m_pack = pack;

    CR_TypeID tid;
    assert(dl);
    for (auto& decl : *dl)
    {
        switch (decl->m_decl_type)
        {
        case Decl::DECLORLIST:
            tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
            CrAnalyseStructDeclorList(namescope, tid, decl->m_declor_list.get(), ls);
            break;

        case Decl::SINGLE:
            tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
            if (tid != cr_invalid_id)
            {
                ls.m_type_list.push_back(tid);
                ls.m_name_list.push_back("");
            }
            break;

        case Decl::STATIC_ASSERT:
            {
                shared_ptr<CondExpr> const_expr =
                    decl->m_static_assert_decl->m_const_expr;
                if (CrCalcConstIntCondExpr(namescope, const_expr.get()) == 0)
                {
                    assert(0);
                }
            }
            break;

        default:
            assert(0);
            return cr_invalid_id;
        }
    }

    return namescope.AddStructType(name, ls);
}

CR_TypeID CrAnalyseUnionDeclList(CR_NameScope& namescope,
                                 const CR_String& name, DeclList *dl)
{
    CR_LogStruct ls;
    ls.m_struct_or_union = false;   // union

    assert(dl);
    for (auto& decl : *dl)
    {
        switch (decl->m_decl_type)
        {
        case Decl::DECLORLIST:
            {
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
                CrAnalyseStructDeclorList(namescope, tid, decl->m_declor_list.get(),
                                          ls);
            }
            break;

        case Decl::SINGLE:
            {
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, decl->m_decl_specs.get());
                if (tid != cr_invalid_id)
                {
                    ls.m_type_list.push_back(tid);
                    ls.m_name_list.push_back("");
                }
            }
            break;

        case Decl::STATIC_ASSERT:
            {
                shared_ptr<CondExpr> const_expr =
                    decl->m_static_assert_decl->m_const_expr;
                if (CrCalcConstIntCondExpr(namescope, const_expr.get()) == 0)
                {
                    assert(0);
                }
            }
            break;

        default:
            assert(0);
            return cr_invalid_id;
        }
    }

    return namescope.AddStructType(name, ls);
}

CR_TypeID CrAnalyseEnumorList(CR_NameScope& namescope,
                              const CR_String& name, EnumorList *el)
{
    CR_LogEnum le;

    int value, next_value = 0;
    assert(el);
    CR_TypeID tid_int = namescope.TypeIDFromName("int");
    CR_TypeID tid_const_int = namescope.AddConstType(tid_int);
    for (auto& e : *el)
    {
        if (e->m_const_expr)
            value = CrCalcConstIntCondExpr(namescope, e->m_const_expr.get());
        else
            value = next_value;

        le.MapNameToValue()[e->m_name.c_str()] = value;
        le.MapValueToName()[value] = e->m_name.c_str();
        CR_VarID vid = namescope.AddVar(e->m_name, tid_const_int);
        namescope.LogVar(vid).m_has_value = true;
        namescope.LogVar(vid).m_int_value = value;
        next_value = value + 1;
    }

    return namescope.AddEnumType(name, le);
}

CR_TypeID CrAnalyseAtomic(CR_NameScope& namescope, AtomicTypeSpec *ats)
{
    // TODO: TF_ATOMIC
    assert(0);
    return 0;
}

CR_TypeID CrAnalyseDeclSpecs(CR_NameScope& namescope, DeclSpecs *ds)
{
    CR_TypeID tid;
    CR_TypeFlags flag, flags = 0;
    if (ds == NULL)
        return namescope.TypeIDFromName("int");

    while (ds)
    {
        CR_String name;
        switch (ds->m_spec_type)
        {
        case DeclSpecs::STORCLSSPEC:
            flag = ds->m_stor_cls_spec->m_flag;
            flags |= flag;
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
            break;

        case DeclSpecs::FUNCSPEC:
            flag = ds->m_func_spec->m_flag;
            flags |= flag;
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
            break;

        case DeclSpecs::TYPESPEC:
            assert(ds->m_type_spec);
            flag = ds->m_type_spec->m_flag;
            switch (flag)
            {
            case TF_ALIAS:
                name = ds->m_type_spec->m_name;
                assert(!name.empty());
                #ifdef __GNUC__
                    if (name == "__builtin_va_list")
                        name = "va_list";
                #endif
                tid = namescope.TypeIDFromName(name);
                assert(tid != cr_invalid_id);
                return tid;

            case TF_STRUCT:
                {
                    TypeSpec *ts = ds->m_type_spec.get();
                    name = ts->m_name;
                    if (ts->m_decl_list)
                    {
                        tid = CrAnalyseStructDeclList(
                            namescope, name, ts->m_decl_list.get(), ts->m_pack);
                    }
                    else
                    {
                        CR_LogStruct ls;
                        ls.m_struct_or_union = true;
                        tid = namescope.AddStructType(name, ls);
                    }
                }
                if (flags & TF_CONST)
                {
                    tid = namescope.AddConstType(tid);
                }
                assert(tid != cr_invalid_id);
                return tid;

            case TF_UNION:
                {
                    TypeSpec *ts = ds->m_type_spec.get();
                    name = ts->m_name;
                    if (ts->m_decl_list)
                    {
                        tid = CrAnalyseUnionDeclList(
                            namescope, name, ts->m_decl_list.get());
                    }
                    else
                    {
                        CR_LogStruct ls;
                        ls.m_struct_or_union = false;
                        tid = namescope.AddStructType(name, ls);
                    }
                }
                if (flags & TF_CONST)
                {
                    tid = namescope.AddConstType(tid);
                }
                assert(tid != cr_invalid_id);
                return tid;

            case TF_ENUM:
                name = ds->m_type_spec->m_name;
                if (ds->m_type_spec->m_enumor_list)
                {
                    tid = CrAnalyseEnumorList(
                        namescope, name, ds->m_type_spec->m_enumor_list.get());
                }
                else
                {
                    CR_LogEnum le;
                    tid = namescope.AddEnumType(name, le);
                }
                if (flags & TF_CONST)
                {
                    tid = namescope.AddConstType(tid);
                }
                assert(tid != cr_invalid_id);
                return tid;

            case TF_ATOMIC:
                return CrAnalyseAtomic(namescope,
                    ds->m_type_spec.get()->m_atomic_type_spec.get());

            default:
                flags |= flag;
                if (ds->m_decl_specs)
                {
                    ds = ds->m_decl_specs.get();
                    continue;
                }
            }
            break;

        case DeclSpecs::TYPEQUAL:
            flag = ds->m_type_qual->m_flag;
            flags |= flag;
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
            break;

        case DeclSpecs::ALIGNSPEC:
            if (ds->m_decl_specs)
            {
                ds = ds->m_decl_specs.get();
                continue;
            }
        }
        break;
    }

    flags = CrNormalizeTypeFlags(flags);
    if (flags & TF_CONST)
    {
        tid = namescope.AddType("", flags & ~TF_CONST);
        assert(tid != cr_invalid_id);
        tid = namescope.AddConstType(tid);
    }
    else
    {
        tid = namescope.AddType("", flags);
    }
    assert(tid != cr_invalid_id);
    return tid;
}

////////////////////////////////////////////////////////////////////////////
// exit codes

#define cr_exit_ok                  0
#define cr_exit_parse_error         1
#define cr_exit_cpp_error           2
#define cr_exit_wrong_ext           3
#define cr_exit_bits_mismatched     4
#define cr_exit_cant_load           5

// do input
int CrInputCSrc(shared_ptr<TransUnit>& tu, int argc, char **args, bool is_64bit)
{
    char *pchDotExt = MzcFindDotExt(args[0]);
    // if file extension is ".i",
    if (_stricmp(pchDotExt, ".i") == 0)
    {
        // directly parse
        if (!cparser::parse_file(tu, args[0], is_64bit))
        {
            fprintf(stderr, "ERROR: Failed to parse file '%s'\n", args[0]);
            return cr_exit_parse_error;   // failure
        }
    }
    else if (_stricmp(pchDotExt, ".h") == 0)
    {
        // if file extension is ".h",
        BOOL bOK = FALSE;
        // create temporary file
        MFile hTmpFile;
        cr_tmpfile = _tempnam(".", "coderev_temp");
        if (hTmpFile.OpenFileForOutput(cr_tmpfile))
        {
            atexit(CrDeleteTempFileAtExit);

            // setup process maker
            MProcessMaker pmaker;
            pmaker.SetShowWindow(SW_HIDE);
            pmaker.SetCreationFlags(CREATE_NEW_CONSOLE);

            MFile hInputWrite, hOutputRead, hErrorRead;
            if (pmaker.PrepareForRedirect(&hInputWrite, &hOutputRead,
                                          &hErrorRead))
            {
                // build command line
                #ifdef __GNUC__
                    CR_String cmdline("gcc -E");
                #elif defined(_MSC_VER)
                    CR_String cmdline("cl /nologo /E");
                #endif

                for (int i = 1; i < argc; i++)
                {
                    cmdline += " ";
                    cmdline += args[i];
                }
                cmdline += " ";
                cmdline += args[0];

                // create process
                if (pmaker.CreateProcess(NULL, cmdline.c_str()))
                {
                    DWORD cbAvail, cbRead;
                    BYTE szBuf[1024];

                    bOK = TRUE;
                    for (;;)
                    {
                        if (hOutputRead.PeekNamedPipe(NULL, 0, NULL, &cbAvail) &&
                            cbAvail > 0)
                        {
                            // read from child process output
                            if (hOutputRead.ReadFile(szBuf, 1024, &cbRead))
                            {
                                // write to temporary file
                                if (!hTmpFile.WriteFile(szBuf, cbRead, &cbRead))
                                {
                                    fprintf(stderr,
                                        "ERROR: Cannot write to temporary file '%s'\n",
                                        cr_tmpfile);
                                    bOK = FALSE;
                                    break;
                                }
                            }
                            else
                            {
                                DWORD dwError = ::GetLastError();
                                if (dwError != ERROR_MORE_DATA)
                                {
                                    fprintf(stderr, "ERROR: Cannot read input\n");
                                    break;
                                }
                            }
                        }
                        else if (!pmaker.IsRunning())
                            break;
                    }
                    // check error output
                    if (hErrorRead.PeekNamedPipe(NULL, 0, NULL, &cbAvail) &&
                        cbAvail > 0)
                    {
                        while (hErrorRead.PeekNamedPipe(NULL, 0, NULL, &cbAvail) &&
                               cbAvail > 0)
                        {
                            hErrorRead.ReadFile(szBuf, 1024, &cbRead);
                            fwrite(szBuf, cbRead, 1, stderr);
                            if (cbRead == 0)
                                break;
                        }
                    }
                    bOK = (pmaker.GetExitCode() == 0);
                }
                else
                {
                    fprintf(stderr, "ERROR: Cannot create process\n");
                }
            }
            else
            {
                fprintf(stderr, "ERROR: Cannot create process\n");
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Cannot create temporary file '%s'\n",
                cr_tmpfile);
        }

        // close temporary file
        hTmpFile.CloseHandle();

        if (bOK)
        {
            if (!cparser::parse_file(tu, cr_tmpfile, is_64bit))
            {
                fprintf(stderr, "ERROR: Failed to parse file '%s'\n",
                        args[0]);
                return cr_exit_parse_error;   // failure
            }
        }
        else
        {
            return cr_exit_cpp_error;   // failure
        }
    }
    else
    {
        fprintf(stderr,
            "ERROR: Unknown input file extension '%s'. Please use .i or .h\n",
            pchDotExt);
        return cr_exit_wrong_ext;   // failure
    }
    return cr_exit_ok;   // success
}

////////////////////////////////////////////////////////////////////////////
// semantic analysis

int CrSemanticAnalysis(CR_NameScope& namescope, shared_ptr<TransUnit>& tu)
{
    assert(tu.get());
    for (shared_ptr<Decl>& decl : *tu.get())
    {
        switch (decl->m_decl_type)
        {
        case Decl::FUNCTION:
            {
                fflush(stderr);
                shared_ptr<DeclSpecs>& ds = decl->m_decl_specs;
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, ds.get());
                shared_ptr<DeclorList>& dl = decl->m_declor_list;
                assert(dl.get());
                auto& declor = (*dl.get())[0];
                CrAnalyseFunc(namescope, tid, declor.get(),
                              decl->m_decl_list.get());
            }
            break;

        case Decl::TYPEDEF:
        case Decl::DECLORLIST:
            {
                shared_ptr<DeclSpecs>& ds = decl->m_decl_specs;
                shared_ptr<DeclorList>& dl = decl->m_declor_list;
                CR_TypeID tid = CrAnalyseDeclSpecs(namescope, ds.get());
                if (decl->m_decl_type == Decl::TYPEDEF)
                {
                    fflush(stderr);
                    CrAnalyseTypedefDeclorList(namescope, tid, dl.get());
                }
                else
                {
                    fflush(stderr);
                    CrAnalyseDeclorList(namescope, tid, dl.get());
                }
            }
            break;

        default:
            break;
        }
    }

    return cr_exit_ok;   // success
}

////////////////////////////////////////////////////////////////////////////

void CrDumpSemantic(CR_NameScope& namescope)
{
    printf("\n### TYPES ###\n");

    for (auto& it : namescope.MapNameToTypeID())
    {
        auto tid = it.second;
        auto& type = namescope.LogType(tid);
        if (type.m_flags & TF_ALIAS)
        {
            auto& name = it.first;
            auto str = namescope.StringOfType(type.m_id, name);
            if (!str.empty())
                printf("typedef %s;\n", str.c_str());
        }
    }
    printf("\n");

    printf("\n### VARIABLES ###\n");
    auto& vars = namescope.Vars();
    for (CR_VarID i = 0; i < vars.size(); ++i)
    {
        auto& var = vars[i];
        auto& name = namescope.MapVarIDToName()[i];
        if (var.m_has_value && namescope.IsIntegerType(var.m_type_id))
        {
            if (namescope.IsUnsignedType(var.m_type_id))
            {
                printf("%s = %u\n;",
                       namescope.StringOfType(var.m_type_id, name).c_str(),
                       var.m_int_value);
            }
            else
            {
                printf("%s = %d;\n",
                       namescope.StringOfType(var.m_type_id, name).c_str(),
                       var.m_int_value);
            }
        }
        else
        {
            printf("%s;\n",
                   namescope.StringOfType(var.m_type_id, name).c_str());
        }
    }
    printf("\n");
}

////////////////////////////////////////////////////////////////////////////

void CrShowHelp(void)
{
#ifdef _WIN64
    fprintf(stderr,
        " Usage: coderev64 [options] exefile.exe [input-file.h] [compiler_options]\n");
#else
    fprintf(stderr,
        " Usage: coderev [options] exefile.exe [input-file.h] [compiler_options]\n");
#endif
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, " -h    Dump headers\n");
    fprintf(stderr, " -i    Dump import table\n");
    fprintf(stderr, " -e    Dump export table\n");
    fprintf(stderr, " -r    Dump resource\n");
    fprintf(stderr, " -d    Dump delayload info\n");
    fprintf(stderr, " -p    Parse input file and do semantic analysis\n");
    fprintf(stderr, " -a    Dump disassembly\n");
#ifdef _WIN64
    fprintf(stderr, " -32   32-bit mode\n");
    fprintf(stderr, " -64   64-bit mode (default)\n");
#else
    fprintf(stderr, " -32   32-bit mode (default)\n");
    fprintf(stderr, " -64   64-bit mode\n");
#endif
}

////////////////////////////////////////////////////////////////////////////

void CrDumpCommandLine(int argc, char **argv)
{
    printf("Command Line:");
    for (int i = 0; i < argc; ++i)
    {
        if (i == 0)
        {
            #ifdef _WIN64
                printf(" coderev64");
            #else
                printf(" coderev");
            #endif
        }
        else
        {
            if (strchr(argv[i], ' ') || strchr(argv[i], '\t'))
                printf(" \"%s\"", argv[i]);
            else
                printf(" %s", argv[i]);
        }
    }
    printf("\n");
    fflush(stdout);
}

////////////////////////////////////////////////////////////////////////////

extern "C"
int main(int argc, char **argv)
{
    puts(cr_logo);

    if (argc <= 1 || strcmp(argv[1], "/?") == 0 ||
        _stricmp(argv[1], "--help") == 0)
    {
        CrShowHelp();
        return cr_exit_ok;
    }

    if (_stricmp(argv[1], "--version") == 0)
    {
        return cr_exit_ok;
    }

    CrDumpCommandLine(argc, argv);

    enum MODE_INDEXES
    {
        MODE_DUMP_HEADERS,
        MODE_DUMP_IMPORT,
        MODE_DUMP_EXPORT,
        MODE_DUMP_RESOURCE,
        MODE_DUMP_DELAYLOAD,
        MODE_DUMP_SEMANTIC,
        MODE_DUMP_DISASM,
        MODE_64BIT
    };

    bool modes[8];
    char **args = argv + 1;
    --argc;
    if (**args == '-')
    {
        memset(modes, 0, sizeof(modes));
        #ifdef _WIN64
            modes[MODE_64BIT] = true;
        #else
            modes[MODE_64BIT] = false;
        #endif

        while (*args && **args == '-')
        {
            if (strchr(*args, 'h') || strchr(*args, 'H'))
                modes[MODE_DUMP_HEADERS] = true;
            if (strchr(*args, 'i') || strchr(*args, 'I'))
                modes[MODE_DUMP_IMPORT] = true;
            if (strchr(*args, 'e') || strchr(*args, 'e'))
                modes[MODE_DUMP_EXPORT] = true;
            if (strchr(*args, 'r') || strchr(*args, 'R'))
                modes[MODE_DUMP_RESOURCE] = true;
            if (strchr(*args, 'd') || strchr(*args, 'D'))
                modes[MODE_DUMP_DELAYLOAD] = true;
            if (strchr(*args, 'p') || strchr(*args, 'P'))
                modes[MODE_DUMP_SEMANTIC] = true;
            if (strchr(*args, 'a') || strchr(*args, 'A'))
                modes[MODE_DUMP_DISASM] = true;
            if (strstr(*args, "32"))
                modes[MODE_64BIT] = false;
            if (strstr(*args, "64"))
                modes[MODE_64BIT] = true;

            ++args; --argc;
        }
    }
    else
    {
        #ifdef _WIN64
            modes[MODE_64BIT] = true;
        #else
            modes[MODE_64BIT] = false;
        #endif
        // dump all
        for (int i = 0; i < 7; ++i)
        {
            modes[i] = true;
        }
    }

    shared_ptr<TransUnit> tu;
    if (modes[MODE_DUMP_SEMANTIC])
    {
        if (argc >= 2)
        {
            // args[0] == file.exe
            // args[1] == input-file
            // ...compiler_options...
            int result = CrInputCSrc(tu, argc - 1, args + 1, modes[MODE_64BIT]);
            if (result)
                return result;
        }
        else
        {
            // args[0] == file.exe
            // (no compiler_options)
            char path[MAX_PATH];
            ::GetModuleFileNameA(NULL, path, MAX_PATH);

            char *title = MzcFindFileTitle(path);
            #ifdef _DEBUG
                strcpy(title, "coderev-test.h");
                if (GetFileAttributesA(path) == 0xFFFFFFFF)
                    strcpy(title, "..\\coderev-test.h");
            #else
                strcpy(title, "coderev-default.h");
                if (GetFileAttributesA(path) == 0xFFFFFFFF)
                    strcpy(title, "..\\coderev-default.h");
            #endif

            char *p = path;
            char **args = {&p};
            int result = CrInputCSrc(tu, 1, args, modes[MODE_64BIT]);
            if (result)
                return result;
        }
    }

    char *pszModule = args[0];
    fprintf(stderr, "Loading module %s...\n", pszModule);

    CR_Module module;
    if (!module.LoadModule(pszModule))
    {
        fprintf(stderr, "ERROR: Cannot load module '%s', LastError = %lu\n",
                pszModule, module.LastError());
        return cr_exit_cant_load;
    }

    if (modes[MODE_DUMP_HEADERS])
    {
        fprintf(stderr, "Dumping module %s headers...\n", pszModule);
        module.DumpHeaders();
    }
    if (modes[MODE_DUMP_IMPORT])
    {
        fprintf(stderr, "Dumping module %s import table...\n", pszModule);
        module.DumpImportSymbols();
    }
    if (modes[MODE_DUMP_EXPORT])
    {
        fprintf(stderr, "Dumping module %s export table...\n", pszModule);
        module.DumpExportSymbols();
    }
    if (modes[MODE_DUMP_RESOURCE])
    {
        fprintf(stderr, "Dumping module %s resource...\n", pszModule);
        module.DumpResource();
    }
    if (modes[MODE_DUMP_DELAYLOAD])
    {
        fprintf(stderr, "Dumping module %s delayload info...\n", pszModule);
        module.DumpDelayLoad();
    }

    if (module.Is64Bit() && !modes[MODE_64BIT])
    {
        fprintf(stderr, "ERROR: Bits mismatched.\n");
        fprintf(stderr, "       The module was 64-bit and the mode was 32-bit.\n");
        return cr_exit_bits_mismatched;
    }

    if (!module.Is64Bit() && modes[MODE_64BIT])
    {
        fprintf(stderr, "ERROR: Bits mismatched.\n");
        fprintf(stderr, "       The module was 32-bit and the mode was 64-bit.\n");
        return cr_exit_bits_mismatched;
    }

    if (modes[MODE_64BIT])
    {
        CR_NameScope namescope;
        namescope.Set64Bit(true);

        if (modes[MODE_DUMP_SEMANTIC])
        {
            fprintf(stderr, "Semantic analysis...\n");
            int result = CrSemanticAnalysis(namescope, tu);
            if (result)
                return result;

            tu = shared_ptr<TransUnit>();
            fprintf(stderr, "Dumping semantic...\n");
            CrDumpSemantic(namescope);
        }

        CR_DisAsmInfo64 info;
        module.DisAsm64(info);
        module.FixupAsm64(info);

        if (modes[MODE_DUMP_DISASM])
        {
            fprintf(stderr, "Dumping disassembly...\n");
            module.DumpDisAsm64(info);
        }
    }
    else
    {
        CR_NameScope namescope;
        namescope.Set64Bit(false);

        if (modes[MODE_DUMP_SEMANTIC])
        {
            fprintf(stderr, "Semantic analysis...\n");
            int result = CrSemanticAnalysis(namescope, tu);
            if (result)
                return result;

            tu = shared_ptr<TransUnit>();
            fprintf(stderr, "Dumping semantic...\n");
            CrDumpSemantic(namescope);
        }

        CR_DisAsmInfo32 info;
        module.DisAsm32(info);
        module.FixupAsm32(info);

        if (modes[MODE_DUMP_DISASM])
        {
            fprintf(stderr, "Dumping disassembly...\n");
            module.DumpDisAsm32(info);
        }
    }

    return cr_exit_ok;
}

////////////////////////////////////////////////////////////////////////////
