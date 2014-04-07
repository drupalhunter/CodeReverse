////////////////////////////////////////////////////////////////////////////
// CParser.h
// Copyright (C) 2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#ifndef CPARSER_H_
#define CPARSER_H_

#include "CScanner.hpp"      // cparser::Scanner
#include "CParserSite.hpp"   // cparser::ParserSite
#include "CParserAST.hpp"    // cparser::Node, cparser::TokenInfo
#include "CParser.hpp"       // cparser::Parser

#include <cstring>      // std::strlen
#include <vector>       // std::vector
#include <istream>      // std::ifstream
#include <fstream>      // std::ifstream
#include <iterator>     // std::istreambuf_iterator

namespace cparser
{
    template <class CompilerSite, class Iterator>
    bool parse(CompilerSite& cs, Iterator begin, Iterator end)
    {
        using namespace cparser;
        ParserSite ps;
        Scanner<Iterator, ParserSite> scanner(ps);

        std::vector<TokenValue > infos;
        scanner.scan(infos, begin, end);
        //scanner.show_tokens(infos.begin(), infos.end());

        //std::cout << std::endl << "--------------" << std::endl;
        Parser<shared_ptr<Node>, ParserSite> parser(ps);
        std::vector<TokenValue >::iterator it, end2 = infos.end();
        for (it = infos.begin(); it != end2; ++it)
        {
            //std::cout << scanner.token_to_string(*it) << std::endl;
            if (parser.post(it->m_token, make_shared<TokenValue >(*it)))
            {
                if (parser.error())
                {
                    ps.location() = it->location();
                    ps.message(std::string("ERROR: syntax error near ") +
                        scanner.token_to_string(*it));
                }
                break;
            }
        }

        shared_ptr<Node> node;
        if (parser.accept(node))
        {
            //std::cerr << "Accepted!" << std::endl;
            shared_ptr<TransUnit> trans_unit;
            trans_unit = static_pointer_cast<TransUnit, Node>(node);
            return ps.compile(cs, *trans_unit.get());
        }

        return false;
    }

    template <class CompilerSite>
    bool parse_string(CompilerSite& cs, const char *s)
    {
        return parse(cs, s, s + std::strlen(s));
    }

    template <class CompilerSite>
    bool parse_string(CompilerSite& cs, const std::string& str)
    {
        return parse(cs, str.begin(), str.end());
    }

    template <class CompilerSite>
    bool parse_file(CompilerSite& cs, const char *filename)
    {
        std::ifstream file(filename);
        if (file.is_open())
        {
            std::istreambuf_iterator<char> begin(file), end;
            bool ok = parse(cs, begin, end);
            file.close();
            return ok;
        }
        return false;
    }

    template <class CompilerSite>
    bool parse_file(CompilerSite& cs, const wchar_t *filename)
    {
        std::ifstream file(filename);
        if (file.is_open())
        {
            std::istreambuf_iterator<char> begin(file), end;
            bool ok = parse(cs, begin, end);
            file.close();
            return ok;
        }
        return false;
    }
} // namespace cparser

#endif  // ndef CPARSER_H_
