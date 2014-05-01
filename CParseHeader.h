////////////////////////////////////////////////////////////////////////////
// CParseHeader.h
// Copyright (C) 2014 Katayama Hirofumi MZ.  All rights reserved.
////////////////////////////////////////////////////////////////////////////
// This file is part of CodeReverse.
////////////////////////////////////////////////////////////////////////////

#ifndef CPARSEHEADER_H_
#define CPARSEHEADER_H_

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
    template <class Iterator>
    bool parse(shared_ptr<TransUnit>& tu, Iterator begin, Iterator end)
    {
        using namespace cparser;
        ParserSite ps;
        Scanner<Iterator, ParserSite> scanner(ps);

        std::vector<TokenValue > infos;
        scanner.scan(infos, begin, end);
        //scanner.show_tokens(infos.begin(), infos.end());

        //printf("\n--------------\n");
        Parser<shared_ptr<Node>, ParserSite> parser(ps);
        std::vector<TokenValue >::iterator it, end2 = infos.end();
        for (it = infos.begin(); it != end2; ++it)
        {
            //printf("%s\n", scanner.token_to_string(*it));
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
            printf("parser accepted!\n");
            tu = static_pointer_cast<TransUnit, Node>(node);
            return true;
        }

        return false;
    }

    inline bool parse_string(shared_ptr<TransUnit>& ts, const char *s)
    {
        return parse(ts, s, s + std::strlen(s));
    }

    inline bool parse_string(shared_ptr<TransUnit>& ts, const std::string& str)
    {
        return parse(ts, str.begin(), str.end());
    }

    inline bool parse_file(shared_ptr<TransUnit>& ts, const char *filename)
    {
        std::ifstream file(filename);
        if (file.is_open())
        {
            std::istreambuf_iterator<char> begin(file), end;
            bool ok = parse(ts, begin, end);
            file.close();
            return ok;
        }
        return false;
    }
} // namespace cparser

#endif  // ndef CPARSEHEADER_H_
