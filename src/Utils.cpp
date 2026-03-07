/**
 * @file Utils.cpp
 * @brief String, hex, and file utility implementations for seal.
 * @author seal Contributors
 */

#include "Utils.h"

#include <algorithm>

namespace seal::utils
{

std::string trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a]))
        ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1]))
        --b;
    return s.substr(a, b - a);
}

std::string stripQuotes(const std::string& s)
{
    if (s.size() >= 2 &&
        ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\'')))
        return s.substr(1, s.size() - 2);
    return s;
}

std::string basenameA(const std::string& p)
{
    size_t i = p.find_last_of("\\/");
    return (i == std::string::npos) ? p : p.substr(i + 1);
}

bool endsWithCi(const std::string& s, const char* suf)
{
    return ends_with_ci(std::string_view{s}, std::string_view{suf});
}

std::string stripSpaces(const std::string& s)
{
    std::string r;
    r.reserve(s.size());
    for (unsigned char c : s)
        if (!std::isspace(c))
            r.push_back((char)c);
    return r;
}

std::vector<std::string> extractHexTokens(const std::string& raw)
{
    std::vector<std::string> tokens;
    std::string cur;
    for (unsigned char c : raw)
    {
        if (std::isspace(c))
        {
            if (!cur.empty())
            {
                tokens.push_back(cur);
                cur.clear();
            }
        }
        else
        {
            cur.push_back((char)c);
        }
    }
    if (!cur.empty())
        tokens.push_back(cur);

    constexpr size_t min_hex_chars = (cfg::SALT_LEN + cfg::IV_LEN + cfg::TAG_LEN) * 2;
    std::vector<std::string> good;
    for (auto& t : tokens)
    {
        if ((t.size() % 2) == 0 && t.size() >= min_hex_chars)
        {
            bool allhex = std::all_of(
                t.begin(), t.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
            if (allhex)
                good.push_back(t);
        }
    }
    return good;
}

std::string add_ext(const std::string& s, std::string_view ext)
{
    return std::string(s) + std::string(ext);
}

std::string strip_ext_ci(const std::string& s, std::string_view ext)
{
    using CharT = char;
    if (s.size() >= ext.size() &&
        ends_with_ci(
            std::basic_string_view<CharT>(s.data(), s.size()).substr(s.size() - ext.size()), ext))
    {
        return s.substr(0, s.size() - ext.size());
    }
    return s;
}

bool fileExistsA(const std::string& path)
{
    DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool isDirectoryA(const std::string& path)
{
    DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string joinPath(const std::string& dir, const char* name)
{
    std::string r = dir;
    if (!r.empty() && r.back() != '\\' && r.back() != '/')
        r.push_back('\\');
    r.append(name);
    return r;
}

}  // namespace seal::utils
