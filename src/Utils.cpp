#include "Utils.hpp"

#include <openssl/evp.h>

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

    // Minimum hex length: salt + IV + GCM tag (each *2 for hex). Shorter
    // tokens cannot be real ciphertext; filter to avoid false matches.
    constexpr size_t min_hex_chars = (cfg::SALT_LEN + cfg::IV_LEN + cfg::TAG_LEN) * 2;
    std::vector<std::string> good;
    for (auto& t : tokens)
    {
        // Even length, >= header minimum, all xdigit.
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
    std::string result;
    result.reserve(s.size() + ext.size());
    result.append(s);
    result.append(ext);
    return result;
}

std::string strip_ext_ci(const std::string& s, std::string_view ext)
{
    if (ends_with_ci(std::string_view{s}, ext))
        return s.substr(0, s.size() - ext.size());
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

// UTF-8 -> VirtualLock'd wchar_t string (Win32 size-then-convert pattern).
seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> utf8ToSecureWide(
    const std::string& utf8)
{
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> result;
    if (utf8.empty())
        return result;
    int need = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (need > 0)
    {
        result.resize(need);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), result.data(), need);
    }
    return result;
}

// Inverse of utf8ToSecureWide; output is NOT locked memory -- caller
// must cleanse promptly after use.
std::string secureWideToUtf8(
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& wide)
{
    if (wide.empty())
        return {};
    int need = WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
    std::string out(need, '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), (int)wide.size(), out.data(), need, nullptr, nullptr);
    return out;
}

std::string toBase64(std::span<const unsigned char> data)
{
    if (data.empty())
        return {};
    // 4 * ceil(n/3) + 1 (NUL).
    size_t outLen = 4 * ((data.size() + 2) / 3) + 1;
    std::string out(outLen, '\0');
    int written = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(out.data()), data.data(), static_cast<int>(data.size()));
    out.resize(static_cast<size_t>(written));
    return out;
}

std::vector<unsigned char> fromBase64(const std::string& b64)
{
    if (b64.empty())
        return {};
    // 3 * ceil(n/4).
    size_t maxOut = 3 * ((b64.size() + 3) / 4);
    std::vector<unsigned char> out(maxOut);
    int written = EVP_DecodeBlock(out.data(),
                                  reinterpret_cast<const unsigned char*>(b64.data()),
                                  static_cast<int>(b64.size()));
    if (written < 0)
        return {};
    // Trim padding '=' (EVP_DecodeBlock doesn't account for it).
    size_t pad = 0;
    if (b64.size() >= 2 && b64[b64.size() - 1] == '=')
        ++pad;
    if (b64.size() >= 2 && b64[b64.size() - 2] == '=')
        ++pad;
    out.resize(static_cast<size_t>(written) - pad);
    return out;
}

bool isBase64(const std::string& s)
{
    if (s.empty() || s.size() < 4)
    {
        return false;
    }
    // Base64 output is always a multiple of 4.
    if (s.size() % 4 != 0)
    {
        return false;
    }
    // Require >=1 character that distinguishes Base64 from hex (G-Z, g-z,
    // '+', '/', '='). Otherwise pure hex would pass the alphabet check and
    // get misrouted through Base64 decode in handleStringMode.
    bool hasNonHex = false;
    for (char c : s)
    {
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
              c == '+' || c == '/' || c == '='))
        {
            return false;
        }
        if ((c >= 'G' && c <= 'Z') || (c >= 'g' && c <= 'z') || c == '+' || c == '/' || c == '=')
        {
            hasNonHex = true;
        }
    }
    return hasNonHex;
}

}  // namespace seal::utils
