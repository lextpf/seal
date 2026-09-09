#pragma once

#include "Cryptography.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace seal::utils
{

/**
 * @brief shared byte, encoding and path helpers.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * case folding is ASCII-only; whitespace uses std::isspace in the unchanged C locale.
 * fileExistsA/isDirectoryA use the process ANSI code page; unrepresentable paths appear missing.
 * basenameA/joinPath manipulate strings without I/O.
 * only utf8ToSecureWide returns locked storage; other results are pageable.
 */

/**
 * @brief compare suffix bytes with ASCII-only case folding.
 * @ingroup Utilities
 */
template <class CharT>
[[nodiscard]] constexpr bool ends_with_ci(std::basic_string_view<CharT> s,
                                          std::basic_string_view<CharT> suf)
{
    if (s.size() < suf.size())
        return false;
    const size_t off = s.size() - suf.size();
    auto tolow = [](CharT c) constexpr -> CharT
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<CharT>(c | 0x20);
        return c;
    };
    for (size_t i = 0; i < suf.size(); ++i)
    {
        if (tolow(s[off + i]) != tolow(suf[i]))
            return false;
    }
    return true;
}

/**
 * @brief copy without leading or trailing C-locale whitespace.
 * @ingroup Utilities
 */
[[nodiscard]] std::string trim(const std::string& s);

/**
 * @brief strip only a matching outermost pair of single or double quotes.
 * @ingroup Utilities
 */
[[nodiscard]] std::string stripQuotes(const std::string& s);

/**
 * @brief split at the final slash or backslash without normalization.
 * @ingroup Utilities
 *
 * trailing separators yield empty output; no separator returns the whole input.
 */
[[nodiscard]] std::string basenameA(const std::string& p);

/**
 * @brief apply ASCII suffix comparison to a non-null C-string suffix.
 * @ingroup Utilities
 *
 * @pre suf is not nullptr.
 */
[[nodiscard]] bool endsWithCi(const std::string& s, const char* suf);

/**
 * @brief emit two lowercase hex characters per byte.
 * @ingroup Utilities
 */
template <std::ranges::input_range R>
    requires byte_like<std::ranges::range_value_t<R>>
[[nodiscard]] constexpr std::string to_hex(R&& range)
{
    std::string out;
    constexpr auto hex_str = "0123456789abcdef";
    for (auto&& byte : range)
    {
        const auto b = static_cast<unsigned char>(byte);
        out.push_back(hex_str[b >> 4]);
        out.push_back(hex_str[b & 0x0F]);
    }
    return out;
}

/**
 * @brief decode either hex case, retaining bytes written before an invalid pair.
 * @ingroup Utilities
 *
 * @return false for empty, odd-length or invalid input; discard partial output.
 */
[[nodiscard]] constexpr bool from_hex_sv(std::string_view hex,
                                         std::output_iterator<unsigned char> auto out)
{
    constexpr auto nib = [](unsigned char c) constexpr -> int
    {
        if (c >= '0' && c <= '9')
            return c - '0';
        c |= 0x20;
        if (c >= 'a' && c <= 'f')
            return 10 + (c - 'a');
        return -1;
    };
    if (hex.empty() || (hex.size() & 1))
        return false;
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const auto hi = nib(static_cast<unsigned char>(hex[i]));
        const auto lo = nib(static_cast<unsigned char>(hex[i + 1]));
        if ((hi | lo) < 0)
            return false;
        *out++ = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

/**
 * @brief clear the destination, then decode either hex case.
 * @ingroup Utilities
 *
 * @return false on invalid input; out can retain a decoded prefix.
 */
template <std::ranges::contiguous_range Cont>
    requires byte_like<std::ranges::range_value_t<Cont>>
[[nodiscard]] constexpr bool from_hex(std::string_view hex, Cont& out)
{
    out.clear();
    out.reserve(hex.size() / 2);
    return from_hex_sv(hex, std::back_inserter(out));
}

/**
 * @brief copy without C-locale whitespace, including interior whitespace.
 * @ingroup Utilities
 */
[[nodiscard]] std::string stripSpaces(const std::string& s);

/**
 * @brief retain even-length hex tokens of at least 88 characters in input order.
 * @ingroup Utilities
 *
 * split on whitespace and preserve case. the threshold omits AAD overhead and stays below the
 * true 104-character minimum packet size.
 *
 * | framing part    | bytes | hex characters |
 * |-----------------|-------|----------------|
 * | salt + IV + tag | 44    | 88             |
 * | AAD             | 8     | 16             |
 * | minimum packet  | 52    | 104            |
 */
[[nodiscard]] std::vector<std::string> extractHexTokens(const std::string& raw);

/**
 * @brief buffer an entire binary file using its queried byte size.
 * @ingroup Utilities
 *
 * the destination keeps its resized length on read failure; discard it unless true is returned.
 *
 * @return false for open/read failure or negative size. path-construction failure returns false
 *         without changing out.
 */
template <std::ranges::range PathLike, std::ranges::contiguous_range Cont>
    requires(byte_like<std::ranges::range_value_t<Cont>> ||
             std::same_as<std::ranges::range_value_t<Cont>, char>)
[[nodiscard]] constexpr bool read_bin(const PathLike& p, Cont& out)
{
    if constexpr (requires { std::filesystem::path{p}; })
    {
        std::ifstream in(std::filesystem::path{p}, std::ios::binary);
        if (!in)
            return false;
        in.seekg(0, std::ios::end);
        const auto sz = in.tellg();
        if (sz < 0)
            return false;
        out.resize(static_cast<size_t>(sz));
        in.seekg(0, std::ios::beg);
        if (sz > 0)
            in.read(reinterpret_cast<char*>(out.data()), sz);
        return static_cast<bool>(in);
    }
    else
    {
        return false;
    }
}

/**
 * @brief concatenate a suffix without adding a dot or replacing an extension.
 * @ingroup Utilities
 */
[[nodiscard]] std::string add_ext(const std::string& s, std::string_view ext);

/**
 * @brief remove a matching suffix using ASCII-insensitive comparison.
 * @ingroup Utilities
 */
[[nodiscard]] std::string strip_ext_ci(const std::string& s, std::string_view ext);

/**
 * @brief accept readable ANSI attributes for any non-directory entry, including reparse points.
 * @ingroup Utilities
 */
[[nodiscard]] bool fileExistsA(const std::string& path);

/**
 * @brief test the directory attribute using the process ANSI code page.
 * @ingroup Utilities
 */
[[nodiscard]] bool isDirectoryA(const std::string& path);

/**
 * @brief insert a backslash unless the directory is empty or already ends in a separator.
 * @ingroup Utilities
 *
 * name is appended verbatim; a leading separator can produce a doubled separator.
 *
 * @pre name is not nullptr.
 */
[[nodiscard]] std::string joinPath(const std::string& dir, const char* name);

/**
 * @brief convert to locked UTF-16 without a terminator.
 * @ingroup Utilities
 *
 * invalid sequences become U+FFFD; non-BMP characters occupy two code units.
 *
 * @param utf8 caller retains and wipes the pageable input.
 * @return empty on empty input or conversion failure; these cases are indistinguishable.
 */
[[nodiscard]] seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> utf8ToSecureWide(
    const std::string& utf8);

/**
 * @brief convert all UTF-16 units to pageable UTF-8, preserving embedded nulls.
 * @ingroup Utilities
 *
 * @return empty on empty input or conversion failure; these cases are indistinguishable.
 * @warning cleanse returned secrets after use.
 */
[[nodiscard]] std::string secureWideToUtf8(
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& wide);

/**
 * @brief encode standard Base64 with padding and no line breaks.
 * @ingroup Utilities
 *
 * @return pageable output; empty for empty input.
 */
[[nodiscard]] std::string toBase64(std::span<const unsigned char> data);

/**
 * @brief decode Base64 and remove bytes represented by trailing padding.
 * @ingroup Utilities
 *
 * requires a multiple-of-four length; strip embedded whitespace first.
 *
 * @param b64 use isBase64 as the dispatch check for untrusted input.
 * @return empty for empty or invalid input.
 */
[[nodiscard]] std::vector<unsigned char> fromBase64(const std::string& b64);

/**
 * @brief distinguish Base64 candidates from pure hex before dispatch.
 * @ingroup Utilities
 *
 * | check    | requirement                      |
 * |----------|----------------------------------|
 * | length   | at least 4; multiple of 4        |
 * | alphabet | A-Z, a-z, 0-9, +, / or =         |
 * | non-hex  | at least one G-Z, g-z, +, / or = |
 */
[[nodiscard]] bool isBase64(const std::string& s);

}  // namespace seal::utils
