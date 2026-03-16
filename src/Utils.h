#pragma once

#include "Cryptography.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace seal::utils
{

/**
 * @brief Case-insensitive suffix check (ASCII fold).
 * @ingroup Utilities
 * @tparam CharT Character type.
 * @param s   String to test.
 * @param suf Suffix to look for.
 * @return `true` if @p s ends with @p suf (case-insensitive).
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
 * @brief Trim leading and trailing whitespace from a string.
 * @ingroup Utilities
 * @param s Input string.
 * @return A copy of @p s with leading/trailing whitespace removed.
 */
[[nodiscard]] std::string trim(const std::string& s);

/**
 * @brief Remove surrounding quotes (single or double) from a string.
 * @ingroup Utilities
 * @param s Input string (e.g. `"\"hello\""` or `"'hello'"`).
 * @return A copy with the outermost matching quotes stripped, or @p s unchanged.
 */
[[nodiscard]] std::string stripQuotes(const std::string& s);

/**
 * @brief Get the basename of a file path (filename without directory).
 * @ingroup Utilities
 * @param p File path.
 * @return The trailing filename component.
 */
[[nodiscard]] std::string basenameA(const std::string& p);

/**
 * @brief Case-insensitive suffix check wrapper for narrow strings.
 * @ingroup Utilities
 * @param s   String to test.
 * @param suf Null-terminated suffix to look for.
 * @return `true` if @p s ends with @p suf (case-insensitive).
 */
[[nodiscard]] bool endsWithCi(const std::string& s, const char* suf);

/**
 * @brief Encode a byte range as lowercase hex.
 * @ingroup Utilities
 * @tparam R Input range of byte-like elements.
 * @param range Bytes to encode.
 * @return Lowercase hex string (two characters per byte).
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
 * @brief Decode a hex string_view into an output iterator.
 * @ingroup Utilities
 * @param hex Hex-encoded input (must be even length).
 * @param out Output iterator receiving decoded bytes.
 * @return `true` on success, `false` on odd-length or invalid hex characters.
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
 * @brief Decode hex into a contiguous container.
 * @ingroup Utilities
 * @tparam Cont Contiguous byte-like container (e.g. `std::vector<unsigned char>`).
 * @param hex Hex-encoded input.
 * @param out Destination container (cleared and resized).
 * @return `true` on success, `false` on invalid hex.
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
 * @brief Remove all whitespace characters from a string.
 * @ingroup Utilities
 * @param s Input string.
 * @return A copy with all whitespace removed.
 */
[[nodiscard]] std::string stripSpaces(const std::string& s);

/**
 * @brief Extract candidate hex tokens from free text.
 * @ingroup Utilities
 * @param raw Input text potentially containing hex-encoded data.
 * @return Vector of hex token strings. Tokens shorter than the minimum
 *         AES-256-GCM packet size (AAD + salt + IV + tag = 98 hex chars)
 *         are discarded.
 */
[[nodiscard]] std::vector<std::string> extractHexTokens(const std::string& raw);

/**
 * @brief Read an entire file into a contiguous container.
 * @ingroup Utilities
 * @tparam PathLike Path-like type convertible to `std::filesystem::path`.
 * @tparam Cont     Contiguous container of byte-like or char elements.
 * @param p   File path.
 * @param out Destination container (resized to exact file size in bytes).
 * @return `true` on success, `false` if the file cannot be opened, read,
 *         or if the reported size is negative.
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
 * @brief Append a suffix/extension to a path string.
 * @ingroup Utilities
 * @param s   Base path.
 * @param ext Extension to append (e.g. `".seal"`).
 * @return Concatenated path string.
 */
[[nodiscard]] std::string add_ext(const std::string& s, std::string_view ext);

/**
 * @brief Remove a trailing extension case-insensitively.
 * @ingroup Utilities
 * @param s   Path string.
 * @param ext Extension to strip (e.g. `".seal"`).
 * @return Path with @p ext removed, or @p s unchanged if it doesn't end with @p ext.
 */
[[nodiscard]] std::string strip_ext_ci(const std::string& s, std::string_view ext);

/**
 * @brief Check whether a path refers to an existing file.
 * @ingroup Utilities
 * @param path File path to test.
 * @return `true` if the path exists and is a regular file.
 */
[[nodiscard]] bool fileExistsA(const std::string& path);

/**
 * @brief Test whether a path refers to a directory.
 * @ingroup Utilities
 * @param path Path to test.
 * @return `true` if the path exists and is a directory.
 */
[[nodiscard]] bool isDirectoryA(const std::string& path);

/**
 * @brief Join a directory and a leaf name with a backslash.
 * @ingroup Utilities
 * @param dir  Directory path.
 * @param name Leaf filename.
 * @return `dir\name`.
 */
[[nodiscard]] std::string joinPath(const std::string& dir, const char* name);

/**
 * @brief Convert a UTF-8 string to a secure wide string.
 * @ingroup Utilities
 * @param utf8 Input UTF-8 string.
 * @return Wide string in locked, guard-paged memory.
 */
[[nodiscard]] seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> utf8ToSecureWide(
    const std::string& utf8);

/**
 * @brief Convert a secure wide string to a UTF-8 std::string.
 * @ingroup Utilities
 * @param wide Input secure wide string.
 * @return UTF-8 string in regular heap memory.
 * @warning The returned std::string is **not** in locked memory and may be
 *          swapped to disk. Use only when an insecure copy is acceptable.
 */
[[nodiscard]] std::string secureWideToUtf8(
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& wide);

/**
 * @brief Encode binary data as a Base64 string.
 * @ingroup Utilities
 * @param data Raw bytes to encode.
 * @return Base64-encoded string.
 */
[[nodiscard]] std::string toBase64(std::span<const unsigned char> data);

/**
 * @brief Decode a Base64 string to raw bytes.
 * @ingroup Utilities
 * @param b64 Base64-encoded input.
 * @return Decoded bytes, or empty vector on invalid input.
 */
[[nodiscard]] std::vector<unsigned char> fromBase64(const std::string& b64);

/**
 * @brief Check whether a string looks like valid Base64.
 * @ingroup Utilities
 * @param s String to test.
 * @return `true` if the string contains only Base64 characters.
 */
[[nodiscard]] bool isBase64(const std::string& s);

}  // namespace seal::utils
