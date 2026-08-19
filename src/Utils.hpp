#pragma once

#include "Cryptography.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace seal::utils
{

/**
 * @brief Small string, hex, Base64, path and file helpers shared by CLI and GUI.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Header-only where the operation is a template (hex, `read_bin`), out-of-line
 * where it needs OpenSSL or Win32. Three conventions hold across the file:
 *
 * - **ASCII-only case folding.** `A`-`Z` folds by setting bit 0x20; bytes above
 *   127 compare as-is, so no locale or code page is consulted. trim() and
 *   stripSpaces() classify with `std::isspace`, and the process never changes
 *   the locale, so they act on the C-locale ASCII set too.
 * - **ANSI path APIs.** fileExistsA() and isDirectoryA() read through the ANSI
 *   Win32 API: a path is interpreted in the process code page, and one the code
 *   page cannot represent reads as missing. basenameA() and joinPath() only
 *   manipulate the string and call no API, despite the naming.
 * - **No secure storage.** Only utf8ToSecureWide() returns locked memory; every
 *   other return value is a pageable `std::string` or vector.
 *
 * @see seal::Cryptography, seal::basic_secure_string
 */

/**
 * @brief Case-insensitive suffix check (ASCII fold).
 * @ingroup Utilities
 * @return `true` when @p s ends with @p suf, ignoring case.
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
 * @return A copy of @p s with leading and trailing whitespace removed.
 */
[[nodiscard]] std::string trim(const std::string& s);

/**
 * @brief Remove surrounding single or double quotes from a string.
 * @ingroup Utilities
 * @param s Input string (e.g. `"\"hello\""` or `"'hello'"`).
 * @return A copy with the outermost matching quotes stripped, or @p s unchanged.
 */
[[nodiscard]] std::string stripQuotes(const std::string& s);

/**
 * @brief Get the basename of a file path (filename without directory).
 * @ingroup Utilities
 *
 * Splits on the last `\` or `/`, so both separator styles work in one string.
 * Nothing is normalised: a trailing separator yields an empty result.
 *
 * @return The trailing filename component, or @p p unchanged when it holds
 *         no separator.
 */
[[nodiscard]] std::string basenameA(const std::string& p);

/**
 * @brief Case-insensitive suffix check wrapper for narrow strings.
 * @ingroup Utilities
 * @return `true` when @p s ends with @p suf, ignoring case.
 *
 * @pre @p suf is not null; it is wrapped in a `std::string_view` without a
 *      null check.
 */
[[nodiscard]] bool endsWithCi(const std::string& s, const char* suf);

/**
 * @brief Encode a byte range as lowercase hex.
 * @ingroup Utilities
 * @return Lowercase hex string, two characters per byte.
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
 *
 * Accepts both cases (`a`-`f` and `A`-`F`). Decoding stops at the first invalid
 * pair, and the bytes written before that point stay written, so the caller
 * discards whatever it collected on failure.
 *
 * @param hex Hex-encoded input; must be non-empty and of even length.
 * @param out Output iterator receiving decoded bytes.
 * @return `true` on success, `false` on empty, odd-length, or invalid hex input.
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
 * @param out Cleared on entry, then filled with the decoded bytes. On failure it
 *            can hold a partial prefix: the bytes decoded before the invalid
 *            character.
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
 * @brief Remove every whitespace character from a string.
 * @ingroup Utilities
 * @return A copy with all whitespace removed.
 */
[[nodiscard]] std::string stripSpaces(const std::string& s);

/**
 * @brief Extract candidate hex tokens from free text.
 * @ingroup Utilities
 *
 * Splits @p raw on whitespace and keeps a token when its length is even, reaches
 * the framing minimum below, and every character is a hex digit. Case is
 * preserved and tokens come back in input order.
 *
 * @param raw Input text that may contain hex-encoded data.
 * @return Hex token strings. The 88-char discard threshold is deliberately below
 *         the 104-char true minimum packet length, so the length test never
 *         discards a real packet.
 *
 * @par Framing overhead
 * Byte sizes are the @c cfg constants `SALT_LEN`, `IV_LEN`, `TAG_LEN` and
 * `HDR_LEN`; hex encodes two chars per byte:
 * | Component         | Bytes | Hex chars |
 * |-------------------|-------|-----------|
 * | Salt              | 16    | 32        |
 * | IV                | 12    | 24        |
 * | Tag               | 16    | 32        |
 * | Discard threshold | 44    | 88        |
 * | AAD header        | 8     | 16        |
 * | True min packet   | 52    | 104       |
 */
[[nodiscard]] std::vector<std::string> extractHexTokens(const std::string& raw);

/**
 * @brief Read an entire file into a contiguous container.
 * @ingroup Utilities
 *
 * Opens the file in binary mode and sizes @p out by seeking to the end, so the
 * whole file is held in memory at once with no text translation. The
 * destination is pageable memory and cannot hold a secret that must stay
 * unpageable.
 *
 * @tparam PathLike Path-like type convertible to `std::filesystem::path`.
 * @tparam Cont     Contiguous container of byte-like or char elements.
 * @param out Resized to the exact file size in bytes. It keeps that size even
 *            when the read fails, so its tail can hold value-initialised bytes;
 *            discard it unless `true` is returned.
 * @return `true` on success. `false` when the file cannot be opened or read,
 *         when the reported size is negative, or when no
 *         `std::filesystem::path` can be built from @p p - in that last case
 *         @p out is left untouched.
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
 *
 * Plain concatenation: no dot is inserted and no existing extension is replaced.
 *
 * @param ext Extension to append. It carries its own leading dot (e.g. `".seal"`).
 * @return Concatenated path string.
 */
[[nodiscard]] std::string add_ext(const std::string& s, std::string_view ext);

/**
 * @brief Remove a trailing extension case-insensitively.
 * @ingroup Utilities
 * @param ext Extension to strip (e.g. `".seal"`).
 * @return Path with @p ext removed, or @p s unchanged when it does not end with
 *         @p ext.
 */
[[nodiscard]] std::string strip_ext_ci(const std::string& s, std::string_view ext);

/**
 * @brief Check whether a path refers to an existing non-directory entry.
 * @ingroup Utilities
 *
 * Reads `GetFileAttributesA`, with the ANSI constraint above. The test excludes
 * directories only: every other entry whose attributes can be read, a reparse
 * point included, reports `true`.
 *
 * @return `true` when the attributes could be read and the entry is not a
 *         directory.
 */
[[nodiscard]] bool fileExistsA(const std::string& path);

/**
 * @brief Test whether a path refers to a directory.
 * @ingroup Utilities
 *
 * Same ANSI-API constraint as fileExistsA().
 *
 * @return `true` when the path exists and is a directory.
 */
[[nodiscard]] bool isDirectoryA(const std::string& path);

/**
 * @brief Join a directory and a leaf name with a backslash.
 * @ingroup Utilities
 *
 * The separator is inserted only when needed: an empty @p dir, or one already
 * ending in `\` or `/`, is concatenated as-is. @p name is appended verbatim, so
 * a leading separator on it produces a doubled separator.
 *
 * @param name Leaf filename.
 * @return `dir\name`.
 *
 * @pre @p name is not null; it is appended without a null check.
 */
[[nodiscard]] std::string joinPath(const std::string& dir, const char* name);

/**
 * @brief Convert a UTF-8 string to a secure wide string.
 * @ingroup Utilities
 *
 * The result holds exactly the converted UTF-16 code units and no trailing null,
 * so a caller that needs a C string appends one. A character outside the BMP
 * becomes a surrogate pair, so the unit count can exceed the character count.
 * The conversion does not pass `MB_ERR_INVALID_CHARS`: an ill-formed byte
 * sequence becomes U+FFFD instead of failing.
 *
 * @param utf8 Input UTF-8 string. It stays in pageable memory and the caller
 *             wipes it.
 * @return Wide string in locked, guard-paged memory. Empty when @p utf8 is empty
 *         or the conversion fails; failure is not reported separately.
 */
[[nodiscard]] seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> utf8ToSecureWide(
    const std::string& utf8);

/**
 * @brief Convert a secure wide string to a UTF-8 std::string.
 * @ingroup Utilities
 *
 * Inverse of utf8ToSecureWide(). Converts exactly `wide.size()` code units and
 * adds no trailing null, so an embedded null is preserved rather than ending the
 * string.
 *
 * @return UTF-8 string in regular heap memory. Empty when @p wide is empty or
 *         the conversion fails; failure is not reported separately.
 * @warning The returned std::string is not locked memory and can be swapped to
 *          disk. Use it only when an insecure copy is acceptable.
 */
[[nodiscard]] std::string secureWideToUtf8(
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& wide);

/**
 * @brief Encode binary data as a Base64 string.
 * @ingroup Utilities
 *
 * Standard alphabet with `=` padding and no line breaks (OpenSSL
 * `EVP_EncodeBlock`). The result is not locked memory, so it must not hold a
 * secret that has to stay unpageable.
 *
 * @return Base64-encoded string, empty when @p data is empty.
 */
[[nodiscard]] std::string toBase64(std::span<const unsigned char> data);

/**
 * @brief Decode a Base64 string to raw bytes.
 * @ingroup Utilities
 *
 * Wraps `EVP_DecodeBlock`, which needs a length that is a multiple of 4 and
 * rejects embedded whitespace or newlines, so strip those first. The padding
 * bytes `EVP_DecodeBlock` leaves behind are trimmed here by counting the
 * trailing `=` characters of the input.
 *
 * @param b64 Base64-encoded input. The alphabet is not validated: pair this with
 *            isBase64() when the input is untrusted.
 * @return Decoded bytes, or an empty vector on empty or invalid input.
 */
[[nodiscard]] std::vector<unsigned char> fromBase64(const std::string& b64);

/**
 * @brief Check whether a string looks like valid Base64.
 * @ingroup Utilities
 *
 * The hex-ambiguity check below is what stops a pure-hex string from being
 * misrouted through Base64 decoding by the string-mode dispatchers.
 *
 * @return `true` only when all three checks in the table hold.
 *
 * @par Classification predicate
 * | Check         | Requirement                                                |
 * |---------------|------------------------------------------------------------|
 * | Length        | at least 4 and a multiple of 4                             |
 * | Alphabet      | every char in `A`-`Z` `a`-`z` `0`-`9` `+` `/` `=`          |
 * | Hex-ambiguity | at least one char in `G`-`Z` `g`-`z` `+` `/` `=` (non-hex) |
 */
[[nodiscard]] bool isBase64(const std::string& s);

}  // namespace seal::utils
