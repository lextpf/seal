#pragma once

#include "Cryptography.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace seal::utils
{

/// @brief Case-insensitive suffix check (ASCII fold).
/// @ingroup Utilities
template <class CharT>
[[nodiscard]] constexpr bool ends_with_ci(std::basic_string_view<CharT> s,
                                          std::basic_string_view<CharT> suf)
{
    if (s.size() < suf.size())
        return false;
    const size_t off = s.size() - suf.size();
    auto tolow = [](CharT c) constexpr -> CharT
    {
        if constexpr (sizeof(CharT) == 1)
        {
            if (c >= 'A' && c <= 'Z')
                c = static_cast<CharT>(c | 0x20);
        }
        else
        {
            if (c >= 'A' && c <= 'Z')
                c = static_cast<CharT>(c | 0x20);
        }
        return c;
    };
    for (size_t i = 0; i < suf.size(); ++i)
    {
        if (tolow(s[off + i]) != tolow(suf[i]))
            return false;
    }
    return true;
}

/// @brief Trim leading and trailing whitespace from a string.
/// @ingroup Utilities
[[nodiscard]] std::string trim(const std::string& s);

/// @brief Remove surrounding quotes (single or double) from a string.
/// @ingroup Utilities
[[nodiscard]] std::string stripQuotes(const std::string& s);

/// @brief Get the basename of a file path.
/// @ingroup Utilities
[[nodiscard]] std::string basenameA(const std::string& p);

/// @brief Case-insensitive suffix check wrapper.
/// @ingroup Utilities
[[nodiscard]] bool endsWithCi(const std::string& s, const char* suf);

/// @brief Encode a byte range as lowercase hex.
/// @ingroup Utilities
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

/// @brief Decode a hex string_view into an output iterator.
/// @ingroup Utilities
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

/// @brief Decode hex into a contiguous container.
/// @ingroup Utilities
template <std::ranges::contiguous_range Cont>
    requires byte_like<std::ranges::range_value_t<Cont>>
[[nodiscard]] constexpr bool from_hex(std::string_view hex, Cont& out)
{
    out.clear();
    out.reserve(hex.size() / 2);
    return from_hex_sv(hex, std::back_inserter(out));
}

/// @brief Remove all whitespace characters from a string.
/// @ingroup Utilities
[[nodiscard]] std::string stripSpaces(const std::string& s);

/// @brief Extract candidate hex tokens from free text.
/// @ingroup Utilities
[[nodiscard]] std::vector<std::string> extractHexTokens(const std::string& raw);

/// @brief Read an entire file into a contiguous container.
/// @ingroup Utilities
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

/// @brief Append a suffix/extension to a path string.
/// @ingroup Utilities
[[nodiscard]] std::string add_ext(const std::string& s, std::string_view ext);

/// @brief Remove a trailing extension case-insensitively.
/// @ingroup Utilities
[[nodiscard]] std::string strip_ext_ci(const std::string& s, std::string_view ext);

/// @brief Check whether a path refers to an existing file.
/// @ingroup Utilities
[[nodiscard]] bool fileExistsA(const std::string& path);

/// @brief Test whether a path refers to a directory.
/// @ingroup Utilities
[[nodiscard]] bool isDirectoryA(const std::string& path);

/// @brief Join a directory and a leaf name with a backslash.
/// @ingroup Utilities
[[nodiscard]] std::string joinPath(const std::string& dir, const char* name);

}  // namespace seal::utils
