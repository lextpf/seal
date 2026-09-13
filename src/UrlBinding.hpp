#pragma once

/**
 * @brief Bind browser release to stored domains and provide display-only fuzzy matching.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * Extension-driven browser credential gates must use platformMatchesHostForSecretRelease.
 * hostsMatch authorizes equal hosts and child page hosts, never parents or siblings.
 * extractKey/keysMatch discard TLDs and cannot authorize secrets.
 *
 * Functions are pure and thread-safe. isPublicSuffix, hostsMatch, and keysMatch
 * allocate nothing; extractors return owned strings.
 *
 * The curated suffix snapshot uses an implicit final-label fallback. Missing
 * multi-label rules are permissive: unlisted co.zw appears registrable and could
 * authorize all children; bank.co.zw displays as co. Edit scripts/public_suffixes.txt
 * and regenerate PublicSuffixTable.hpp instead of editing the generated table.
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart TD
 *     classDef step fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
 *     classDef branch fill:#4a3520,stroke:#f59e0b,color:#e2e8f0
 *     classDef out fill:#1e4a3a,stroke:#22c55e,color:#e2e8f0
 *
 *     IN([input]):::step
 *     HOST{extractHost<br/>succeeds?}:::branch
 *     LABEL[take registrable label<br/>strip dashes / underscores]:::step
 *     TOK[tokenise on non-alnum<br/>drop stop-words<br/>first >= 4 chars, else any]:::step
 *     KEY([normalised key]):::out
 *     NONE([empty = no key]):::branch
 *     EQ([keysMatch<br/>= equality]):::out
 *
 *     IN --> HOST
 *     HOST -->|yes, hostname / URL| LABEL
 *     HOST -->|no, free-form label| TOK
 *     LABEL -->|single label or<br/>registrable domain| KEY
 *     LABEL -->|multi-label public suffix| NONE
 *     TOK -->|brand token found| KEY
 *     TOK -->|non-ASCII or all stop-words| NONE
 *     KEY --> EQ
 * ```
 */

#include "PublicSuffixTable.hpp"

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace seal::url
{

namespace detail
{

/**
 * @fn char asciiLower(char c) noexcept
 * @brief Lower-case one ASCII letter.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Bytes outside `A`-`Z` are returned unchanged.
 */
inline char asciiLower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

/**
 * @fn bool isHostChar(char c) noexcept
 * @brief Test the ASCII character set accepted by host extraction.
 * @author Alex (<https://github.com/lextpf>)
 */
inline bool isHostChar(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '-' || c == '_';
}

/**
 * @fn bool hasDotAlignedSuffix(std::string_view host, std::string_view suffix) noexcept
 * @brief Match an exact suffix or a dot-aligned tail.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Dot alignment prevents notgoogle.com from matching google.com.
 *
 * @pre `suffix` is non-empty with no leading dot. Empty suffixes are not rejected
 *      and match only empty or dot-terminated hosts.
 */
inline bool hasDotAlignedSuffix(std::string_view host, std::string_view suffix) noexcept
{
    return host == suffix ||
           (host.size() > suffix.size() && host[host.size() - suffix.size() - 1] == '.' &&
            host.substr(host.size() - suffix.size()) == suffix);
}

/**
 * @fn std::size_t labelCount(std::string_view value) noexcept
 * @brief Count dot-separated host labels.
 * @author Alex (<https://github.com/lextpf>)
 *
 * An empty view counts as 0.
 */
inline std::size_t labelCount(std::string_view value) noexcept
{
    if (value.empty())
    {
        return 0;
    }
    std::size_t count = 1;
    for (const char c : value)
    {
        if (c == '.')
        {
            ++count;
        }
    }
    return count;
}

/**
 * @fn std::string_view publicSuffixView(std::string_view host) noexcept
 * @brief Apply curated PSL rules to a normalized host.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Exceptions win and drop their leftmost label. Otherwise the longest exact or
 * wildcard rule wins; the implicit wildcard selects the final label.
 *
 * | Host              | Rule kind    | Public suffix | RegistrableDomain |
 * |-------------------|--------------|---------------|-------------------|
 * | `mail.google.com` | implicit `*` | `com`         | `google.com`      |
 * | `a.example.co.uk` | exact        | `co.uk`       | `example.co.uk`   |
 * | `foo.bar.ck`      | wildcard     | `bar.ck`      | `foo.bar.ck`      |
 * | `www.ck`          | exception    | `ck`          | `www.ck`          |
 *
 * @return View into host, valid while host lives; empty only for empty input.
 * @pre `host` is normalized by extractHost.
 */
inline std::string_view publicSuffixView(std::string_view host) noexcept
{
    if (host.empty())
    {
        return {};
    }

    std::string_view bestException;
    for (const std::string_view rule : kPublicSuffixExceptions)
    {
        if (hasDotAlignedSuffix(host, rule) && labelCount(rule) > labelCount(bestException))
        {
            bestException = rule;
        }
    }
    if (!bestException.empty())
    {
        const std::size_t dot = bestException.find('.');
        const std::string_view suffix =
            dot == std::string_view::npos ? bestException : bestException.substr(dot + 1);
        return host.substr(host.size() - suffix.size());
    }

    std::string_view best;
    std::size_t bestLabels = 0;
    for (const std::string_view rule : kExactPublicSuffixes)
    {
        if (!hasDotAlignedSuffix(host, rule))
        {
            continue;
        }
        const std::size_t labels = labelCount(rule);
        if (labels > bestLabels)
        {
            best = host.substr(host.size() - rule.size());
            bestLabels = labels;
        }
    }

    // wildcards consume exactly one label.
    for (const std::string_view base : kWildcardPublicSuffixes)
    {
        if (!hasDotAlignedSuffix(host, base) || host.size() <= base.size())
        {
            continue;
        }
        const std::size_t baseStart = host.size() - base.size();
        if (baseStart == 0 || host[baseStart - 1] != '.')
        {
            continue;
        }
        const std::size_t wildcardEnd = baseStart - 1;
        const std::size_t previousDot =
            wildcardEnd == 0 ? std::string_view::npos : host.rfind('.', wildcardEnd - 1);
        const std::size_t wildcardStart =
            previousDot == std::string_view::npos ? 0 : previousDot + 1;
        const std::string_view candidate = host.substr(wildcardStart);
        const std::size_t labels = labelCount(candidate);
        if (labels > bestLabels)
        {
            best = candidate;
            bestLabels = labels;
        }
    }

    if (!best.empty())
    {
        return best;
    }

    // implicit wildcard: unknown final labels are public suffixes.
    const std::size_t lastDot = host.find_last_of('.');
    return lastDot == std::string_view::npos ? host : host.substr(lastDot + 1);
}

}  // namespace detail

/// Date/version of the checked-in curated public suffix list snapshot.
inline constexpr std::string_view kSuffixTableSnapshot = detail::kSuffixTableSnapshot;

/// Upstream PSL commit used to review the curated snapshot.
inline constexpr std::string_view kSuffixTableCommit = detail::kSuffixTableCommit;

/**
 * @fn std::string extractHost(std::string_view input)
 * @brief Normalize the host portion of a URL or label.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Removes surrounding ASCII whitespace, scheme, path/query/fragment, credentials,
 * and port. Internal whitespace remains invalid.
 * Lowercases ASCII and strips a trailing dot and leading www., except when www.
 * Is needed for a registrable host such as www.ck.
 *
 * Single labels and underscores are accepted. Callers needing a domain must test
 * for a dot. Scheme detection is unanchored: see https://x.com yields x.com.
 *
 * @verbatim
 * "https://accounts.google.com/path"          -> "accounts.google.com"
 * "accounts.google.com"                       -> "accounts.google.com"
 * "https://user:pw@accounts.google.com:8443"  -> "accounts.google.com"
 * "  www.google.com  "                        -> "google.com"
 * "Gmail"                                     -> "gmail"
 * @endverbatim
 *
 * @return Empty if no host remains or a byte is outside ASCII letters, digits,
 *         dots, underscores, and hyphens. Unicode is rejected; browsers send punycode.
 */
inline std::string extractHost(std::string_view input)
{
    while (!input.empty() && (input.front() == ' ' || input.front() == '\t' ||
                              input.front() == '\r' || input.front() == '\n'))
    {
        input.remove_prefix(1);
    }
    while (!input.empty() && (input.back() == ' ' || input.back() == '\t' || input.back() == '\r' ||
                              input.back() == '\n'))
    {
        input.remove_suffix(1);
    }
    if (input.empty())
    {
        return {};
    }

    const auto schemeEnd = input.find("://");
    if (schemeEnd != std::string_view::npos)
    {
        input.remove_prefix(schemeEnd + 3);
    }

    for (const char c : {'/', '?', '#'})
    {
        const auto pos = input.find(c);
        if (pos != std::string_view::npos)
        {
            input = input.substr(0, pos);
        }
    }

    const auto at = input.find('@');
    if (at != std::string_view::npos)
    {
        input.remove_prefix(at + 1);
    }

    // IPv6 literals fail the subsequent host-character validation.
    const auto colon = input.find(':');
    if (colon != std::string_view::npos)
    {
        input = input.substr(0, colon);
    }

    if (input.empty())
    {
        return {};
    }

    // reject unicode; browser hosts use punycode.
    for (const char c : input)
    {
        if (!detail::isHostChar(c))
        {
            return {};
        }
    }

    std::string host;
    host.reserve(input.size());
    for (const char c : input)
    {
        host.push_back(detail::asciiLower(c));
    }
    if (!host.empty() && host.back() == '.')
    {
        host.pop_back();
    }
    if (host.empty())
    {
        return {};
    }

    // keep www when stripping it would leave a public suffix, including !www.ck.
    static constexpr std::string_view kWwwPrefix = "www.";
    if (host.size() > kWwwPrefix.size() && host.compare(0, kWwwPrefix.size(), kWwwPrefix) == 0)
    {
        const std::string_view withoutWww(host.data() + kWwwPrefix.size(),
                                          host.size() - kWwwPrefix.size());
        if (detail::publicSuffixView(withoutWww) != withoutWww)
        {
            host.erase(0, kWwwPrefix.size());
        }
    }
    return host;
}

/**
 * @fn bool isPublicSuffix(std::string_view host) noexcept
 * @brief Test whether the complete normalized host is a public suffix.
 * @author Alex (<https://github.com/lextpf>)
 *
 * The implicit wildcard makes every single label a suffix, including localhost
 * and gmail. multi-label hosts use the curated snapshot.
 *
 * @return `false` for empty input.
 * @pre `host` is normalized by extractHost.
 */
inline bool isPublicSuffix(std::string_view host) noexcept
{
    if (host.empty())
    {
        return false;
    }
    return detail::publicSuffixView(host) == host;
}

/**
 * @fn std::string registrableDomain(std::string_view input)
 * @brief Normalize and return one label plus the public suffix.
 * @author Alex (<https://github.com/lextpf>)
 *
 * | Input                 | Result           |
 * |-----------------------|------------------|
 * | accounts.google.com   | google.com       |
 * | accounts.google.co.uk | google.co.uk     |
 * | tenant.github.io      | tenant.github.io |
 * | github.io             | empty            |
 *
 * @return Empty for invalid input, single labels, or a complete public suffix.
 */
inline std::string registrableDomain(std::string_view input)
{
    const std::string host = extractHost(input);
    if (host.empty() || !host.contains('.'))
    {
        return {};
    }

    const std::string_view suffix = detail::publicSuffixView(host);
    if (suffix.empty() || suffix.size() == host.size())
    {
        return {};
    }

    const std::size_t suffixStart = host.size() - suffix.size();
    if (suffixStart == 0 || host[suffixStart - 1] != '.')
    {
        return {};
    }
    const std::size_t registrableEnd = suffixStart - 1;
    const std::size_t previousDot =
        registrableEnd == 0 ? std::string::npos : host.rfind('.', registrableEnd - 1);
    const std::size_t registrableStart = previousDot == std::string::npos ? 0 : previousDot + 1;
    return host.substr(registrableStart);
}

/**
 * @fn std::string platformDisplayName(std::string_view input)
 * @brief Display the registrable label without changing stored platform text.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Preserves dashes and underscores.
 *
 * | Input                          | Result  |
 * |--------------------------------|---------|
 * | github.com                     | github  |
 * | accounts.google.co.uk          | google  |
 * | alice.github.io                | alice   |
 * | https://login.my-site.com/path | my-site |
 * | GitHub                         | GitHub  |
 *
 * @return An exact input copy if no registrable domain exists, including original
 *         case, whitespace, scheme, and path.
 */
inline std::string platformDisplayName(std::string_view input)
{
    const std::string domain = registrableDomain(input);
    if (domain.empty())
    {
        return std::string(input);
    }

    const std::string_view suffix = detail::publicSuffixView(domain);
    if (suffix.empty() || suffix.size() >= domain.size())
    {
        return std::string(input);
    }

    const std::size_t separator = domain.size() - suffix.size() - 1;
    if (domain[separator] != '.')
    {
        return std::string(input);
    }
    return domain.substr(0, separator);
}

/**
 * @fn bool hostsMatch(std::string_view recordHost, std::string_view pageHost) noexcept
 * @brief Authorize equal hosts and dot-aligned child page hosts.
 * @author Alex (<https://github.com/lextpf>)
 *
 * google.com authorizes accounts.google.com. login.example.com authorizes neither
 * example.com nor siblings. Public suffix records, including single labels,
 * authorize nothing.
 *
 * @return `false` if either argument is empty.
 * @pre Both hosts are normalized by extractHost.
 */
inline bool hostsMatch(std::string_view recordHost, std::string_view pageHost) noexcept
{
    if (recordHost.empty() || pageHost.empty() || isPublicSuffix(recordHost))
    {
        return false;
    }
    if (recordHost == pageHost)
    {
        return true;
    }

    if (pageHost.size() > recordHost.size() + 1 &&
        pageHost[pageHost.size() - recordHost.size() - 1] == '.' &&
        pageHost.compare(pageHost.size() - recordHost.size(), recordHost.size(), recordHost) == 0)
    {
        return true;
    }
    return false;
}

/**
 * @fn std::string extractKey(std::string_view input)
 * @brief Derive a display-only fuzzy brand key.
 * @author Alex (<https://github.com/lextpf>)
 *
 * If extractHost succeeds, take the registrable label and remove dashes and
 * underscores. Single labels remain keys; multi-label public suffixes yield empty.
 * Otherwise split ASCII alphanumeric tokens, drop stop-words, and choose the first
 * token of at least 4 characters, or the first remaining token if all are shorter.
 * Any non-ASCII byte rejects the input.
 *
 * | Input                                  | Key    |
 * |----------------------------------------|--------|
 * | paypal.com                             | paypal |
 * | PayPal                                 | paypal |
 * | https://login.paypal.com/signin?next=x | paypal |
 * | my-site.com                            | mysite |
 * | accounts.google.com                    | google |
 * | google.co.uk                           | google |
 * | my PayPal account                      | paypal |
 *
 * @return Empty for invalid input, multi-label public suffixes, or no usable token.
 * @warning Keys are TLD-blind and cannot authorize secrets.
 */
inline std::string extractKey(std::string_view input)
{
    const std::string host = extractHost(input);
    if (!host.empty())
    {
        std::string label;
        if (!host.contains('.'))
        {
            label = host;
        }
        else
        {
            const std::string domain = registrableDomain(host);
            if (domain.empty())
            {
                return {};
            }
            label = domain.substr(0, domain.find('.'));
        }

        std::string key;
        key.reserve(label.size());
        for (char c : label)
        {
            if (c != '-' && c != '_')
            {
                key.push_back(c);
            }
        }
        return key;
    }

    // reject non-ASCII before tokenizing free-form labels.
    for (char c : input)
    {
        if (static_cast<unsigned char>(c) >= 0x80)
        {
            return {};
        }
    }

    std::vector<std::string> tokens;
    {
        std::string cur;
        for (char c : input)
        {
            const char lo = detail::asciiLower(c);
            if ((lo >= 'a' && lo <= 'z') || (lo >= '0' && lo <= '9'))
            {
                cur.push_back(lo);
            }
            else if (!cur.empty())
            {
                tokens.push_back(std::move(cur));
                cur.clear();
            }
        }
        if (!cur.empty())
        {
            tokens.push_back(std::move(cur));
        }
    }
    if (tokens.empty())
    {
        return {};
    }

    static constexpr std::array<std::string_view, 19> kStopWords = {{
        "a",  "an",      "the",   "my",     "your", "our", "for",      "to",   "of",       "and",
        "or", "account", "login", "signin", "sign", "in",  "password", "work", "personal",
    }};
    auto isStopWord = [](std::string_view w) noexcept
    {
        for (const auto& sw : kStopWords)
        {
            if (w == sw)
            {
                return true;
            }
        }
        return false;
    };

    // prefer tokens of at least 4 characters over initials and possessive s.
    constexpr std::size_t kMinBrandLen = 4;
    for (const auto& tok : tokens)
    {
        if (isStopWord(tok))
        {
            continue;
        }
        if (tok.size() >= kMinBrandLen)
        {
            return tok;
        }
    }
    // if all candidates are short, retain labels such as AOL.
    for (const auto& tok : tokens)
    {
        if (!isStopWord(tok))
        {
            return tok;
        }
    }

    return {};
}

/**
 * @fn bool keysMatch(std::string_view recordKey, std::string_view pageKey) noexcept
 * @brief Compare non-empty normalized brand keys by byte equality.
 * @author Alex (<https://github.com/lextpf>)
 *
 * paypal.com and paypal.co both reduce to paypal; never use this for secret release.
 */
inline bool keysMatch(std::string_view recordKey, std::string_view pageKey) noexcept
{
    if (recordKey.empty() || pageKey.empty())
    {
        return false;
    }
    return recordKey == pageKey;
}

/**
 * @fn bool platformMatchesHost(std::string_view recordPlatform, std::string_view pageHost)
 * @brief Match a domain strictly or a free-form label by fuzzy key.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Both inputs are normalized here. Fuzzy matching requires non-empty keys.
 *
 * | # | Condition                                | Result                             |
 * |---|------------------------------------------|------------------------------------|
 * | 1 | page host fails @ref extractHost         | `false` (fail closed)              |
 * | 2 | record parses to a host containing a `.` | strict @ref hostsMatch (TLD-aware) |
 * | 3 | otherwise (bare / free-form label)       | fuzzy @ref keysMatch (TLD-blind)   |
 *
 * @warning Browser release must use platformMatchesHostForSecretRelease;
 *          this matcher discards TLDs for bare labels.
 */
inline bool platformMatchesHost(std::string_view recordPlatform, std::string_view pageHost)
{
    const std::string page = extractHost(pageHost);
    if (page.empty())
    {
        return false;  // no real page host -> fail closed.
    }
    const std::string recordHost = extractHost(recordPlatform);
    if (!recordHost.empty() && recordHost.contains('.'))
    {
        return hostsMatch(recordHost, page);
    }

    const std::string recordKey = extractKey(recordPlatform);
    const std::string pageKey = extractKey(page);
    return !recordKey.empty() && !pageKey.empty() && keysMatch(recordKey, pageKey);
}

/**
 * @fn bool platformMatchesHostForSecretRelease(std::string_view recordPlatform, std::string_view
 *     pageHost)
 * @brief Authorize browser release only for a stored domain or URL.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Normalizes both inputs and applies directional hostsMatch. Bare labels such as
 * PayPal fail even if their fuzzy key matches. Public suffixes authorize nothing.
 * Record selection and every extension-driven release path must use this same gate.
 *
 * This gate compares hosts only. It discards scheme, port, path, and credentials;
 * the caller must enforce secure context and document freshness separately.
 *
 * @return `false` for invalid inputs or a record host without a dot.
 */
inline bool platformMatchesHostForSecretRelease(std::string_view recordPlatform,
                                                std::string_view pageHost)
{
    const std::string page = extractHost(pageHost);
    if (page.empty())
    {
        return false;
    }
    const std::string recordHost = extractHost(recordPlatform);
    if (recordHost.empty() || !recordHost.contains('.'))
    {
        return false;
    }
    return hostsMatch(recordHost, page);
}

}  // namespace seal::url
