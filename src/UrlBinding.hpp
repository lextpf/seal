#pragma once

/**
 * @brief Host extraction and matching for URL/platform binding.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Phishing-resistance gate for the auto-fill path: a credential whose platform
 * field names site A must not be typed into site B. The header is Qt-free, so
 * the test target, which links no Qt, covers it directly.
 *
 * Three tiers of strictness, strictest first:
 *  - @ref platformMatchesHostForSecretRelease - the browser credential release
 *    gate. The record platform must itself carry a domain or URL, and that host
 *    must authorize the page host. A bare label fails closed. Every
 *    browser-facing gate uses this tier alone.
 *  - @ref hostsMatch - directional dot-aligned tail match between two
 *    normalised hosts. Identical hosts match and a parent record authorizes its
 *    subdomains. A child never authorizes its parent, siblings never match, and
 *    a record host that is itself a public suffix authorizes nothing.
 *  - @ref extractKey + @ref keysMatch - fuzzy match for free-form record labels
 *    like "PayPal Login" or "Bob's Gmail". Both sides reduce to one brand-name
 *    token; equality wins. This tier is TLD-blind, so it never gates secret
 *    release.
 *
 * @ref registrableDomain is the shared public-suffix helper behind
 * @ref extractKey, @ref platformDisplayName and the staging preview. It is not
 * part of the release path: @ref hostsMatch never calls it and is stricter than
 * registrable-domain equality, because two siblings under one registrable
 * domain do not match.
 *
 * ## :material-link-variant: Fuzzy Key Flow
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
 *
 * @par Purity
 * Every function here is pure and thread-safe: no mutable state, no I/O, no
 * cache. The rule tables are `constexpr`, so concurrent calls share nothing
 * writable. @ref isPublicSuffix, @ref hostsMatch and @ref keysMatch are
 * `noexcept` and allocate nothing; the extractors return a freshly built
 * `std::string`.
 *
 * @par Suffix table
 * The compiled-in snapshot is curated, not fetched at run time: common
 * country-code registration namespaces plus well-known shared-hosting suffixes.
 * Ordinary domains are handled by the implicit last-label rule, so a missing
 * multi-label rule degrades to that fallback rather than failing. The fallback
 * is permissive, not closed. An unlisted multi-label rule such as `co.zw`
 * counts as registrable, so @ref isPublicSuffix reports false for it, a record
 * that stores the suffix itself authorizes every host below it, and
 * @ref registrableDomain and @ref platformDisplayName split one label too far
 * right (`bank.co.zw` -> `co.zw`, chip label `co`).
 * `PublicSuffixTable.hpp` is generated - change a rule in
 * `scripts/public_suffixes.txt` and re-run
 * `scripts/generate_public_suffix_table.py`. A hand edit there is lost.
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

/// Lower-case one ASCII letter. Bytes outside `A`-`Z` are returned unchanged.
inline char asciiLower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

/// Whether @p c may appear in an accepted host: ASCII alphanumeric, `.`, `-` or `_`.
inline bool isHostChar(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '-' || c == '_';
}

/**
 * @brief Whether @p host equals @p suffix or ends with `"." + suffix`.
 *
 * The dot alignment is what stops `notgoogle.com` from matching the rule
 * `google.com`.
 *
 * @pre @p suffix is a non-empty table rule without a leading dot. An empty rule
 *      is not rejected; it matches only an empty or dot-terminated @p host.
 * @param host Normalised hostname.
 * @return true on an exact match or a dot-aligned tail match.
 */
inline bool hasDotAlignedSuffix(std::string_view host, std::string_view suffix) noexcept
{
    return host == suffix ||
           (host.size() > suffix.size() && host[host.size() - suffix.size() - 1] == '.' &&
            host.substr(host.size() - suffix.size()) == suffix);
}

/// Number of dot-separated labels in @p value. An empty view counts as 0.
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
 * @brief Return the prevailing public suffix of @p host.
 *
 * Applies the PSL rules over the generated curated table. An exception rule
 * wins outright and yields the rule minus its left-most label.
 *
 * Otherwise the exact or wildcard rule with the most labels wins; failing that,
 * the implicit `*` rule returns the final label, so a single-label host is its
 * own suffix.
 *
 * @par Worked examples
 * | host              | rule kind    | public suffix | registrableDomain |
 * |-------------------|--------------|---------------|-------------------|
 * | `mail.google.com` | implicit `*` | `com`         | `google.com`      |
 * | `a.example.co.uk` | exact        | `co.uk`       | `example.co.uk`   |
 * | `foo.bar.ck`      | wildcard     | `bar.ck`      | `foo.bar.ck`      |
 * | `www.ck`          | exception    | `ck`          | `www.ck`          |
 *
 * @pre @p host is lowercase, has no trailing dot, and contains only host
 *      characters - that is, the output of extractHost().
 * @param host Normalised hostname to classify.
 * @return A view into @p host, valid only while @p host stays alive. Empty only
 *         when @p host is empty.
 */
inline std::string_view publicSuffixView(std::string_view host) noexcept
{
    if (host.empty())
    {
        return {};
    }

    // An exception rule wins over exact/wildcard rules. The public suffix of
    // !www.ck is ck (the exception's left-most label is removed).
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

    // A wildcard rule such as *.ck consumes exactly one additional label.
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

    // PSL's implicit "*" rule: an otherwise unknown final label is the suffix.
    // Ordinary two-label domains keep working without compiling every
    // single-label TLD into the table.
    const std::size_t lastDot = host.find_last_of('.');
    return lastDot == std::string_view::npos ? host : host.substr(lastDot + 1);
}

}  // namespace detail

/// Date/version of the checked-in curated Public Suffix List snapshot.
inline constexpr std::string_view kSuffixTableSnapshot = detail::kSuffixTableSnapshot;

/// Upstream PSL commit the curated snapshot is reviewed against.
inline constexpr std::string_view kSuffixTableCommit = detail::kSuffixTableCommit;

/**
 * @brief Pull a normalised hostname out of a URL or bare-host string.
 *
 * Strips, in order: ASCII whitespace, the `scheme://` prefix, everything from
 * the first `/`, `?` or `#`, `user[:password]@` credentials, and the `:port`
 * tail. The remainder is lower-cased, a legal FQDN trailing dot is dropped, and
 * a leading `www.` is removed unless that would leave a bare public suffix
 * (`www.ck` stays `www.ck`).
 *
 * @par Accepted forms
 * @verbatim
 * "https://accounts.google.com/path"          -> "accounts.google.com"
 * "accounts.google.com"                       -> "accounts.google.com"
 * "https://user:pw@accounts.google.com:8443"  -> "accounts.google.com"
 * "  www.google.com  "                        -> "google.com"
 * "Gmail"                                     -> "gmail"
 * @endverbatim
 *
 * @par Traps
 * A single-label input is a legal host, so a one-word label such as "Gmail" is
 * normalised rather than rejected; a caller that needs a real domain must test
 * the result for a `.` itself. The search for `://` is not anchored, so a label
 * that embeds a URL keeps only that URL's host: "see https://x.com" yields
 * "x.com". An underscore is accepted even though DNS forbids it in a hostname,
 * so an internal name such as "my_host.example.com" survives.
 *
 * @param input URL, bare host, or free-form label.
 * @return Lower-cased hostname. Empty when the trimmed input is empty, when
 *         nothing survives the strips, or when any remaining byte falls outside
 *         `[A-Za-z0-9._-]`. That last rule rejects spaces, label punctuation
 *         and every non-ASCII byte: the extension always reports punycode, so a
 *         unicode host fails closed instead of being coerced.
 */
inline std::string extractHost(std::string_view input)
{
    // ASCII-trim whitespace.
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

    // Strip scheme.
    const auto schemeEnd = input.find("://");
    if (schemeEnd != std::string_view::npos)
    {
        input.remove_prefix(schemeEnd + 3);
    }

    // Cut at the first path / query / fragment delimiter.
    for (const char c : {'/', '?', '#'})
    {
        const auto pos = input.find(c);
        if (pos != std::string_view::npos)
        {
            input = input.substr(0, pos);
        }
    }

    // Strip credentials (user[:password]@host).
    const auto at = input.find('@');
    if (at != std::string_view::npos)
    {
        input.remove_prefix(at + 1);
    }

    // Strip the port at the first colon. Credentials are already gone, so the
    // first colon can only start the port. An IPv6 literal is not expected in a
    // record platform, and cutting one at the wrong colon is safe: it then fails
    // the host-char validation below and returns empty.
    const auto colon = input.find(':');
    if (colon != std::string_view::npos)
    {
        input = input.substr(0, colon);
    }

    if (input.empty())
    {
        return {};
    }

    // Only ASCII host chars are accepted. Rejecting non-ASCII avoids a silent
    // punycode-vs-unicode misclassification; the extension always sends
    // ASCII-encoded hosts, so empty is the right answer for unicode input.
    for (const char c : input)
    {
        if (!detail::isHostChar(c))
        {
            return {};
        }
    }

    // Build the lowercase output and canonicalise a legal FQDN trailing dot
    // before applying suffix rules.
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

    // Strip a leading "www." once, except when doing so would turn a
    // registrable name into a public suffix (including !www.ck).
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
 * @brief Whether a normalised hostname is itself a public suffix.
 *
 * Every single-label host is one, by the PSL implicit `*` rule: `com`, but also
 * `gmail` and `localhost`, report true. Multi-label hosts are decided by the
 * curated exact/wildcard/exception snapshot.
 *
 * @pre @p host is already normalised. This function does no parsing, so a
 *      caller holding a URL or mixed case must pass @ref extractHost output.
 * @return true when the whole host is a public suffix. An empty @p host returns
 *         false.
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
 * @brief Return the registrable domain (one label plus public suffix).
 *
 * URLs and bare hosts are accepted and normalised via @ref extractHost, so the
 * result is lower-cased and has already lost any `www.` prefix.
 *
 * @par Examples
 * - `accounts.google.com` -> `google.com`
 * - `accounts.google.co.uk` -> `google.co.uk`
 * - `tenant.github.io` -> `tenant.github.io`
 * - `github.io` -> empty (shared public suffix)
 *
 * @param input URL, bare host, or free-form label.
 * @return The registrable domain, or empty for a single-label input, a host
 *         that is entirely a public suffix, or anything @ref extractHost
 *         rejects.
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
 * @brief Presentation-only label for a platform shown on an account chip.
 *
 * Bindable domains and URLs collapse to their registrable label, dropping the
 * whole public suffix rather than only the final TLD. Dashes and underscores
 * survive, unlike in @ref extractKey. The stored platform is never rewritten
 * and stays available for binding and tooltips.
 *
 * @par Examples
 * - `github.com` -> `github`
 * - `accounts.google.co.uk` -> `google`
 * - `alice.github.io` -> `alice`
 * - `https://login.my-site.com/path` -> `my-site`
 * - `GitHub` -> `GitHub`
 *
 * @param input The stored platform label, in any form.
 * @return The registrable label, or @p input copied verbatim when it has no
 *         registrable domain. Verbatim is literal: a free-form label, a bare
 *         public suffix and an unparsable URL all come back with their original
 *         case, whitespace, scheme and path intact.
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
 * @brief Directional dot-boundary host match: does @p recordHost authorize
 *        @p pageHost?
 *
 * True when the hosts are identical, or when @p pageHost is a dot-aligned
 * subdomain of @p recordHost: a parent record authorizes its children, so a
 * record for `google.com` binds `accounts.google.com`. The reverse direction is
 * deliberately unmatched - a record for `login.example.com` authorizes neither
 * `example.com` nor a sibling. The asymmetry blocks a child record from
 * widening to its parent while keeping the common "saved the apex, log in on a
 * subdomain" flow.
 *
 * A @p recordHost that is a public suffix authorizes nothing, not even an
 * identical host. That stops a record named `github.io` or `pages.dev` from
 * authorizing unrelated tenants below the shared boundary. Every single-label
 * host counts as a public suffix (see @ref isPublicSuffix), so a bare
 * `localhost` or `gmail` record never matches either.
 *
 * @pre Both arguments are already normalised - the output of @ref extractHost
 *      or an equivalent. This function lower-cases nothing and parses nothing,
 *      so a raw URL or mixed case will not match.
 * @param recordHost Normalised host stored on the record; the authorizer.
 * @param pageHost   Normalised host of the live page; the authorized side.
 * @return true when @p recordHost authorizes @p pageHost. An empty argument on
 *         either side returns false.
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
    // pageHost is a subdomain of recordHost: record google.com authorizes
    // accounts.google.com. The reverse is intentionally unmatched - a subdomain
    // record must not authorize its parent domain or its siblings.
    if (pageHost.size() > recordHost.size() + 1 &&
        pageHost[pageHost.size() - recordHost.size() - 1] == '.' &&
        pageHost.compare(pageHost.size() - recordHost.size(), recordHost.size(), recordHost) == 0)
    {
        return true;
    }
    return false;
}

/**
 * @brief Reduce a hostname or free-form platform string to a fuzzy brand key.
 *
 * Two consumers: the fuzzy tier of @ref platformMatchesHost, and
 * `AppViewModel::previewSiteBinding`, which offers `<key>.com` as the
 * "did you mean" suggestion for an unbindable label. The key drops everything
 * likely to differ between a loose label and the real page host:
 *   - whitespace, scheme, credentials, port, path, query, fragment and the
 *     leading `www.` (all via @ref extractHost)
 *   - the public suffix (`com`, `co.uk`, `com.au`, ...)
 *   - dashes and underscores ("my-site" -> "mysite")
 *   - case ("PayPal" -> "paypal")
 *
 * @par Two passes
 * - @ref extractHost succeeds: the key is the label immediately before the
 *   prevailing public suffix. A single-label input has no suffix to remove and
 *   becomes the key as-is, so `com` yields `com`. Only a multi-label public
 *   suffix such as `co.uk` yields empty here.
 * - @ref extractHost fails, which for a platform label means it held a space or
 *   another non-host character: the string is split into ASCII alphanumeric
 *   tokens, stop-words ("my", "the", "login", "account", ...) are dropped, and
 *   the first remaining token of 4 or more characters wins. If no token is that
 *   long the first non-stop-word wins, so "AOL" still resolves. A non-ASCII
 *   byte anywhere rejects the whole input.
 *
 * @par Examples
 *   - "paypal.com"                             -> "paypal"
 *   - "PayPal"                                 -> "paypal"
 *   - "https://login.paypal.com/signin?next=x" -> "paypal"
 *   - "my-site.com"                            -> "mysite"
 *   - "accounts.google.com"                    -> "google"
 *   - "google.co.uk"                           -> "google"
 *   - "My PayPal Account"                      -> "paypal"
 *
 * @param input Hostname, URL, or free-form platform label.
 * @return Lower-case brand key, or empty for an empty input, a multi-label
 *         public suffix, a non-ASCII input, a label with no ASCII
 *         alphanumeric byte, or a label made only of stop-words. An empty key
 *         can never match in @ref keysMatch.
 */
inline std::string extractKey(std::string_view input)
{
    // Pass 1: hostname extraction. URLs and bare hostnames - what
    // `record.platform` looks like when the user pasted a URL - go through here.
    const std::string host = extractHost(input);
    if (!host.empty())
    {
        std::string label;
        if (!host.contains('.'))
        {
            // No dots, e.g. "Gmail" / "paypal".
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

        // Strip dashes and underscores so "my-site" matches "mysite".
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

    // Pass 2 (extractHost failed): a free-form label with spaces, such as
    // "Paypal Login". Split into ASCII alphanumeric tokens, drop stop-words, take
    // the first token of 4 or more characters. Non-ASCII is rejected up front:
    // this is a phishing gate, so coercing UTF-8 would fail open.
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

    // Pass A: first non-stop-word of 4 or more characters. Skipping short
    // tokens defeats noise such as single-letter initials, a possessive 's and
    // short connectors, which would otherwise out-rank the real service name.
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
    // Pass B: first non-stop-word of any length. Reached only when pass A found
    // no candidate, so it catches a degenerate label such as "AOL".
    for (const auto& tok : tokens)
    {
        if (!isStopWord(tok))
        {
            return tok;
        }
    }
    // All tokens were stop-words: there is no brand to compare, so return no
    // key. keysMatch() then reports false and the fuzzy tier cannot bind.
    return {};
}

/**
 * @brief Whether two fuzzy keys bind to the same brand.
 *
 * Byte equality on keys produced by @ref extractKey. It normalises nothing of
 * its own, so a raw label passed instead of a key will not match. The key has
 * already lost its public suffix, so the comparison is TLD-blind: `paypal.com`
 * and `paypal.co` share the key `paypal`. That is why this pair never gates
 * secret release.
 *
 * @param recordKey Key extracted from the record platform label.
 * @param pageKey   Key extracted from the live page host.
 * @return true when both keys are non-empty and equal. An empty key means
 *         @ref extractKey found no brand, and reports false rather than
 *         guessing.
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
 * @brief Tiered match between a record's platform label and a live page host.
 *
 * @warning This is not the browser secret-release gate, and no shipping path
 *          calls it. Every browser gate - the @ref seal::resolveStageRecord
 *          selector, FillController's staged release, its zero-click username
 *          fill, and the manual Ctrl+Click path when a bridge entry exists -
 *          calls @ref platformMatchesHostForSecretRelease instead. This is the
 *          permissive variant for non-secret matching, covered by
 *          `tests/test_url_binding.cpp`. Do not route a release gate through
 *          it: the fuzzy tier is TLD-blind.
 *
 * ## The two tiers
 *
 * - **Record carries a real domain** (its platform parses to a host with a dot,
 *   such as "paypal.com") -> strict @ref hostsMatch: eTLD-boundary and
 *   TLD-sensitive, so a typosquat on another TLD (`paypal.co`) does not match.
 *   Prefer this tier for high-value credentials.
 * - **Record is a bare or free-form label** ("PayPal", "My PayPal") -> fuzzy
 *   registrable-name match via @ref extractKey / @ref keysMatch. It is
 *   TLD-blind: "PayPal" matches `paypal.com` and `paypal.co`. It exists so a
 *   brand-labelled vault binds at all, and carries the same phishing exposure
 *   the manual Ctrl+Click path has for such records.
 *
 * @par Decision order
 * | # | Condition                                | Result                             |
 * |---|------------------------------------------|------------------------------------|
 * | 1 | page host fails @ref extractHost         | `false` (fail closed)              |
 * | 2 | record parses to a host containing a `.` | strict @ref hostsMatch (TLD-aware) |
 * | 3 | otherwise (bare / free-form label)       | fuzzy @ref keysMatch (TLD-blind)   |
 *
 * Row 3 also needs both keys to be non-empty, so a stop-word-only label and a
 * page host that reduces to nothing both fail closed.
 *
 * @param recordPlatform The record's stored platform label, in any form; parsed
 *                       here, so a URL or mixed case is accepted.
 * @param pageHost       The live page host or URL (a `location.hostname` in
 *                       practice); parsed here as well.
 * @return true when the record binds to this host under the tiers above.
 */
inline bool platformMatchesHost(std::string_view recordPlatform, std::string_view pageHost)
{
    const std::string page = extractHost(pageHost);
    if (page.empty())
    {
        return false;  // No real page host -> fail closed.
    }
    const std::string recordHost = extractHost(recordPlatform);
    if (!recordHost.empty() && recordHost.contains('.'))
    {
        // Record carries a real domain -> strict, TLD-sensitive match.
        return hostsMatch(recordHost, page);
    }
    // Bare or free-form label -> fuzzy registrable-name match, TLD-blind.
    const std::string recordKey = extractKey(recordPlatform);
    const std::string pageKey = extractKey(page);
    return !recordKey.empty() && !pageKey.empty() && keysMatch(recordKey, pageKey);
}

/**
 * @brief Strict browser credential release gate.
 *
 * Browser-fill secret release needs a stronger policy than display or search
 * matching: the saved platform must itself contain a real domain or URL, and
 * that domain must match the live page host by the dot-boundary
 * @ref hostsMatch rule. A free-form label such as "PayPal" returns false even
 * when its fuzzy key would match `paypal.com`; the user must store
 * `paypal.com` or a URL to enable browser auto-stage and release.
 *
 * @ref hostsMatch supplies the rest of the policy. The match is directional, so
 * a `paypal.com` record authorizes `login.paypal.com` but a `login.paypal.com`
 * record does not authorize `paypal.com`, and a record holding only a public
 * suffix (`github.io`) authorizes nothing.
 *
 * @ref seal::resolveStageRecord and every FillController credential-release
 * path use this one gate, including manual Ctrl+Click whenever the click
 * resolves to a bridge entry. Keep them on this function so selection and
 * release cannot drift apart.
 *
 * @param recordPlatform The record's stored platform label; parsed here, so a
 *                       URL or mixed case is accepted.
 * @param pageHost       The live page host or URL; parsed here as well.
 * @return true only for strict domain-bound matches. Anything @ref extractHost
 *         rejects, and any record label without a dot, returns false.
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
