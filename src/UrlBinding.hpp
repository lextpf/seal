#pragma once

/**
 * @brief Lightweight host extraction and matching for URL/platform binding.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Phishing-resistance gate for the auto-fill path: a credential whose
 * platform field names site A must not be typed into site B. This header
 * is deliberately Qt-free and allocation-light so it can be unit-tested in
 * the no-USE_QT_UI test target.
 *
 * Two distinct levels of strictness are exposed:
 *  - @ref hostsMatch - strict eTLD-boundary suffix match between two
 *    normalised hostnames. Used when the record platform is itself a URL
 *    and an exact-subdomain match is appropriate.
 *  - @ref extractKey + @ref keysMatch - fuzzy match suitable for
 *    free-form record labels like "PayPal Login" or "Bob's Gmail". Both
 *    sides reduce to a single brand-name token; equality wins.
 *
 * ## :material-link-variant: Matching Flow
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
 *     TOK[tokenise on non-alnum<br/>drop stop-words<br/>pick first >= 4 chars]:::step
 *     KEY([normalised key]):::out
 *     EQ([keysMatch<br/>= equality]):::out
 *
 *     IN --> HOST
 *     HOST -->|yes, hostname / URL| LABEL --> KEY
 *     HOST -->|no, free-form label| TOK --> KEY
 *     KEY --> EQ
 * ```
 *
 * @note **PSL v1 caveat.** No public-suffix list is consulted. Hostnames
 *       with multi-label suffixes (`co.uk`, `com.au`, `gov.br`, ...) reduce
 *       to the suffix label rather than the registrable name - e.g.
 *       `google.co.uk` reduces to the key `co`. This is acceptable
 *       because the binding is a phishing GATE: the worst-case failure
 *       on a ccTLD is a visible "Site mismatch" dialog that the user
 *       cancels and re-arms a different record around. A real PSL pass
 *       is a follow-up if it becomes a real-world friction point.
 */

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace seal::url
{

namespace detail
{

inline char asciiLower(char c) noexcept
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

inline bool isHostChar(char c) noexcept
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '-' || c == '_';
}

}  // namespace detail

/**
 * @brief Pull a normalised hostname out of a URL or bare-host string.
 *
 * Accepts forms like:
 *   - "https://accounts.google.com/path"          -> "google.com"
 *   - "accounts.google.com"                       -> "google.com"
 *   - "https://user:pw@accounts.google.com:8443"  -> "google.com"
 *   - "  www.google.com  "                        -> "google.com"
 *
 * Returns empty when the input doesn't parse as a hostname (e.g., a
 * free-form service name like "Gmail"), when the host contains
 * non-ASCII bytes (caller must punycode-encode upstream), or when it
 * contains characters outside [A-Za-z0-9.-_].
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

    // Strip port (last colon, because IPv6 isn't expected in a record
    // platform; if it shows up we'd cut at the wrong colon, but we'd then
    // fail the host-char validation below and return empty - safe).
    const auto colon = input.find(':');
    if (colon != std::string_view::npos)
    {
        input = input.substr(0, colon);
    }

    if (input.empty())
    {
        return {};
    }

    // Validate: only ASCII host-chars are accepted. Reject non-ASCII so we
    // never silently misclassify a punycode-vs-unicode mismatch (the
    // extension always sends ASCII-encoded hosts, so empty here is the
    // right answer for unicode input).
    for (const char c : input)
    {
        if (!detail::isHostChar(c))
        {
            return {};
        }
    }

    // Build the lowercase output and strip a leading "www." once.
    std::string host;
    host.reserve(input.size());
    for (const char c : input)
    {
        host.push_back(detail::asciiLower(c));
    }
    static constexpr std::string_view kWwwPrefix = "www.";
    if (host.size() > kWwwPrefix.size() && host.compare(0, kWwwPrefix.size(), kWwwPrefix) == 0)
    {
        host.erase(0, kWwwPrefix.size());
    }
    // A trailing dot ("google.com.") is a legal FQDN form but uncommon in
    // browser hostnames; strip it so the comparison is canonical.
    if (!host.empty() && host.back() == '.')
    {
        host.pop_back();
    }
    if (host.empty())
    {
        return {};
    }
    return host;
}

/**
 * @brief Compare two already-extracted hosts with dot-boundary suffix match.
 *
 * Returns true when the hosts are identical, or when either is a
 * dot-aligned suffix of the other. The bidirectional match handles the
 * case where the user saved a more-specific URL in the record platform
 * (e.g., `accounts.google.com`) but lands on the eTLD+1 page
 * (`google.com`), and vice versa.
 *
 * Callers MUST pass strings already returned by extractHost() (or
 * already-normalised equivalents). Empty inputs return false.
 */
inline bool hostsMatch(std::string_view recordHost, std::string_view pageHost) noexcept
{
    if (recordHost.empty() || pageHost.empty())
    {
        return false;
    }
    if (recordHost == pageHost)
    {
        return true;
    }
    // pageHost is more specific: e.g., accounts.google.com vs google.com.
    if (pageHost.size() > recordHost.size() + 1 &&
        pageHost[pageHost.size() - recordHost.size() - 1] == '.' &&
        pageHost.compare(pageHost.size() - recordHost.size(), recordHost.size(), recordHost) == 0)
    {
        return true;
    }
    // recordHost is more specific.
    if (recordHost.size() > pageHost.size() + 1 &&
        recordHost[recordHost.size() - pageHost.size() - 1] == '.' &&
        recordHost.compare(recordHost.size() - pageHost.size(), pageHost.size(), pageHost) == 0)
    {
        return true;
    }
    return false;
}

/**
 * @brief Reduce a hostname or free-form platform string to a fuzzy
 *        matching key suitable for "site mismatch" warnings.
 *
 * Designed for the auto-fill flow where the user labels records loosely
 * ("PayPal", "paypal.com", "https://login.paypal.com"). The key drops
 * everything that's likely to differ between the label and the actual
 * page host:
 *   - leading/trailing whitespace, scheme, credentials, port, path,
 *     query, fragment (via extractHost)
 *   - the leading "www." (via extractHost)
 *   - the trailing TLD label ("com", "net", "co", "uk", ...)
 *   - dashes and underscores ("my-site" -> "mysite")
 *   - case ("PayPal" -> "paypal")
 *
 * For a hostname with N dot-separated labels, the key is the
 * second-to-last label (the "registrable name" in non-ccTLD cases). For
 * a single-label string (no dots), the whole label is used. Empty input
 * or input that doesn't pass extractHost() returns empty - callers
 * should fail OPEN on empty record keys (free-form labels can't bind).
 *
 * Examples:
 *   - "paypal.com"             -> "paypal"
 *   - "PayPal"                 -> "paypal"
 *   - "www.paypal.com"         -> "paypal"
 *   - "https://login.paypal.com/signin?next=x" -> "paypal"
 *   - "my-site.com"            -> "mysite"
 *   - "accounts.google.com"    -> "google"
 *   - "google.co.uk"           -> "co"   (no PSL; ccTLDs are imperfect)
 *
 * The ccTLD imperfection is documented and acceptable: this key is
 * advisory (used for a warning, not a block), and a real PSL pass is a
 * follow-up if we ever want stronger matching.
 */
inline std::string extractKey(std::string_view input)
{
    // First-pass: try the hostname extraction. URLs and bare hostnames
    // (which is what `record.platform` looks like when the user pasted
    // a URL) go through here.
    const std::string host = extractHost(input);
    if (!host.empty())
    {
        // Split on '.' and pick the second-to-last label (the
        // registrable name in non-ccTLD cases). Single-label inputs
        // use the whole label.
        std::size_t lastDot = host.find_last_of('.');
        std::string label;
        if (lastDot == std::string::npos)
        {
            // No dots, e.g. "Gmail" / "paypal".
            label = host;
        }
        else
        {
            const std::size_t prevDot = host.find_last_of('.', lastDot - 1);
            if (prevDot == std::string::npos)
            {
                // Two-label host (e.g. "paypal.com"): take the first
                // label.
                label = host.substr(0, lastDot);
            }
            else
            {
                // 3+ labels: take the label between the last two dots
                // (e.g. "accounts.google.com" -> "google").
                label = host.substr(prevDot + 1, lastDot - prevDot - 1);
            }
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

    // Second-pass (input failed extractHost): a free-form label with spaces like
    // "Paypal Login" / "Bob's Paypal". Split into ASCII-alnum tokens, drop stop-words,
    // pick the first >= 4-char token (brand names; skips connectors/initials). Reject
    // non-ASCII up front - this is a phishing gate, so coercing UTF-8 fails closed.
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

    // Pass A: first non-stop-word with >= 4 chars (brand names).
    // Skipping short tokens defeats noise like single-letter
    // initials, possessive 's, and short connectors that would
    // otherwise out-rank the real service name.
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
    // Pass B: first non-stop-word of any length (only reached when
    // there's no >= 4 char candidate, e.g. "X Twitter" already
    // exited via Pass A's "twitter"; this catches a degenerate
    // label like "AOL").
    for (const auto& tok : tokens)
    {
        if (!isStopWord(tok))
        {
            return tok;
        }
    }
    // All tokens were stop-words. Fail open.
    return {};
}

/**
 * @brief Whether two fuzzy keys match for the URL-binding warning.
 *
 * Trivial equality on the keys returned by @ref extractKey. Empty inputs
 * return false (callers treat that as "no opinion, don't warn").
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
 * @brief Tiered match between a record's platform label and a live page host,
 *        for zero-gesture auto-fill (selection AND the fill-time gate).
 *
 * The two callers that decide/authorize a staged auto-fill (the
 * @ref seal::resolveStageRecord selector and FillController's fail-closed
 * release gate) MUST agree, so the policy lives here in one place.
 *
 * ## The two tiers
 *
 * - **Record carries a real domain** (its platform parses to a host with a
 *   dot - "paypal.com", "https://login.paypal.com") -> **strict**
 *   @ref hostsMatch: eTLD-boundary, TLD-sensitive. A typosquat on a different
 *   TLD (`paypal.co`) does NOT match. This is the safe tier and the one to
 *   prefer for high-value credentials.
 * - **Record is a bare brand label or free-form label** ("PayPal",
 *   "My PayPal") -> **fuzzy** registrable-name match via
 *   @ref extractKey / @ref keysMatch. This is **TLD-BLIND**: "PayPal" matches
 *   `paypal.com` AND `paypal.co`. It exists so the common brand-label vault
 *   auto-fills at all, and it is exactly the phishing exposure the manual
 *   Ctrl+Click path already has for such records - so the auto path is no
 *   weaker than manual for labels, and strictly safer for domain records.
 *
 * @par Decision order
 * | # | Condition                                | Result                             |
 * |---|------------------------------------------|------------------------------------|
 * | 1 | page host fails @ref extractHost         | `false` (fail closed)              |
 * | 2 | record parses to a host containing a `.` | strict @ref hostsMatch (TLD-aware) |
 * | 3 | otherwise (bare / free-form label)       | fuzzy @ref keysMatch (TLD-blind)   |
 *
 * @note SECURITY TRADEOFF. The fuzzy tier is the deliberate relaxation that
 *       makes brand-label records usable. To make auto-fill strictly
 *       typosquat-resistant for ALL records, delete the fuzzy fallback below
 *       (return false there) - then only records storing a real domain
 *       auto-fill. Keep the two callers in lockstep either way.
 *
 * @param recordPlatform The record's stored platform label (any form).
 * @param pageHost       The live page hostname (a real `location.hostname`).
 * @return true when the record should bind to this host under the tiers above.
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
    // Bare/free-form label -> fuzzy registrable-name match (TLD-blind).
    const std::string recordKey = extractKey(recordPlatform);
    const std::string pageKey = extractKey(page);
    return !recordKey.empty() && !pageKey.empty() && keysMatch(recordKey, pageKey);
}

}  // namespace seal::url
