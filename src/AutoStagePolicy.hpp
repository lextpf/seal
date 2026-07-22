#pragma once

#include "UrlBinding.hpp"
#include "VaultRecord.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace seal
{

/**
 * @struct StageResolution
 * @brief Outcome of matching a navigated host against the vault records.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Produced by @ref resolveStageRecord, the pure site-to-record resolver for
 * zero-gesture auto-staging. The header is Qt-free, so the staging policy is
 * unit-testable in the no-Qt test target. StagingController feeds it the
 * navigated host and the live record vector on the GUI thread.
 *
 * @par Matching policy
 * Browser auto-stage uses the strict secret-release matcher
 * @ref seal::url::platformMatchesHostForSecretRelease: a record must store a
 * real domain or URL, and that host must match the live page by dot-boundary
 * suffix rules. A bare label such as "PayPal" stays useful for display and
 * search, but cannot release browser credentials. The page host always arrives
 * as a real `location.hostname`.
 */
struct StageResolution
{
    /// @enum Kind
    /// @brief How many eligible records bound to the navigated host.
    enum class Kind : std::uint8_t
    {
        None,      ///< Zero eligible records match; do nothing.
        Single,    ///< Exactly one match; auto-arm @ref m_Index.
        Multiple,  ///< Two or more match; ambiguous, do nothing.
    };

    Kind m_Kind = Kind::None;  ///< Match outcome; governs whether @ref m_Index is set.
    int m_Index = -1;          ///< Record index into the input span; valid only when Kind::Single.
};

/**
 * @struct SiteBindingPreview
 * @brief Non-secret browser-binding preview for a platform/service label.
 * @ingroup FillController
 *
 * Filled by @ref previewSiteBinding for the account editor and the account
 * chips. Presentation metadata only: it never exposes or inspects encrypted
 * credential fields. @ref m_Host is set only when the label satisfies the same
 * domain requirement as browser secret release, and it holds the full
 * normalised host, not the registrable domain ("https://login.example.co.uk/x"
 * gives "login.example.co.uk").
 */
struct SiteBindingPreview
{
    bool m_Bindable = false;  ///< Label contains a non-public-suffix domain/URL.
    std::string m_Host;       ///< Normalised host shown to the user, or empty when unbindable.
    /// Other non-deleted records whose platform normalises to the same host.
    /// Exact equality, so a parent/child pair is not a duplicate. Stays 0 when
    /// @ref m_Bindable is false, because the scan is then skipped entirely.
    std::size_t m_DuplicateCount = 0;
};

/**
 * @brief Preview whether a service label can bind to a site and whether it collides.
 * @ingroup FillController
 *
 * Bindable means @ref seal::url::extractHost parses the label, the result
 * contains a dot, and it has a registrable domain. A bare label ("GitHub") and
 * a public suffix ("github.io", "co.uk") are unbindable, and the host is
 * cleared.
 *
 * @par Duplicate scan
 * Hosts are compared for exact equality, not the subdomain-authorizing
 * @ref seal::url::hostsMatch rule that @ref resolveStageRecord applies. A count
 * of 0 is therefore no promise of @ref StageResolution::Kind::Single: records
 * for "github.com" and "login.github.com" are not duplicates here, yet both
 * bind a page on "login.github.com". Deleted records and
 * @p excludedRecordIndex are skipped.
 *
 * @param records             Live vault records. An empty span turns duplicate
 *                            detection off, which is how VaultListModel reads
 *                            one chip's bindable state without scanning the
 *                            whole vector per row.
 * @param platform            Proposed service label, in any form.
 * @param excludedRecordIndex Record to omit while editing, or -1 to count every
 *                            live record.
 * @return The preview; the host is empty and the count is 0 when the label
 *         cannot bind.
 */
inline SiteBindingPreview previewSiteBinding(std::span<const VaultRecord> records,
                                             std::string_view platform,
                                             int excludedRecordIndex = -1)
{
    SiteBindingPreview preview;
    preview.m_Host = url::extractHost(platform);
    if (preview.m_Host.empty() || !preview.m_Host.contains('.') ||
        url::registrableDomain(preview.m_Host).empty())
    {
        preview.m_Host.clear();
        return preview;
    }

    preview.m_Bindable = true;
    for (int i = 0; i < static_cast<int>(records.size()); ++i)
    {
        if (i == excludedRecordIndex || records[i].deleted)
        {
            continue;
        }
        const std::string otherHost = url::extractHost(records[i].platform);
        if (otherHost == preview.m_Host && otherHost.contains('.') &&
            !url::registrableDomain(otherHost).empty())
        {
            ++preview.m_DuplicateCount;
        }
    }
    return preview;
}

/**
 * @brief Resolve a navigated host to a unique auto-stage record, or none.
 * @ingroup FillController
 *
 * Counts non-deleted records whose `platform` binds to @p navHost under the
 * strict @ref seal::url::platformMatchesHostForSecretRelease policy. Anything
 * unresolvable yields None (fail closed): an empty or unparseable @p navHost,
 * bare-label records, no match at all.
 *
 * @par Direction
 * Binding is directional: a record for the apex ("paypal.com") binds a page on
 * a subdomain, while a record for a subdomain ("login.paypal.com") binds
 * neither the apex nor a sibling. A stored public suffix ("github.io") binds
 * nothing. That direction turns an apex record plus a subdomain record into
 * Multiple on the subdomain page, and Single on the apex page.
 *
 * @par Resolution outcomes
 * | Non-deleted matches for navHost | Kind     | m_Index | Caller action            |
 * |---------------------------------|----------|---------|--------------------------|
 * | 0 (or empty/unparseable host)   | None     | -1      | do nothing (fail closed) |
 * | exactly 1                       | Single   | matched | auto-arm that record     |
 * | 2 or more                       | Multiple | -1      | do nothing (ambiguous)   |
 *
 * @param records Live vault records, soft-deleted included. Deleted records are
 *                skipped, but a Single result carries the raw index into this
 *                span, so it maps straight back to the caller's vector.
 * @param navHost Page hostname reported by the extension ("www.paypal.com").
 *                URLs are accepted; the host is extracted.
 * @return The resolution; @ref StageResolution::m_Index is set only for
 *         @ref StageResolution::Kind::Single.
 */
inline StageResolution resolveStageRecord(std::span<const VaultRecord> records,
                                          std::string_view navHost)
{
    const std::string pageHost = url::extractHost(navHost);
    if (pageHost.empty())
    {
        return {};  // Unparseable page host -> no opinion.
    }

    int matchIndex = -1;
    int matchCount = 0;
    for (int i = 0; i < static_cast<int>(records.size()); ++i)
    {
        if (records[i].deleted)
        {
            continue;
        }
        // Browser secret release: strict domain/URL records only.
        if (url::platformMatchesHostForSecretRelease(records[i].platform, navHost))
        {
            if (++matchCount == 1)
            {
                matchIndex = i;
            }
        }
    }

    if (matchCount == 0)
    {
        return {StageResolution::Kind::None, -1};
    }
    if (matchCount == 1)
    {
        return {StageResolution::Kind::Single, matchIndex};
    }
    return {StageResolution::Kind::Multiple, -1};
}

/**
 * @brief Whether a staged login page warrants a zero-click username fill.
 * @ingroup FillController
 *
 * Evaluated only after @ref resolveStageRecord returns a unique match, so the
 * page already binds to exactly one record. Either flag marks a confirmed login
 * surface:
 *  - @p hasUsernameField - the extension saw a standards-tagged identifier
 *    (`autocomplete="username"`), the email-first / multi-step first screen,
 *    which has no password field yet.
 *  - @p hasPasswordForm - a visible password field, itself proof of a login
 *    form, so a combined form whose identifier input carries no `autocomplete`
 *    token (Duolingo, for example) qualifies too.
 *
 * @par Why both flags
 * The two probes are not the same predicate. The nav report's identifier flag
 * is a strict `autocomplete="username"` scan, so a newsletter or contact email
 * box on a password-less page never sets it. The fill-side classifier in
 * content.js is deliberately broader (name, id, aria and placeholder
 * heuristics). The caller's login-page gate accepts either flag, so on a page
 * with no password field the strict nav flag is the only signal that can mark
 * the page as a login surface. That is why the narrow probe exists next to the
 * broad one.
 *
 * @par Where the fill lands
 * content.js `findUsernameField` is the where-gate: it writes only a field it
 * classifies as username or email, so a password-only page with no such field
 * fills nothing.
 *
 * @par Injection truth table
 * | hasUsernameField | hasPasswordForm | inject? | Typical page                    |
 * |------------------|-----------------|---------|---------------------------------|
 * | yes              | no              | yes     | email-first / multi-step screen |
 * | no               | yes             | yes     | password-only or combined form  |
 * | yes              | yes             | yes     | combined login form             |
 * | no               | no              | no      | not a login surface             |
 *
 * @param hasUsernameField Nav report saw a standards-tagged identifier.
 * @param hasPasswordForm  Nav report saw a visible password field.
 * @return true when either flag is set.
 */
inline bool navShouldInjectUsername(bool hasUsernameField, bool hasPasswordForm)
{
    return hasUsernameField || hasPasswordForm;
}

/**
 * @brief Whether a cached click authorization may fill the current document.
 * @ingroup FillController
 *
 * A browser click bridge entry carries the per-document visit token that was
 * live when the extension reported the click. At fill time this gate compares
 * that stored token against the visit of the document now loaded in the same
 * browser process (the freshest nav report).
 *
 * @par What it blocks
 * Cross-document replay: a stale entry, such as a legitimate site's earlier
 * focus-click, survives a navigation or tab switch at the same screen location
 * and would otherwise authorize typing into a different document.
 *
 * @par Fails open
 * The rule blocks on a positive mismatch only: both tokens are non-empty and
 * differ. An unknown token on either side (the extension did not tag the click,
 * or no navigation was seen for the process) returns true and defers to the
 * other gates (host binding, dual-PID, M5). A caller that needs a strict
 * document match (the fail-closed auto-release path) must also require both
 * tokens to be non-empty.
 *
 * @param entryVisit   Visit token stored on the click bridge entry.
 * @param currentVisit Visit token of the document now loaded in the click's
 *                     browser process.
 * @return false only when both tokens are non-empty and differ.
 */
inline bool visitAuthorizes(std::string_view entryVisit, std::string_view currentVisit) noexcept
{
    if (entryVisit.empty() || currentVisit.empty())
    {
        return true;  // Unknown on either side -> defer to the other gates.
    }
    return entryVisit == currentVisit;
}

/**
 * @class StageVisitTracker
 * @brief Per-page-visit one-shot latches for staged auto-fill.
 * @ingroup FillController
 *
 * A visit is one document lifetime: content.js mints a random token per
 * document and sends it with every nav report. A reload or a reopened tab is a
 * new visit; SPA route churn, MutationObserver re-reports and field-composition
 * flaps all keep the same token.
 *
 * @par Contract
 *  - The username is injected at most once per visit.
 *  - The password is click-filled at most once per visit.
 *  - After the password fill the visit is inert (no injection, no re-arm) until
 *    a page load mints a new token, however many nav reports arrive meanwhile.
 *  - An empty token fails closed, both latches reading "done", so an extension
 *    that sends no token never repeat-fills.
 *
 * @par Latching is the caller's duty
 * The tracker records only what it is told. StagingController calls
 * @ref noteUsernameInjected after a successful push to the browser, so a failed
 * push is retried on the next nav report of the same visit.
 *
 * @par Threading
 * Qt-free and clock-free, so the once-per-visit contract is enforced by unit
 * tests. StagingController owns one instance on the GUI thread; the class is
 * neither thread-safe nor reentrant.
 *
 * @par Memory
 * At most @ref kMaxVisits visits are remembered, evicting the least recently
 * written; only the note methods refresh recency. Eviction needs kMaxVisits
 * later visits to latch while that page stays open. An evicted spent visit
 * reads untracked again, so its document can arm once more; the password fill
 * still needs a fresh user click, and content.js holds its own per-document
 * latch that refuses a second username injection. Tokens are never reused, so
 * no other document inherits these latches.
 *
 * @par Per-visit latch states
 * | Visit state       | usernameDone() | passwordDone() | Effect                     |
 * |-------------------|----------------|----------------|----------------------------|
 * | empty token       | true           | true           | fail closed - never stages |
 * | untracked (fresh) | false          | false          | may inject + arm           |
 * | username injected | true           | false          | password still armable     |
 * | password filled   | true           | true           | visit inert - nothing more |
 */
class StageVisitTracker
{
public:
    /// Visits remembered before the least-recently-written is evicted.
    static constexpr std::size_t kMaxVisits = 8;

    /**
     * @brief Whether the username injection for @p visit is already spent.
     *
     * @param visit Per-document token from the nav report.
     * @return true when the username was already injected for @p visit, the
     *         visit is inert (password filled), or the token is empty.
     */
    bool usernameDone(std::string_view visit) const
    {
        if (visit.empty())
        {
            return true;  // Fail closed: no token, no staging.
        }
        const Visit* entry = find(visit);
        return entry != nullptr && (entry->m_UsernameDone || entry->m_PasswordDone);
    }

    /**
     * @brief Whether @p visit is inert, so nothing may stage on it again.
     *
     * @param visit Per-document token from the nav report.
     * @return true when the password was already filled for @p visit (the
     *         visit is inert) or the token is empty.
     */
    bool passwordDone(std::string_view visit) const
    {
        if (visit.empty())
        {
            return true;  // Fail closed: no token, no staging.
        }
        const Visit* entry = find(visit);
        return entry != nullptr && entry->m_PasswordDone;
    }

    /**
     * @brief Latch "username injected" for @p visit. No-op on an empty token.
     *
     * Inserts the visit when it is untracked and refreshes its recency, which
     * may evict the least-recently-written visit.
     */
    void noteUsernameInjected(std::string_view visit)
    {
        if (Visit* entry = touch(visit))
        {
            entry->m_UsernameDone = true;
        }
    }

    /**
     * @brief Latch "password filled" for @p visit - the visit goes inert.
     *        No-op on an empty token.
     *
     * Both latches then read "done", so nothing stages on this visit until a
     * page load mints a new token. Inserts and refreshes recency exactly like
     * @ref noteUsernameInjected.
     */
    void notePasswordFilled(std::string_view visit)
    {
        if (Visit* entry = touch(visit))
        {
            entry->m_PasswordDone = true;
        }
    }

private:
    /**
     * @struct Visit
     * @brief One remembered document lifetime and its two latches.
     */
    struct Visit
    {
        std::string m_Token;          ///< The per-document token, never empty here.
        bool m_UsernameDone = false;  ///< Username was injected for this visit.
        bool m_PasswordDone = false;  ///< Password was filled; the visit is inert.
    };

    /// @brief Locate @p visit without changing recency. Null when untracked.
    const Visit* find(std::string_view visit) const
    {
        const auto it = std::find_if(m_Visits.begin(),
                                     m_Visits.end(),
                                     [visit](const Visit& v) { return v.m_Token == visit; });
        return it == m_Visits.end() ? nullptr : &*it;
    }

    /**
     * @brief Find-or-insert @p visit as the most recently written entry.
     *
     * Moves an existing entry to the back, or appends a new one, evicting the
     * front (least recently written) at @ref kMaxVisits. The returned pointer
     * is invalidated by the next call. Null on an empty token.
     */
    Visit* touch(std::string_view visit)
    {
        if (visit.empty())
        {
            return nullptr;
        }
        const auto it = std::find_if(m_Visits.begin(),
                                     m_Visits.end(),
                                     [visit](const Visit& v) { return v.m_Token == visit; });
        if (it != m_Visits.end())
        {
            std::rotate(it, it + 1, m_Visits.end());  // Refresh recency.
            return &m_Visits.back();
        }
        if (m_Visits.size() >= kMaxVisits)
        {
            m_Visits.erase(m_Visits.begin());
        }
        m_Visits.push_back(Visit{std::string(visit), false, false});
        return &m_Visits.back();
    }

    std::vector<Visit> m_Visits;  ///< Insertion-ordered, LRU-on-write.
};

}  // namespace seal
