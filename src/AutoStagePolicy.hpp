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
 * @brief Pure site->record resolver for zero-gesture auto-staging.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Given the host of the page the user just navigated to, decide whether
 * exactly one vault record should be auto-armed. Kept Qt-free so the
 * policy is unit-testable in the no-Qt test target; StagingController feeds
 * it the navigated host and the live record vector on the GUI thread.
 *
 * ## Matching policy (see @ref seal::url::platformMatchesHostForSecretRelease)
 *
 * Browser auto-stage uses the strict secret-release matcher: a record must
 * store a real domain/URL, and that host must match the live page by
 * dot-boundary suffix rules. Bare labels stay useful for display/search but
 * do not provide enough binding material for browser credential release.
 *
 * The page host always arrives as a real `location.hostname`.
 */
struct StageResolution
{
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
 * @brief Resolve a navigated host to a unique auto-stage record, or none.
 * @ingroup FillController
 *
 * Counts non-deleted records whose `platform` binds to @p navHost under the
 * strict @ref seal::url::platformMatchesHostForSecretRelease policy. Exactly
 * one -> Single(index); zero -> None; two or more -> Multiple. An empty /
 * unparseable @p navHost, a bare-label record, or a set with no matching
 * records yields None (fail closed).
 *
 * @par Resolution outcomes
 * | Non-deleted matches for navHost | Kind     | m_Index | Caller action            |
 * |---------------------------------|----------|---------|--------------------------|
 * | 0 (or empty/unparseable host)   | None     | -1      | do nothing (fail closed) |
 * | exactly 1                       | Single   | matched | auto-arm that record     |
 * | 2 or more                       | Multiple | -1      | do nothing (ambiguous)   |
 *
 * @param records Live vault record vector (index of a Single result maps
 *                directly to this span).
 * @param navHost The page hostname reported by the extension (e.g.
 *                "www.paypal.com").
 * @return The resolution; @ref StageResolution::m_Index is only meaningful
 *         for @ref StageResolution::Kind::Single.
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
 * page already binds to exactly one record. Returns true when the page is a
 * confirmed login surface:
 *  - @p hasUsernameField - the extension saw a standards-tagged identifier
 *    (`autocomplete="username"`): the email-first / multi-step first screen,
 *    which has no password field yet; OR
 *  - @p hasPasswordForm - a visible password field is present. A password
 *    field is itself proof of a login form, so a COMBINED form whose identifier
 *    input carries no `autocomplete` token (e.g. Duolingo) still qualifies.
 *
 * content.js's `findUsernameField` remains the where-gate: it writes only a
 * field it confidently classifies as username/email, so a password-only page
 * with no such field simply fills nothing.
 *
 * The asymmetry this closes: the nav-report `user` flag is a STRICT
 * `autocomplete="username"` probe (so a newsletter/contact email box on a
 * password-less page can never trigger a fill), but the actual fill classifier
 * is broad. Keying injection on the identifier flag ALONE stranded combined
 * forms that omit the token. Including @p hasPasswordForm restores them without
 * relaxing the password-less case: with no password field, the caller's own
 * login-page gate still requires @p hasUsernameField, so this predicate
 * independently preserves that strictness (defense in depth).
 *
 * @par Injection truth table (returns hasUsernameField || hasPasswordForm)
 * | hasUsernameField | hasPasswordForm | inject? | Typical page                    |
 * |------------------|-----------------|---------|---------------------------------|
 * | yes              | no              | yes     | email-first / multi-step screen |
 * | no               | yes             | yes     | password-only or combined form  |
 * | yes              | yes             | yes     | combined login form             |
 * | no               | no              | no      | not a login surface             |
 */
inline bool navShouldInjectUsername(bool hasUsernameField, bool hasPasswordForm)
{
    return hasUsernameField || hasPasswordForm;
}

/**
 * @brief Whether a cached click authorization may fill the current document.
 * @ingroup FillController
 *
 * A browser click bridge entry now carries the per-document visit token that
 * was live when the extension reported the click. At fill time the gate
 * compares that stored token against the visit of the document currently
 * loaded in the same browser process (the freshest nav report). This is the
 * guard against the cross-document REPLAY where a stale entry - a legitimate
 * site's earlier focus-click - survives a navigation or tab switch at the same
 * screen location and would otherwise authorize typing into a different
 * document.
 *
 * The rule blocks ONLY on a positive mismatch: both tokens are known
 * (non-empty) and differ. When either token is unknown - an older extension
 * that does not tag clicks with a visit, or no navigation seen yet for the
 * process - it returns true and defers to the other gates (host binding,
 * dual-PID, M5). A caller that needs a strict document match (the fail-closed
 * auto-release path) must additionally require both tokens to be non-empty.
 *
 * @param entryVisit   The visit token stored on the click bridge entry.
 * @param currentVisit The visit token of the document currently loaded in the
 *                     click's browser process.
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
 * @brief Per-page-visit one-shot latches for staged auto-fill.
 * @ingroup FillController
 *
 * A *visit* is one document lifetime in the browser: content.js mints a
 * random token per document and sends it with every nav report, so a reload
 * or a reopened tab is a NEW visit while SPA route churn, MutationObserver
 * re-reports, and field-composition flaps all keep the SAME token. The
 * tracker pins the user-facing contract of zero-gesture staging:
 *
 *  - the username is injected at most ONCE per visit;
 *  - the password is click-filled at most ONCE per visit;
 *  - after the password fill the visit is INERT - no injection, no re-arm,
 *    no matter how many further nav reports the page produces - until a
 *    fresh page load produces a new token.
 *
 * An EMPTY token fails closed (both latches read "done") so a stale
 *  extension that predates the token can never repeat-fill.
 *
 * Kept Qt-free and clock-free so the once-per-visit contract is enforced by
 * unit tests; StagingController owns one instance on the GUI thread (not
 * thread-safe). Memory is bounded: at most @ref kMaxVisits visits are
 * remembered, evicting least-recently-written. Tokens are random per page
 * load and never reused, so an evicted visit reading fresh again is
 * harmless in practice (eviction needs kMaxVisits interleaved newer visits
 * while that page stays open and churning).
 *
 * @par Per-visit latch states
 * | Visit state       | usernameDone() | passwordDone() | Effect                     |
 * |-------------------|----------------|----------------|----------------------------|
 * | empty token       | true           | true           | fail closed - never stages |
 * | untracked (fresh) | false          | false          | may inject + arm           |
 * | username injected | true           | false          | password still armable     |
 * | password filled   | true           | true           | visit INERT - nothing more |
 */
class StageVisitTracker
{
public:
    /// Visits remembered before the least-recently-written is evicted.
    static constexpr std::size_t kMaxVisits = 8;

    /**
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

    /// @brief Latch "username injected" for @p visit. No-op on an empty token.
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
     */
    void notePasswordFilled(std::string_view visit)
    {
        if (Visit* entry = touch(visit))
        {
            entry->m_PasswordDone = true;
        }
    }

private:
    struct Visit
    {
        std::string m_Token;
        bool m_UsernameDone = false;
        bool m_PasswordDone = false;
    };

    const Visit* find(std::string_view visit) const
    {
        const auto it = std::find_if(m_Visits.begin(),
                                     m_Visits.end(),
                                     [visit](const Visit& v) { return v.m_Token == visit; });
        return it == m_Visits.end() ? nullptr : &*it;
    }

    /**
     * Find-or-insert @p visit and move it to the back (most recent), evicting
     * the front (least recently written) at capacity. Null on empty token.
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
