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
 * @brief Result of strict browser host binding.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Records require a domain or URL; bare display labels cannot release browser
 * credentials. Matching uses platformMatchesHostForSecretRelease.
 */
struct StageResolution
{
    /**
     * @enum Kind
     * @brief How many eligible records bound to the navigated host.
     * @author Alex (<https://github.com/lextpf>)
     */
    enum class Kind : std::uint8_t
    {
        None,      ///< Zero eligible records match; do nothing.
        Single,    ///< Exactly one match; auto-arm `m_Index`.
        Multiple,  ///< Two or more match; ambiguous, do nothing.
    };

    Kind m_Kind = Kind::None;  ///< Match outcome; governs whether `m_Index` is set.
    int m_Index = -1;          ///< Record index into the input span; valid only when Kind::Single.
};

/**
 * @struct SiteBindingPreview
 * @brief Account-editor metadata without access to encrypted credentials.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * m_Host retains the full normalised host when bindable: for example,
 * https://login.example.co.uk/x becomes login.example.co.uk.
 */
struct SiteBindingPreview
{
    bool m_Bindable = false;  ///< Label contains a non-public-suffix domain/URL.
    std::string m_Host;       ///< Normalised host shown to the user, or empty when unbindable.
    /**
     * Other non-deleted records whose platform normalises to the same host.
     * Exact equality, so a parent/child pair is not a duplicate. Stays 0 when
     * `m_Bindable` is false, because the scan is then skipped entirely.
     */
    std::size_t m_DuplicateCount = 0;
};

/**
 * @fn inline SiteBindingPreview previewSiteBinding(std::span<const VaultRecord> records,
 *     std::string_view platform, int excludedRecordIndex = -1)
 * @brief Check strict site binding and exact-host duplicates.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Bare labels and public suffixes are unbindable. Duplicate detection skips
 * deleted and excluded records. It uses exact host equality, so parent and child
 * records are distinct here but may both authorize the same subdomain page.
 *
 * @param records Empty disables duplicate detection.
 * @param excludedRecordIndex -1 includes every live record.
 * @return Empty host and zero duplicates if unbindable.
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
 * @fn inline StageResolution resolveStageRecord(std::span<const VaultRecord> records,
 *     std::string_view navHost)
 * @brief Select one non-deleted record under strict browser host binding.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Binding is directional: paypal.com authorizes its subdomains, while
 * login.paypal.com authorizes neither the apex nor siblings. A public suffix
 * authorizes nothing. Apex and child records produce Multiple on the child page.
 *
 * | Non-deleted matches for navHost | Kind     | m_Index | Caller action            |
 * |---------------------------------|----------|---------|--------------------------|
 * | 0 (or empty/unparseable host)   | None     | -1      | Do nothing (fail closed) |
 * | Exactly 1                       | Single   | Matched | Auto-arm that record     |
 * | 2 or more                       | Multiple | -1      | Do nothing (ambiguous)   |
 *
 * @param navHost Hostname or URL; empty or invalid input yields None.
 * @return Single carries the original span index. Other results carry -1.
 */
inline StageResolution resolveStageRecord(std::span<const VaultRecord> records,
                                          std::string_view navHost)
{
    const std::string pageHost = url::extractHost(navHost);
    if (pageHost.empty())
    {
        return {};  // unparseable page host -> no opinion.
    }

    int matchIndex = -1;
    int matchCount = 0;
    for (int i = 0; i < static_cast<int>(records.size()); ++i)
    {
        if (records[i].deleted)
        {
            continue;
        }
        // browser secret release: strict domain/URL records only.
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
 * @fn inline bool navShouldInjectUsername(bool hasUsernameField, bool hasPasswordForm)
 * @brief Allow username injection on a confirmed login page.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Call only after unique record resolution. The username flag requires
 * autocomplete=username; the password flag also permits combined forms without
 * that attribute. This excludes password-less newsletter/contact email fields.
 * Content.js still requires a visible username or email target; password-only
 * pages without one receive nothing.
 *
 * | hasUsernameField | hasPasswordForm | Inject? | Typical page                    |
 * |------------------|-----------------|---------|---------------------------------|
 * | Yes              | No              | Yes     | Email-first / multi-step screen |
 * | No               | Yes             | Yes     | Password-only or combined form  |
 * | Yes              | Yes             | Yes     | Combined login form             |
 * | No               | No              | No      | Not a login surface             |
 */
inline bool navShouldInjectUsername(bool hasUsernameField, bool hasPasswordForm)
{
    return hasUsernameField || hasPasswordForm;
}

/**
 * @fn inline bool visitAuthorizes(std::string_view entryVisit, std::string_view currentVisit)
 *     noexcept
 * @brief Reject click authorization from a different document.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * @return False only if both tokens are non-empty and unequal. Missing tokens
 *         defer to host, PID, and corroboration gates.
 * @warning Auto release must also require both tokens to be non-empty.
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
 * @brief Track username and password completion per document token.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Reloads mint new tokens; SPA routes retain them. The caller latches only after
 * successful sends, so failures remain retryable. Empty tokens fail closed.
 * GUI-thread use only; neither thread-safe nor reentrant.
 *
 * Only note methods refresh recency. After kMaxVisits later writes, an evicted
 * visit may arm again and still requires a fresh password click. Content.js keeps
 * its own username latch for the document lifetime.
 *
 * | Visit state       | usernameDone() | passwordDone() | Effect                     |
 * |-------------------|----------------|----------------|----------------------------|
 * | Empty token       | True           | True           | Fail closed - never stages |
 * | Untracked (fresh) | False          | False          | May inject + arm           |
 * | Username injected | True           | False          | Password still armable     |
 * | Password filled   | True           | True           | Visit inert - nothing more |
 */
class StageVisitTracker
{
public:
    /// Visits remembered before the least-recently-written is evicted.
    static constexpr std::size_t kMaxVisits = 8;

    /**
     * @fn bool usernameDone(std::string_view visit) const
     * @brief True for injected usernames, completed passwords, or empty tokens.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool usernameDone(std::string_view visit) const
    {
        if (visit.empty())
        {
            return true;  // fail closed: no token, no staging.
        }
        const Visit* entry = find(visit);
        return entry != nullptr && (entry->m_UsernameDone || entry->m_PasswordDone);
    }

    /**
     * @fn bool passwordDone(std::string_view visit) const
     * @brief True for completed passwords or empty tokens.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool passwordDone(std::string_view visit) const
    {
        if (visit.empty())
        {
            return true;  // fail closed: no token, no staging.
        }
        const Visit* entry = find(visit);
        return entry != nullptr && entry->m_PasswordDone;
    }

    /**
     * @fn void noteUsernameInjected(std::string_view visit)
     * @brief Mark username completion and refresh visit recency.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op for an empty token. May evict the least recently written visit.
     */
    void noteUsernameInjected(std::string_view visit)
    {
        if (Visit* entry = touch(visit))
        {
            entry->m_UsernameDone = true;
        }
    }

    /**
     * @fn void notePasswordFilled(std::string_view visit)
     * @brief Mark both fields complete and refresh visit recency.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op for an empty token. May evict the least recently written visit.
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
        std::string m_Token;          ///< The per-document token, never empty here.
        bool m_UsernameDone = false;  ///< Username was injected for this visit.
        bool m_PasswordDone = false;  ///< Password was filled; the visit is inert.
    };

    /**
     * @fn const Visit* find(std::string_view visit) const
     * @brief Locate visit without changing recency.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Null when untracked.
     */
    const Visit* find(std::string_view visit) const
    {
        const auto it = std::find_if(m_Visits.begin(),
                                     m_Visits.end(),
                                     [visit](const Visit& v) { return v.m_Token == visit; });
        return it == m_Visits.end() ? nullptr : &*it;
    }

    /**
     * @fn Visit* touch(std::string_view visit)
     * @brief Refresh or insert a visit, evicting the least recently written at capacity.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return Null for an empty token; otherwise valid until the next call.
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
            std::rotate(it, it + 1, m_Visits.end());  // refresh recency.
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
