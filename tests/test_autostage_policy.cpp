#include "../src/AutoStagePolicy.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using seal::resolveStageRecord;
using seal::StageResolution;
using seal::VaultRecord;

namespace
{

VaultRecord rec(std::string platform, bool deleted = false)
{
    VaultRecord r;
    r.platform = std::move(platform);
    r.deleted = deleted;
    return r;
}

}  // namespace

TEST(AutoStagePolicyTest, EmptyRecordsIsNone)
{
    const std::vector<VaultRecord> records;
    const auto res = resolveStageRecord(records, "paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(res.m_Index, -1);
}

TEST(AutoStagePolicyTest, EmptyNavHostIsNone)
{
    const std::vector<VaultRecord> records = {rec("paypal.com")};
    const auto res = resolveStageRecord(records, "");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, ExactHostSingleMatch)
{
    const std::vector<VaultRecord> records = {
        rec("github.com"), rec("paypal.com"), rec("example.org")};
    const auto res = resolveStageRecord(records, "paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(res.m_Index, 1);
}

TEST(AutoStagePolicyTest, WwwPrefixAndSubdomainStillMatch)
{
    const std::vector<VaultRecord> records = {rec("paypal.com")};
    // extractHost strips www.; hostsMatch treats accounts.* as a more-specific
    // dot-aligned suffix of the record host.
    EXPECT_EQ(resolveStageRecord(records, "www.paypal.com").m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(records, "login.paypal.com").m_Kind,
              StageResolution::Kind::Single);
}

TEST(AutoStagePolicyTest, RecordStoredAsUrlMatches)
{
    const std::vector<VaultRecord> records = {rec("https://login.paypal.com/signin?x=1")};
    const auto res = resolveStageRecord(records, "www.paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(res.m_Index, 0);
}

TEST(AutoStagePolicyTest, DomainRecordStaysStrictAcrossTlds)
{
    // A record that carries a real DOMAIN is matched strictly (the safe tier):
    // a different TLD or the subdomain trick must not auto-stage it.
    const std::vector<VaultRecord> records = {rec("paypal.com")};
    EXPECT_EQ(resolveStageRecord(records, "paypal.co").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(records, "paypal.xyz").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(records, "paypal.com.evil.com").m_Kind,
              StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, FreeFormLabelMatchesByBrandName)
{
    // Fuzzy tier: a free-form label with no parseable host still matches by
    // registrable brand name so brand-label vaults auto-fill. "My PayPal"
    // reduces to "paypal"; "Bob's Gmail" to "gmail".
    const std::vector<VaultRecord> records = {rec("My PayPal"), rec("Bob's Gmail")};
    const auto res = resolveStageRecord(records, "www.paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(res.m_Index, 0);
}

TEST(AutoStagePolicyTest, LabelTierIsTldBlindButDomainTierIsNot)
{
    // The deliberate tradeoff, pinned: a BARE LABEL is TLD-blind (matches a
    // lookalike TLD), but a DOMAIN record is not. Store the domain for the
    // strict guarantee.
    const std::vector<VaultRecord> label = {rec("PayPal")};
    const std::vector<VaultRecord> domain = {rec("paypal.com")};
    EXPECT_EQ(resolveStageRecord(label, "paypal.co").m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(domain, "paypal.co").m_Kind, StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, DeletedRecordsSkipped)
{
    const std::vector<VaultRecord> records = {rec("paypal.com", /*deleted=*/true),
                                              rec("github.com")};
    EXPECT_EQ(resolveStageRecord(records, "paypal.com").m_Kind, StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, TwoRecordsSameSiteIsMultiple)
{
    const std::vector<VaultRecord> records = {rec("paypal.com"), rec("login.paypal.com")};
    // Both match paypal.com (one exact, one dot-aligned suffix) -> ambiguous.
    const auto res = resolveStageRecord(records, "paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::Multiple);
    EXPECT_EQ(res.m_Index, -1);
}

TEST(AutoStagePolicyTest, PunycodeHostMatchesLiterally)
{
    // Punycode arrives as ASCII (xn--...); a stored punycode host matches the
    // same punycode page host, and a different one does not.
    const std::vector<VaultRecord> records = {rec("xn--pypal-4ve.com")};
    EXPECT_EQ(resolveStageRecord(records, "xn--pypal-4ve.com").m_Kind,
              StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(records, "paypal.com").m_Kind, StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, BareBrandLabelMatchesDomainByBrandName)
{
    // The reported bug's fix: a bare brand label ("PayPal", no TLD) now DOES
    // auto-stage on www.paypal.com via the fuzzy tier (registrable-name match),
    // so brand-label vaults work. Before the tiered change this returned None.
    const std::vector<VaultRecord> label = {rec("PayPal")};
    const std::vector<VaultRecord> lowerLabel = {rec("paypal")};
    const std::vector<VaultRecord> domain = {rec("paypal.com")};
    EXPECT_EQ(resolveStageRecord(label, "www.paypal.com").m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(lowerLabel, "www.paypal.com").m_Kind,
              StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(domain, "www.paypal.com").m_Kind, StageResolution::Kind::Single);
}

TEST(AutoStagePolicyTest, CcTldDistinctHostsDoNotCollide)
{
    // Documented extractKey ccTLD imperfection (google.co.uk -> key "co") does
    // NOT affect strict hostsMatch: google.com and google.co.uk are distinct.
    const std::vector<VaultRecord> records = {rec("google.com")};
    EXPECT_EQ(resolveStageRecord(records, "google.co.uk").m_Kind, StageResolution::Kind::None);
}

// ---------------------------------------------------------------------------
// StageVisitTracker -- per-page-visit one-shot latches. A visit is one
// document lifetime in the browser (content.js mints a random token per
// document; reload / reopen = new token). The user-facing contract under
// test: the username fills at most ONCE per visit, the password at most
// ONCE per visit, and after the password fill the visit is inert -- no
// staging action of any kind until a fresh page load produces a new token.
// ---------------------------------------------------------------------------

using seal::StageVisitTracker;

TEST(StageVisitTrackerTest, FreshVisitAllowsBothActions)
{
    StageVisitTracker tracker;
    EXPECT_FALSE(tracker.usernameDone("visit-a"));
    EXPECT_FALSE(tracker.passwordDone("visit-a"));
}

TEST(StageVisitTrackerTest, EmptyTokenFailsClosed)
{
    // A stale extension that sends no visit token must never stage: both
    // latches read as "already done" and notes are no-ops.
    StageVisitTracker tracker;
    EXPECT_TRUE(tracker.usernameDone(""));
    EXPECT_TRUE(tracker.passwordDone(""));
    tracker.noteUsernameInjected("");
    tracker.notePasswordFilled("");
    EXPECT_TRUE(tracker.usernameDone(""));
    EXPECT_TRUE(tracker.passwordDone(""));
}

TEST(StageVisitTrackerTest, UsernameLatchesOncePerVisitButArmStaysAllowed)
{
    StageVisitTracker tracker;
    tracker.noteUsernameInjected("visit-a");
    EXPECT_TRUE(tracker.usernameDone("visit-a"));
    // The password click-fill is still pending for this visit.
    EXPECT_FALSE(tracker.passwordDone("visit-a"));
}

TEST(StageVisitTrackerTest, PasswordLatchMakesVisitFullyInert)
{
    // After the one password fill, NOTHING more fills on this visit -- the
    // username latch reads done too (a pw-only page never injected one).
    StageVisitTracker tracker;
    tracker.notePasswordFilled("visit-a");
    EXPECT_TRUE(tracker.passwordDone("visit-a"));
    EXPECT_TRUE(tracker.usernameDone("visit-a"));
}

TEST(StageVisitTrackerTest, VisitsAreIndependent)
{
    // Two tabs of the same site: latching one leaves the other fresh.
    StageVisitTracker tracker;
    tracker.noteUsernameInjected("visit-a");
    tracker.notePasswordFilled("visit-a");
    EXPECT_FALSE(tracker.usernameDone("visit-b"));
    EXPECT_FALSE(tracker.passwordDone("visit-b"));
}

TEST(StageVisitTrackerTest, ReloadedPageGetsFreshLatches)
{
    // A refresh mints a NEW token; the old visit's latches must not carry
    // over. (The old token never reappears -- documents are never revived.)
    StageVisitTracker tracker;
    tracker.notePasswordFilled("visit-load1");
    EXPECT_FALSE(tracker.passwordDone("visit-load2"));
    EXPECT_FALSE(tracker.usernameDone("visit-load2"));
}

TEST(StageVisitTrackerTest, OldestVisitEvictedAtCapacity)
{
    StageVisitTracker tracker;
    tracker.noteUsernameInjected("visit-0");
    for (std::size_t i = 1; i <= StageVisitTracker::kMaxVisits; ++i)
    {
        tracker.noteUsernameInjected("visit-" + std::to_string(i));
    }
    // visit-0 was evicted (bounded memory); it reads fresh again. Harmless:
    // a real visit-0 document would long since have re-latched, and tokens
    // are never reused across page loads.
    EXPECT_FALSE(tracker.usernameDone("visit-0"));
    // The most recent kMaxVisits entries are intact.
    EXPECT_TRUE(tracker.usernameDone("visit-" + std::to_string(StageVisitTracker::kMaxVisits)));
}

TEST(StageVisitTrackerTest, WriteRefreshesRecency)
{
    // LRU-on-write: re-noting a visit moves it to the back, so a busy tab is
    // not evicted by churn from other tabs.
    StageVisitTracker tracker;
    tracker.noteUsernameInjected("hot");
    for (std::size_t i = 1; i < StageVisitTracker::kMaxVisits; ++i)
    {
        tracker.noteUsernameInjected("cold-" + std::to_string(i));
    }
    tracker.noteUsernameInjected("hot");  // Refresh recency; tracker is full.
    tracker.noteUsernameInjected("new");  // Evicts cold-1, not hot.
    EXPECT_TRUE(tracker.usernameDone("hot"));
    EXPECT_FALSE(tracker.usernameDone("cold-1"));
}

// ---------------------------------------------------------------------------
// navShouldInjectUsername -- the zero-click username-fill trigger. The nav
// report's `user` flag is a STRICT autocomplete="username" probe; keying
// injection on it alone stranded combined login forms whose identifier field
// omits the token (the password armed but the username never injected).
// ---------------------------------------------------------------------------

using seal::navShouldInjectUsername;

TEST(NavInjectUsernameTest, EmailFirstIdentifierTriggers)
{
    // Email-first step 1: autocomplete="username" present, no password field yet.
    EXPECT_TRUE(navShouldInjectUsername(/*hasUsernameField=*/true, /*hasPasswordForm=*/false));
}

TEST(NavInjectUsernameTest, CombinedFormWithoutAutocompleteStillTriggers)
{
    // The Duolingo regression, pinned: a combined login form (password field
    // present) whose identifier input carries NO autocomplete="username" token.
    // The old gate keyed on the identifier flag alone and returned false here,
    // so the password armed but the username never injected. A visible password
    // field is proof of a login, so this MUST trigger.
    EXPECT_TRUE(navShouldInjectUsername(/*hasUsernameField=*/false, /*hasPasswordForm=*/true));
}

TEST(NavInjectUsernameTest, BothSignalsTrigger)
{
    EXPECT_TRUE(navShouldInjectUsername(/*hasUsernameField=*/true, /*hasPasswordForm=*/true));
}

TEST(NavInjectUsernameTest, NeitherSignalDoesNotTrigger)
{
    // Not a login page (the caller's nav gate rejects this earlier too). Pinned
    // so a password-less page with no autocomplete="username" identifier -- a
    // bare newsletter/contact email box -- can never trigger a username write.
    EXPECT_FALSE(navShouldInjectUsername(/*hasUsernameField=*/false, /*hasPasswordForm=*/false));
}
