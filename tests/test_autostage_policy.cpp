#include "../src/AutoStagePolicy.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using seal::previewSiteBinding;
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

TEST(AutoStagePolicyTest, RecordStoredAsUrlMatchesSameAndDeeperHost)
{
    const std::vector<VaultRecord> records = {rec("https://login.paypal.com/signin?x=1")};
    EXPECT_EQ(resolveStageRecord(records, "login.paypal.com").m_Kind,
              StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(records, "mfa.login.paypal.com").m_Kind,
              StageResolution::Kind::Single);
}

TEST(AutoStagePolicyTest, RecordStoredAsSubdomainUrlDoesNotMatchParent)
{
    // subdomain records cannot stage on the parent domain.
    const std::vector<VaultRecord> records = {rec("https://login.paypal.com/signin?x=1")};
    const auto res = resolveStageRecord(records, "www.paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(res.m_Index, -1);
}

TEST(AutoStagePolicyTest, DomainRecordStaysStrictAcrossTlds)
{
    const std::vector<VaultRecord> records = {rec("paypal.com")};
    EXPECT_EQ(resolveStageRecord(records, "paypal.co").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(records, "paypal.xyz").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(records, "paypal.com.evil.com").m_Kind,
              StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, FreeFormLabelDoesNotAutoStage)
{
    // browser fill requires a stored domain; fuzzy labels serve UI lookup only.
    const std::vector<VaultRecord> records = {rec("My PayPal"), rec("Bob's Gmail")};
    const auto res = resolveStageRecord(records, "www.paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(res.m_Index, -1);
}

TEST(AutoStagePolicyTest, LabelTierDoesNotAutoStageAcrossTlds)
{
    const std::vector<VaultRecord> label = {rec("PayPal")};
    const std::vector<VaultRecord> domain = {rec("paypal.com")};
    EXPECT_EQ(resolveStageRecord(label, "paypal.co").m_Kind, StageResolution::Kind::None);
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
    // parent and exact records both bind the login subdomain, making selection ambiguous.
    const auto res = resolveStageRecord(records, "login.paypal.com");
    EXPECT_EQ(res.m_Kind, StageResolution::Kind::Multiple);
    EXPECT_EQ(res.m_Index, -1);
}

TEST(AutoStagePolicyTest, PunycodeHostMatchesLiterally)
{
    const std::vector<VaultRecord> records = {rec("xn--pypal-4ve.com")};
    EXPECT_EQ(resolveStageRecord(records, "xn--pypal-4ve.com").m_Kind,
              StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(records, "paypal.com").m_Kind, StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, BareBrandLabelDoesNotMatchDomainForAutoStage)
{
    const std::vector<VaultRecord> label = {rec("PayPal")};
    const std::vector<VaultRecord> lowerLabel = {rec("paypal")};
    const std::vector<VaultRecord> domain = {rec("paypal.com")};
    EXPECT_EQ(resolveStageRecord(label, "www.paypal.com").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(lowerLabel, "www.paypal.com").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(domain, "www.paypal.com").m_Kind, StageResolution::Kind::Single);
}

TEST(AutoStagePolicyTest, CcTldDistinctHostsDoNotCollide)
{
    // Registrable-name extraction is PSL-aware, while strict host matching
    // still keeps google.com and google.co.uk distinct.
    const std::vector<VaultRecord> records = {rec("google.com")};
    EXPECT_EQ(resolveStageRecord(records, "google.co.uk").m_Kind, StageResolution::Kind::None);
}

TEST(AutoStagePolicyTest, CcTldRecordMatchesPageAndSubdomain)
{
    const std::vector<VaultRecord> records = {rec("google.co.uk")};
    EXPECT_EQ(resolveStageRecord(records, "google.co.uk").m_Kind, StageResolution::Kind::Single);
    EXPECT_EQ(resolveStageRecord(records, "accounts.google.co.uk").m_Kind,
              StageResolution::Kind::Single);
}

TEST(AutoStagePolicyTest, PublicSuffixRecordNeverStages)
{
    const std::vector<VaultRecord> records = {rec("github.io"), rec("co.uk")};
    EXPECT_EQ(resolveStageRecord(records, "evil.github.io").m_Kind, StageResolution::Kind::None);
    EXPECT_EQ(resolveStageRecord(records, "example.co.uk").m_Kind, StageResolution::Kind::None);
}

TEST(SiteBindingPreviewTest, DomainAndUrlAreBindable)
{
    const std::vector<VaultRecord> records;
    const auto domain = previewSiteBinding(records, "github.com");
    EXPECT_TRUE(domain.m_Bindable);
    EXPECT_EQ(domain.m_Host, "github.com");

    const auto url = previewSiteBinding(records, "https://login.example.co.uk/sign-in");
    EXPECT_TRUE(url.m_Bindable);
    EXPECT_EQ(url.m_Host, "login.example.co.uk");
}

TEST(SiteBindingPreviewTest, BareLabelAndPublicSuffixAreUnbindable)
{
    const std::vector<VaultRecord> records;
    EXPECT_FALSE(previewSiteBinding(records, "GitHub").m_Bindable);
    EXPECT_FALSE(previewSiteBinding(records, "github.io").m_Bindable);
    EXPECT_FALSE(previewSiteBinding(records, "co.uk").m_Bindable);
}

TEST(SiteBindingPreviewTest, CountsLiveExactHostDuplicates)
{
    const std::vector<VaultRecord> records = {
        rec("github.com"),
        rec("https://github.com/login"),
        rec("login.github.com"),
        rec("github.com", /*deleted=*/true),
    };
    const auto preview = previewSiteBinding(records, "GITHUB.COM");
    EXPECT_TRUE(preview.m_Bindable);
    EXPECT_EQ(preview.m_DuplicateCount, 2U);

    const auto editingFirst = previewSiteBinding(records, "github.com", 0);
    EXPECT_EQ(editingFirst.m_DuplicateCount, 1U);
}

TEST(SiteBindingPreviewTest, DeletedRecordsAreExcluded)
{
    const std::vector<VaultRecord> records = {rec("example.com", /*deleted=*/true)};
    const auto preview = previewSiteBinding(records, "example.com");
    EXPECT_TRUE(preview.m_Bindable);
    EXPECT_EQ(preview.m_DuplicateCount, 0U);
}

// each document has a distinct visit token. username and password fill at most once;
// a password fill also consumes the username latch.

using seal::StageVisitTracker;

TEST(StageVisitTrackerTest, FreshVisitAllowsBothActions)
{
    StageVisitTracker tracker;
    EXPECT_FALSE(tracker.usernameDone("visit-a"));
    EXPECT_FALSE(tracker.passwordDone("visit-a"));
}

TEST(StageVisitTrackerTest, EmptyTokenFailsClosed)
{
    // missing visit tokens disable both latches.
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

    EXPECT_FALSE(tracker.passwordDone("visit-a"));
}

TEST(StageVisitTrackerTest, PasswordLatchMakesVisitFullyInert)
{
    // password fill consumes the username latch even on password-only pages.
    StageVisitTracker tracker;
    tracker.notePasswordFilled("visit-a");
    EXPECT_TRUE(tracker.passwordDone("visit-a"));
    EXPECT_TRUE(tracker.usernameDone("visit-a"));
}

TEST(StageVisitTrackerTest, VisitsAreIndependent)
{
    // two tabs of the same site: latching one leaves the other fresh.
    StageVisitTracker tracker;
    tracker.noteUsernameInjected("visit-a");
    tracker.notePasswordFilled("visit-a");
    EXPECT_FALSE(tracker.usernameDone("visit-b"));
    EXPECT_FALSE(tracker.passwordDone("visit-b"));
}

TEST(StageVisitTrackerTest, ReloadedPageGetsFreshLatches)
{
    // a reload creates a new token with fresh latches.
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
    // evicted visits read as fresh; tokens are not reused across document loads.
    EXPECT_FALSE(tracker.usernameDone("visit-0"));

    EXPECT_TRUE(tracker.usernameDone("visit-" + std::to_string(StageVisitTracker::kMaxVisits)));
}

TEST(StageVisitTrackerTest, WriteRefreshesRecency)
{
    // writes refresh LRU position so active tabs survive churn from other tabs.
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

// a visible password field can trigger username injection without autocomplete="username".

using seal::navShouldInjectUsername;

TEST(NavInjectUsernameTest, EmailFirstIdentifierTriggers)
{
    // Email-first step 1: autocomplete="username" present, no password field yet.
    EXPECT_TRUE(navShouldInjectUsername(/*hasUsernameField=*/true, /*hasPasswordForm=*/false));
}

TEST(NavInjectUsernameTest, CombinedFormWithoutAutocompleteStillTriggers)
{
    // combined login forms can omit autocomplete="username" from the identifier field.
    EXPECT_TRUE(navShouldInjectUsername(/*hasUsernameField=*/false, /*hasPasswordForm=*/true));
}

TEST(NavInjectUsernameTest, BothSignalsTrigger)
{
    EXPECT_TRUE(navShouldInjectUsername(/*hasUsernameField=*/true, /*hasPasswordForm=*/true));
}

TEST(NavInjectUsernameTest, NeitherSignalDoesNotTrigger)
{
    // an unlabelled email field without a password must not trigger injection.
    EXPECT_FALSE(navShouldInjectUsername(/*hasUsernameField=*/false, /*hasPasswordForm=*/false));
}

// click authorization belongs to the document that produced its visit token.

using seal::visitAuthorizes;

TEST(VisitAuthorizesTest, SameDocumentAuthorizes)
{
    EXPECT_TRUE(visitAuthorizes("visit-a", "visit-a"));
}

TEST(VisitAuthorizesTest, DifferentDocumentBlocks)
{
    // a matching screen position cannot authorize a different document.
    EXPECT_FALSE(visitAuthorizes("visit-old", "visit-new"));
}

TEST(VisitAuthorizesTest, UnknownTokenDefersToOtherGates)
{
    // missing visit data defers to caller gates.
    EXPECT_TRUE(visitAuthorizes("", "visit-new"));
    EXPECT_TRUE(visitAuthorizes("visit-old", ""));
    EXPECT_TRUE(visitAuthorizes("", ""));
}
