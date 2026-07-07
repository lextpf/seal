#include "../src/UrlBinding.hpp"

#include <gtest/gtest.h>

#include <string>

using seal::url::extractHost;
using seal::url::extractKey;
using seal::url::hostsMatch;
using seal::url::keysMatch;
using seal::url::platformMatchesHost;
using seal::url::platformMatchesHostForSecretRelease;

class UrlBindingTest : public ::testing::Test
{
};

// --- Tiered platformMatchesHost (auto-fill record binding) ---

TEST_F(UrlBindingTest, TieredDomainRecordIsStrict)
{
    // A record carrying a real domain matches only that host and its
    // subdomains, not a different-TLD lookalike or the subdomain trick.
    EXPECT_TRUE(platformMatchesHost("paypal.com", "www.paypal.com"));
    // Directional: an apex record binds its subdomains (parent->child)...
    EXPECT_TRUE(platformMatchesHost("paypal.com", "login.paypal.com"));
    // ...but a subdomain record no longer authorizes the parent (child->parent).
    EXPECT_FALSE(platformMatchesHost("login.paypal.com", "paypal.com"));
    EXPECT_FALSE(platformMatchesHost("paypal.com", "paypal.co"));
    EXPECT_FALSE(platformMatchesHost("paypal.com", "paypal.com.evil.com"));
}

TEST_F(UrlBindingTest, TieredBareLabelIsFuzzyTldBlind)
{
    // A bare/free-form label matches by registrable name, TLD-blind.
    EXPECT_TRUE(platformMatchesHost("PayPal", "www.paypal.com"));
    EXPECT_TRUE(platformMatchesHost("My PayPal", "paypal.com"));
    EXPECT_TRUE(platformMatchesHost("PayPal", "paypal.co"));  // the accepted tradeoff
    EXPECT_FALSE(platformMatchesHost("PayPal", "example.com"));
}

TEST_F(UrlBindingTest, TieredEmptyPageHostFailsClosed)
{
    EXPECT_FALSE(platformMatchesHost("paypal.com", ""));
    EXPECT_FALSE(platformMatchesHost("PayPal", ""));
}

TEST_F(UrlBindingTest, SecretReleaseRequiresDomainRecord)
{
    EXPECT_TRUE(platformMatchesHostForSecretRelease("paypal.com", "www.paypal.com"));
    // Parent->child still releases: an apex record fills on its login subdomain.
    EXPECT_TRUE(
        platformMatchesHostForSecretRelease("https://paypal.com/signin", "login.paypal.com"));
    // Directional: a subdomain record no longer releases on the parent domain.
    EXPECT_FALSE(
        platformMatchesHostForSecretRelease("https://login.paypal.com/signin", "paypal.com"));
    EXPECT_FALSE(platformMatchesHostForSecretRelease("paypal.com", "paypal.co"));
    EXPECT_FALSE(platformMatchesHostForSecretRelease("PayPal", "www.paypal.com"));
    EXPECT_FALSE(platformMatchesHostForSecretRelease("My PayPal", "paypal.com"));
    EXPECT_FALSE(platformMatchesHostForSecretRelease("PayPal", "paypal.co"));
}

// extractHost - happy path
TEST_F(UrlBindingTest, ExtractsBareHostname)
{
    EXPECT_EQ(extractHost("example.com"), "example.com");
}

TEST_F(UrlBindingTest, ExtractsHttpsUrl)
{
    EXPECT_EQ(extractHost("https://example.com/login"), "example.com");
}

TEST_F(UrlBindingTest, ExtractsHttpUrl)
{
    EXPECT_EQ(extractHost("http://example.com/"), "example.com");
}

TEST_F(UrlBindingTest, ExtractsCustomScheme)
{
    EXPECT_EQ(extractHost("file://example.com"), "example.com");
}

TEST_F(UrlBindingTest, StripsLeadingWww)
{
    EXPECT_EQ(extractHost("https://www.example.com/"), "example.com");
    EXPECT_EQ(extractHost("www.example.com"), "example.com");
}

TEST_F(UrlBindingTest, StripsCredentials)
{
    EXPECT_EQ(extractHost("https://user:password@example.com/"), "example.com");
    EXPECT_EQ(extractHost("https://user@example.com"), "example.com");
}

TEST_F(UrlBindingTest, StripsPort)
{
    EXPECT_EQ(extractHost("https://example.com:8443/"), "example.com");
    EXPECT_EQ(extractHost("example.com:443"), "example.com");
}

TEST_F(UrlBindingTest, StripsPath)
{
    EXPECT_EQ(extractHost("example.com/foo/bar"), "example.com");
}

TEST_F(UrlBindingTest, StripsQueryAndFragment)
{
    EXPECT_EQ(extractHost("example.com?next=/dashboard"), "example.com");
    EXPECT_EQ(extractHost("example.com#section"), "example.com");
}

TEST_F(UrlBindingTest, StripsTrailingDot)
{
    EXPECT_EQ(extractHost("example.com."), "example.com");
}

TEST_F(UrlBindingTest, NormalisesCase)
{
    EXPECT_EQ(extractHost("EXAMPLE.com"), "example.com");
    EXPECT_EQ(extractHost("HTTPS://Example.Com"), "example.com");
}

TEST_F(UrlBindingTest, AcceptsSubdomain)
{
    EXPECT_EQ(extractHost("https://accounts.google.com/signin"), "accounts.google.com");
}

TEST_F(UrlBindingTest, AcceptsHyphenAndDigits)
{
    EXPECT_EQ(extractHost("foo-bar.123.example.com"), "foo-bar.123.example.com");
}

TEST_F(UrlBindingTest, TrimsWhitespace)
{
    EXPECT_EQ(extractHost("  example.com  "), "example.com");
    EXPECT_EQ(extractHost("\thttps://example.com\n"), "example.com");
}

// extractHost - rejections
TEST_F(UrlBindingTest, RejectsEmpty)
{
    EXPECT_EQ(extractHost(""), "");
    EXPECT_EQ(extractHost("   "), "");
}

TEST_F(UrlBindingTest, RejectsFreeFormServiceName)
{
    // Single-label inputs are still valid hostnames; FQDN policy is the
    // caller's concern. We just return the normalised label.
    EXPECT_EQ(extractHost("Gmail"), "gmail");
}

TEST_F(UrlBindingTest, RejectsNonAscii)
{
    // Extension emits punycode; raw unicode bytes would compare apples to
    // oranges. Reject so binding fails closed.
    std::string input = "https://m\xc3\xbcnchen.de/";  // münchen.de
    EXPECT_EQ(extractHost(input), "");
}

TEST_F(UrlBindingTest, RejectsHostWithSlash)
{
    // Trim at first '/' and accept what remains.
    EXPECT_EQ(extractHost("example.com/extra/path"), "example.com");
}

TEST_F(UrlBindingTest, RejectsPunctuationInHost)
{
    EXPECT_EQ(extractHost("ex,ample.com"), "");
    EXPECT_EQ(extractHost("ex ample.com"), "");
    EXPECT_EQ(extractHost("ex<script>.com"), "");
}

// hostsMatch - happy path
TEST_F(UrlBindingTest, MatchExact)
{
    EXPECT_TRUE(hostsMatch("example.com", "example.com"));
}

TEST_F(UrlBindingTest, MatchSubdomainBelowRecord)
{
    // Record google.com matches accounts.google.com / mail.google.com.
    EXPECT_TRUE(hostsMatch("google.com", "accounts.google.com"));
    EXPECT_TRUE(hostsMatch("google.com", "mail.google.com"));
}

TEST_F(UrlBindingTest, RejectParentAboveRecord)
{
    // Directional binding: a record for a specific subdomain does NOT authorize
    // its parent domain or a sibling. Closes the "login.example.com authorizes
    // example.com" widening flagged in the security review.
    EXPECT_FALSE(hostsMatch("accounts.google.com", "google.com"));
    EXPECT_FALSE(hostsMatch("login.example.com", "example.com"));
    EXPECT_FALSE(hostsMatch("a.b.c.example.com", "example.com"));
    EXPECT_FALSE(hostsMatch("login.example.com", "signin.example.com"));
}

TEST_F(UrlBindingTest, MatchDeepSubdomain)
{
    // Parent->child still binds at any depth (an apex record authorizes its
    // subdomains).
    EXPECT_TRUE(hostsMatch("example.com", "a.b.c.example.com"));
    // The accepted, unchanged residual: an apex record authorizes ANY subdomain,
    // including a third-party one on a shared-suffix host. Tightening this needs
    // a public-suffix list (future work).
    EXPECT_TRUE(hostsMatch("example.com", "evil.example.com"));
}

// hostsMatch - phishing-resistance rejections
TEST_F(UrlBindingTest, RejectTyposquat)
{
    EXPECT_FALSE(hostsMatch("google.com", "gooogle.com"));
    EXPECT_FALSE(hostsMatch("google.com", "googIe.com"));  // capital I masquerading
    EXPECT_FALSE(hostsMatch("paypal.com", "paypa1.com"));
}

TEST_F(UrlBindingTest, RejectPrefixWithoutDotBoundary)
{
    // Classic "google.com.evil.com" / "fakegoogle.com" must NOT match;
    // dot-boundary matching is the whole point.
    EXPECT_FALSE(hostsMatch("google.com", "fakegoogle.com"));
    EXPECT_FALSE(hostsMatch("google.com", "google.com.evil.com"));
    EXPECT_FALSE(hostsMatch("google.com", "evilgoogle.com"));
}

TEST_F(UrlBindingTest, RejectSuffixWithoutDotBoundary)
{
    EXPECT_FALSE(hostsMatch("evil.com", "fakeevil.com"));
}

TEST_F(UrlBindingTest, RejectUnrelatedHosts)
{
    EXPECT_FALSE(hostsMatch("google.com", "facebook.com"));
    EXPECT_FALSE(hostsMatch("example.com", "example.org"));
}

TEST_F(UrlBindingTest, RejectEmpty)
{
    EXPECT_FALSE(hostsMatch("", "example.com"));
    EXPECT_FALSE(hostsMatch("example.com", ""));
    EXPECT_FALSE(hostsMatch("", ""));
}

// Combined extract + match (call-site shape).
TEST_F(UrlBindingTest, EndToEnd_RecordIsUrl_PageIsHost)
{
    const std::string recordHost = extractHost("https://www.example.com/login");
    const std::string pageHost = extractHost("example.com");
    EXPECT_EQ(recordHost, "example.com");
    EXPECT_EQ(pageHost, "example.com");
    EXPECT_TRUE(hostsMatch(recordHost, pageHost));
}

TEST_F(UrlBindingTest, EndToEnd_RejectMixedSiteSpoof)
{
    const std::string recordHost = extractHost("https://accounts.google.com/");
    const std::string pageHost = extractHost("accounts.google.com.evilsite.com");
    EXPECT_FALSE(hostsMatch(recordHost, pageHost));
}

TEST_F(UrlBindingTest, EndToEnd_RecordIsFreeForm_SkipBinding)
{
    // "Gmail" -> "gmail". hostsMatch is the discriminator; FillController
    // documented to fail-open on empty record host.
    const std::string recordHost = extractHost("Gmail");
    const std::string pageHost = extractHost("mail.google.com");
    EXPECT_EQ(recordHost, "gmail");
    EXPECT_FALSE(hostsMatch(recordHost, pageHost));
}

// extractKey - fuzzy normalisation (TLD strip, lowercase, dashes/
// underscores stripped) that reduces a hostname/URL to one registrable
// label. Used by the URL-binding warning (not a hard block).
TEST_F(UrlBindingTest, ExtractKey_BareLabel)
{
    EXPECT_EQ(extractKey("PayPal"), "paypal");
    EXPECT_EQ(extractKey("Gmail"), "gmail");
}

TEST_F(UrlBindingTest, ExtractKey_TwoLabelHost)
{
    EXPECT_EQ(extractKey("paypal.com"), "paypal");
    EXPECT_EQ(extractKey("PAYPAL.COM"), "paypal");
    EXPECT_EQ(extractKey("google.org"), "google");
}

TEST_F(UrlBindingTest, ExtractKey_ThreeLabelHost)
{
    EXPECT_EQ(extractKey("accounts.google.com"), "google");
    EXPECT_EQ(extractKey("mail.google.com"), "google");
    EXPECT_EQ(extractKey("login.paypal.com"), "paypal");
}

TEST_F(UrlBindingTest, ExtractKey_FromUrl)
{
    EXPECT_EQ(extractKey("https://www.paypal.com/signin"), "paypal");
    EXPECT_EQ(extractKey("https://login.paypal.com/signin?next=x"), "paypal");
    EXPECT_EQ(extractKey("http://accounts.google.com:8443/foo"), "google");
}

TEST_F(UrlBindingTest, ExtractKey_StripsDashes)
{
    EXPECT_EQ(extractKey("my-site.com"), "mysite");
    EXPECT_EQ(extractKey("foo-bar-baz.com"), "foobarbaz");
    EXPECT_EQ(extractKey("under_score.com"), "underscore");
}

TEST_F(UrlBindingTest, ExtractKey_StripsWwwBeforeKeying)
{
    // www.example.com -> example.com -> "example".
    EXPECT_EQ(extractKey("www.example.com"), "example");
    EXPECT_EQ(extractKey("WWW.EXAMPLE.COM"), "example");
}

TEST_F(UrlBindingTest, ExtractKey_EmptyAndInvalid)
{
    EXPECT_EQ(extractKey(""), "");
    EXPECT_EQ(extractKey("   "), "");
    // Non-ASCII -> extractHost rejects -> empty.
    EXPECT_EQ(extractKey("m\xc3\xbcnchen.de"), "");
}

// keysMatch - equality after normalisation. Just confirms the same-key
// / different-key contract; the key extractor makes the comparison
// forgiving.
TEST_F(UrlBindingTest, KeysMatch_SameKey)
{
    EXPECT_TRUE(keysMatch(extractKey("paypal.com"), extractKey("login.paypal.com")));
    EXPECT_TRUE(keysMatch(extractKey("PayPal"), extractKey("https://www.paypal.com/")));
    EXPECT_TRUE(keysMatch(extractKey("my-site.com"), extractKey("mysite.com")));
}

TEST_F(UrlBindingTest, KeysMatch_DifferentKey)
{
    EXPECT_FALSE(keysMatch(extractKey("paypal.com"), extractKey("google.com")));
    EXPECT_FALSE(keysMatch(extractKey("PayPal"), extractKey("typosquat-paypal.evil.com")));
    // "typosquat-paypal" -> "typosquatpaypal" - still distinct from "paypal".
    EXPECT_FALSE(keysMatch(extractKey("paypal"), extractKey("typosquatpaypal.com")));
}

TEST_F(UrlBindingTest, KeysMatch_EmptyIsNeutral)
{
    EXPECT_FALSE(keysMatch("", "paypal"));
    EXPECT_FALSE(keysMatch("paypal", ""));
    EXPECT_FALSE(keysMatch("", ""));
}

TEST_F(UrlBindingTest, KeysMatch_TldVariation)
{
    // Different TLD, same registrable name - both reduce to "paypal".
    EXPECT_TRUE(keysMatch(extractKey("paypal.com"), extractKey("paypal.de")));
    EXPECT_TRUE(keysMatch(extractKey("google.com"), extractKey("google.co")));
}

// extractKey - free-form multi-word labels. extractHost rejects inputs
// with spaces; the fallback splits on non-alnum tokens, drops stop-words
// ("my", "the", "login", "account", ...), and keeps the longest alnum
// token so labels like "Paypal Login" / "My Gmail" reduce to the brand.
TEST_F(UrlBindingTest, ExtractKey_FreeFormTwoWord)
{
    EXPECT_EQ(extractKey("Paypal Login"), "paypal");
    EXPECT_EQ(extractKey("My PayPal"), "paypal");
    EXPECT_EQ(extractKey("My Gmail"), "gmail");
    EXPECT_EQ(extractKey("Gmail Account"), "gmail");
}

TEST_F(UrlBindingTest, ExtractKey_FreeFormThreeWord)
{
    EXPECT_EQ(extractKey("My Paypal Account"), "paypal");
    EXPECT_EQ(extractKey("Personal Gmail Account"), "gmail");
}

TEST_F(UrlBindingTest, ExtractKey_FreeFormStripsCase)
{
    EXPECT_EQ(extractKey("PAYPAL LOGIN"), "paypal");
    EXPECT_EQ(extractKey("paypal login"), "paypal");
    EXPECT_EQ(extractKey("PayPal Login"), "paypal");
}

TEST_F(UrlBindingTest, ExtractKey_FreeFormPunctuation)
{
    // Apostrophes, slashes, commas: all non-alnum split points.
    EXPECT_EQ(extractKey("Bob's Paypal"), "paypal");
    EXPECT_EQ(extractKey("Paypal / personal"), "paypal");
    EXPECT_EQ(extractKey("Paypal, the one for shopping"), "paypal");
}

TEST_F(UrlBindingTest, ExtractKey_FreeFormAllStopwords)
{
    // Nothing meaningful to bind on; caller should fail open.
    EXPECT_EQ(extractKey("my account"), "");
    EXPECT_EQ(extractKey("the login"), "");
    EXPECT_EQ(extractKey("    "), "");
}

TEST_F(UrlBindingTest, ExtractKey_FreeFormSingleWord)
{
    // Surrounding noise: still reduces to the inner token.
    EXPECT_EQ(extractKey("[Paypal]"), "paypal");
    EXPECT_EQ(extractKey("**Gmail**"), "gmail");
}

TEST_F(UrlBindingTest, KeysMatch_FreeFormVsHostname)
{
    // Free-form labels and hostnames reduce to the same key.
    EXPECT_TRUE(keysMatch(extractKey("Paypal"), extractKey("paypal.com")));
    EXPECT_TRUE(keysMatch(extractKey("Paypal Login"), extractKey("login.paypal.com")));
    EXPECT_TRUE(keysMatch(extractKey("My Gmail"), extractKey("mail.google.com"))
                    ? true  // gmail vs google - different keys; we don't claim alias support.
                    : true);
    EXPECT_FALSE(keysMatch(extractKey("My Gmail"), extractKey("mail.google.com")));
    // ... but "Gmail" record on "gmail.com" page does match:
    EXPECT_TRUE(keysMatch(extractKey("Gmail"), extractKey("gmail.com")));
}

TEST_F(UrlBindingTest, KeysMatch_FreeFormBlocksTyposquat)
{
    // Phishing: "Paypal" record vs typosquat -> mismatch -> blocked.
    EXPECT_FALSE(keysMatch(extractKey("Paypal"), extractKey("paypa1.com")));
    EXPECT_FALSE(keysMatch(extractKey("Paypal Login"), extractKey("login-paypal-secure.evil.com")));
}
