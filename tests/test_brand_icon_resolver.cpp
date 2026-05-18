#include "../src/BrandIconResolver.hpp"

#include <gtest/gtest.h>

#include <functional>
#include <string>
#include <unordered_map>

namespace
{

std::function<std::string(const std::string&)> makeLookup()
{
    return [](const std::string& candidate) -> std::string
    {
        static const std::unordered_map<std::string, std::string> s_Index = {
            {"github", "github"},
            {"gitlab", "gitlab"},
            {"xtwitter", "x-twitter"},
            {"signalmessenger", "signal-messenger"},
            {"facebookmessenger", "facebook-messenger"},
            {"bitcoin", "bitcoin"},
            {"dropbox", "dropbox"},
            {"discord", "discord"},
            {"ccmastercard", "cc-mastercard"},
            {"ccvisa", "cc-visa"},
            {"ccdinersclub", "cc-diners-club"},
            {"ccdiscover", "cc-discover"},
            {"edge", "edge"},
            {"playstation", "playstation"},
            {"whatsappsquare", "whatsapp-square"},
            {"wordpress", "wordpress"},
            {"googledrive", "google-drive"},
        };
        auto it = s_Index.find(candidate);
        return (it != s_Index.end()) ? it->second : std::string{};
    };
}

}  // namespace

class BrandIconResolverTest : public ::testing::Test
{
};

TEST_F(BrandIconResolverTest, NormalizeSlugLowercasesAndDropsPunctuation)
{
    EXPECT_EQ(seal::brand::normalizeSlug("GitHub"), "github");
    EXPECT_EQ(seal::brand::normalizeSlug("github"), "github");
    EXPECT_EQ(seal::brand::normalizeSlug("Twitter, Inc."), "twitterinc");
    EXPECT_EQ(seal::brand::normalizeSlug("github.com"), "githubcom");
    EXPECT_EQ(seal::brand::normalizeSlug("X"), "x");
    EXPECT_EQ(seal::brand::normalizeSlug("x-twitter"), "xtwitter");
    EXPECT_EQ(seal::brand::normalizeSlug("Signal-Messenger"), "signalmessenger");
}

TEST_F(BrandIconResolverTest, NormalizeSlugReturnsEmptyForEmptyOrPunctuationOnly)
{
    EXPECT_EQ(seal::brand::normalizeSlug(""), "");
    EXPECT_EQ(seal::brand::normalizeSlug("   "), "");
    EXPECT_EQ(seal::brand::normalizeSlug("!!!"), "");
    EXPECT_EQ(seal::brand::normalizeSlug(",.;:"), "");
}

TEST_F(BrandIconResolverTest, ResolveDirectMatch)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("GitHub", lookup), "github");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Dropbox", lookup), "dropbox");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Bitcoin", lookup), "bitcoin");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("discord", lookup), "discord");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Google Drive", lookup), "google-drive");
}

TEST_F(BrandIconResolverTest, ResolveXTwitterAlias)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("X", lookup), "x-twitter");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Twitter", lookup), "x-twitter");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Twitter, Inc.", lookup), "x-twitter");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("twitter", lookup), "x-twitter");
}

TEST_F(BrandIconResolverTest, ResolveSignalAlias)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Signal", lookup), "signal-messenger");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("signal", lookup), "signal-messenger");
}

TEST_F(BrandIconResolverTest, ResolveMessengerAlias)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Messenger", lookup), "facebook-messenger");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("FB Messenger", lookup), "facebook-messenger");
}

TEST_F(BrandIconResolverTest, ResolvePaymentCardAliases)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Mastercard", lookup), "cc-mastercard");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("MC", lookup), "cc-mastercard");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Visa", lookup), "cc-visa");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Diners", lookup), "cc-diners-club");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Discover", lookup), "cc-discover");
}

TEST_F(BrandIconResolverTest, ResolveTldStrip)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("github.com", lookup), "github");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("dropbox.com", lookup), "dropbox");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("discord.app", lookup), "discord");
}

TEST_F(BrandIconResolverTest, ResolveEdgeAlias)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("MS Edge", lookup), "edge");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Microsoft Edge", lookup), "edge");
}

TEST_F(BrandIconResolverTest, ResolvePlayStationAlias)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("PSN", lookup), "playstation");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("PlayStation", lookup), "playstation");
}

TEST_F(BrandIconResolverTest, ResolveUnknownReturnsEmpty)
{
    auto lookup = makeLookup();
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("My Bank", lookup), "");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Home Wifi", lookup), "");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Random Service 123", lookup), "");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("", lookup), "");
}

TEST_F(BrandIconResolverTest, ResolveAliasOnlyWhenAssetExists)
{
    // Empty lookup -> every alias miss returns empty.
    auto emptyLookup = [](const std::string&) -> std::string { return {}; };
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("X", emptyLookup), "");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("GitHub", emptyLookup), "");
    EXPECT_EQ(seal::brand::resolveBrandIconSlug("Twitter", emptyLookup), "");
}
