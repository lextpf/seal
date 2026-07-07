#include "../src/SignerUtils.hpp"

#include <gtest/gtest.h>

#include <string>

using seal::signer::BrowserKind;
using seal::signer::browserKindToken;
using seal::signer::browserPublisherMatches;
using seal::signer::identifyBrowser;
using seal::signer::isShellImage;

namespace
{

// The bridge attributes each connection to a specific browser via
// identifyBrowser() on the WinVerifyTrust-validated ancestor image, so the
// per-browser status dots depend on Chrome and Brave mapping to distinct kinds.
TEST(SignerFamilyTest, ChromeAndBraveAreDistinct)
{
    EXPECT_EQ(identifyBrowser(L"chrome.exe"), BrowserKind::Chrome);
    EXPECT_EQ(identifyBrowser(L"brave.exe"), BrowserKind::Brave);
    EXPECT_NE(identifyBrowser(L"chrome.exe"), identifyBrowser(L"brave.exe"));
}

TEST(SignerFamilyTest, RecognisesKnownBrowsers)
{
    EXPECT_EQ(identifyBrowser(L"msedge.exe"), BrowserKind::Edge);
    EXPECT_EQ(identifyBrowser(L"firefox.exe"), BrowserKind::Firefox);
    EXPECT_EQ(identifyBrowser(L"vivaldi.exe"), BrowserKind::Vivaldi);
    EXPECT_EQ(identifyBrowser(L"opera.exe"), BrowserKind::Opera);
    EXPECT_EQ(identifyBrowser(L"librewolf.exe"), BrowserKind::LibreWolf);
}

// Mirrors how the ancestry walk hands identifyBrowser a full image path.
TEST(SignerFamilyTest, StripsDirectoryAndIsCaseInsensitive)
{
    EXPECT_EQ(
        identifyBrowser(L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
        BrowserKind::Brave);
    EXPECT_EQ(identifyBrowser(L"C:/Program Files/Google/Chrome/Application/CHROME.EXE"),
              BrowserKind::Chrome);
    EXPECT_EQ(identifyBrowser(L"Brave.Exe"), BrowserKind::Brave);
}

TEST(SignerFamilyTest, UnknownForNonBrowsers)
{
    EXPECT_EQ(identifyBrowser(L""), BrowserKind::Unknown);
    EXPECT_EQ(identifyBrowser(L"malware.exe"), BrowserKind::Unknown);
    EXPECT_EQ(identifyBrowser(L"explorer.exe"), BrowserKind::Unknown);
}

TEST(SignerFamilyTest, TokensAreStableAndLowercase)
{
    EXPECT_EQ(browserKindToken(BrowserKind::Chrome), "chrome");
    EXPECT_EQ(browserKindToken(BrowserKind::Brave), "brave");
    EXPECT_EQ(browserKindToken(BrowserKind::Edge), "edge");
    EXPECT_EQ(browserKindToken(BrowserKind::Firefox), "firefox");
    EXPECT_EQ(browserKindToken(BrowserKind::Unknown), "unknown");
}

TEST(SignerFamilyTest, BrowserPublisherPolicyAcceptsExpectedVendors)
{
    EXPECT_TRUE(browserPublisherMatches(BrowserKind::Chrome, L"Google LLC"));
    EXPECT_TRUE(browserPublisherMatches(BrowserKind::Edge, L"Microsoft Corporation"));
    EXPECT_TRUE(browserPublisherMatches(BrowserKind::Brave, L"Brave Software, Inc."));
    EXPECT_TRUE(browserPublisherMatches(BrowserKind::Firefox, L"Mozilla Corporation"));
    EXPECT_TRUE(browserPublisherMatches(BrowserKind::Opera, L"Opera Norway AS"));
    EXPECT_TRUE(browserPublisherMatches(BrowserKind::Vivaldi, L"Vivaldi Technologies AS"));
}

TEST(SignerFamilyTest, BrowserPublisherPolicyRejectsRenamedTrustedExecutable)
{
    EXPECT_FALSE(browserPublisherMatches(BrowserKind::Chrome, L"Contoso Code Signing LLC"));
    EXPECT_FALSE(browserPublisherMatches(BrowserKind::Firefox, L"Google LLC"));
    EXPECT_FALSE(browserPublisherMatches(BrowserKind::Unknown, L"Google LLC"));
    EXPECT_FALSE(browserPublisherMatches(BrowserKind::Chrome, L""));
}

TEST(SignerFamilyTest, ShellHopPolicyRejectsBasenameOnlyAndUserWritablePaths)
{
    EXPECT_FALSE(isShellImage(L"cmd.exe"));
    EXPECT_FALSE(isShellImage(L"powershell.exe"));
    EXPECT_FALSE(isShellImage(L"pwsh.exe"));
    EXPECT_FALSE(isShellImage(L"conhost.exe"));

    EXPECT_FALSE(isShellImage(L"C:\\Users\\Alice\\AppData\\Local\\Temp\\cmd.exe"));
    EXPECT_FALSE(isShellImage(L"C:\\Users\\Alice\\AppData\\Local\\Temp\\powershell.exe"));
    EXPECT_FALSE(isShellImage(L"C:\\Users\\Alice\\AppData\\Local\\Temp\\pwsh.exe"));
    EXPECT_FALSE(isShellImage(L"C:\\Users\\Alice\\AppData\\Local\\Temp\\conhost.exe"));
}

}  // namespace
