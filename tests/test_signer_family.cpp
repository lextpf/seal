#include "../src/SignerUtils.hpp"

#include <gtest/gtest.h>

#include <string>

using seal::signer::BrowserEngineFamily;
using seal::signer::BrowserKind;
using seal::signer::browserKindToken;
using seal::signer::browserMetadata;
using seal::signer::browserPublisherMatches;
using seal::signer::identifyBrowser;
using seal::signer::identifyShell;
using seal::signer::isChromiumBrowser;
using seal::signer::isShellImage;
using seal::signer::isShellPathAllowed;
using seal::signer::isTrustedShellImage;
using seal::signer::kBrowserMetadata;
using seal::signer::ShellKind;

namespace
{

// resolve System32 through GetWindowsDirectoryW so tests also cover non-C: installations.
std::wstring system32Path(const wchar_t* leaf)
{
    wchar_t buf[MAX_PATH * 2]{};
    const UINT chars = GetWindowsDirectoryW(buf, static_cast<UINT>(std::size(buf)));
    if (chars == 0 || chars >= std::size(buf))
    {
        return {};
    }
    std::wstring path(buf, chars);
    if (!path.empty() && path.back() != L'\\')
    {
        path.push_back(L'\\');
    }
    path.append(L"System32\\");
    path.append(leaf);
    return path;
}

// browser status depends on distinct kinds for trusted ancestor images.
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

TEST(SignerFamilyTest, MetadataExhaustivelyCoversEveryKnownKind)
{
    EXPECT_EQ(kBrowserMetadata.size(), static_cast<std::size_t>(BrowserKind::Count) - 1U);

    for (int raw = static_cast<int>(BrowserKind::Chrome);
         raw < static_cast<int>(BrowserKind::Count);
         ++raw)
    {
        const auto kind = static_cast<BrowserKind>(raw);
        const auto* metadata = browserMetadata(kind);
        ASSERT_NE(metadata, nullptr) << raw;
        EXPECT_FALSE(metadata->m_ImageName.empty()) << raw;
        EXPECT_FALSE(metadata->m_DisplayName.empty()) << raw;
        EXPECT_FALSE(metadata->m_Token.empty()) << raw;
        EXPECT_FALSE(metadata->m_BrandIconToken.empty()) << raw;
        EXPECT_FALSE(metadata->m_ExtensionsPage.empty()) << raw;
        EXPECT_EQ(identifyBrowser(std::wstring(metadata->m_ImageName)), kind) << raw;
        EXPECT_EQ(browserKindToken(kind), metadata->m_Token) << raw;
    }
    EXPECT_EQ(browserMetadata(BrowserKind::Unknown), nullptr);
    EXPECT_EQ(browserMetadata(BrowserKind::Count), nullptr);
}

TEST(SignerFamilyTest, EveryChromiumKindHasACompleteRegistrationTarget)
{
    constexpr std::wstring_view suffix = L"\\NativeMessagingHosts\\com.seal.fill";
    for (const auto& browser : kBrowserMetadata)
    {
        if (browser.m_EngineFamily != BrowserEngineFamily::Chromium)
        {
            EXPECT_FALSE(isChromiumBrowser(browser.m_Kind));
            continue;
        }

        EXPECT_TRUE(isChromiumBrowser(browser.m_Kind));
        ASSERT_FALSE(browser.m_NativeMessagingSubKeys.front().empty()) << browser.m_DisplayName;
        for (const auto subKey : browser.m_NativeMessagingSubKeys)
        {
            if (!subKey.empty())
            {
                EXPECT_TRUE(subKey.ends_with(suffix)) << browser.m_DisplayName;
            }
        }
    }
}

TEST(SignerFamilyTest, OperaStableAndGxHaveSymmetricTargets)
{
    const auto* opera = browserMetadata(BrowserKind::Opera);
    ASSERT_NE(opera, nullptr);
    EXPECT_FALSE(opera->m_NativeMessagingSubKeys[0].empty());
    EXPECT_FALSE(opera->m_NativeMessagingSubKeys[1].empty());
    EXPECT_NE(opera->m_NativeMessagingSubKeys[0], opera->m_NativeMessagingSubKeys[1]);
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

// inbox shells use catalog signatures with empty PE certificate tables.
// exercise the shipped binaries: synthetic paths cannot verify the signature carrier.
// Chrome native-host ancestry includes chrome.exe -> cmd.exe -> seal-browser.exe.
TEST(SignerFamilyTest, TrustsCatalogSignedInboxShells)
{
    const std::wstring cmdPath = system32Path(L"cmd.exe");
    ASSERT_FALSE(cmdPath.empty());
    ASSERT_NE(GetFileAttributesW(cmdPath.c_str()), INVALID_FILE_ATTRIBUTES)
        << "cmd.exe missing from System32";

    EXPECT_EQ(identifyShell(cmdPath), ShellKind::Cmd);
    EXPECT_TRUE(isShellPathAllowed(ShellKind::Cmd, cmdPath));
    EXPECT_TRUE(isTrustedShellImage(cmdPath));

    const std::wstring conhostPath = system32Path(L"conhost.exe");
    if (GetFileAttributesW(conhostPath.c_str()) != INVALID_FILE_ATTRIBUTES)
    {
        EXPECT_TRUE(isTrustedShellImage(conhostPath));
    }
}

// catalog trust follows file bytes across locations. isShellPathAllowed must separately
// reject trusted shell copies in user-writable directories.
TEST(SignerFamilyTest, ShellPathAllowListCarriesTheLocationCheckAlone)
{
    const std::wstring cmdPath = system32Path(L"cmd.exe");
    ASSERT_FALSE(cmdPath.empty());

    std::wstring publisher;
    EXPECT_TRUE(seal::signer::detail::catalogTrustOk(cmdPath, publisher));
    EXPECT_TRUE(seal::signer::shellPublisherMatches(ShellKind::Cmd, publisher));

    constexpr const wchar_t* kLookalike = L"C:\\Users\\Alice\\AppData\\Local\\Temp\\cmd.exe";
    EXPECT_EQ(identifyShell(kLookalike), ShellKind::Cmd);
    EXPECT_FALSE(isShellPathAllowed(ShellKind::Cmd, kLookalike));
    EXPECT_FALSE(isTrustedShellImage(kLookalike));
}

}  // namespace
