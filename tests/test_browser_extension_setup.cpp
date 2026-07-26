#include "../src/CliModes.hpp"
#include "../src/SignerUtils.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>

namespace
{
namespace fs = std::filesystem;

class BrowserExtensionSetupTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_Root = fs::temp_directory_path() / "seal_browser_extension_setup_test";
        std::error_code error;
        fs::remove_all(m_Root, error);
        fs::create_directories(m_Root);
    }

    void TearDown() override
    {
        std::error_code error;
        fs::remove_all(m_Root, error);
    }

    fs::path m_Root;
};

TEST_F(BrowserExtensionSetupTest, FindsRepositoryExtensionFolderFromBuildTree)
{
    const fs::path extension = m_Root / "extensions" / "browser";
    const fs::path executable = m_Root / "build" / "bin" / "Release";
    fs::create_directories(extension);
    fs::create_directories(executable);

    EXPECT_EQ(seal::findBrowserExtensionDirectory(executable), extension);
}

TEST_F(BrowserExtensionSetupTest, MissingFolderReturnsActionableInstalledLocation)
{
    const fs::path executable = m_Root / "bin";
    fs::create_directories(executable);

    EXPECT_EQ(seal::findBrowserExtensionDirectory(executable),
              executable / "extensions" / "browser");
}

TEST(BrowserExtensionReportTest, InstallMessageCarriesPathOutcomesAndInstructions)
{
    seal::BrowserExtensionInstallReport report;
    report.m_Success = true;
    report.m_ManifestPath = "C:/seal/com.seal.fill.json";
    report.m_ExtensionDirectory = "C:/seal/extensions/browser";
    report.m_ExtensionDirectoryFound = true;
    report.m_ExtensionDirectoryCopied = true;
    report.m_Browsers = {
        {seal::signer::BrowserKind::Chrome, seal::BrowserRegistrationOutcome::Registered, 1},
        {seal::signer::BrowserKind::Edge, seal::BrowserRegistrationOutcome::SkippedNotInstalled, 0},
    };

    const std::string message = seal::formatBrowserExtensionInstallReport(report);
    EXPECT_NE(message.find("C:/seal/extensions/browser"), std::string::npos);
    EXPECT_NE(message.find("Chrome: registered"), std::string::npos);
    EXPECT_NE(message.find("Edge: not installed (skipped)"), std::string::npos);
    EXPECT_NE(message.find("1) Open"), std::string::npos);
    EXPECT_NE(message.find("2) Turn on Developer mode"), std::string::npos);
    EXPECT_NE(message.find("3) Click Load unpacked"), std::string::npos);
    EXPECT_NE(message.find("copied to the clipboard"), std::string::npos);
}

TEST(BrowserExtensionReportTest, MissingExtensionFolderHasDistinctMessage)
{
    seal::BrowserExtensionInstallReport report;
    report.m_Success = true;
    report.m_ManifestPath = "C:/seal/com.seal.fill.json";
    report.m_ExtensionDirectory = "C:/seal/extensions/browser";

    const std::string message = seal::formatBrowserExtensionInstallReport(report);
    EXPECT_NE(message.find("Extension folder not found"), std::string::npos);
    EXPECT_EQ(message.find("3) Click Load unpacked"), std::string::npos);
}

TEST(BrowserExtensionReportTest, UninstallMessageIsHonestAboutUnpackedExtension)
{
    seal::BrowserExtensionUninstallReport report;
    report.m_Success = true;
    report.m_Browsers = {
        {seal::signer::BrowserKind::Chrome, seal::BrowserRegistrationOutcome::Removed, 1},
        {seal::signer::BrowserKind::Edge, seal::BrowserRegistrationOutcome::AlreadyAbsent, 0},
    };

    const std::string message = seal::formatBrowserExtensionUninstallReport(report);
    EXPECT_NE(message.find("Chrome: removed"), std::string::npos);
    EXPECT_NE(message.find("Edge: already absent"), std::string::npos);
    EXPECT_NE(message.find("cannot remove an unpacked extension"), std::string::npos);
}

}  // namespace
