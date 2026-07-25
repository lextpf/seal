#include "src/ProtectedFolderProfile.hpp"

#include "src/Cryptography.hpp"

#include <gtest/gtest.h>

#include <windows.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{

namespace fs = std::filesystem;

seal::ProtectedFolderPassword widePassword(std::wstring_view value)
{
    seal::ProtectedFolderPassword password;
    password.assign(value.begin(), value.end());
    return password;
}

class TemporaryDirectory
{
public:
    TemporaryDirectory()
    {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        m_Path = fs::temp_directory_path() /
                 (L"seal-folder-profile-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                  std::to_wstring(nonce));
        fs::create_directories(m_Path);
    }

    ~TemporaryDirectory()
    {
        std::error_code error;
        fs::remove_all(m_Path, error);
    }

    [[nodiscard]] const fs::path& path() const { return m_Path; }

private:
    fs::path m_Path;
};

constexpr seal::cfg::KdfParams kTestKdf{
    seal::cfg::KDF_ALG_SCRYPT,
    seal::cfg::KDF_LOG2N_MIN,
    1,
    1,
};

}  // namespace

TEST(ProtectedFolderProfileTest, CreatesAndVerifiesWithoutStoringThePassword)
{
    TemporaryDirectory directory;
    const fs::path profile = directory.path() / seal::kProtectedFolderProfileFileName;
    auto password = widePassword(L"folder-only secret");

    std::string error;
    ASSERT_TRUE(seal::createProtectedFolderProfile(profile, password, &error, kTestKdf)) << error;

    const seal::ProtectedFolderProfileInspection inspection =
        seal::inspectProtectedFolderProfile(profile);
    EXPECT_EQ(inspection.state, seal::ProtectedFolderProfileState::Valid);
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, password).result,
              seal::ProtectedFolderProfileVerification::Verified);

    std::ifstream input(profile, std::ios::binary);
    const std::string bytes((std::istreambuf_iterator<char>(input)), {});
    EXPECT_EQ(bytes.find("folder-only secret"), std::string::npos);
}

TEST(ProtectedFolderProfileTest, WrongPasswordIsDistinctFromMalformedProfile)
{
    TemporaryDirectory directory;
    const fs::path profile = directory.path() / seal::kProtectedFolderProfileFileName;
    auto correct = widePassword(L"correct");
    auto wrong = widePassword(L"wrong");

    ASSERT_TRUE(seal::createProtectedFolderProfile(profile, correct, nullptr, kTestKdf));
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, wrong).result,
              seal::ProtectedFolderProfileVerification::WrongPassword);

    {
        std::fstream file(profile, std::ios::binary | std::ios::in | std::ios::out);
        ASSERT_TRUE(file.good());
        file.seekg(16);
        char byte = '\0';
        file.read(&byte, 1);
        file.seekp(16);
        byte ^= 0x40;
        file.write(&byte, 1);
    }

    EXPECT_EQ(seal::inspectProtectedFolderProfile(profile).state,
              seal::ProtectedFolderProfileState::Invalid);
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, correct).result,
              seal::ProtectedFolderProfileVerification::Invalid);
}

TEST(ProtectedFolderProfileTest, MissingTruncatedAndUnrelatedFilesFailClosed)
{
    TemporaryDirectory directory;
    const fs::path profile = directory.path() / seal::kProtectedFolderProfileFileName;
    auto password = widePassword(L"secret");

    EXPECT_EQ(seal::inspectProtectedFolderProfile(profile).state,
              seal::ProtectedFolderProfileState::Missing);
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, password).result,
              seal::ProtectedFolderProfileVerification::Missing);

    {
        std::ofstream output(profile, std::ios::binary);
        output << "SFP1";
    }
    EXPECT_EQ(seal::inspectProtectedFolderProfile(profile).state,
              seal::ProtectedFolderProfileState::Invalid);

    {
        std::ofstream output(profile, std::ios::binary | std::ios::trunc);
        output << "not a profile";
    }
    EXPECT_EQ(seal::inspectProtectedFolderProfile(profile).state,
              seal::ProtectedFolderProfileState::Invalid);
}

TEST(ProtectedFolderProfileTest, CreateRefusesClobberAndReplaceRotatesVerifier)
{
    TemporaryDirectory directory;
    const fs::path profile = directory.path() / seal::kProtectedFolderProfileFileName;
    auto oldPassword = widePassword(L"old password");
    auto newPassword = widePassword(L"new password");

    ASSERT_TRUE(seal::createProtectedFolderProfile(profile, oldPassword, nullptr, kTestKdf));

    std::string error;
    EXPECT_FALSE(seal::createProtectedFolderProfile(profile, newPassword, &error, kTestKdf));
    EXPECT_FALSE(error.empty());
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, oldPassword).result,
              seal::ProtectedFolderProfileVerification::Verified);

    error.clear();
    ASSERT_TRUE(seal::replaceProtectedFolderProfile(profile, newPassword, &error, kTestKdf))
        << error;
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, oldPassword).result,
              seal::ProtectedFolderProfileVerification::WrongPassword);
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, newPassword).result,
              seal::ProtectedFolderProfileVerification::Verified);
}

TEST(ProtectedFolderProfileTest, OccupiedStagingPathIsNeverClobbered)
{
    TemporaryDirectory directory;
    const fs::path profile = directory.path() / seal::kProtectedFolderProfileFileName;
    fs::path staging = profile;
    staging += L".tmp";
    {
        std::ofstream output(staging, std::ios::binary);
        output << "user-owned staging file";
    }
    auto password = widePassword(L"secret");

    std::string error;
    EXPECT_FALSE(seal::createProtectedFolderProfile(profile, password, &error, kTestKdf));
    EXPECT_FALSE(fs::exists(profile));

    std::ifstream input(staging, std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(input)), {});
    EXPECT_EQ(contents, "user-owned staging file");
}
