#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "ProtectedFolderProfile.hpp"
#include "Vault.hpp"

namespace
{
namespace fs = std::filesystem;

using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

SecureWide pw()
{
    SecureWide s;
    for (wchar_t c : std::wstring(L"dir-master"))
    {
        s.push_back(c);
    }
    return s;
}

fs::path makeTree()
{
    fs::path root = fs::temp_directory_path() / "seal_dircrypto_test";
    fs::remove_all(root);
    for (const char* sub : {"", "a", "a/aa", "b"})
    {
        fs::path d = (sub[0] != '\0') ? root / sub : root;
        fs::create_directories(d);
        for (int i = 0; i < 3; ++i)
        {
            std::ofstream(d / ("f" + std::to_string(i) + ".txt")) << "payload " << sub << i;
        }
    }
    return root;
}

int countExt(const fs::path& root, const std::string& ext)
{
    int n = 0;
    for (auto& e : fs::recursive_directory_iterator(root))
    {
        if (e.is_regular_file() && e.path().extension() == ext)
        {
            ++n;
        }
    }
    return n;
}
}  // namespace

TEST(DirectoryCryptoTest, FolderOnlyProfileSurvivesAFullRoundTripWithoutVault)
{
    const fs::path root = fs::temp_directory_path() / "seal_dircrypto_folder_only_test";
    fs::remove_all(root);
    fs::create_directories(root);

    const SecureWide password = pw();
    const fs::path profile = root / seal::kProtectedFolderProfileFileName;
    constexpr seal::cfg::KdfParams testKdf{
        seal::cfg::KDF_ALG_SCRYPT,
        seal::cfg::KDF_LOG2N_MIN,
        1,
        1,
    };
    ASSERT_TRUE(seal::createProtectedFolderProfile(profile, password, nullptr, testKdf));
    std::ofstream(root / "notes.txt") << "folder-only payload";

    const auto readProfile = [&profile]()
    {
        std::ifstream input(profile, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    };
    const std::string profileBefore = readProfile();

    seal::ProtectedFolderScan scan = seal::scanProtectedFolder(root);
    ASSERT_EQ(scan.failures, 0u);
    seal::protected_folder::FolderPlan plan = seal::protected_folder::planEncrypt(scan.entries, {});
    const seal::DirectoryProcessResult encrypted =
        seal::processFolderPlan(root, plan, password, true);
    EXPECT_EQ(encrypted.succeeded, 1u);
    EXPECT_EQ(encrypted.failed, 0u);
    EXPECT_FALSE(fs::exists(root / "notes.txt"));
    EXPECT_TRUE(fs::exists(root / "notes.txt.seal"));
    EXPECT_EQ(readProfile(), profileBefore);
    EXPECT_EQ(seal::verifyProtectedFolderProfile(profile, password).result,
              seal::ProtectedFolderProfileVerification::Verified);

    scan = seal::scanProtectedFolder(root);
    plan = seal::protected_folder::planDecrypt(scan.entries, {});
    const seal::DirectoryProcessResult decrypted =
        seal::processFolderPlan(root, plan, password, false);
    EXPECT_EQ(decrypted.succeeded, 1u);
    EXPECT_EQ(decrypted.failed, 0u);
    EXPECT_TRUE(fs::exists(root / "notes.txt"));
    EXPECT_FALSE(fs::exists(root / "notes.txt.seal"));
    EXPECT_EQ(readProfile(), profileBefore);

    fs::remove_all(root);
}

TEST(DirectoryCryptoTest, NestedTreeRoundTrips)
{
    const fs::path root = makeTree();
    const int total = countExt(root, ".txt");
    ASSERT_EQ(total, 12);

    EXPECT_EQ(seal::encryptDirectory(root, pw()), total);
    EXPECT_EQ(countExt(root, ".txt"), 0);
    EXPECT_EQ(countExt(root, ".seal"), total);

    EXPECT_EQ(seal::decryptDirectory(root, pw()), total);
    EXPECT_EQ(countExt(root, ".txt"), total);
    EXPECT_EQ(countExt(root, ".seal"), 0);

    fs::remove_all(root);
}

TEST(DirectoryCryptoTest, ProtectedVaultAndQtDeploymentFilesSurviveRoundTrip)
{
    const fs::path root = fs::temp_directory_path() / "seal_dircrypto_policy_test";
    fs::remove_all(root);
    fs::create_directories(root / "qml");

    const SecureWide password = pw();
    const fs::path vault = root / "vault.seal";
    ASSERT_TRUE(seal::saveVault(vault, {}, password));
    const std::string vaultBefore = [&vault]()
    {
        std::ifstream input(vault, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    }();

    std::ofstream(root / "notes.txt") << "payload";
    std::ofstream(root / "vault") << "must not replace the credential vault";
    std::ofstream(root / "collision.txt") << "must not replace a transform temporary";
    std::ofstream(root / "collision.txt.seal.tmp") << "user-owned temporary";
    std::ofstream(root / "qml" / "runtime.qml") << "Qt runtime";
    std::ofstream(root / "qt.conf") << "[Paths]";
    std::ofstream(root / ".seal-folder-profile") << "protected metadata";

    const seal::ProtectedFolderScan scan = seal::scanProtectedFolder(root);
    ASSERT_EQ(scan.failures, 0u);
    const seal::protected_folder::FolderPlan plan =
        seal::protected_folder::planEncrypt(scan.entries, {});
    const seal::DirectoryProcessResult encrypted =
        seal::processFolderPlan(root, plan, password, true);
    EXPECT_EQ(encrypted.succeeded, 1u);
    EXPECT_EQ(encrypted.failed, 3u);
    EXPECT_TRUE(fs::exists(vault));
    EXPECT_TRUE(fs::exists(root / "vault"));
    EXPECT_TRUE(fs::exists(root / "collision.txt"));
    EXPECT_TRUE(fs::exists(root / "collision.txt.seal.tmp"));
    EXPECT_TRUE(fs::exists(root / "qml" / "runtime.qml"));
    EXPECT_TRUE(fs::exists(root / "qt.conf"));
    EXPECT_TRUE(fs::exists(root / ".seal-folder-profile"));
    EXPECT_TRUE(fs::exists(root / "notes.txt.seal"));

    EXPECT_EQ(seal::decryptDirectory(root, password), 1);
    EXPECT_TRUE(fs::exists(vault));
    EXPECT_TRUE(fs::exists(root / "notes.txt"));
    EXPECT_TRUE(fs::exists(root / "vault"));
    EXPECT_TRUE(fs::exists(root / "collision.txt"));
    EXPECT_TRUE(fs::exists(root / "collision.txt.seal.tmp"));
    EXPECT_TRUE(fs::exists(root / ".seal-folder-profile"));

    std::ifstream vaultAfterInput(vault, std::ios::binary);
    const std::string vaultAfter{std::istreambuf_iterator<char>(vaultAfterInput),
                                 std::istreambuf_iterator<char>()};
    EXPECT_EQ(vaultAfter, vaultBefore);
    vaultAfterInput.close();

    fs::remove_all(root);
}
