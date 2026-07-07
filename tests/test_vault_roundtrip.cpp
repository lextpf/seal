#include <gtest/gtest.h>

#include "src/CliModes.hpp"
#include "src/Cryptography.hpp"
#include "src/Utils.hpp"
#include "src/Vault.hpp"
#include "src/VaultRecord.hpp"

#include <process.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{

namespace fs = std::filesystem;

// Test-only password; not a secret. Mirrors the wide master-password type.
seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> goldenPassword()
{
    return seal::utils::utf8ToSecureWide("golden-master-pw");
}

seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> wrongPassword()
{
    return seal::utils::utf8ToSecureWide("not-the-password");
}

struct GoldenEntry
{
    const char* platform;
    const char* username;
    const char* password;
};

// Passwords deliberately include ',', ':', '"' and non-ASCII to stress
// downstream import/export and unicode handling.
constexpr GoldenEntry kGoldenEntries[] = {
    {"alpha", "alice", "pw-alpha-1"},
    {"beta", "bob", "p@ss:with,delim\""},
    {"gamma", "carol", "umlaut-\xC3\xA4\xC3\xB6\xC3\xBC"},
};

std::vector<unsigned char> readAllBytes(const fs::path& p)
{
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void writeAllBytes(const fs::path& p, const std::vector<unsigned char>& bytes)
{
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

class VaultRoundtripTest : public ::testing::Test
{
protected:
    // Build the test vault once per suite, in the current packet format,
    // into a private temp file. Self-contained: no committed fixture to keep in
    // sync and nothing to regenerate by hand.
    static void SetUpTestSuite()
    {
        s_goldenVault =
            fs::temp_directory_path() / ("seal_golden_" + std::to_string(::_getpid()) + ".seal");
        const auto pw = goldenPassword();
        std::vector<seal::VaultRecord> records;
        for (const auto& e : kGoldenEntries)
        {
            auto user = seal::utils::utf8ToSecureWide(e.username);
            auto pass = seal::utils::utf8ToSecureWide(e.password);
            records.push_back(seal::encryptCredential(e.platform, user, pass, pw));
        }
        ASSERT_TRUE(seal::saveVault(s_goldenVault, records, pw));
    }

    static void TearDownTestSuite()
    {
        std::error_code ec;
        fs::remove(s_goldenVault, ec);
    }

    // A throwaway copy for tests that mutate the vault on disk.
    fs::path tempCopyOfGoldenVault() const
    {
        const fs::path dst =
            fs::temp_directory_path() / ("seal_roundtrip_" + std::to_string(::_getpid()) + ".seal");
        fs::copy_file(s_goldenVault, dst, fs::copy_options::overwrite_existing);
        return dst;
    }

    static fs::path s_goldenVault;
};

fs::path VaultRoundtripTest::s_goldenVault;

TEST_F(VaultRoundtripTest, SaveThenReloadIsEquivalent)
{
    const auto pw = goldenPassword();
    const fs::path tmp = tempCopyOfGoldenVault();
    auto records = seal::loadVaultIndex(tmp, pw);
    ASSERT_TRUE(seal::saveVault(tmp, records, pw));
    auto reloaded = seal::loadVaultIndex(tmp, pw);
    ASSERT_EQ(reloaded.size(), records.size());
    for (size_t i = 0; i < reloaded.size(); ++i)
    {
        EXPECT_EQ(reloaded[i].platform, records[i].platform);
        // Untouched records must reuse the encrypted packets byte-for-byte.
        EXPECT_EQ(reloaded[i].encryptedBlob, records[i].encryptedBlob);
    }
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, WrongPasswordThrowsWrongPassword)
{
    const auto bad = wrongPassword();
    EXPECT_THROW(
        {
            try
            {
                (void)seal::loadVaultIndex(s_goldenVault, bad);
            }
            catch (const std::runtime_error& e)
            {
                EXPECT_STREQ(e.what(), "Wrong password");
                throw;
            }
        },
        std::runtime_error);
}

TEST_F(VaultRoundtripTest, DeletedRecordsAreOmittedOnSave)
{
    const auto pw = goldenPassword();
    const fs::path tmp = tempCopyOfGoldenVault();
    auto records = seal::loadVaultIndex(tmp, pw);
    records[1].deleted = true;
    ASSERT_TRUE(seal::saveVault(tmp, records, pw));
    auto reloaded = seal::loadVaultIndex(tmp, pw);
    ASSERT_EQ(reloaded.size(), records.size() - 1);
    EXPECT_EQ(reloaded[0].platform, "alpha");
    EXPECT_EQ(reloaded[1].platform, "gamma");
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, CorruptMagicIsRejected)
{
    const auto pw = goldenPassword();
    const fs::path tmp = tempCopyOfGoldenVault();
    auto hexBytes = readAllBytes(tmp);
    ASSERT_GE(hexBytes.size(), 2u);
    // First hex byte pair encodes 'S' of SVH2; flip it.
    hexBytes[0] = (hexBytes[0] == '0') ? '1' : '0';
    writeAllBytes(tmp, hexBytes);
    EXPECT_THROW((void)seal::loadVaultIndex(tmp, pw), std::runtime_error);
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, TruncatedPayloadIsRejected)
{
    const auto pw = goldenPassword();
    const fs::path tmp = tempCopyOfGoldenVault();
    auto hexBytes = readAllBytes(tmp);
    hexBytes.resize(hexBytes.size() / 2);
    // Keep even length so hex decode succeeds and framing (not hex) fails.
    if (hexBytes.size() % 2 != 0)
    {
        hexBytes.pop_back();
    }
    writeAllBytes(tmp, hexBytes);
    EXPECT_THROW((void)seal::loadVaultIndex(tmp, pw), std::runtime_error);
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, EmptyVaultFileYieldsNoRecords)
{
    const auto pw = goldenPassword();
    const fs::path tmp =
        fs::temp_directory_path() / ("seal_empty_" + std::to_string(::_getpid()) + ".seal");
    {
        std::ofstream out(tmp, std::ios::trunc);
    }
    auto records = seal::loadVaultIndex(tmp, pw);
    EXPECT_TRUE(records.empty());
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, RekeySwapsPasswordAtomicallyAndUpgradesPackets)
{
    const auto oldPw = goldenPassword();
    const auto newPw = seal::utils::utf8ToSecureWide("brand-new-pw");
    const fs::path tmp = tempCopyOfGoldenVault();

    const size_t count = seal::rekeyVault(tmp, oldPw, newPw);
    EXPECT_EQ(count, std::size(kGoldenEntries));

    EXPECT_THROW((void)seal::loadVaultIndex(tmp, oldPw), std::runtime_error);
    auto records = seal::loadVaultIndex(tmp, newPw);
    ASSERT_EQ(records.size(), std::size(kGoldenEntries));
    for (size_t i = 0; i < records.size(); ++i)
    {
        EXPECT_EQ(records[i].platform, kGoldenEntries[i].platform);
        // Every packet must now carry the self-describing header.
        ASSERT_GE(records[i].encryptedBlob.size(), 4u);
        EXPECT_EQ(std::memcmp(records[i].encryptedBlob.data(), "seal", 4), 0);
        auto cred = seal::decryptCredentialOnDemand(records[i], newPw);
        EXPECT_EQ(seal::utils::secureWideToUtf8(cred.password), kGoldenEntries[i].password);
        cred.cleanse();
    }
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, UsernameOnlyDecryptReturnsUsernameWithoutCredentialPair)
{
    const auto pw = goldenPassword();
    auto records = seal::loadVaultIndex(s_goldenVault, pw);
    ASSERT_EQ(records.size(), std::size(kGoldenEntries));

    auto username = seal::decryptUsernameOnDemand(records[0], pw);
    EXPECT_EQ(seal::utils::secureWideToUtf8(username), kGoldenEntries[0].username);
    seal::Cryptography::cleanseString(username);
}

TEST_F(VaultRoundtripTest, RekeyWithWrongCurrentPasswordLeavesFileUntouched)
{
    const auto bad = wrongPassword();
    const auto newPw = seal::utils::utf8ToSecureWide("brand-new-pw");
    const fs::path tmp = tempCopyOfGoldenVault();
    const auto before = readAllBytes(tmp);

    EXPECT_THROW((void)seal::rekeyVault(tmp, bad, newPw), std::runtime_error);

    EXPECT_EQ(readAllBytes(tmp), before);
    const auto good = goldenPassword();
    EXPECT_NO_THROW((void)seal::loadVaultIndex(tmp, good));
    fs::remove(tmp);
}

TEST_F(VaultRoundtripTest, RekeyCleansUpTempFileOnFailure)
{
    const auto bad = wrongPassword();
    const auto newPw = seal::utils::utf8ToSecureWide("brand-new-pw");
    const fs::path tmp = tempCopyOfGoldenVault();
    EXPECT_THROW((void)seal::rekeyVault(tmp, bad, newPw), std::runtime_error);
    fs::path rekeyTmp = tmp;
    rekeyTmp += ".rekey.tmp";
    EXPECT_FALSE(fs::exists(rekeyTmp));
    fs::remove(tmp);
}

TEST(VaultLookupTest, MatchPlatformExactCaseInsensitivePrefixAndAmbiguity)
{
    const std::vector<std::string> names{"GitHub", "GitLab", "Google", "npm"};

    auto exact = seal::matchPlatform(names, "github");
    EXPECT_EQ(exact.outcome, seal::MatchOutcome::Found);
    EXPECT_EQ(exact.index, 0);

    auto uniquePrefix = seal::matchPlatform(names, "np");
    EXPECT_EQ(uniquePrefix.outcome, seal::MatchOutcome::Found);
    EXPECT_EQ(uniquePrefix.index, 3);

    auto ambiguous = seal::matchPlatform(names, "git");
    EXPECT_EQ(ambiguous.outcome, seal::MatchOutcome::Ambiguous);
    ASSERT_EQ(ambiguous.candidates.size(), 2u);
    EXPECT_EQ(ambiguous.candidates[0], "GitHub");
    EXPECT_EQ(ambiguous.candidates[1], "GitLab");

    auto none = seal::matchPlatform(names, "bitbucket");
    EXPECT_EQ(none.outcome, seal::MatchOutcome::NotFound);

    auto empty = seal::matchPlatform(names, "");
    EXPECT_EQ(empty.outcome, seal::MatchOutcome::NotFound);

    // Exact match wins even when it is also a prefix of others.
    const std::vector<std::string> shadow{"Go", "Google"};
    auto shadowed = seal::matchPlatform(shadow, "go");
    EXPECT_EQ(shadowed.outcome, seal::MatchOutcome::Found);
    EXPECT_EQ(shadowed.index, 0);
}

TEST(VaultLookupTest, FindDefaultVaultHonoursEnvOverride)
{
    const auto tmp = std::filesystem::temp_directory_path() /
                     ("seal_env_" + std::to_string(::_getpid()) + ".seal");
    {
        std::ofstream out(tmp, std::ios::trunc);
    }
    ::_putenv_s("SEAL_VAULT", tmp.string().c_str());
    const auto found = seal::findDefaultVault();
    ::_putenv_s("SEAL_VAULT", "");
    EXPECT_EQ(found, tmp);
    std::filesystem::remove(tmp);
}

TEST(VaultLookupTest, GetOptionValidationRules)
{
    // both requires stdout; ttl clamps to [1, 600] seconds.
    EXPECT_FALSE(seal::GetOptionsValid("both", false));
    EXPECT_TRUE(seal::GetOptionsValid("both", true));
    EXPECT_TRUE(seal::GetOptionsValid("pass", false));
    EXPECT_TRUE(seal::GetOptionsValid("user", false));
    EXPECT_FALSE(seal::GetOptionsValid("banana", true));

    EXPECT_EQ(seal::ClampGetTtlSeconds(0), 1);
    EXPECT_EQ(seal::ClampGetTtlSeconds(6), 6);
    EXPECT_EQ(seal::ClampGetTtlSeconds(100000), 600);
}
