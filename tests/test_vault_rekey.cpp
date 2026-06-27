#include <gtest/gtest.h>

#include "Cryptography.hpp"
#include "SecureString.hpp"
#include "Utils.hpp"
#include "Vault.hpp"
#include "VaultRecord.hpp"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace
{
// Mirror the wide master-password helper from test_vault_roundtrip.cpp.
// Converts a narrow UTF-8 literal to the locked-wide SecureWide type used
// by encryptCredential / saveVault / loadVaultIndex.
seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> makeSecureWide(
    const wchar_t* lit)
{
    // Convert via UTF-8 round-trip: wide literal -> narrow UTF-8 -> SecureWide.
    const std::wstring ws(lit);
    std::string narrow;
    narrow.reserve(ws.size());
    for (const wchar_t wc : ws)
    {
        narrow.push_back(static_cast<char>(wc));  // ASCII-only test literals; no surrogate pairs.
    }
    return seal::utils::utf8ToSecureWide(narrow);
}

// Hex-encode a raw byte frame and write it to path as a vault file.
// The vault file format is a hex-encoded blob, matching how saveVault writes on disk.
void writeHexFrame(const std::filesystem::path& path, const std::vector<unsigned char>& frame)
{
    static const char kHexDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(frame.size() * 2);
    for (const unsigned char b : frame)
    {
        hex += kHexDigits[(b >> 4) & 0xF];
        hex += kHexDigits[b & 0xF];
    }
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(hex.data(), static_cast<std::streamsize>(hex.size()));
}

// Source-scan helpers (mirror tests/test_ui_secret_boundaries.cpp).
std::string readSourceFile(const std::string& relativePath)
{
    const std::filesystem::path full = std::filesystem::path(SEAL_SOURCE_DIR) / relativePath;
    std::ifstream in(full, std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("failed to open " + full.string());
    }
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

void expectPresent(const std::string& haystack, const std::string& needle)
{
    EXPECT_NE(haystack.find(needle), std::string::npos) << "Expected source token: " << needle;
}

}  // namespace

TEST(VaultRekeyTest, RoundTripPreservesData)
{
    namespace fs = std::filesystem;
    const fs::path path = fs::temp_directory_path() / "seal_rekey_roundtrip_test.seal";
    fs::remove(path);
    auto oldPw = makeSecureWide(L"old master");
    auto newPw = makeSecureWide(L"new master");

    std::vector<seal::VaultRecord> records;
    records.push_back(
        seal::encryptCredential("svc", makeSecureWide(L"user"), makeSecureWide(L"secret"), oldPw));
    ASSERT_TRUE(seal::saveVault(path, records, oldPw));

    // Rekey old -> new: every record is re-encrypted under the new password.
    EXPECT_EQ(seal::rekeyVault(path, oldPw, newPw), 1u);

    // The old password no longer opens the vault (fail-fast on the first record).
    EXPECT_THROW((void)seal::loadVaultIndex(path, oldPw), std::runtime_error);

    // The new password opens it and the credential is preserved verbatim.
    auto loaded = seal::loadVaultIndex(path, newPw);
    ASSERT_EQ(loaded.size(), 1u);
    auto cred = seal::decryptCredentialOnDemand(loaded[0], newPw);
    EXPECT_EQ(seal::utils::secureWideToUtf8(cred.password), "secret");
    cred.cleanse();
    fs::remove(path);
}

TEST(VaultRekeyTest, FutureVersionIsRejected)
{
    namespace fs = std::filesystem;
    const fs::path path = fs::temp_directory_path() / "seal_vault_future_version_test.seal";
    // magic "SVH2", version 0x02, record_count 0 (4 bytes), hex-encoded.
    const std::vector<unsigned char> frame{'S', 'V', 'H', '2', 0x02, 0, 0, 0, 0};
    writeHexFrame(path, frame);
    auto pw = makeSecureWide(L"x");
    EXPECT_THROW((void)seal::loadVaultIndex(path, pw), std::runtime_error);
    fs::remove(path);
}

TEST(VaultRekeySourceScanTest, VersionDispatchIsStructured)
{
    const std::string src = readSourceFile("src/Vault.cpp");
    expectPresent(src, "switch (version)");
    expectPresent(src, "direction");
    expectPresent(src, "written by a newer version of seal");
}

TEST(VaultRekeySourceScanTest, DurableFlushBeforeRename)
{
    // saveVault and rekeyVault must push the temp file's data to stable storage
    // before the rename/replace; a rename persists metadata, not file contents,
    // so without this a power-loss could leave a renamed-but-empty vault.
    const std::string src = readSourceFile("src/Vault.cpp");
    expectPresent(src, "flushPathToDisk");
    expectPresent(src, "FlushFileBuffers");
}

TEST(VaultRekeySourceScanTest, RekeyRespectsAutoLock)
{
    // The rekey worker's onDone must not silently re-unlock after a mid-rekey
    // auto-lock: adoptPassword/reload is guarded by isPasswordSet(), and the
    // session-cleared branch tells the user to unlock with the new password.
    const std::string vm = readSourceFile("src/AppViewModel.cpp");
    expectPresent(vm, "Unlock with your new password");
}
