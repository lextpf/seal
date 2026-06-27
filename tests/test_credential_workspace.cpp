#include <gtest/gtest.h>

#include <filesystem>

#include "CredentialWorkspace.hpp"
#include "Vault.hpp"

namespace
{
using SecureWide = seal::CredentialWorkspace::SecureWide;

SecureWide wide(const wchar_t* s)
{
    SecureWide out;
    for (const wchar_t* p = s; *p; ++p)
    {
        out.push_back(*p);
    }
    return out;
}
}  // namespace

TEST(CredentialWorkspaceTest, AdoptThenIsPasswordSet)
{
    seal::CredentialWorkspace ws;
    EXPECT_FALSE(ws.isPasswordSet());
    ws.adoptPassword(wide(L"master-pw"));
    EXPECT_TRUE(ws.isPasswordSet());
    ws.clearPassword();
    EXPECT_FALSE(ws.isPasswordSet());
}

TEST(CredentialWorkspaceTest, AddRecordBumpsGenerationAndStores)
{
    seal::CredentialWorkspace ws;
    ws.adoptPassword(wide(L"master-pw"));
    const uint64_t g0 = ws.generation();
    ws.addRecord("github", wide(L"alice"), wide(L"hunter2"));
    EXPECT_EQ(ws.records().size(), 1u);
    EXPECT_EQ(ws.records()[0].platform, "github");
    EXPECT_GT(ws.generation(), g0);
}

TEST(CredentialWorkspaceTest, DecryptRoundTripsAddedCredential)
{
    seal::CredentialWorkspace ws;
    ws.adoptPassword(wide(L"master-pw"));
    ws.addRecord("github", wide(L"alice"), wide(L"hunter2"));
    seal::DecryptedCredential cred = ws.decrypt(0);
    EXPECT_EQ(std::wstring(cred.username.begin(), cred.username.end()), L"alice");
    EXPECT_EQ(std::wstring(cred.password.begin(), cred.password.end()), L"hunter2");
    cred.cleanse();
}

TEST(CredentialWorkspaceTest, EditKeepsCurrentWhenFieldNull)
{
    seal::CredentialWorkspace ws;
    ws.adoptPassword(wide(L"master-pw"));
    ws.addRecord("github", wide(L"alice"), wide(L"hunter2"));
    const SecureWide newPass = wide(L"newpw");
    ws.editRecord(0, "github", /*username*/ nullptr, &newPass);  // keep username, change password
    seal::DecryptedCredential cred = ws.decrypt(0);
    EXPECT_EQ(std::wstring(cred.username.begin(), cred.username.end()), L"alice");
    EXPECT_EQ(std::wstring(cred.password.begin(), cred.password.end()), L"newpw");
    cred.cleanse();
}

TEST(CredentialWorkspaceTest, MarkDeletedFlagsAndBumpsGeneration)
{
    seal::CredentialWorkspace ws;
    ws.adoptPassword(wide(L"master-pw"));
    ws.addRecord("github", wide(L"alice"), wide(L"hunter2"));
    const uint64_t g0 = ws.generation();
    ws.markDeleted(0);
    EXPECT_TRUE(ws.records()[0].deleted);
    EXPECT_EQ(ws.recordCount(), 0u);
    EXPECT_GT(ws.generation(), g0);
}

TEST(CredentialWorkspaceTest, SaveThenLoadRoundTrips)
{
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "seal_ws_test.seal";
    fs::remove(tmp);
    {
        seal::CredentialWorkspace ws;
        ws.adoptPassword(wide(L"master-pw"));
        ws.setVaultPath(tmp);
        ws.addRecord("github", wide(L"alice"), wide(L"hunter2"));
        ASSERT_TRUE(ws.save());
    }
    {
        seal::CredentialWorkspace ws;
        ws.adoptPassword(wide(L"master-pw"));
        ws.load(tmp);
        ASSERT_EQ(ws.records().size(), 1u);
        EXPECT_EQ(ws.records()[0].platform, "github");
        seal::DecryptedCredential cred = ws.decrypt(0);
        EXPECT_EQ(std::wstring(cred.password.begin(), cred.password.end()), L"hunter2");
        cred.cleanse();
    }
    fs::remove(tmp);
}

TEST(CredentialWorkspaceTest, LoadWithWrongPasswordThrows)
{
    namespace fs = std::filesystem;
    const fs::path tmp = fs::temp_directory_path() / "seal_ws_wrongpw.seal";
    fs::remove(tmp);
    {
        seal::CredentialWorkspace ws;
        ws.adoptPassword(wide(L"right-pw"));
        ws.setVaultPath(tmp);
        ws.addRecord("github", wide(L"alice"), wide(L"hunter2"));
        ASSERT_TRUE(ws.save());
    }
    seal::CredentialWorkspace ws;
    ws.adoptPassword(wide(L"wrong-pw"));
    EXPECT_THROW(ws.load(tmp), std::runtime_error);
    fs::remove(tmp);
}
