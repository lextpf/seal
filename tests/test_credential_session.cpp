#include "CredentialSession.hpp"

#include <gtest/gtest.h>

namespace
{
seal::CredentialSession::SecureWide makePw(const wchar_t* s)
{
    seal::CredentialSession::SecureWide pw;
    for (const wchar_t* p = s; *p; ++p)
    {
        pw.push_back(*p);
    }
    return pw;
}
}  // namespace

TEST(CredentialSessionTest, StartsUnset)
{
    seal::CredentialSession session;
    EXPECT_FALSE(session.isSet());
}

TEST(CredentialSessionTest, AdoptSetsAndUnlockExposesPlaintext)
{
    seal::CredentialSession session;
    session.adopt(makePw(L"correct horse"));
    ASSERT_TRUE(session.isSet());

    auto access = session.unlock();
    ASSERT_TRUE(access.ok());
    const auto& pw = access.password();
    ASSERT_EQ(pw.size(), 13u);
    EXPECT_EQ(pw[0], L'c');
    EXPECT_EQ(pw[12], L'e');
}

TEST(CredentialSessionTest, ReprotectsAfterScopeAndUnlocksAgain)
{
    seal::CredentialSession session;
    session.adopt(makePw(L"secret"));
    {
        auto a1 = session.unlock();
        ASSERT_TRUE(a1.ok());
        EXPECT_EQ(a1.password().size(), 6u);
    }
    // Second unlock must still succeed (the first scope re-protected).
    auto a2 = session.unlock();
    ASSERT_TRUE(a2.ok());
    EXPECT_EQ(a2.password().size(), 6u);
}

TEST(CredentialSessionTest, ClearWipesAndUnsets)
{
    seal::CredentialSession session;
    session.adopt(makePw(L"secret"));
    session.clear();
    EXPECT_FALSE(session.isSet());
}

TEST(CredentialSessionTest, UnlockOnUnsetSessionIsNotOk)
{
    seal::CredentialSession session;
    auto access = session.unlock();
    EXPECT_FALSE(access.ok());  // nothing to expose; must not claim plaintext
}

TEST(CredentialSessionTest, AdoptReplacesPreviousPassword)
{
    seal::CredentialSession session;
    session.adopt(makePw(L"first"));
    session.adopt(makePw(L"second-longer"));
    auto access = session.unlock();
    ASSERT_TRUE(access.ok());
    EXPECT_EQ(access.password().size(), 13u);
    EXPECT_EQ(access.password()[0], L's');
}
