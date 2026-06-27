#include <gtest/gtest.h>

#include <string>
#include <string_view>

#include "SecureString.hpp"

namespace
{
using SW = seal::basic_secure_string<wchar_t>;

SW make(const wchar_t* s)
{
    SW out;
    for (const wchar_t* p = s; *p; ++p)
    {
        out.push_back(*p);
    }
    return out;
}

std::wstring str(const SW& s)
{
    return std::wstring(s.begin(), s.end());
}
}  // namespace

TEST(SecureStringTest, AssignClonesRange)
{
    SW src = make(L"hunter2");
    SW dst;
    dst.assign(src.begin(), src.end());
    EXPECT_EQ(str(dst), L"hunter2");
    EXPECT_EQ(str(src), L"hunter2");  // source unchanged: sanctioned copy of a move-only type
    EXPECT_EQ(dst.size(), 7u);
}

TEST(SecureStringTest, ResizeGrowAndShrinkPreservesPrefix)
{
    SW s = make(L"abcdef");
    s.resize(3);
    EXPECT_EQ(s.size(), 3u);
    EXPECT_EQ(str(s), L"abc");
    s.resize(5);  // grows; new code units are value-initialized (zero)
    EXPECT_EQ(s.size(), 5u);
    EXPECT_EQ(s.view().substr(0, 3), std::wstring_view(L"abc"));
}

TEST(SecureStringTest, BackReserveSizeViewCStrEmpty)
{
    SW s = make(L"xy");
    EXPECT_EQ(s.back(), L'y');
    s.back() = L'Z';  // non-const back() is writable
    EXPECT_EQ(s.back(), L'Z');
    s.reserve(64);
    EXPECT_EQ(s.size(), 2u);  // reserve raises capacity, not size
    EXPECT_FALSE(s.empty());
    EXPECT_EQ(s.view(), std::wstring_view(L"xZ"));  // view() first: no trailing null
    EXPECT_EQ(std::wstring_view(s.c_str()),
              std::wstring_view(L"xZ"));  // c_str() last: appends \0
}

TEST(SecureStringTest, SecureClearEmpties)
{
    SW s = make(L"secret");
    s.clear();
    EXPECT_TRUE(s.empty());
    EXPECT_EQ(s.size(), 0u);
}

TEST(SecureStringTest, TripletStructuredBindingStillWorks)
{
    seal::secure_triplet16_t t{make(L"svc"), make(L"user"), make(L"pass")};
    auto& [svc, usr, pwd] = t;
    EXPECT_EQ(str(svc), L"svc");
    EXPECT_EQ(str(usr), L"user");
    EXPECT_EQ(str(pwd), L"pass");
}
