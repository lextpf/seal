#include <gtest/gtest.h>

#include "src/AutoLockPolicy.hpp"

TEST(AutoLockPolicyTest, LocksExactlyAtTimeout)
{
    EXPECT_FALSE(seal::ShouldAutoLock(0, 299'999, 300));
    EXPECT_TRUE(seal::ShouldAutoLock(0, 300'000, 300));
    EXPECT_TRUE(seal::ShouldAutoLock(1'000, 301'000, 300));
}

TEST(AutoLockPolicyTest, ZeroOrNegativeTimeoutDisables)
{
    EXPECT_FALSE(seal::ShouldAutoLock(0, 1'000'000'000, 0));
    EXPECT_FALSE(seal::ShouldAutoLock(0, 1'000'000'000, -5));
}
