#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <thread>

#include "CancellationToken.hpp"

TEST(CancellationTokenTest, DefaultIsNeverCancelled)
{
    seal::CancellationToken token;
    EXPECT_FALSE(token.cancelled());
}

TEST(CancellationTokenTest, ReflectsTheSharedFlag)
{
    auto flag = std::make_shared<std::atomic<bool>>(false);
    seal::CancellationToken token(flag);
    EXPECT_FALSE(token.cancelled());
    flag->store(true, std::memory_order_release);
    EXPECT_TRUE(token.cancelled());
}

TEST(CancellationTokenTest, ReadIsValidAfterConcurrentSet)
{
    auto flag = std::make_shared<std::atomic<bool>>(false);
    seal::CancellationToken token(flag);
    std::atomic<bool> seen{false};
    std::thread setter([&] { flag->store(true, std::memory_order_release); });
    setter.join();
    EXPECT_TRUE(token.cancelled());
    (void)seen;
}
