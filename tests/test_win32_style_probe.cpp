#include "../src/Probe.hpp"
#include "../src/Win32StyleProbe.hpp"

#include <gtest/gtest.h>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <chrono>

using seal::ProbeContext;
using seal::Verdict;
using seal::Win32StyleProbe;

namespace
{

ProbeContext makeContext(HWND hwnd)
{
    RECT rect{};
    if (hwnd != nullptr)
    {
        GetWindowRect(hwnd, &rect);
    }
    ProbeContext ctx;
    ctx.m_ClickPoint = POINT{(rect.left + rect.right) / 2, (rect.top + rect.bottom) / 2};
    ctx.m_TargetWindow = hwnd;
    if (hwnd != nullptr)
    {
        GetWindowThreadProcessId(hwnd, &ctx.m_TargetProcessId);
    }
    ctx.m_Deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
    return ctx;
}

}  // namespace

class HiddenEditFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        m_Host = CreateWindowExW(0,
                                 L"STATIC",
                                 L"host",
                                 WS_POPUP,
                                 0,
                                 0,
                                 400,
                                 200,
                                 nullptr,
                                 nullptr,
                                 GetModuleHandleW(nullptr),
                                 nullptr);
        ASSERT_NE(m_Host, nullptr);

        m_PasswordEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
                                         L"EDIT",
                                         L"",
                                         WS_CHILD | WS_VISIBLE | ES_PASSWORD,
                                         10,
                                         10,
                                         180,
                                         24,
                                         m_Host,
                                         nullptr,
                                         GetModuleHandleW(nullptr),
                                         nullptr);
        ASSERT_NE(m_PasswordEdit, nullptr);

        m_PlainEdit = CreateWindowExW(WS_EX_CLIENTEDGE,
                                      L"EDIT",
                                      L"",
                                      WS_CHILD | WS_VISIBLE,
                                      200,
                                      10,
                                      180,
                                      24,
                                      m_Host,
                                      nullptr,
                                      GetModuleHandleW(nullptr),
                                      nullptr);
        ASSERT_NE(m_PlainEdit, nullptr);
    }

    void TearDown() override
    {
        if (m_Host != nullptr)
        {
            DestroyWindow(m_Host);
            m_Host = nullptr;
        }
    }

    HWND m_Host = nullptr;
    HWND m_PasswordEdit = nullptr;
    HWND m_PlainEdit = nullptr;
};

TEST_F(HiddenEditFixture, EsPasswordEditYieldsTier1Password)
{
    Win32StyleProbe probe;
    const auto result = probe.run(makeContext(m_PasswordEdit));

    EXPECT_EQ(result.m_Verdict, Verdict::Password);
    EXPECT_GE(result.m_Confidence, 0.95F);
    EXPECT_STREQ(result.m_ProbeName, "win32_es_password");
}

TEST_F(HiddenEditFixture, PlainEditYieldsTier2Username)
{
    Win32StyleProbe probe;
    const auto result = probe.run(makeContext(m_PlainEdit));

    EXPECT_EQ(result.m_Verdict, Verdict::Username);
    EXPECT_LT(result.m_Confidence, 0.95F);
    EXPECT_GE(result.m_Confidence, 0.50F);
    EXPECT_STREQ(result.m_ProbeName, "win32_es_password");
}

TEST_F(HiddenEditFixture, NonEditClassYieldsUnknown)
{
    // Midpoint lands in the gap below the child edits, so
    // RealChildWindowFromPoint returns host_ itself. Class "STATIC" is
    // not edit-like -> Unknown.
    Win32StyleProbe probe;
    const auto result = probe.run(makeContext(m_Host));

    EXPECT_EQ(result.m_Verdict, Verdict::Unknown);
    EXPECT_EQ(result.m_Confidence, 0.0F);
    EXPECT_STREQ(result.m_ProbeName, "win32_es_password");
}

TEST(Win32StyleProbeNullCtx, NullHwndYieldsUnknown)
{
    Win32StyleProbe probe;
    const ProbeContext ctx;  // all defaults; no targetWindow, clickPoint (0,0)
    const auto result = probe.run(ctx);

    EXPECT_EQ(result.m_Verdict, Verdict::Unknown);
    EXPECT_EQ(result.m_Confidence, 0.0F);
}
