#include <gtest/gtest.h>

#include "ProcessPin.hpp"

#include <algorithm>
#include <cwctype>
#include <optional>
#include <string>
#include <utility>

namespace
{
using seal::signer::PinnedProcess;

std::wstring toLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) { return std::towlower(c); });
    return s;
}

// Spawn cmd.exe /c exit 0 and return its PROCESS_INFORMATION. Exit code 0 is
// chosen deliberately: it is NOT 259 (STILL_ACTIVE), so alive() reads false
// after the child exits.
PROCESS_INFORMATION spawnShortLivedChild()
{
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    wchar_t cmdline[] = L"cmd.exe /c exit 0";  // mutable buffer required by CreateProcessW
    const BOOL ok = CreateProcessW(L"C:\\Windows\\System32\\cmd.exe",
                                   cmdline,
                                   nullptr,
                                   nullptr,
                                   FALSE,
                                   CREATE_NO_WINDOW,
                                   nullptr,
                                   nullptr,
                                   &si,
                                   &pi);
    EXPECT_TRUE(ok) << "CreateProcessW failed: " << GetLastError();
    return pi;
}
}  // namespace

TEST(ProcessPinTest, PinSelf)
{
    PinnedProcess self(GetCurrentProcessId());
    ASSERT_TRUE(self.valid());
    EXPECT_EQ(self.pid(), GetCurrentProcessId());
    EXPECT_EQ(self.lastError(), 0u);
    EXPECT_TRUE(self.alive());
    ASSERT_TRUE(self.creationTime().has_value());
    EXPECT_NE(*self.creationTime(), 0u);
    const std::wstring path = toLower(self.imagePath());
    EXPECT_NE(path.find(L"seal_tests.exe"), std::wstring::npos);
}

TEST(ProcessPinTest, InvalidPidIsInvalid)
{
    PinnedProcess zero(0);  // PID 0 (System Idle) cannot be opened.
    EXPECT_FALSE(zero.valid());
    EXPECT_FALSE(static_cast<bool>(zero));
    EXPECT_TRUE(zero.imagePath().empty());
    EXPECT_FALSE(zero.alive());
    EXPECT_FALSE(zero.creationTime().has_value());
    EXPECT_NE(zero.lastError(), 0u);

    PinnedProcess bogus(0x7FFFFFF0);  // exceedingly unlikely to be a live PID
    EXPECT_FALSE(bogus.valid());
}

TEST(ProcessPinTest, DeadChildDetected)
{
    PROCESS_INFORMATION pi = spawnShortLivedChild();
    ASSERT_NE(pi.hProcess, nullptr);

    PinnedProcess child(pi.dwProcessId);
    ASSERT_TRUE(child.valid());

    ASSERT_EQ(WAIT_OBJECT_0, WaitForSingleObject(pi.hProcess, 5000))
        << "child did not exit within 5 s";

    // The held handle survives the child's exit: identity stays stable while
    // alive() flips to false (EPROCESS persistence the pin relies on).
    EXPECT_FALSE(child.alive());
    EXPECT_EQ(child.pid(), pi.dwProcessId);
    EXPECT_TRUE(child.valid());

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

TEST(ProcessPinTest, CreationTimeOrdering)
{
    PROCESS_INFORMATION pi = spawnShortLivedChild();
    ASSERT_NE(pi.hProcess, nullptr);

    PinnedProcess parent(GetCurrentProcessId());
    PinnedProcess child(pi.dwProcessId);
    ASSERT_TRUE(parent.valid());
    ASSERT_TRUE(child.valid());
    ASSERT_TRUE(parent.creationTime().has_value());
    ASSERT_TRUE(child.creationTime().has_value());

    // The walk's invariant: a parent is created no later than its child.
    EXPECT_LE(*parent.creationTime(), *child.creationTime());

    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}

TEST(ProcessPinTest, MoveLeavesSourceEmpty)
{
    PinnedProcess a(GetCurrentProcessId());
    ASSERT_TRUE(a.valid());
    const DWORD pid = a.pid();

    PinnedProcess b(std::move(a));
    EXPECT_FALSE(a.valid());
    EXPECT_EQ(a.pid(), 0u);
    EXPECT_TRUE(b.valid());
    EXPECT_EQ(b.pid(), pid);

    PinnedProcess c(GetCurrentProcessId());
    c = std::move(b);
    EXPECT_FALSE(b.valid());
    EXPECT_TRUE(c.valid());
    EXPECT_EQ(c.pid(), pid);
    // a and b are empty; c holds the only handle. Destructors run with no double-close.
}

#include <filesystem>
#include <fstream>
#include <sstream>

namespace
{
std::string readBridgeSource()
{
    const std::filesystem::path path =
        std::filesystem::path(SEAL_SOURCE_DIR) / "src/BrowserBridge.cpp";
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("failed to open " + path.string());
    }
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

void expectBridgeContains(const std::string& haystack, const std::string& needle)
{
    EXPECT_NE(haystack.find(needle), std::string::npos)
        << "Bridge TOCTOU invariant missing: " << needle;
}
}  // namespace

TEST(BridgeSourceScanTest, CheckPhasePins)
{
    const std::string src = readBridgeSource();
    expectBridgeContains(src, "#include \"ProcessPin.hpp\"");
    expectBridgeContains(src, "seal::signer::PinnedProcess peer(peerPid)");
    expectBridgeContains(src, "reason=pin_failed");
    expectBridgeContains(src, "reason=peer_pid_changed");
    expectBridgeContains(src, "seal::signer::PinnedProcess browser");
    expectBridgeContains(src, "stale_parent_link");
    expectBridgeContains(src, "creation_time_unavailable");
}

TEST(BridgeSourceScanTest, UsePhaseLiveness)
{
    const std::string src = readBridgeSource();
    // Liveness threaded INTO the read poll-loop (load-bearing), not just above it.
    expectBridgeContains(src, "|| !peer.alive() || !browser.alive()");
    expectBridgeContains(src, "reason=peer_exited");
    expectBridgeContains(src, "reason=browser_exited");
    // Refcount-gated purge on the LAST disconnect.
    expectBridgeContains(src, "noteBrowserConnected");
    expectBridgeContains(src, "noteBrowserDisconnected");
    expectBridgeContains(src, "m_BrowserConnCounts");
}
