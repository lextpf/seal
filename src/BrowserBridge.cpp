#ifdef USE_QT_UI

#include "BrowserBridge.hpp"

#include "BridgeMessage.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"
#include "ProcessPin.hpp"
#include "SignerUtils.hpp"

#include <QtCore/QString>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <stop_token>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>
#include <sddl.h>

#pragma comment(lib, "Bcrypt.lib")

namespace seal
{

namespace
{

// Call immediately after pipe creation fails, before another API overwrites GetLastError.
void logPipeCreateFailed()
{
    const DWORD err = GetLastError();
    qCWarning(logBridge).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.bridge.start_failed",
                                "reason=pipe_create_failed",
                                seal::diag::kv("gle", static_cast<unsigned int>(err))}));
}

// Poll stop every pollMs; timeoutMs=0 waits indefinitely.
// Stop, timeout, or wait failure cancels pending I/O and returns false.
template <typename StopFn>
bool waitOverlappedOrStop(
    HANDLE pipe, OVERLAPPED& overlapped, DWORD pollMs, DWORD timeoutMs, StopFn isStopping)
{
    DWORD elapsedMs = 0;
    while (true)
    {
        const DWORD wait = WaitForSingleObject(overlapped.hEvent, pollMs);
        if (isStopping())
        {
            CancelIoEx(pipe, &overlapped);
            return false;
        }
        if (wait == WAIT_OBJECT_0)
        {
            return true;
        }
        if (wait == WAIT_TIMEOUT)
        {
            if (timeoutMs != 0)
            {
                elapsedMs += pollMs;
                if (elapsedMs >= timeoutMs)
                {
                    CancelIoEx(pipe, &overlapped);
                    return false;
                }
            }
            continue;
        }
        // WAIT_FAILED / WAIT_ABANDONED - treat as fatal.
        CancelIoEx(pipe, &overlapped);
        return false;
    }
}

constexpr DWORD kPipeInBufferBytes = 8192;
constexpr DWORD kPipeOutBufferBytes = 8192;
constexpr DWORD kAcceptBackoffMs = 50;
constexpr DWORD kMessageReadTimeoutMs = 5000;
constexpr DWORD kMaxMessageBytes = 4096;
// Keep focus-click reports for the manual arm window.
constexpr auto kEntryLifetime = std::chrono::seconds(30);

constexpr int kQuantShift = 2;

constexpr auto kNavLifetime = std::chrono::seconds(10);

// Bound each connection against navigation floods, independently of content.js debounce.
constexpr auto kNavThrottleWindow = std::chrono::seconds(2);
constexpr int kNavBurst = 4;

// Worker-local throttle state needs no lock.
struct NavThrottle
{
    std::chrono::steady_clock::time_point m_WindowStart;
    int m_Count = 0;
};

// Bound thread and handle use even for peers that pass authentication.
constexpr std::size_t kMaxConnectionWorkers = 8;

// Clicks in the same PID and coordinate bucket replace one another.
struct BridgeKey
{
    DWORD m_BrowserPid = 0;
    int m_QuantX = 0;
    int m_QuantY = 0;

    bool operator==(const BridgeKey& other) const noexcept
    {
        return m_BrowserPid == other.m_BrowserPid && m_QuantX == other.m_QuantX &&
               m_QuantY == other.m_QuantY;
    }
};

struct BridgeKeyHash
{
    std::size_t operator()(const BridgeKey& key) const noexcept
    {
        std::uint64_t h = static_cast<std::uint64_t>(key.m_BrowserPid);
        h ^= static_cast<std::uint64_t>(static_cast<std::uint32_t>(key.m_QuantX)) << 21;
        h ^= static_cast<std::uint64_t>(static_cast<std::uint32_t>(key.m_QuantY)) << 42;

        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        return static_cast<std::size_t>(h);
    }
};

struct HandleGuard
{
    HANDLE m_Handle = INVALID_HANDLE_VALUE;

    HandleGuard() = default;
    explicit HandleGuard(HANDLE h) noexcept
        : m_Handle(h)
    {
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    HandleGuard(HandleGuard&& other) noexcept
        : m_Handle(other.m_Handle)
    {
        other.m_Handle = INVALID_HANDLE_VALUE;
    }
    HandleGuard& operator=(HandleGuard&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_Handle = other.m_Handle;
            other.m_Handle = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    ~HandleGuard() { reset(); }

    void reset() noexcept
    {
        if (m_Handle != INVALID_HANDLE_VALUE && m_Handle != nullptr)
        {
            CloseHandle(m_Handle);
        }
        m_Handle = INVALID_HANDLE_VALUE;
    }

    HANDLE get() const noexcept { return m_Handle; }
};

// The acceptor joins the worker and closes its pipe after m_Done is set.
struct ConnectionWorker
{
    std::jthread m_Thread;
    HANDLE m_Pipe = INVALID_HANDLE_VALUE;
    std::shared_ptr<std::atomic<bool>> m_Done;
};

// Grant only the current user SID. Descriptor, ACL, and token buffer must
// outlive CreateNamedPipe, which borrows their storage.
struct PipeSecurity
{
    SECURITY_ATTRIBUTES m_Attributes{};
    SECURITY_DESCRIPTOR m_Descriptor{};
    std::vector<BYTE> m_Acl;
    std::vector<BYTE> m_UserBuf;
};

bool buildPipeSecurity(PipeSecurity& out)
{
    HandleGuard token;
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    {
        return false;
    }
    token = HandleGuard(rawToken);

    DWORD requiredBytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &requiredBytes);
    if (requiredBytes == 0)
    {
        return false;
    }
    out.m_UserBuf.assign(requiredBytes, 0);
    if (!GetTokenInformation(
            token.get(), TokenUser, out.m_UserBuf.data(), requiredBytes, &requiredBytes))
    {
        return false;
    }
    const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(out.m_UserBuf.data());
    if (tokenUser->User.Sid == nullptr || !IsValidSid(tokenUser->User.Sid))
    {
        return false;
    }
    const DWORD sidLength = GetLengthSid(tokenUser->User.Sid);

    const DWORD aclBytes = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sidLength - sizeof(DWORD);
    out.m_Acl.assign(aclBytes, 0);
    auto* acl = reinterpret_cast<ACL*>(out.m_Acl.data());
    if (!InitializeAcl(acl, aclBytes, ACL_REVISION))
    {
        return false;
    }
    if (!AddAccessAllowedAce(
            acl, ACL_REVISION, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, tokenUser->User.Sid))
    {
        return false;
    }

    if (!InitializeSecurityDescriptor(&out.m_Descriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        return false;
    }
    if (!SetSecurityDescriptorDacl(&out.m_Descriptor, TRUE, acl, FALSE))
    {
        return false;
    }
    out.m_Attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    out.m_Attributes.lpSecurityDescriptor = &out.m_Descriptor;
    out.m_Attributes.bInheritHandle = FALSE;
    return true;
}

std::string hexEncode(const unsigned char* data, std::size_t length)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(length * 2);
    for (std::size_t i = 0; i < length; ++i)
    {
        const unsigned char byte = data[i];
        out[2 * i] = kHex[byte >> 4];
        out[2 * i + 1] = kHex[byte & 0x0F];
    }
    return out;
}

bool generateRandom(unsigned char* out, std::size_t bytes)
{
    return BCRYPT_SUCCESS(
        BCryptGenRandom(nullptr, out, static_cast<ULONG>(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// out must hold at least 32 bytes.
bool sha256(const unsigned char* in, std::size_t inLen, unsigned char* out, std::size_t outLen)
{
    if (outLen < 32)
    {
        return false;
    }
    const NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE,
                                       nullptr,
                                       0,
                                       const_cast<unsigned char*>(in),
                                       static_cast<ULONG>(inLen),
                                       out,
                                       static_cast<ULONG>(outLen));
    return BCRYPT_SUCCESS(status);
}

// Neutral tags do not enter the verdict map.
struct VerdictMapping
{
    Verdict m_Verdict = Verdict::Unknown;
    bool m_ShouldInsert = false;
};

VerdictMapping mapTag(BridgeTag tag) noexcept
{
    switch (tag)
    {
        case BridgeTag::Password:
            return {Verdict::Password, true};
        case BridgeTag::Username:
        case BridgeTag::Email:
            return {Verdict::Username, true};
        case BridgeTag::Text:
        case BridgeTag::Other:
        default:
            return {Verdict::Unknown, false};
    }
}

constexpr int quantise(LONG raw) noexcept
{
    return static_cast<int>(raw) >> kQuantShift;
}

}  // namespace

struct BrowserBridge::Impl
{
    HANDLE m_ListenPipe = INVALID_HANDLE_VALUE;  // first instance pre-created by startImpl().
    std::jthread m_AcceptThread;
    std::atomic<bool> m_Running{false};
    std::atomic<bool> m_Disabled{false};
    // Reference counts permit several relay connections for each browser kind.
    std::array<std::atomic<int>, static_cast<std::size_t>(seal::signer::BrowserKind::Count)>
        m_PeerCounts{};
    // Despite its name, this seed only derives the pipe suffix. No MAC uses it.
    std::array<unsigned char, 32> m_HmacKey{};
    std::wstring m_PipeName;
    PipeSecurity m_PipeSecurity;  // per-user DACL, built once, applied to every pipe instance.
    mutable std::shared_mutex m_MapMutex;
    std::unordered_map<BridgeKey, BridgeEntry, BridgeKeyHash> m_Map;
    std::unordered_map<DWORD, int> m_BrowserConnCounts;  // guarded by m_MapMutex
    std::string m_ExpectedSignerIdentity;

    // Navigation uses a separate mutex to avoid contention with click lookup.
    mutable std::mutex m_NavMutex;
    NavSnapshot m_PendingNav;
    std::uint64_t m_NavSeq = 0;  // guarded by m_NavMutex

    // m_NavMutex guards per-PID document tokens used to reject click replay.
    std::unordered_map<DWORD, std::string> m_CurrentVisitByPid;  // guarded by m_NavMutex

    // The worker reads; GUI writes hold m_WriteMutex and check m_Alive.
    // The worker marks dead under that mutex before the acceptor joins and closes.
    struct PeerConn
    {
        HANDLE m_Pipe = INVALID_HANDLE_VALUE;
        std::mutex m_WriteMutex;
        std::atomic<bool> m_Alive{true};
        explicit PeerConn(HANDLE pipe)
            : m_Pipe(pipe)
        {
        }
    };
    mutable std::mutex m_PeerConnMutex;
    std::unordered_map<DWORD, std::shared_ptr<PeerConn>> m_PeerConns;  // browserPid -> connection

    // Shared by start and enable without duplicate logging.
    bool startImpl();
    void stopImpl();
    HANDLE createPipeInstance(bool firstInstance);
    void acceptorLoop(std::stop_token stopToken);
    void serveConnection(HANDLE pipe, std::stop_token stopToken);
    bool verifySignerMatches(const std::wstring& peerPath) const;
    void handleMessage(DWORD browserPid, std::string_view payload, NavThrottle& navThrottle);
    void notePendingNavigation(DWORD browserPid, const ParsedBridgeMessage& parsed);
    void pruneExpiredLocked(const std::chrono::steady_clock::time_point& now);
    void noteBrowserConnected(DWORD browserPid);
    void noteBrowserDisconnected(DWORD browserPid);
    bool readFramedMessage(HANDLE pipe,
                           std::vector<char>& outBuf,
                           OVERLAPPED& overlapped,
                           std::stop_token stopToken,
                           const seal::signer::PinnedProcess& peer,
                           const seal::signer::PinnedProcess& browser);
    bool writeFramedMessage(HANDLE pipe, std::string_view payload, OVERLAPPED& overlapped);
};

HANDLE BrowserBridge::Impl::createPipeInstance(bool firstInstance)
{
    DWORD openMode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if (firstInstance)
    {
        // Claim the first pipe instance against same-user precreation.
        // Later instances must omit the flag to avoid ERROR_ACCESS_DENIED.
        openMode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    return CreateNamedPipeW(m_PipeName.c_str(),
                            openMode,
                            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                            PIPE_UNLIMITED_INSTANCES,
                            kPipeOutBufferBytes,
                            kPipeInBufferBytes,
                            0,
                            &m_PipeSecurity.m_Attributes);
}

bool BrowserBridge::Impl::startImpl()
{
    if (m_Running.load())
    {
        return true;
    }
#ifdef SEAL_REQUIRE_SIGNED_PEER
    // Enforce signed startup here so start and enable apply the same requirement.
    if (m_ExpectedSignerIdentity.empty())
    {
        qCCritical(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.signer_check", "result=fail", "reason=unsigned_production"}));
        return false;
    }
#endif
    if (!generateRandom(m_HmacKey.data(), m_HmacKey.size()))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed", "reason=rng_failed"}));
        return false;
    }

    std::array<unsigned char, 32> keyHash{};
    if (!sha256(m_HmacKey.data(), m_HmacKey.size(), keyHash.data(), keyHash.size()))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed", "reason=hash_failed"}));
        return false;
    }
    const std::string hashHex = hexEncode(keyHash.data(), keyHash.size());

    // M7: rotate the pipe name without transmitting the seed.
    std::wstring name;
    name.reserve(32 + hashHex.size());
    name.assign(L"\\\\.\\pipe\\seal-fill-");
    for (const char c : hashHex)
    {
        name.push_back(static_cast<wchar_t>(c));
    }
    m_PipeName = name;

    if (!buildPipeSecurity(m_PipeSecurity))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed", "reason=acl_build_failed"}));
        return false;
    }

    // Create synchronously so failures reach the caller and the first extension
    // connection does not miss the pipe and enter reconnect backoff.
    HANDLE first = createPipeInstance(true);
    if (first == INVALID_HANDLE_VALUE)
    {
        logPipeCreateFailed();
        return false;
    }
    m_ListenPipe = first;
    m_Running.store(true);

    qCInfo(logBridge).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.bridge.start", "result=ok"}));

    m_AcceptThread = std::jthread([this](std::stop_token stopToken) { acceptorLoop(stopToken); });
    return true;
}

void BrowserBridge::Impl::stopImpl()
{
    m_Running.store(false);
    if (m_AcceptThread.joinable())
    {
        // Joining the acceptor also cancels and joins every worker before handles close.
        m_AcceptThread.request_stop();
        m_AcceptThread.join();
    }
    // Close a pre-created instance if the acceptor never consumed it.
    if (m_ListenPipe != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(m_ListenPipe);
        CloseHandle(m_ListenPipe);
        m_ListenPipe = INVALID_HANDLE_VALUE;
    }
    for (auto& count : m_PeerCounts)
    {
        count.store(0, std::memory_order_relaxed);
    }
}

bool BrowserBridge::Impl::verifySignerMatches(const std::wstring& peerPath) const
{
    // M6: unsigned development builds accept any peer signer.
    if (m_ExpectedSignerIdentity.empty())
    {
        return true;
    }
    if (!seal::signer::winVerifyTrustOk(peerPath))
    {
        return false;
    }
    const std::string peerIdentity = seal::signer::extractSignerIdentityFromFile(peerPath);
    if (peerIdentity.empty())
    {
        return false;
    }
    return peerIdentity == m_ExpectedSignerIdentity;
}

void BrowserBridge::Impl::pruneExpiredLocked(const std::chrono::steady_clock::time_point& now)
{
    for (auto it = m_Map.begin(); it != m_Map.end();)
    {
        if (it->second.m_ExpiresAt <= now)
        {
            it = m_Map.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

void BrowserBridge::Impl::noteBrowserConnected(DWORD browserPid)
{
    std::unique_lock<std::shared_mutex> lock(m_MapMutex);
    ++m_BrowserConnCounts[browserPid];
}

void BrowserBridge::Impl::noteBrowserDisconnected(DWORD browserPid)
{
    std::unique_lock<std::shared_mutex> lock(m_MapMutex);
    auto it = m_BrowserConnCounts.find(browserPid);
    if (it == m_BrowserConnCounts.end())
    {
        return;
    }
    if (--it->second <= 0)
    {
        m_BrowserConnCounts.erase(it);

        for (auto mit = m_Map.begin(); mit != m_Map.end();)
        {
            if (mit->first.m_BrowserPid == browserPid)
            {
                mit = m_Map.erase(mit);
            }
            else
            {
                ++mit;
            }
        }
        // Lock order is m_MapMutex then m_NavMutex; never reverse it.
        {
            std::lock_guard<std::mutex> navLock(m_NavMutex);
            m_CurrentVisitByPid.erase(browserPid);
        }
    }
}

void BrowserBridge::Impl::handleMessage(DWORD browserPid,
                                        std::string_view payload,
                                        NavThrottle& navThrottle)
{
    if (m_Disabled.load())
    {
        return;
    }
    ParsedBridgeMessage parsed;
    const BridgeParseError err = parseBridgeMessage(payload, &parsed);
    if (err != BridgeParseError::None)
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             seal::diag::kv("reason", bridgeParseErrorToken(err)),
             seal::diag::kv("browser_pid", static_cast<unsigned int>(browserPid))}));
        return;
    }

    if (parsed.m_Kind == BridgeKind::Nav)
    {
        const auto now = std::chrono::steady_clock::now();
        if (navThrottle.m_Count == 0 || now - navThrottle.m_WindowStart >= kNavThrottleWindow)
        {
            navThrottle.m_WindowStart = now;
            navThrottle.m_Count = 0;
        }
        if (navThrottle.m_Count >= kNavBurst)
        {
            // Use debug logging to avoid an info-log flood from rejected reports.
            qCDebug(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=fill.bridge.nav",
                 "result=throttled",
                 seal::diag::kv("browser_pid", static_cast<unsigned int>(browserPid))}));
            return;
        }
        ++navThrottle.m_Count;
        notePendingNavigation(browserPid, parsed);
        return;
    }

    if (!parsed.m_Secure)
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=insecure_click",
             seal::diag::kv("browser_pid", static_cast<unsigned int>(browserPid))}));
        return;
    }

    const VerdictMapping mapping = mapTag(parsed.m_Tag);
    if (!mapping.m_ShouldInsert)
    {
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    BridgeEntry entry;
    entry.m_Verdict = mapping.m_Verdict;
    entry.m_ExpiresAt = now + kEntryLifetime;
    entry.m_UrlHost =
        QString::fromUtf8(parsed.m_UrlHost.data(), static_cast<int>(parsed.m_UrlHost.size()));

    entry.m_Visit = parsed.m_Visit;

    BridgeKey key;
    key.m_BrowserPid = browserPid;
    key.m_QuantX = quantise(parsed.m_X);
    key.m_QuantY = quantise(parsed.m_Y);

    {
        std::unique_lock<std::shared_mutex> lock(m_MapMutex);
        pruneExpiredLocked(now);
        m_Map.insert_or_assign(key, std::move(entry));
    }

    // Keep raw hosts out of logs. string_view forces kv to select its string
    // overload; const char* otherwise selects bool and prints verdict=true.
    qCInfo(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=fill.bridge.msg",
         seal::diag::kv("browser_pid", static_cast<unsigned int>(browserPid)),
         seal::diag::kv(
             "verdict",
             std::string_view(mapping.m_Verdict == Verdict::Password ? "password" : "username")),
         seal::diag::kv("x", parsed.m_X),
         seal::diag::kv("y", parsed.m_Y),
         seal::diag::kv("qx", key.m_QuantX),
         seal::diag::kv("qy", key.m_QuantY)}));
}

void BrowserBridge::Impl::notePendingNavigation(DWORD browserPid, const ParsedBridgeMessage& parsed)
{
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(m_NavMutex);
        m_PendingNav.m_Host = parsed.m_UrlHost;
        m_PendingNav.m_Secure = parsed.m_Secure;
        m_PendingNav.m_HasPasswordForm = parsed.m_HasPasswordForm;
        m_PendingNav.m_HasUsernameField = parsed.m_HasUsernameField;
        m_PendingNav.m_Visit = parsed.m_Visit;
        m_PendingNav.m_BrowserPid = browserPid;
        m_PendingNav.m_At = now;
        m_PendingNav.m_Seq = ++m_NavSeq;

        m_CurrentVisitByPid[browserPid] = parsed.m_Visit;
    }
    // Log host length only; never the hostname.
    qCInfo(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=fill.bridge.nav",
         "result=ok",
         seal::diag::kv("browser_pid", static_cast<unsigned int>(browserPid)),
         seal::diag::kv("host_len", static_cast<unsigned int>(parsed.m_UrlHost.size())),
         seal::diag::kv("secure", parsed.m_Secure ? 1 : 0),
         seal::diag::kv("form", parsed.m_HasPasswordForm ? 1 : 0)}));
}

bool BrowserBridge::Impl::readFramedMessage(HANDLE pipe,
                                            std::vector<char>& outBuf,
                                            OVERLAPPED& overlapped,
                                            std::stop_token stopToken,
                                            const seal::signer::PinnedProcess& peer,
                                            const seal::signer::PinnedProcess& browser)
{
    // Idle connections wait indefinitely for a length, with stop polling.
    // Once a length arrives, cap payload wait to reject peers that stall mid-frame.
    constexpr DWORD kStopPollMs = 1000;

    auto isStopping = [&]() noexcept
    {
        const bool stopping = stopToken.stop_requested() || !m_Running.load() || m_Disabled.load();
        return stopping || !peer.alive() || !browser.alive();
    };

    std::uint32_t lengthBytes = 0;
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(
        pipe, reinterpret_cast<char*>(&lengthBytes), sizeof(lengthBytes), nullptr, &overlapped);
    if (!ok)
    {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING && err != ERROR_MORE_DATA)
        {
            return false;
        }
    }

    if (!waitOverlappedOrStop(pipe, overlapped, kStopPollMs, 0, isStopping))
    {
        return false;
    }
    if (!GetOverlappedResult(pipe, &overlapped, &bytesRead, FALSE) ||
        bytesRead != sizeof(lengthBytes))
    {
        return false;
    }
    if (lengthBytes == 0 || lengthBytes > kMaxMessageBytes)
    {
        return false;
    }
    outBuf.assign(lengthBytes, '\0');
    ResetEvent(overlapped.hEvent);
    ok = ReadFile(pipe, outBuf.data(), lengthBytes, nullptr, &overlapped);
    if (!ok)
    {
        const DWORD err = GetLastError();
        if (err != ERROR_IO_PENDING && err != ERROR_MORE_DATA)
        {
            return false;
        }
    }

    if (!waitOverlappedOrStop(pipe, overlapped, kStopPollMs, kMessageReadTimeoutMs, isStopping))
    {
        return false;
    }
    DWORD readBytes = 0;
    if (!GetOverlappedResult(pipe, &overlapped, &readBytes, FALSE) || readBytes != lengthBytes)
    {
        return false;
    }
    return true;
}

bool BrowserBridge::Impl::writeFramedMessage(HANDLE pipe,
                                             std::string_view payload,
                                             OVERLAPPED& overlapped)
{
    if (payload.size() > kMaxMessageBytes)
    {
        return false;
    }
    const std::uint32_t lengthBytes = static_cast<std::uint32_t>(payload.size());
    ResetEvent(overlapped.hEvent);
    BOOL ok = WriteFile(pipe,
                        reinterpret_cast<const char*>(&lengthBytes),
                        sizeof(lengthBytes),
                        nullptr,
                        &overlapped);
    if (!ok && GetLastError() != ERROR_IO_PENDING)
    {
        return false;
    }
    DWORD written = 0;
    if (!GetOverlappedResult(pipe, &overlapped, &written, TRUE) || written != sizeof(lengthBytes))
    {
        return false;
    }
    ResetEvent(overlapped.hEvent);
    ok = WriteFile(pipe, payload.data(), lengthBytes, nullptr, &overlapped);
    if (!ok && GetLastError() != ERROR_IO_PENDING)
    {
        return false;
    }
    if (!GetOverlappedResult(pipe, &overlapped, &written, TRUE) || written != lengthBytes)
    {
        return false;
    }
    return true;
}

void BrowserBridge::Impl::acceptorLoop(std::stop_token stopToken)
{
    // Only the acceptor mutates the worker list. It joins workers before closing
    // their pipe handles, including during shutdown.
    std::vector<ConnectionWorker> workers;

    auto reapFinished = [&workers]()
    {
        for (auto it = workers.begin(); it != workers.end();)
        {
            if (it->m_Done->load(std::memory_order_acquire))
            {
                if (it->m_Thread.joinable())
                {
                    it->m_Thread.join();
                }
                if (it->m_Pipe != INVALID_HANDLE_VALUE)
                {
                    DisconnectNamedPipe(it->m_Pipe);
                    CloseHandle(it->m_Pipe);
                }
                it = workers.erase(it);
            }
            else
            {
                ++it;
            }
        }
    };

    HANDLE inst = m_ListenPipe;
    m_ListenPipe = INVALID_HANDLE_VALUE;

    while (!stopToken.stop_requested() && m_Running.load())
    {
        if (inst == INVALID_HANDLE_VALUE)
        {
            inst = createPipeInstance(false);
            if (inst == INVALID_HANDLE_VALUE)
            {
                logPipeCreateFailed();
                reapFinished();
                Sleep(kAcceptBackoffMs);
                continue;
            }
        }

        HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (event.get() == nullptr)
        {
            DisconnectNamedPipe(inst);
            CloseHandle(inst);
            inst = INVALID_HANDLE_VALUE;
            break;
        }
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();

        const BOOL connected = ConnectNamedPipe(inst, &overlapped);
        const DWORD err = connected != 0 ? ERROR_SUCCESS : GetLastError();
        if (!connected && err != ERROR_IO_PENDING && err != ERROR_PIPE_CONNECTED)
        {
            DisconnectNamedPipe(inst);
            CloseHandle(inst);
            inst = INVALID_HANDLE_VALUE;
            reapFinished();
            continue;
        }

        bool stopping = false;
        bool connectFailed = false;
        if (err == ERROR_IO_PENDING)
        {
            while (true)
            {
                const DWORD wait = WaitForSingleObject(overlapped.hEvent, 200);
                if (stopToken.stop_requested() || !m_Running.load())
                {
                    CancelIoEx(inst, &overlapped);
                    stopping = true;
                    break;
                }
                if (wait == WAIT_OBJECT_0)
                {
                    break;
                }
                if (wait == WAIT_TIMEOUT)
                {
                    reapFinished();
                    continue;
                }
                CancelIoEx(inst, &overlapped);
                connectFailed = true;
                break;
            }
            if (!stopping && !connectFailed)
            {
                DWORD ignored = 0;
                if (!GetOverlappedResult(inst, &overlapped, &ignored, FALSE))
                {
                    connectFailed = true;
                }
            }
        }

        if (stopping)
        {
            DisconnectNamedPipe(inst);
            CloseHandle(inst);
            inst = INVALID_HANDLE_VALUE;
            break;
        }
        if (connectFailed)
        {
            DisconnectNamedPipe(inst);
            CloseHandle(inst);
            inst = INVALID_HANDLE_VALUE;
            reapFinished();
            continue;
        }
        if (m_Disabled.load())
        {
            DisconnectNamedPipe(inst);
            CloseHandle(inst);
            inst = INVALID_HANDLE_VALUE;
            reapFinished();
            continue;
        }

        reapFinished();
        if (workers.size() >= kMaxConnectionWorkers)
        {
            qCWarning(logBridge).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=fill.bridge.reject", "reason=worker_cap_reached"}));
            DisconnectNamedPipe(inst);
            CloseHandle(inst);
            inst = INVALID_HANDLE_VALUE;
            continue;
        }

        HANDLE served = inst;
        inst = INVALID_HANDLE_VALUE;
        auto done = std::make_shared<std::atomic<bool>>(false);
        ConnectionWorker slot;
        slot.m_Pipe = served;
        slot.m_Done = done;
        slot.m_Thread = std::jthread(
            [this, served, done](std::stop_token workerStop)
            {
                serveConnection(served, workerStop);
                done->store(true, std::memory_order_release);
            });
        workers.push_back(std::move(slot));
    }

    for (auto& worker : workers)
    {
        worker.m_Thread.request_stop();
        if (worker.m_Pipe != INVALID_HANDLE_VALUE)
        {
            CancelIoEx(worker.m_Pipe, nullptr);
        }
    }
    for (auto& worker : workers)
    {
        if (worker.m_Thread.joinable())
        {
            worker.m_Thread.join();
        }
        if (worker.m_Pipe != INVALID_HANDLE_VALUE)
        {
            DisconnectNamedPipe(worker.m_Pipe);
            CloseHandle(worker.m_Pipe);
        }
    }
    workers.clear();
    if (inst != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(inst);
        CloseHandle(inst);
    }
}

void BrowserBridge::Impl::serveConnection(HANDLE pipe, std::stop_token stopToken)
{
    // This worker owns its event and OVERLAPPED; the acceptor owns pipe closure.
    HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (event.get() == nullptr)
    {
        return;
    }
    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();

    DWORD peerPid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &peerPid) || peerPid == 0)
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.reject", "reason=peer_pid_unknown"}));
        return;
    }

    seal::signer::PinnedProcess peer(peerPid);
    if (!peer)
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=pin_failed",
             "sub=peer",
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid)),
             seal::diag::kv("last_error", static_cast<unsigned int>(peer.lastError()))}));
        return;
    }

    // Re-read the pipe PID to reject reuse between the first query and OpenProcess.
    DWORD peerPidCheck = 0;
    if (!GetNamedPipeClientProcessId(pipe, &peerPidCheck) || peerPidCheck != peer.pid())
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=peer_pid_changed",
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid))}));
        return;
    }

    // The path comes from the pin; on-disk authenticode verification retains file TOCTOU risk.
    const std::wstring peerPath = peer.imagePath();
    if (peerPath.empty())
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=peer_path_unknown",
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid))}));
        return;
    }
    if (!verifySignerMatches(peerPath))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=untrusted_peer",
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid))}));
        return;
    }

    // Pin each ancestor and reject parent PIDs created after their child.
    constexpr int kMaxAncestorDepth = 6;
    seal::signer::PinnedProcess browser;  // retained for the connection if found
    std::wstring browserPath;
    std::string parentChain;
    std::string failSubReason = "browser_ancestor_not_found";
    std::string failedImage;
    std::optional<std::uint64_t> childCreation = peer.creationTime();
    DWORD curPid = seal::signer::resolveParentPid(peerPid);
    for (int depth = 0; depth < kMaxAncestorDepth && curPid != 0; ++depth)
    {
        seal::signer::PinnedProcess cur(curPid);
        if (!cur)
        {
            failSubReason = "path_unresolved";
            break;
        }

        const std::wstring curPath = cur.imagePath();
        if (curPath.empty())
        {
            failSubReason = "path_unresolved";
            break;
        }

        // Record each hop before rejecting it so failure diagnostics include its image.
        {
            const auto sep = curPath.find_last_of(L"\\/");
            const std::wstring basename =
                (sep == std::wstring::npos) ? curPath : curPath.substr(sep + 1);
            std::string base;
            base.reserve(basename.size());
            for (wchar_t c : basename)
            {
                base.push_back((c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?');
            }
            if (!parentChain.empty())
            {
                parentChain += '>';
            }
            parentChain += base;
            failedImage = base;
        }

        // Equal FILETIME ticks are valid; absent creation times fail closed.
        const std::optional<std::uint64_t> curCreation = cur.creationTime();
        if (!curCreation || !childCreation)
        {
            failSubReason = "creation_time_unavailable";
            break;
        }
        if (*curCreation > *childCreation)
        {
            failSubReason = "stale_parent_link";
            break;
        }

        if (seal::signer::isKnownBrowserImage(curPath))
        {
            if (!seal::signer::winVerifyTrustOk(curPath))
            {
                failSubReason = "winverifytrust_failed";
                break;
            }
            const seal::signer::BrowserKind kind = seal::signer::identifyBrowser(curPath);
            const std::wstring publisher = seal::signer::extractSignerPublisherFromFile(curPath);
            if (!seal::signer::browserPublisherMatches(kind, publisher))
            {
                failSubReason = "browser_publisher_mismatch";
                break;
            }
            browser = std::move(cur);
            browserPath = curPath;
            break;
        }
        if (!seal::signer::isTrustedShellImage(curPath))
        {
            failSubReason =
                (seal::signer::identifyShell(curPath) == seal::signer::ShellKind::Unknown)
                    ? "image_not_in_browser_list"
                    : "shell_not_trusted";
            break;
        }

        childCreation = curCreation;  // shell hop: ordering carries upward
        curPid = seal::signer::resolveParentPid(cur.pid());
    }
    if (!browser && failSubReason == "browser_ancestor_not_found" && curPid == 0)
    {
        failSubReason = "parent_pid_unknown_in_chain";
    }

    if (!browser)
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=parent_not_trusted_browser",
             seal::diag::kv("sub_reason", std::string_view(failSubReason)),
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid)),
             seal::diag::kv("parent_chain",
                            parentChain.empty() ? std::string("<empty>") : parentChain),
             seal::diag::kv("failed_image",
                            failedImage.empty() ? std::string("<empty>") : failedImage)}));
        return;
    }
    // The validated browser ancestor owns the window and supplies the map key.
    const DWORD parentPid = browser.pid();

    // A fresh nonce checks framing and replay. Signer and ancestor gates authenticate.
    std::array<unsigned char, 32> connectionNonce{};
    if (!generateRandom(connectionNonce.data(), connectionNonce.size()))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.reject", "reason=nonce_rng_failed"}));
        return;
    }
    const std::string handshake = std::string("{\"v\":1,\"hello\":\"seal-bridge\",\"nonce\":\"") +
                                  hexEncode(connectionNonce.data(), connectionNonce.size()) +
                                  std::string("\"}");

    if (!writeFramedMessage(pipe, handshake, overlapped))
    {
        return;
    }

    std::vector<char> echoBuf;
    if (!readFramedMessage(pipe, echoBuf, overlapped, stopToken, peer, browser))
    {
        return;
    }
    if (echoBuf.size() != handshake.size() ||
        std::memcmp(echoBuf.data(), handshake.data(), handshake.size()) != 0)
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.reject", "reason=handshake_mismatch"}));
        return;
    }

    const seal::signer::BrowserKind kind = seal::signer::identifyBrowser(browserPath);
    const std::size_t kindIdx = static_cast<std::size_t>(kind);
    m_PeerCounts[kindIdx].fetch_add(1, std::memory_order_relaxed);
    noteBrowserConnected(parentPid);
    qCInfo(logBridge).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.bridge.accept",
                                "result=ok",
                                seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid)),
                                seal::diag::kv("browser_pid", static_cast<unsigned int>(parentPid)),
                                seal::diag::kv("browser", seal::signer::browserKindToken(kind))}));

    // Latest authenticated connection per browser PID receives reverse writes.
    auto conn = std::make_shared<PeerConn>(pipe);
    {
        std::lock_guard<std::mutex> lock(m_PeerConnMutex);
        m_PeerConns[parentPid] = conn;
    }

    std::vector<char> message;
    NavThrottle navThrottle;  // per-connection nav rate-limit state (worker-local).
    while (m_Running.load() && !stopToken.stop_requested() && !m_Disabled.load())
    {
        if (!peer.alive() || !browser.alive())
        {
            break;
        }
        if (!readFramedMessage(pipe, message, overlapped, stopToken, peer, browser))
        {
            break;
        }

        handleMessage(parentPid, std::string_view(message.data(), message.size()), navThrottle);
    }

    // Liveness failure already logs its reason; other exits log disconnect only.
    if (!peer.alive())
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.disconnect",
             "reason=peer_exited",
             seal::diag::kv("browser_pid", static_cast<unsigned int>(parentPid))}));
    }
    else if (!browser.alive())
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.disconnect",
             "reason=browser_exited",
             seal::diag::kv("browser_pid", static_cast<unsigned int>(parentPid))}));
    }

    // Mark dead under the write mutex before the acceptor can close the pipe.
    {
        std::lock_guard<std::mutex> writeLock(conn->m_WriteMutex);
        conn->m_Alive.store(false);
    }
    {
        std::lock_guard<std::mutex> lock(m_PeerConnMutex);
        auto it = m_PeerConns.find(parentPid);
        if (it != m_PeerConns.end() && it->second == conn)
        {
            m_PeerConns.erase(it);
        }
    }

    m_PeerCounts[kindIdx].fetch_sub(1, std::memory_order_relaxed);
    qCInfo(logBridge).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.bridge.disconnect",
                                seal::diag::kv("browser_pid", static_cast<unsigned int>(parentPid)),
                                seal::diag::kv("browser", seal::signer::browserKindToken(kind))}));
    noteBrowserDisconnected(parentPid);
}

BrowserBridge::BrowserBridge()
    : m_Impl(std::make_unique<Impl>())
{
    m_Impl->m_ExpectedSignerIdentity = seal::signer::readOwnSignerIdentity();
    if (m_Impl->m_ExpectedSignerIdentity.empty())
    {
        qCWarning(logBridge).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=fill.bridge.signer_check",
                                                              "reason=seal_unsigned_dev_mode",
                                                              "result=peers_unrestricted"}));
    }
}

BrowserBridge::~BrowserBridge()
{
    if (m_Impl)
    {
        m_Impl->stopImpl();
    }
}

bool BrowserBridge::start()
{
    if (m_Impl->m_Disabled.load())
    {
        return false;
    }
    return m_Impl->startImpl();
}

void BrowserBridge::stop()
{
    m_Impl->stopImpl();
}

bool BrowserBridge::isRunning() const noexcept
{
    return m_Impl->m_Running.load();
}

bool BrowserBridge::isPeerAuthEnforced() const noexcept
{
    return !m_Impl->m_ExpectedSignerIdentity.empty();
}

void BrowserBridge::disable()
{
    m_Impl->m_Disabled.store(true);
    m_Impl->stopImpl();
    {
        std::unique_lock<std::shared_mutex> lock(m_Impl->m_MapMutex);
        m_Impl->m_Map.clear();

        m_Impl->m_BrowserConnCounts.clear();
    }
    {
        // Discard pending navigation so enable cannot stage a pre-disable report.
        std::lock_guard<std::mutex> navLock(m_Impl->m_NavMutex);
        m_Impl->m_PendingNav = NavSnapshot{};
        m_Impl->m_CurrentVisitByPid.clear();
    }
    qCInfo(logBridge).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.bridge.disabled"}));
}

void BrowserBridge::enable()
{
    if (!m_Impl->m_Disabled.load())
    {
        return;
    }
    m_Impl->m_Disabled.store(false);
    (void)m_Impl->startImpl();
}

bool BrowserBridge::isDisabled() const noexcept
{
    return m_Impl->m_Disabled.load();
}

bool BrowserBridge::isPeerConnected() const noexcept
{
    for (const auto& count : m_Impl->m_PeerCounts)
    {
        if (count.load(std::memory_order_relaxed) > 0)
        {
            return true;
        }
    }
    return false;
}

bool BrowserBridge::isPeerConnected(seal::signer::BrowserKind kind) const noexcept
{
    return m_Impl->m_PeerCounts[static_cast<std::size_t>(kind)].load(std::memory_order_relaxed) > 0;
}

std::size_t BrowserBridge::mapEntryCount() const noexcept
{
    std::shared_lock<std::shared_mutex> lock(m_Impl->m_MapMutex);
    return m_Impl->m_Map.size();
}

std::optional<BridgeEntry> BrowserBridge::lookup(DWORD browserPid, POINT screenPoint) const noexcept
{
    if (m_Impl->m_Disabled.load())
    {
        return std::nullopt;
    }
    const auto now = std::chrono::steady_clock::now();
    std::shared_lock<std::shared_mutex> lock(m_Impl->m_MapMutex);

    // Nearby fields may collide within 48 px; prefer the freshest entry and require M5.
    constexpr int kLookupToleranceRawPx = 48;
    constexpr int kBucketCenterOffset = 1 << (kQuantShift - 1);

    const BridgeEntry* freshest = nullptr;
    for (const auto& kv : m_Impl->m_Map)
    {
        if (kv.first.m_BrowserPid != browserPid)
        {
            continue;
        }
        if (kv.second.m_ExpiresAt <= now)
        {
            continue;
        }
        const int entryRawX = (kv.first.m_QuantX << kQuantShift) + kBucketCenterOffset;
        const int entryRawY = (kv.first.m_QuantY << kQuantShift) + kBucketCenterOffset;
        const int dx = std::abs(entryRawX - static_cast<int>(screenPoint.x));
        const int dy = std::abs(entryRawY - static_cast<int>(screenPoint.y));
        if (dx > kLookupToleranceRawPx || dy > kLookupToleranceRawPx)
        {
            continue;
        }
        if (freshest == nullptr || kv.second.m_ExpiresAt > freshest->m_ExpiresAt)
        {
            freshest = &kv.second;
        }
    }
    if (freshest == nullptr)
    {
        return std::nullopt;
    }
    return *freshest;
}

std::optional<NavSnapshot> BrowserBridge::takeNavSince(std::uint64_t& lastSeenSeq) const
{
    if (m_Impl->m_Disabled.load())
    {
        return std::nullopt;
    }
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(m_Impl->m_NavMutex);
    if (m_Impl->m_NavSeq == 0 || m_Impl->m_NavSeq <= lastSeenSeq)
    {
        return std::nullopt;  // nothing new since this caller last looked.
    }
    if (now - m_Impl->m_PendingNav.m_At > kNavLifetime)
    {
        lastSeenSeq = m_Impl->m_NavSeq;
        return std::nullopt;
    }
    lastSeenSeq = m_Impl->m_NavSeq;
    return m_Impl->m_PendingNav;
}

std::optional<std::string> BrowserBridge::currentVisit(DWORD browserPid) const
{
    if (m_Impl->m_Disabled.load())
    {
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(m_Impl->m_NavMutex);
    const auto it = m_Impl->m_CurrentVisitByPid.find(browserPid);
    if (it == m_Impl->m_CurrentVisitByPid.end() || it->second.empty())
    {
        return std::nullopt;  // no navigation seen (or empty token) -> unknown.
    }
    return it->second;
}

namespace
{
// Escape JSON structure and control characters; UTF-8 bytes >= 0x80 pass through.
std::string jsonEscape(std::string_view s)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(s.size() + 8);
    for (const unsigned char c : s)
    {
        switch (c)
        {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                if (c < 0x20)
                {
                    out += "\\u00";
                    out += kHex[(c >> 4) & 0x0F];
                    out += kHex[c & 0x0F];
                }
                else
                {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}
}  // namespace

bool BrowserBridge::sendFillUsername(DWORD browserPid,
                                     const std::string& host,
                                     const std::string& visit,
                                     const std::string& usernameUtf8)
{
    if (m_Impl->m_Disabled.load())
    {
        return false;  // M8 panic: no reverse traffic.
    }
    if (visit.empty())
    {
        return false;
    }

    // Hold shared ownership through the reverse write.
    std::shared_ptr<Impl::PeerConn> conn;
    {
        std::lock_guard<std::mutex> lock(m_Impl->m_PeerConnMutex);
        const auto it = m_Impl->m_PeerConns.find(browserPid);
        if (it == m_Impl->m_PeerConns.end())
        {
            return false;  // no peer connected for this browser
        }
        conn = it->second;
    }

    // Reserve the completed frame before appending the escaped username.
    // The escaping helper can allocate separately; its final string is wiped below.
    std::string escapedUser = jsonEscape(usernameUtf8);
    const std::string escapedHost = jsonEscape(host);
    const std::string escapedVisit = jsonEscape(visit);
    std::string json;
    json.reserve(escapedHost.size() + escapedVisit.size() + escapedUser.size() + 92);
    json += "{\"v\":1,\"kind\":\"fill_username\",\"url_host\":\"";
    json += escapedHost;
    json += "\",\"visit\":\"";
    json += escapedVisit;
    json += "\",\"username\":\"";
    json += escapedUser;  // capacity reserved above -> no realloc frees plaintext
    json += "\"}";
    if (!escapedUser.empty())
    {
        SecureZeroMemory(escapedUser.data(), escapedUser.size());
    }

    bool ok = false;
    {
        // Hold the write mutex through the alive check and write, before worker teardown.
        std::lock_guard<std::mutex> writeLock(conn->m_WriteMutex);
        if (conn->m_Alive.load())
        {
            OVERLAPPED ov{};
            HandleGuard ev(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            if (ev.get() != nullptr)
            {
                ov.hEvent = ev.get();
                ok = m_Impl->writeFramedMessage(conn->m_Pipe, json, ov);
            }
        }
    }

    // Wipe in-process copies; bytes delivered to the pipe or browser are outside this buffer.
    if (!json.empty())
    {
        SecureZeroMemory(json.data(), json.size());
    }
    return ok;
}

#ifdef SEAL_BRIDGE_TEST_HOOKS
bool BrowserBridge::testParseMessage(std::string_view payload, BridgeEntry* out)
{
    ParsedBridgeMessage parsed;
    const BridgeParseError err = parseBridgeMessage(payload, &parsed);
    if (err != BridgeParseError::None)
    {
        return false;
    }
    const VerdictMapping mapping = mapTag(parsed.m_Tag);
    if (!mapping.m_ShouldInsert)
    {
        return false;
    }
    if (out != nullptr)
    {
        out->m_Verdict = mapping.m_Verdict;
        out->m_ExpiresAt = std::chrono::steady_clock::now() + kEntryLifetime;
        out->m_UrlHost =
            QString::fromUtf8(parsed.m_UrlHost.data(), static_cast<int>(parsed.m_UrlHost.size()));
    }
    return true;
}
#endif

}  // namespace seal

#endif  // USE_QT_UI
