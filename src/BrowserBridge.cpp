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

constexpr DWORD kPipeInBufferBytes = 8192;
constexpr DWORD kPipeOutBufferBytes = 8192;
constexpr DWORD kAcceptBackoffMs = 50;
constexpr DWORD kMessageReadTimeoutMs = 5000;
constexpr DWORD kMaxMessageBytes = 4096;
// Bridge-entry TTL. Matches FillController::FILL_TIMEOUT_SECONDS so the
// bridge cache and the armed window share one "30 s from the prior
// mousedown" model -- enough for click-to-focus then alt-tab to seal
// then Ctrl+Click. The earlier 2 s was too tight for human-paced
// autofill and produced silent "browser_extension=unknown" misses.
constexpr auto kEntryLifetime = std::chrono::seconds(30);

// Quantises a raw screen coordinate to the map's bucket resolution.
constexpr int kQuantShift = 2;

// Cap on simultaneously-served connections. Each accepted peer already clears
// the signer + parent-browser gates, but bound the worker count so a local
// actor that survives the gates cannot exhaust threads/handles by spamming
// connections. Two or three browsers connected at once is the realistic max.
constexpr std::size_t kMaxConnectionWorkers = 8;

// Internal map key: (pid, quantised x, quantised y). Click positions within
// the same bucket at the same PID collide on the same entry.
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
        // Xor-shift mix; map is tiny (~10 entries), quality only matters
        // for resilience against accidental collisions.
        h ^= h >> 33;
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 33;
        return static_cast<std::size_t>(h);
    }
};

// RAII guard for a HANDLE; CloseHandle covers every kernel object used here
// (process handle, pipe, event).
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

// One in-flight connection handed from the acceptor thread to a worker thread.
// The acceptor owns the pipe handle (for cleanup); the worker sets m_Done when
// it returns so the acceptor can join it and close the handle.
struct ConnectionWorker
{
    std::jthread m_Thread;
    HANDLE m_Pipe = INVALID_HANDLE_VALUE;
    std::shared_ptr<std::atomic<bool>> m_Done;
};

// Build SECURITY_ATTRIBUTES that grant the current user SID rwx + sync,
// no Authenticated-Users / Administrators ACE. CreateNamedPipe consumes
// the contents, but storage must outlive the call -- hence the carrier.
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

    // ACL with one ACE: our SID + GENERIC_READ|WRITE|SYNCHRONIZE.
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

// Lowercase hex (matches the WebExtension manifest alphabet).
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

// BCrypt RNG wrapper -- system-preferred algorithm is an unbiased CSPRNG
// without us enumerating providers.
bool generateRandom(unsigned char* out, std::size_t bytes)
{
    return BCRYPT_SUCCESS(
        BCryptGenRandom(nullptr, out, static_cast<ULONG>(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// One-shot SHA-256. Caller provides a >=32-byte output buffer.
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

// Map BridgeTag -> Verdict + whether to insert. "text"/"other" never
// insert so the map can't fill with neutral signals (probe returns
// "no_recent_entry" for those sites).
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
    HANDLE m_ListenPipe = INVALID_HANDLE_VALUE;  ///< First instance pre-created by startImpl().
    std::jthread m_AcceptThread;
    std::atomic<bool> m_Running{false};
    std::atomic<bool> m_Disabled{false};
    // Per-browser connected counts (ref-counted: N concurrent hosts of one
    // browser). Indexed by static_cast<size_t>(BrowserKind); a browser counts
    // as connected while its entry is > 0. Replaces the old single-bool flag so
    // distinct browsers can be reported connected at the same time.
    std::array<std::atomic<int>, static_cast<std::size_t>(seal::signer::BrowserKind::Count)>
        m_PeerCounts{};
    std::array<unsigned char, 32> m_HmacKey{};
    std::wstring m_PipeName;
    PipeSecurity m_PipeSecurity;  ///< Per-user DACL, built once, applied to every pipe instance.
    mutable std::shared_mutex m_MapMutex;
    std::unordered_map<BridgeKey, BridgeEntry, BridgeKeyHash> m_Map;
    std::unordered_map<DWORD, int> m_BrowserConnCounts;  // guarded by m_MapMutex
    std::string m_ExpectedSignerIdentity;

    // Internal so enable() can re-call without going through the public
    // start() entrypoint (which would double-log).
    bool startImpl();
    void stopImpl();
    HANDLE createPipeInstance(bool firstInstance);
    void acceptorLoop(std::stop_token stopToken);
    void serveConnection(HANDLE pipe, std::stop_token stopToken);
    bool verifySignerMatches(const std::wstring& peerPath) const;
    void handleMessage(DWORD browserPid, std::string_view payload);
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
        // The very first instance must be the one *we* create, so a same-user
        // process cannot pre-own the (secret) pipe name and accept our hosts.
        // Subsequent instances must omit this flag or CreateNamedPipe fails
        // with ERROR_ACCESS_DENIED.
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

    // M7: pipe name embeds the hashed-key suffix so a stale token from a
    // previous run cannot connect. Hash is one-way; the secret token never
    // leaves process memory until the handshake.
    std::wstring name;
    name.reserve(32 + hashHex.size());
    name.assign(L"\\\\.\\pipe\\seal-fill-");
    for (const char c : hashHex)
    {
        name.push_back(static_cast<wchar_t>(c));
    }
    m_PipeName = name;

    // Built once and reused for every instance the acceptor creates.
    if (!buildPipeSecurity(m_PipeSecurity))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed", "reason=acl_build_failed"}));
        return false;
    }

    // Pre-create the first instance so (a) creation failures surface
    // synchronously to the caller and (b) a listening instance exists before we
    // return -- otherwise the extension's first connectNative would miss and
    // back off for seconds before retrying.
    HANDLE first = createPipeInstance(true);
    if (first == INVALID_HANDLE_VALUE)
    {
        const DWORD err = GetLastError();
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed",
                                    "reason=pipe_create_failed",
                                    seal::diag::kv("gle", static_cast<unsigned int>(err))}));
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
        // The acceptor polls its stop token every 200 ms while waiting for a
        // connection, then cancels + joins every live worker and closes all
        // pipe handles before returning -- so this join is the single sync
        // point for full teardown.
        m_AcceptThread.request_stop();
        m_AcceptThread.join();
    }
    // Any first instance pre-created by startImpl() but never consumed (e.g. the
    // acceptor never started). After a normal run the acceptor clears this.
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
    // M6 dev-mode degradation: if seal itself is unsigned (empty identity),
    // allow all peers so local builds remain usable. Prod must be signed.
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
    // Single-pass prune; map size ~one entry per visible input.
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
        // Erase every map entry for this browserPid. Manual loop mirrors
        // pruneExpiredLocked's iteration style (no dependence on std::erase_if).
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
    }
}

void BrowserBridge::Impl::handleMessage(DWORD browserPid, std::string_view payload)
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

    const VerdictMapping mapping = mapTag(parsed.m_Tag);
    if (!mapping.m_ShouldInsert)
    {
        // No useful signal; nothing to record.
        return;
    }

    const auto now = std::chrono::steady_clock::now();
    BridgeEntry entry;
    entry.m_Verdict = mapping.m_Verdict;
    entry.m_ExpiresAt = now + kEntryLifetime;
    entry.m_UrlHost =
        QString::fromUtf8(parsed.m_UrlHost.data(), static_cast<int>(parsed.m_UrlHost.size()));

    BridgeKey key;
    key.m_BrowserPid = browserPid;
    key.m_QuantX = quantise(parsed.m_X);
    key.m_QuantY = quantise(parsed.m_Y);

    {
        std::unique_lock<std::shared_mutex> lock(m_MapMutex);
        pruneExpiredLocked(now);
        m_Map.insert_or_assign(key, std::move(entry));
    }

    // One info line per accepted report. Verdict + raw/quantised coords
    // are safe to log; URL host stays off this line (privacy).
    //
    // Cast the verdict literal through string_view so kv() picks the
    // string overload -- a bare const char* matches the bool overload via
    // standard-conversion rank and would print "verdict=true".
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

bool BrowserBridge::Impl::readFramedMessage(HANDLE pipe,
                                            std::vector<char>& outBuf,
                                            OVERLAPPED& overlapped,
                                            std::stop_token stopToken,
                                            const seal::signer::PinnedProcess& peer,
                                            const seal::signer::PinnedProcess& browser)
{
    // Two phases:
    //   1. Length prefix: idle is legit (no clicks for hours). Wait
    //      indefinitely, polling stop/running/disabled every kStopPollMs.
    //      Broken pipes still surface via WaitForSingleObject /
    //      GetOverlappedResult, so real disconnects tear the loop down.
    //   2. Payload: once committed to a length, bytes must arrive promptly.
    //      kMessageReadTimeoutMs caps a peer that prefix-then-stalls.
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
    while (true)
    {
        const DWORD wait = WaitForSingleObject(overlapped.hEvent, kStopPollMs);
        if (isStopping())
        {
            CancelIoEx(pipe, &overlapped);
            return false;
        }
        if (wait == WAIT_OBJECT_0)
        {
            break;
        }
        if (wait == WAIT_TIMEOUT)
        {
            // Idle is fine; the poll interval keeps shutdown responsive.
            continue;
        }
        // WAIT_FAILED / WAIT_ABANDONED -- treat as fatal.
        CancelIoEx(pipe, &overlapped);
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
    // Payload phase: stricter timeout. A peer that prefix-then-stalls
    // is suspicious; tear the connection down.
    DWORD elapsedMs = 0;
    while (true)
    {
        const DWORD wait = WaitForSingleObject(overlapped.hEvent, kStopPollMs);
        if (isStopping())
        {
            CancelIoEx(pipe, &overlapped);
            return false;
        }
        if (wait == WAIT_OBJECT_0)
        {
            break;
        }
        if (wait == WAIT_TIMEOUT)
        {
            elapsedMs += kStopPollMs;
            if (elapsedMs >= kMessageReadTimeoutMs)
            {
                CancelIoEx(pipe, &overlapped);
                return false;
            }
            continue;
        }
        CancelIoEx(pipe, &overlapped);
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
    // The acceptor owns every connection's pipe handle and the worker thread
    // serving it. A worker runs the per-connection gates + handshake + read
    // loop; the acceptor reaps finished workers (closing their handles) and, on
    // stop, cancels + joins all of them. Keeping all worker bookkeeping on this
    // one thread avoids cross-thread races on the worker list.
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

    // Consume the instance pre-created by startImpl(); create fresh ones after.
    HANDLE inst = m_ListenPipe;
    m_ListenPipe = INVALID_HANDLE_VALUE;

    while (!stopToken.stop_requested() && m_Running.load())
    {
        if (inst == INVALID_HANDLE_VALUE)
        {
            inst = createPipeInstance(false);
            if (inst == INVALID_HANDLE_VALUE)
            {
                const DWORD err = GetLastError();
                qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.bridge.start_failed",
                     "reason=pipe_create_failed",
                     seal::diag::kv("gle", static_cast<unsigned int>(err))}));
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
                    // Idle wait for a client; reap finished workers each tick.
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

        // Hand the connected instance to a worker; keep accepting on a fresh
        // instance next iteration so a second browser isn't blocked.
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

    // Shutdown: cancel + join every worker, then close its handle.
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
    // Runs on a per-connection worker thread, so it owns its own event +
    // OVERLAPPED. It does NOT close `pipe` -- the acceptor does that after
    // joining this thread. All the accept-time gates that used to live inline
    // in the single accept loop run here, unchanged, per connection.
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

    // The pin closes the recycling window only for events AFTER OpenProcess
    // returned. Re-read the pipe's client PID and require it still equals the
    // pinned PID, rejecting a recycle in the GetNamedPipeClientProcessId ->
    // OpenProcess gap.
    DWORD peerPidCheck = 0;
    if (!GetNamedPipeClientProcessId(pipe, &peerPidCheck) || peerPidCheck != peer.pid())
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.reject",
             "reason=peer_pid_changed",
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid))}));
        return;
    }

    // peerPath comes from the pinned handle; WinVerifyTrust still reads the file
    // from disk (file-level Authenticode TOCTOU is a documented residual).
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

    // Walk up the ancestry from peerPid until we find a signed-browser ancestor.
    // Each hop is pinned; a parent created strictly after its child indicates a
    // recycled (stale) parent-PID link and is rejected fail-closed.
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

        // Append basename to the chain BEFORE the per-hop reject checks, so a
        // hop rejected for stale_parent_link / creation_time_unavailable still
        // appears in parent_chain / failed_image (original always-append order).
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

        // G2 narrowing, FAIL-CLOSED. Strict '>' lets a parent+child sharing one
        // FILETIME tick pass; a missing creation time rejects rather than skips.
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
            browser = std::move(cur);
            browserPath = curPath;
            break;
        }
        if (!seal::signer::isShellImage(curPath))
        {
            failSubReason = "image_not_in_browser_list";
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
    // The "parent" for the rest of the connection is the discovered browser
    // ancestor -- that PID owns the user's window click, hence map key.
    const DWORD parentPid = browser.pid();

    // Per-connection nonce -- NOT the HMAC key (that one only derives
    // the pipe-name suffix and never leaves the process). Fresh per
    // accept so a captured handshake cannot be replayed. The echo is
    // a framing sanity check; authentication is the signer-identity
    // match plus the parent-process gate above.
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

    // Peer authenticated. Attribute it to a specific browser (from the
    // WinVerifyTrust-validated ancestor image, never a self-report) and mark
    // that browser connected so its footer dot lights.
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

    std::vector<char> message;
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
        // Key on the browser's PID (host's parent), not the host's PID
        // -- WindowFromPoint on the lookup side returns the browser PID.
        handleMessage(parentPid, std::string_view(message.data(), message.size()));
    }

    // A liveness trip emits the specific token; otherwise the existing
    // disconnect info line. Teardown latency on browser exit is <= 1 s.
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

void BrowserBridge::disable()
{
    m_Impl->m_Disabled.store(true);
    m_Impl->stopImpl();
    {
        std::unique_lock<std::shared_mutex> lock(m_Impl->m_MapMutex);
        m_Impl->m_Map.clear();
        // Symmetry with m_Map: workers already drained their own counts on join
        // above, so this is a no-op today, but it future-proofs the panic path
        // against any change to the join-before-clear ordering.
        m_Impl->m_BrowserConnCounts.clear();
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

    // Lookup tolerance in raw screen px (Chebyshev distance). The earlier
    // 5-key cross-probe at quant-shift 2 gave only ~+-6 px on cardinal
    // axes and 0 on diagonals, producing silent
    // "browser_extension=unknown" misses when the focus-click and the
    // Ctrl+Click landed on different parts of the same input. 48 px
    // covers natural variance on a typical 40 px tall input. Nearby fields
    // can collide on lookup, but we pick the FRESHEST entry and (M5) the
    // FusionDecider requires a second probe to agree.
    constexpr int kLookupToleranceRawPx = 48;
    constexpr int kBucketCenterOffset = 1 << (kQuantShift - 1);

    // Direct iteration; map is bounded to ~one entry per recently-clicked
    // input and lookup runs once per Ctrl+Click, not in a hot loop.
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
