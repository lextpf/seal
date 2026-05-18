#ifdef USE_QT_UI

#include "BrowserBridge.hpp"

#include "BridgeMessage.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"
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
    HANDLE m_Pipe = INVALID_HANDLE_VALUE;
    std::jthread m_AcceptThread;
    std::atomic<bool> m_Running{false};
    std::atomic<bool> m_Disabled{false};
    std::atomic<bool> m_PeerConnected{false};  ///< True between handshake-ok and peer disconnect.
    std::array<unsigned char, 32> m_HmacKey{};
    std::wstring m_PipeName;
    mutable std::shared_mutex m_MapMutex;
    std::unordered_map<BridgeKey, BridgeEntry, BridgeKeyHash> m_Map;
    std::string m_ExpectedSignerIdentity;

    // Internal so enable() can re-call without going through the public
    // start() entrypoint (which would double-log).
    bool startImpl();
    void stopImpl();
    void acceptLoop(std::stop_token stopToken);
    bool verifySignerMatches(const std::wstring& peerPath) const;
    void handleMessage(DWORD browserPid, std::string_view payload);
    void pruneExpiredLocked(const std::chrono::steady_clock::time_point& now);
    bool readFramedMessage(HANDLE pipe,
                           std::vector<char>& outBuf,
                           OVERLAPPED& overlapped,
                           std::stop_token stopToken);
    bool writeFramedMessage(HANDLE pipe, std::string_view payload, OVERLAPPED& overlapped);
};

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

    PipeSecurity security;
    if (!buildPipeSecurity(security))
    {
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed", "reason=acl_build_failed"}));
        return false;
    }

    HANDLE pipe =
        CreateNamedPipeW(m_PipeName.c_str(),
                         PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
                         1,
                         kPipeOutBufferBytes,
                         kPipeInBufferBytes,
                         0,
                         &security.m_Attributes);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        const DWORD err = GetLastError();
        qCWarning(logBridge).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.bridge.start_failed",
                                    "reason=pipe_create_failed",
                                    seal::diag::kv("gle", static_cast<unsigned int>(err))}));
        return false;
    }
    m_Pipe = pipe;
    m_Running.store(true);

    qCInfo(logBridge).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.bridge.start", "result=ok"}));

    m_AcceptThread = std::jthread([this](std::stop_token stopToken) { acceptLoop(stopToken); });
    return true;
}

void BrowserBridge::Impl::stopImpl()
{
    m_Running.store(false);
    m_PeerConnected.store(false);
    if (m_AcceptThread.joinable())
    {
        m_AcceptThread.request_stop();
        // Wake any blocking ConnectNamedPipe / ReadFile via CancelIoEx.
        if (m_Pipe != INVALID_HANDLE_VALUE)
        {
            CancelIoEx(m_Pipe, nullptr);
        }
        m_AcceptThread.join();
    }
    if (m_Pipe != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(m_Pipe);
        CloseHandle(m_Pipe);
        m_Pipe = INVALID_HANDLE_VALUE;
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
                                            std::stop_token stopToken)
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
    { return stopToken.stop_requested() || !m_Running.load() || m_Disabled.load(); };

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

void BrowserBridge::Impl::acceptLoop(std::stop_token stopToken)
{
    HandleGuard event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (event.get() == nullptr)
    {
        return;
    }

    while (!stopToken.stop_requested() && m_Running.load())
    {
        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();
        ResetEvent(overlapped.hEvent);

        const BOOL connected = ConnectNamedPipe(m_Pipe, &overlapped);
        const DWORD err = connected != 0 ? ERROR_SUCCESS : GetLastError();
        if (!connected && err != ERROR_IO_PENDING && err != ERROR_PIPE_CONNECTED)
        {
            // Unrecoverable pipe state; bail.
            break;
        }
        if (err == ERROR_IO_PENDING)
        {
            while (true)
            {
                const DWORD wait = WaitForSingleObject(overlapped.hEvent, 200);
                if (stopToken.stop_requested() || !m_Running.load())
                {
                    CancelIoEx(m_Pipe, &overlapped);
                    return;
                }
                if (wait == WAIT_OBJECT_0)
                {
                    break;
                }
                if (wait != WAIT_TIMEOUT)
                {
                    CancelIoEx(m_Pipe, &overlapped);
                    Sleep(kAcceptBackoffMs);
                    continue;
                }
            }
            DWORD ignored = 0;
            if (!GetOverlappedResult(m_Pipe, &overlapped, &ignored, FALSE))
            {
                DisconnectNamedPipe(m_Pipe);
                continue;
            }
        }

        if (m_Disabled.load())
        {
            DisconnectNamedPipe(m_Pipe);
            continue;
        }

        DWORD peerPid = 0;
        if (!GetNamedPipeClientProcessId(m_Pipe, &peerPid) || peerPid == 0)
        {
            qCWarning(logBridge).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=fill.bridge.reject", "reason=peer_pid_unknown"}));
            DisconnectNamedPipe(m_Pipe);
            continue;
        }
        const std::wstring peerPath = seal::signer::resolveProcessPath(peerPid);
        if (peerPath.empty())
        {
            qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=fill.bridge.reject",
                 "reason=peer_path_unknown",
                 seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid))}));
            DisconnectNamedPipe(m_Pipe);
            continue;
        }
        if (!verifySignerMatches(peerPath))
        {
            qCWarning(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=fill.bridge.reject",
                 "reason=untrusted_peer",
                 seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid))}));
            DisconnectNamedPipe(m_Pipe);
            continue;
        }

        // Walk up the ancestry from peerPid until we find a signed-browser
        // ancestor (not just the immediate parent: Chromium sometimes
        // launches native-messaging hosts via cmd.exe). The map is keyed
        // on the browser PID because BrowserBridgeProbe lookups come from
        // WindowFromPoint(), which returns the browser's PID.
        //
        // This walk also closes the signed-host-puppeting hole: any
        // non-shell, non-browser ancestor terminates the walk with reject.
        constexpr int kMaxAncestorDepth = 6;
        DWORD browserPid = 0;
        std::wstring browserPath;
        std::string parentChain;  // "cmd.exe>chrome.exe", logged on success and failure.
        std::string failSubReason = "browser_ancestor_not_found";
        std::string failedImage;
        {
            DWORD curPid = seal::signer::resolveParentPid(peerPid);
            for (int depth = 0; depth < kMaxAncestorDepth && curPid != 0; ++depth)
            {
                const std::wstring curPath = seal::signer::resolveProcessPath(curPid);
                if (curPath.empty())
                {
                    failSubReason = "path_unresolved";
                    break;
                }
                // Append basename to the chain string.
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

                if (seal::signer::isKnownBrowserImage(curPath))
                {
                    if (!seal::signer::winVerifyTrustOk(curPath))
                    {
                        failSubReason = "winverifytrust_failed";
                        break;
                    }
                    browserPid = curPid;
                    browserPath = curPath;
                    break;
                }
                if (!seal::signer::isShellImage(curPath))
                {
                    failSubReason = "image_not_in_browser_list";
                    break;
                }
                // Shell hop: walk up another level.
                curPid = seal::signer::resolveParentPid(curPid);
            }
            if (browserPid == 0 && failSubReason == "browser_ancestor_not_found" && curPid == 0)
            {
                failSubReason = "parent_pid_unknown_in_chain";
            }
        }

        if (browserPid == 0)
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
            DisconnectNamedPipe(m_Pipe);
            continue;
        }
        // The "parent" for the rest of the loop is the discovered browser
        // ancestor -- that PID owns the user's window click, hence map key.
        const DWORD parentPid = browserPid;

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
            DisconnectNamedPipe(m_Pipe);
            continue;
        }
        const std::string handshake =
            std::string("{\"v\":1,\"hello\":\"seal-bridge\",\"nonce\":\"") +
            hexEncode(connectionNonce.data(), connectionNonce.size()) + std::string("\"}");

        if (!writeFramedMessage(m_Pipe, handshake, overlapped))
        {
            DisconnectNamedPipe(m_Pipe);
            continue;
        }

        std::vector<char> echoBuf;
        if (!readFramedMessage(m_Pipe, echoBuf, overlapped, stopToken))
        {
            DisconnectNamedPipe(m_Pipe);
            continue;
        }
        if (echoBuf.size() != handshake.size() ||
            std::memcmp(echoBuf.data(), handshake.data(), handshake.size()) != 0)
        {
            qCWarning(logBridge).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=fill.bridge.reject", "reason=handshake_mismatch"}));
            DisconnectNamedPipe(m_Pipe);
            continue;
        }

        // Peer authenticated; mark the bridge active so the diagnose
        // dry-run can confirm a host made it past the gates.
        m_PeerConnected.store(true);
        qCInfo(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.accept",
             "result=ok",
             seal::diag::kv("peer_pid", static_cast<unsigned int>(peerPid)),
             seal::diag::kv("browser_pid", static_cast<unsigned int>(parentPid))}));

        std::vector<char> message;
        while (m_Running.load() && !stopToken.stop_requested() && !m_Disabled.load())
        {
            if (!readFramedMessage(m_Pipe, message, overlapped, stopToken))
            {
                break;
            }
            // Key on the browser's PID (host's parent), not the host's PID
            // -- WindowFromPoint on the lookup side returns the browser PID.
            handleMessage(parentPid, std::string_view(message.data(), message.size()));
        }

        m_PeerConnected.store(false);
        qCInfo(logBridge).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.bridge.disconnect",
             seal::diag::kv("browser_pid", static_cast<unsigned int>(parentPid))}));
        DisconnectNamedPipe(m_Pipe);
    }
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
    return m_Impl->m_PeerConnected.load();
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
