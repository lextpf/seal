#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <QtCore/QString>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace seal
{

namespace signer
{
// defined in SignerUtils.hpp. forward-declared so the public API can take a
// browser kind by value without pulling the wintrust-heavy header into every
// translation unit that includes this one. A caller that passes a kind includes
// SignerUtils.hpp for the complete type.
enum class BrowserKind;
}  // namespace signer

/**
 * @struct BridgeEntry
 * @brief Click verdict keyed by browser PID and quantized screen point.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Expires after 30 s. Lookup skips expired entries; insertion and final browser
 * disconnect prune them. Hosts support URL binding and must not be logged raw.
 */
struct BridgeEntry
{
    Verdict m_Verdict = Verdict::Unknown;               ///< Mapped from BridgeTag at insert time.
    std::chrono::steady_clock::time_point m_ExpiresAt;  ///< Steady-clock prune deadline.
    QString m_UrlHost;    ///< Host token with optional port; no full URL crosses the pipe.
    std::string m_Visit;  ///< Document token; empty when absent.
};

/**
 * @struct NavSnapshot
 * @brief Latest page report in one slot shared by all browsers.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * A new report can overwrite an unconsumed report from another browser.
 * Contains a hostname, never a full URL or credential.
 * Consumers must check m_Secure themselves; insecure navigation reports are stored.
 */
struct NavSnapshot
{
    std::string m_Host;                          ///< Navigated hostname (e.g. "www.paypal.com").
    bool m_Secure = false;                       ///< Page is an https/secure context.
    bool m_HasPasswordForm = false;              ///< A visible <input type=password> exists.
    bool m_HasUsernameField = false;             ///< A visible login identifier field exists.
    std::string m_Visit;                         ///< Document token; empty when absent.
    DWORD m_BrowserPid = 0;                      ///< WinVerifyTrust-validated browser PID.
    std::uint64_t m_Seq = 0;                     ///< Monotonic sequence; consume-once per new seq.
    std::chrono::steady_clock::time_point m_At;  ///< When the report was recorded (freshness TTL).
};

/**
 * @class BrowserBridge
 * @brief Receive browser reports over a bounded named pipe.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * FillController owns the bridge. Serialize lifecycle calls on the owner thread.
 * One accept jthread serves at most 8 concurrent workers; excess connections are dropped.
 * Workers apply all connection gates
 * before reading report JSON.
 *
 * The pipe DACL grants only the current user SID. The peer PID is pinned once and
 * read again from the pipe to reject reuse during open. With a trusted application
 * signer, peer checks require cached whole-chain trust and matching SPKI identity.
 *
 * The ancestor walk checks at most 6 hops through trusted shells to a vendor-signed browser.
 * A parent created after its child is rejected. Map keys use that browser PID,
 * never a client claim. The nonce echo checks framing and replay, not identity;
 * the per-start pipe-name key is never sent.
 *
 * The flat parser caps payloads at 4096 bytes and rejects nested values, unknown
 * or duplicate keys, and invalid fields. It uses no secure-string or DPAPI state.
 * M5 corroboration is enforced by FusionDecider. Disable clears reports and stops
 * connections; re-enable rotates the pipe name. Listening continues while workers
 * gate or serve connections.
 *
 * @verbatim
 * content.js         Classify clicked field; emit
 *                    {v,x,y,tag,url_host,secure,visit,url_path}
 *    | chrome.runtime.sendMessage
 *    v
 * background.js      Own-id check; SHA-256(url_path)->url_path_hash (raw path dropped)
 *    | connectNative("com.seal.fill")
 *    v
 * seal-browser.exe   Authenticate launch and server; relay opaque frames
 *    | named pipe  \\.\pipe\seal-fill-<hex>   hex = SHA-256(per-start key)  [M7]
 *    | frame = uint32 length (native LE) + JSON, <= 4096 bytes
 *    v
 * BrowserBridge      Connection gates: pin peer -> signer [M6] -> browser ancestor -> nonce echo,
 *                    Parse with parseBridgeMessage, then split by kind:
 *                      |- click -> verdict map keyed by (browserPid,qx,qy)  [BrowserBridgeProbe]
 *                      '- nav   -> single NavSnapshot slot + per-PID visit token
 *                                  [takeNavSince -> StagingController]
 * @endverbatim
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * stateDiagram-v2
 *     [*] --> Stopped
 *     Stopped --> Listening : start() / enable()
 *     Listening --> Gating : Peer connects (worker; listener stays active)
 *     Listening --> Listening : Worker cap reached, drop connection
 *     Gating --> Listening : A gate fails
 *     Gating --> Serving : Signer + browser ancestor + nonce echo pass
 *     Serving --> Listening : Peer disconnects
 *     Listening --> Stopped : stop() / disable()
 *     Serving --> Stopped : stop() / disable()
 * ```
 *
 * | Tag | Mitigation                                                       | Where         |
 * |-----|------------------------------------------------------------------|---------------|
 * | M2  | report only via chrome.runtime.sendMessage (no page postMessage) | content.js    |
 * | M3  | trusted events only (e.isTrusted)                                | content.js    |
 * | M4  | top frame only                                                   | content.js    |
 * | M5  | bridge not solely decisive; needs a 2nd on-disk tier-1 probe     | FusionDecider |
 * | M6  | peer signer identity match (WinVerifyTrust + SPKI)               | BrowserBridge |
 * | M7  | per-run pipe-name rotation (SHA-256 of per-start key)            | BrowserBridge |
 * | M8  | panic-mode disable (drop map, close pipe)                        | BrowserBridge |
 * | M9  | only user-visible click targets reported                         | content.js    |
 */
class BrowserBridge
{
public:
    /**
     * @fn BrowserBridge()
     * @brief Construct an idle (un-started) bridge.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Call start() to listen.
     */
    BrowserBridge();

    /**
     * @fn ~BrowserBridge()
     * @brief Stop and join all bridge threads before releasing pipe resources.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~BrowserBridge();

    BrowserBridge(const BrowserBridge&) = delete;
    BrowserBridge& operator=(const BrowserBridge&) = delete;
    BrowserBridge(BrowserBridge&&) = delete;
    BrowserBridge& operator=(BrowserBridge&&) = delete;

    /**
     * @fn bool start()
     * @brief Create the pipe and start accepting peers.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Generates a 32-byte key and SHA-256 pipe suffix, builds the per-user DACL, and
     * creates the first pipe before starting the accept thread. No-op if running.
     *
     * @return `false` when disabled, startup resources fail, or SEAL_REQUIRE_SIGNED_PEER
     *         is set and this executable has no trusted signer identity.
     * @see enable
     */
    bool start();

    /**
     * @fn void stop()
     * @brief Stop and join the accept thread and all workers.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Safe when stopped. The acceptor polls every 200 ms; parked worker reads observe
     * stop within about 1 s. Pending I/O is cancelled before pipes close.
     *
     * Connection counts reset. Final-disconnect bookkeeping removes each browser's
     * click entries and visit token. The pending navigation snapshot and monotonic
     * sequence survive; only disable clears the snapshot.
     */
    void stop();

    /**
     * @fn bool isRunning() const noexcept
     * @brief Whether the accept thread is currently running.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isRunning() const noexcept;

    /**
     * @fn bool isPeerAuthEnforced() const noexcept
     * @brief Report whether the startup signer identity enables peer authentication.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Empty identity means unsigned, untrusted, or revoked. Development builds then
     * accept any peer signer; SEAL_REQUIRE_SIGNED_PEER prevents bridge startup.
     */
    bool isPeerAuthEnforced() const noexcept;

    /**
     * @fn void disable()
     * @brief Stop connections, clear reports, and reject further activity.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Blocks while stop joins all threads. Calls to lookup, takeNavSince, and currentVisit
     * return nullopt; sendFillUsername returns false until enable.
     */
    void disable();

    /**
     * @fn void enable()
     * @brief Restart a disabled bridge with a fresh pipe-name key.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op unless disabled. Startup failure leaves it enabled but not running;
     * query isRunning to detect that state.
     */
    void enable();

    /**
     * @fn bool isDisabled() const noexcept
     * @brief Whether the bridge is in panic-mode disable state.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isDisabled() const noexcept;

    /**
     * @fn std::optional<BridgeEntry> lookup(DWORD browserPid, POINT screenPoint) const noexcept
     * @brief Copy the freshest unexpired entry within the click tolerance.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Quantizes to 4 px buckets, including negative coordinates, and compares the
     * bucket center with a 48 px Chebyshev radius:
     *
     * $$
     * q(v) = \left\lfloor v / 4 \right\rfloor, \qquad \hat{v} = 4\,q(v) + 2
     * $$
     * $$
     * \text{match} \iff \max\bigl(|\hat{x} - x|,\ |\hat{y} - y|\bigr) \le 48
     * $$
     *
     * Takes a shared lock; safe from any thread. Does not prune.
     *
     * @param browserPid Validated browser process ID, not the relay process ID.
     * @param screenPoint Raw screen pixels.
     * @return `nullopt` if disabled or no matching unexpired entry exists.
     */
    std::optional<BridgeEntry> lookup(DWORD browserPid, POINT screenPoint) const noexcept;

    /**
     * @fn std::optional<NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq) const
     * @brief Return a newer navigation snapshot once per caller cursor.
     * @author Alex (<https://github.com/lextpf>)
     *
     * One slot serves all browsers, so reports can be overwritten before consumption.
     * Insecure reports remain visible; auto-arm consumers must check m_Secure.
     *
     * @param lastSeenSeq Advances for new reports even if older than the 10 s TTL.
     * @return `nullopt` if disabled, unchanged, or expired.
     */
    std::optional<NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq) const;

    /**
     * @fn std::optional<std::string> currentVisit(DWORD browserPid) const
     * @brief Copy the latest document token for a validated browser PID.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Does not consume navigation and has no TTL. Final browser disconnect removes it.
     *
     * @return `nullopt` if disabled, no report exists, or the latest report omitted a token.
     */
    std::optional<std::string> currentVisit(DWORD browserPid) const;

    /**
     * @fn bool sendFillUsername(DWORD browserPid, const std::string& host, const std::string&
     *     visit, const std::string& usernameUtf8)
     * @brief Send a username directive to the validated browser peer.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Routes and frames only; the caller decides release. The write mutex synchronizes
     * with worker disconnect. The completed frame reserves its full size before appending.
     * The escaped username and completed frame are wiped on the normal return path.
     * This does not guarantee wiping temporary allocations made while escaping.
     * A successful pipe write does not confirm that the page accepted the directive.
     *
     * @param browserPid Validated browser process ID used to select the relay.
     * @param host Echoed for content-script location verification.
     * @param visit Non-empty document token, echoed for route verification.
     * @param usernameUtf8 Plaintext UTF-8; the caller must wipe its own copy.
     * @return `false` if disabled, visit is empty, no live peer exists, or writing fails.
     * @pre Caller confirmed a strict domain match and decrypted just in time.
     */
    bool sendFillUsername(DWORD browserPid,
                          const std::string& host,
                          const std::string& visit,
                          const std::string& usernameUtf8);

    /**
     * @fn bool isPeerConnected() const noexcept
     * @brief Report whether any peer completed the handshake and remains connected.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isPeerConnected() const noexcept;

    /**
     * @fn bool isPeerConnected(seal::signer::BrowserKind kind) const noexcept
     * @brief Report whether a connected peer has the validated browser ancestor kind.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Attribution comes from OS ancestry and signature checks, never peer claims.
     *
     * @pre `kind` is a BrowserKind value below Count; Count is not a valid index.
     */
    bool isPeerConnected(seal::signer::BrowserKind kind) const noexcept;

    /**
     * @fn std::size_t mapEntryCount() const noexcept
     * @brief Count entries under a shared lock from any thread.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Includes expired entries until insertion or final browser disconnect prunes them.
     */
    std::size_t mapEntryCount() const noexcept;

#ifdef SEAL_BRIDGE_TEST_HOOKS
    /**
     * @fn bool testParseMessage(std::string_view payload, BridgeEntry* out)
     * @brief Test parsing and tag mapping without a live pipe.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param out Nullable; receives verdict, expiry, and host on success. Visit is untouched.
     * @return `false` for navigation and non-insertable tags.
     * @note Omits live disable and secure-context gates; secure:0 clicks may succeed.
     */
    bool testParseMessage(std::string_view payload, BridgeEntry* out);
#endif

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
