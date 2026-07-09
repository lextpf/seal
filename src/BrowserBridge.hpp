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
// Defined in SignerUtils.hpp; forward-declared here so the public API can take
// a browser kind by value without pulling the wintrust-heavy header into every
// translation unit that includes BrowserBridge.hpp. Callers that pass a kind
// (e.g. FillController.cpp) include SignerUtils.hpp for the complete type.
enum class BrowserKind;
}  // namespace signer

/**
 * @brief A single bridge entry recorded from the WebExtension's mousedown report.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Stored in the in-memory bridge map keyed by quantised (browser-pid, x, y).
 * Entries auto-expire after the cache window (currently 30 s, see
 * BrowserBridge.cpp's kEntryLifetime) so a stale click that never produced
 * a Ctrl+Click follow-up doesn't accumulate.
 *
 * @note The hostname is the only privacy-sensitive piece on the wire. It
 *       lives in this struct so the FillController can compare it against
 *       the record's platform label for the URL-binding gate, but it is
 *       NEVER written to logs in plaintext (the bridge probe redacts it
 *       to a short SHA-256 fingerprint at log time).
 */
struct BridgeEntry
{
    Verdict m_Verdict = Verdict::Unknown;               ///< Mapped from BridgeTag at insert time.
    std::chrono::steady_clock::time_point m_ExpiresAt;  ///< Steady-clock prune deadline.
    QString m_UrlHost;    ///< Validated host name (no full URL ever crosses the pipe).
    std::string m_Visit;  ///< Per-document token from the click report; empty on an older
                          ///< extension. The fill gate requires it to match the current document.
};

/**
 * @brief The most-recent navigation report from the WebExtension.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Unlike @ref BridgeEntry (a positional click record), a nav report is
 * page-level: the host the user just navigated to, plus the `secure`/`form`
 * flags. It never enters the click verdict map. The bridge keeps only the
 * latest snapshot per process; StagingController polls it on the GUI thread
 * via @ref BrowserBridge::takeNavSince and decides whether to auto-arm.
 *
 * @note @ref m_Host is the plain, non-secret hostname (no full URL, no
 *       secret ever travels this channel). It is deliberately a plain
 *       std::string so the Qt-free @ref resolveStageRecord can consume it.
 */
struct NavSnapshot
{
    std::string m_Host;                          ///< Navigated hostname (e.g. "www.paypal.com").
    bool m_Secure = false;                       ///< Page is an https/secure context.
    bool m_HasPasswordForm = false;              ///< A visible <input type=password> exists.
    bool m_HasUsernameField = false;             ///< A visible login identifier field exists.
    std::string m_Visit;                         ///< Per-document page-load token (empty on a
                                                 ///< stale extension -> staging fails closed).
    DWORD m_BrowserPid = 0;                      ///< WinVerifyTrust-validated browser PID.
    std::uint64_t m_Seq = 0;                     ///< Monotonic sequence; consume-once per new seq.
    std::chrono::steady_clock::time_point m_At;  ///< When the report was recorded (freshness TTL).
};

/**
 * @brief Bounded named-pipe server that receives extension mousedown reports.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Runs an accept loop on a dedicated jthread that listens on a per-process
 * named pipe `\\.\pipe\seal-fill-<hex>` where `<hex>` is the SHA-256 of a
 * per-start HMAC key (M7: a stale token from a previous run can never
 * reconnect because the pipe name itself changes on every start). Each
 * accepted peer goes through a multi-gate handshake before any payload
 * is parsed; once handshake completes, framed JSON messages are decoded
 * and inserted into the in-memory verdict map that
 * BrowserBridgeProbe::lookup() consults at fill time.
 *
 * @par Inbound report flow
 * @verbatim
 * content.js         classify clicked field; emit {v,x,y,tag,url_host,url_path}
 *    | chrome.runtime.sendMessage
 *    v
 * background.js      own-id check; SHA-256(url_path)->url_path_hash (raw path dropped)
 *    | connectNative("com.seal.fill")
 *    v
 * seal-browser.exe   dumb stdio<->pipe relay (no parsing)
 *    | named pipe  \\.\pipe\seal-fill-<hex>   hex = SHA-256(per-start key)  [M7]
 *    | frame = uint32 length (native LE) + JSON, <= 4096 bytes
 *    v
 * BrowserBridge      per-conn gates: signer [M6] -> browser parent -> nonce echo,
 *                    then parseBridgeMessage -> verdict map keyed by (browserPid,qx,qy)
 * @endverbatim
 *
 * ## :material-shield-lock: Hardening Mitigations
 *
 * The bridge is the highest-risk attack surface in seal: same-user
 * malware that can connect to the pipe can poison the verdict map and
 * potentially bypass the URL-binding gate. The accept loop applies the
 * following checks in order; failure at any gate disconnects the peer
 * before a single byte of its JSON is read.
 *
 * - **Pipe DACL** - only the current user SID gets read/write + sync on
 *   the pipe (Authenticated Users and Administrators are explicitly NOT
 *   granted). Cross-user attacks are blocked at the OS layer.
 * - **M6: Signer identity match** - the peer binary path resolves via
 *   `GetNamedPipeClientProcessId`, then `WinVerifyTrust` with whole-
 *   chain revocation against the OS cache, and finally its SPKI
 *   thumbprint must equal seal.exe's. SPKI (not CN, not serial) binds
 *   to the publisher's public key, so cert renewals with the same key
 *   still match but a key-rotation reissue after a compromise does not.
 * - **Fresh nonce per accept** - after the peer is identity-
 *   matched, the bridge sends a per-connection random nonce and
 *   requires it back verbatim. This is a framing/replay sanity check,
 *   not authentication (that is the signer + parent-process gate); it
 *   carries no M-number. The persistent HMAC key (used only in the
 *   pipe name, M7) is never transmitted.
 * - **Parent process must be a known signed browser** - the host's
 *   parent (via `CreateToolhelp32Snapshot`, walking through cmd.exe /
 *   powershell.exe hops) must (a) match a known browser image name and
 *   (b) pass `WinVerifyTrust`. Closes the "puppet a signed host" hole:
 *   same-user malware launching seal-browser.exe with attacker-
 *   controlled stdin still fails because its parent isn't a browser.
 * - **M5: Bridge-alone short-circuit prohibition** - enforced in
 *   `FusionDecider`, not here. A Tier-1 hit from the bridge probe
 *   alone cannot decide a fill; another Tier-1 probe must agree.
 * - **Browser-PID-keyed map** - entries are indexed by the resolved
 *   parent (browser) PID, not the host's own PID. There is no in-band
 *   `browser_pid` claim from the peer; the wire schema omits the
 *   field entirely so a lying peer cannot poison the map with a wrong
 *   key.
 * - **Bounded JSON parser** - hand-rolled recursive-descent, rejects
 *   messages > 4 KB, nesting depth > 4, unknown / duplicate keys, or
 *   any value outside the kind-selected schema. Never allocates a
 *   `seal::secure_string` / DPAPIGuard (a test-only counter asserts
 *   zero such allocations across the fuzz corpus).
 * - **M8: Panic-mode disable** - `disable()` drops the map, closes
 *   the pipe, and refuses further inserts/lookups until `enable()` is
 *   called. The chip's right-click toggle wires to this.
 *
 * @par Mitigation index (M2-M9)
 * | Tag | Mitigation | Where |
 * |-----|------------|-------|
 * | M2 | Report only via chrome.runtime.sendMessage (no page postMessage) | content.js |
 * | M3 | Trusted events only (e.isTrusted) | content.js |
 * | M4 | Top frame only | content.js |
 * | M5 | Bridge not solely decisive; needs a 2nd on-disk Tier-1 probe | FusionDecider |
 * | M6 | Peer signer identity match (WinVerifyTrust + SPKI) | BrowserBridge |
 * | M7 | Per-run pipe-name rotation (SHA-256 of per-start key) | BrowserBridge |
 * | M8 | Panic-mode disable (drop map, close pipe) | BrowserBridge |
 * | M9 | Only user-visible click targets reported | content.js |
 *
 * ## :material-state-machine: Lifecycle
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * stateDiagram-v2
 *     [*] --> Stopped
 *     Stopped --> Running : start()
 *     Running --> AcceptingPeer : peer connects
 *     AcceptingPeer --> Running : handshake fails / peer disconnects
 *     AcceptingPeer --> ServingPeer : handshake ok
 *     ServingPeer --> Running : peer disconnects
 *     Running --> Stopped : stop() / disable()
 *     ServingPeer --> Stopped : disable()
 * ```
 *
 * The class is non-copyable and non-movable; FillController owns one
 * instance for its lifetime.
 *
 * @note `enable()` after a previous `disable()` regenerates the HMAC
 *       key and the per-connection nonce state, so any token leaked
 *       from a previous run is invalidated.
 */
class BrowserBridge
{
public:
    /// @brief Construct an idle (un-started) bridge. Call start() to listen.
    BrowserBridge();

    /// @brief Destructor. Stops the accept thread and closes the pipe.
    ~BrowserBridge();

    BrowserBridge(const BrowserBridge&) = delete;
    BrowserBridge& operator=(const BrowserBridge&) = delete;
    BrowserBridge(BrowserBridge&&) = delete;
    BrowserBridge& operator=(BrowserBridge&&) = delete;

    /**
     * @brief Start the pipe server and accept thread.
     *
     * Generates a fresh 32-byte HMAC key via @c BCryptGenRandom, derives
     * the pipe-name suffix from its SHA-256 hash, creates the named pipe
     * with the per-user DACL, and spawns the accept jthread. Idempotent
     * (no-op if already running).
     *
     * @return true on success, false if the pipe could not be created or the
     *         HMAC key generation failed. Callers should treat failure as a
     *         non-fatal warning - field detection still works without the
     *         bridge via the other probes.
     *
     * @note Returns false without starting while the bridge is panic-disabled
     *       (see @ref disable); call @ref enable to resume first.
     */
    bool start();

    /**
     * @brief Stop the accept thread and close the pipe. Safe if already stopped.
     *
     * Signals the jthread's stop token, cancels any pending overlapped I/O
     * on the pipe via `CancelIoEx`, joins the thread, and closes the
     * handle. The map is NOT cleared - use @ref disable() for that.
     */
    void stop();

    /// @brief Whether the accept thread is currently running.
    bool isRunning() const noexcept;

    /**
     * @brief Whether peer signer authentication is active (this binary is signed).
     *
     * When false, the binary is unsigned, so the M6 signer-identity gate accepts
     * any peer (dev-mode degradation, see @ref BrowserBridge.cpp verifySignerMatches).
     * The UI surfaces this as a warning so a user running an unsigned build knows
     * peer authentication is off. A release build compiled with
     * @c SEAL_REQUIRE_SIGNED_PEER refuses to start the bridge in this state
     * instead of degrading.
     *
     * @return true iff this binary carries an Authenticode signer identity.
     */
    bool isPeerAuthEnforced() const noexcept;

    /**
     * @brief Panic-mode disable: drop the map and refuse further activity.
     *
     * Lookups return @c std::nullopt immediately; incoming messages are
     * silently discarded; the pipe handle is closed. The bridge will not
     * accept new connections again until @ref enable is called.
     *
     * Wired to the chip's right-click M8 toggle in BridgeSettings.qml.
     */
    void disable();

    /**
     * @brief Re-enable after disable(). No-op if not currently disabled.
     *
     * Restarts the accept thread on a fresh HMAC key, so any previously-
     * issued nonce or hash-of-key suffix is invalidated. Use to recover
     * from a panic-mode disable.
     *
     * @note Equivalent to "start fresh" from the peer's perspective: the
     *       extension will see a port-closed event and reconnect on the
     *       new pipe name once its reconnect timer fires.
     */
    void enable();

    /// @brief Whether the bridge is in panic-mode disable state.
    bool isDisabled() const noexcept;

    /**
     * @brief Look up a recent extension report for the click site.
     *
     * Iterates the bounded in-memory map and returns the freshest entry
     * whose key (browser PID + quantised x/y) is within Chebyshev
     * distance @c kLookupToleranceRawPx of the query point. Tolerance
     * is sized to cover natural click variance on a typical 40 px input
     * field; precise within-pixel match isn't required.
     *
     * @par Bucket geometry
     * Raw coords are quantised to 4 px buckets (arithmetic shift by 2); a
     * bucket's stored point is its centre, and a query matches within a 48 px
     * Chebyshev radius of that centre:
     * @f[
     *   q(v) = \left\lfloor v / 4 \right\rfloor, \qquad \hat{v} = 4\,q(v) + 2
     * @f]
     * @f[
     *   \text{match} \iff \max\bigl(|\hat{x} - x|,\ |\hat{y} - y|\bigr) \le 48
     * @f]
     *
     * @param browserPid Owner PID of the focused window at click time.
     * @param screenPoint Screen-space click coordinates.
     * @return A populated @ref BridgeEntry when a fresh entry exists within a
     *         small jitter tolerance; @c std::nullopt otherwise.
     */
    std::optional<BridgeEntry> lookup(DWORD browserPid, POINT screenPoint) const noexcept;

    /**
     * @brief Consume the latest navigation snapshot if it is newer than seen.
     *
     * Returns the most-recent @ref NavSnapshot exactly once per navigation:
     * the caller threads a @p lastSeenSeq it owns, and the snapshot is
     * returned only when its sequence exceeds it (then @p lastSeenSeq is
     * advanced). Returns @c std::nullopt when the bridge is panic-disabled
     * (M8), when nothing new has arrived, or when the snapshot has aged past
     * its freshness window. Never blocks meaningfully - a short mutex.
     *
     * Called on the GUI thread by StagingController's poll; the snapshot is
     * written by bridge worker threads under a dedicated mutex.
     *
     * @param lastSeenSeq In/out: the last sequence this caller consumed.
     * @return A fresh, not-yet-seen snapshot, or @c std::nullopt.
     */
    std::optional<NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq) const;

    /**
     * @brief The per-document visit token of the page currently loaded in a
     *        browser process, if known.
     *
     * Returns the visit token from the most recent navigation report for
     * @p browserPid - the identity of the document now on screen. The
     * click-fill gate compares this against the token stored on a cached
     * @ref BridgeEntry: a mismatch means the entry belongs to a different
     * document (a stale focus-click that survived a navigation or tab switch)
     * and must not authorize a fill. Unlike @ref takeNavSince this does NOT
     * consume the snapshot - it can be queried repeatedly.
     *
     * @param browserPid The validated browser PID to query.
     * @return The current document token, or @c std::nullopt when the bridge is
     *         disabled, no navigation has been seen for @p browserPid, or the
     *         last report carried no token (older extension).
     */
    std::optional<std::string> currentVisit(DWORD browserPid) const;

    /**
     * @brief Push a username-injection directive to a connected browser peer.
     *
     * The ONE reverse-channel write (bridge -> extension) besides the
     * handshake. Sends a framed
     * `{"v":1,"kind":"fill_username","url_host","visit","username"}` message
     * to the authenticated peer serving @p browserPid, if one is connected.
     * The caller (FillController) MUST have already JIT-decrypted the username
     * and confirmed a STRICT domain match; this method only routes to the
     * correct, already-signer/parent-gated connection and frames the bytes.
     *
     * Thread-safe: called on the GUI thread while a worker thread reads the
     * same full-duplex pipe. Returns false when the bridge is disabled (M8),
     * no peer is connected for @p browserPid, or the write fails.
     *
     * @param browserPid   The validated browser PID whose peer to send to.
     * @param host         The page host (echoed so the content script can
     *                     re-verify its own location before injecting).
     * @param visit        Per-document visit token echoed so the content
     *                     script can reject same-host different-document routes.
     * @param usernameUtf8 The plaintext username (UTF-8). Copied into the wire
     *                     frame; the caller and this method wipe their copies.
     * @return true iff a framed directive was written to a live peer.
     */
    bool sendFillUsername(DWORD browserPid,
                          const std::string& host,
                          const std::string& visit,
                          const std::string& usernameUtf8);

    /**
     * @brief Whether the pipe currently has an accepted peer (handshake done).
     *
     * False between starts, while the accept loop is waiting for a connection,
     * or after a peer disconnect. Used by the diagnose dry-run to surface a
     * helpful "no host connected" hint when the operator's Ctrl+Click doesn't
     * yield a bridge match, and by the chip indicator to drive the green/red
     * pulse colour.
     *
     * @return true when a peer of any browser is currently connected.
     */
    bool isPeerConnected() const noexcept;

    /**
     * @brief Whether a peer launched by a specific browser is connected.
     *
     * Concurrent connections are supported (one named-pipe instance per host),
     * so distinct browsers can be connected simultaneously. The connecting
     * browser is the @c WinVerifyTrust-validated ancestor resolved during the
     * accept handshake (never the peer's self-report), so this cannot be
     * spoofed. Used to drive the per-browser status dots in the footer.
     *
     * @param kind The browser to query.
     * @return true when at least one connected peer was launched by @p kind.
     */
    bool isPeerConnected(seal::signer::BrowserKind kind) const noexcept;

    /**
     * @brief Current size of the in-memory verdict map.
     *
     * Diagnostic only - the contents are not exposed via this API; only the
     * count of live entries. Used by the diagnose dry-run so the operator can
     * tell "peer connected but map empty" from "no peer at all".
     *
     * @return number of live (unexpired) entries currently in the map.
     */
    std::size_t mapEntryCount() const noexcept;

#ifdef SEAL_BRIDGE_TEST_HOOKS
    /**
     * @brief Test-only hook: parse a single message in isolation.
     *
     * Used by tests/test_bridge_fuzz.cpp to feed malformed input without
     * standing up a real pipe. Not compiled in release builds.
     *
     * @param payload Raw JSON payload as it would arrive on the pipe.
     * @param out Optional output; populated on success.
     * @return true iff the payload parsed cleanly and the tag mapped to a
     *         verdict the bridge would actually insert into the map.
     */
    bool testParseMessage(std::string_view payload, BridgeEntry* out);
#endif

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
