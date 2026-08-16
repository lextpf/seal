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
// Defined in SignerUtils.hpp. Forward-declared so the public API can take a
// browser kind by value without pulling the wintrust-heavy header into every
// translation unit that includes this one. A caller that passes a kind includes
// SignerUtils.hpp for the complete type.
enum class BrowserKind;
}  // namespace signer

/**
 * @struct BridgeEntry
 * @brief One mousedown report from the extension, held against a screen point.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * Lives in the in-memory verdict map, keyed by quantised (browser-pid, x, y).
 * An entry expires 30 s after insertion (kEntryLifetime in BrowserBridge.cpp).
 * Expiry is lazy: @ref BrowserBridge::lookup skips expired entries, and the map
 * is pruned on the next insert and when the browser's last connection drops, so
 * a click that never produced a Ctrl+Click follow-up cannot accumulate.
 *
 * @note The hostname is the only privacy-sensitive field. It lives here so
 *       FillController can compare it against the record's platform label for
 *       the URL-binding gate; it is never logged in plaintext, because the
 *       bridge probe redacts it to a short SHA-256 fingerprint.
 */
struct BridgeEntry
{
    Verdict m_Verdict = Verdict::Unknown;               ///< Mapped from BridgeTag at insert time.
    std::chrono::steady_clock::time_point m_ExpiresAt;  ///< Steady-clock prune deadline.
    QString m_UrlHost;    ///< Validated host name (no full URL ever crosses the pipe).
    std::string m_Visit;  ///< Per-document token from the click report; empty when the
                          ///< report carried none. The manual fill gate blocks only on a
                          ///< positive mismatch with the browser's current document token;
                          ///< the staged auto-release also requires a non-empty token.
};

/**
 * @struct NavSnapshot
 * @brief The most recent navigation report from the extension.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * A nav report is page-level rather than positional: the host the user
 * navigated to, plus the `secure`/`form` flags. It never enters the click
 * verdict map. The bridge keeps a single snapshot slot shared by all browsers,
 * so a nav from a second browser overwrites an unconsumed one from the first.
 * StagingController polls it on the GUI thread through
 * FillController::takeNavSince, which forwards to
 * @ref BrowserBridge::takeNavSince, and decides whether to auto-arm.
 *
 * @note @ref m_Host is a plain hostname; no full URL and no secret travels this
 *       channel. It is a plain std::string so the Qt-free
 *       @ref resolveStageRecord can consume it.
 * @note The bridge does not filter a navigation report on @ref m_Secure. It
 *       drops an insecure click report (`reason=insecure_click`), but it stores
 *       and returns an insecure nav report unchanged. A consumer that auto-arms
 *       must test the flag itself; StagingController does.
 */
struct NavSnapshot
{
    std::string m_Host;                          ///< Navigated hostname (e.g. "www.paypal.com").
    bool m_Secure = false;                       ///< Page is an https/secure context.
    bool m_HasPasswordForm = false;              ///< A visible <input type=password> exists.
    bool m_HasUsernameField = false;             ///< A visible login identifier field exists.
    std::string m_Visit;                         ///< Per-document page-load token; empty when the
                                                 ///< report carried none, and staging then
                                                 ///< fails closed.
    DWORD m_BrowserPid = 0;                      ///< WinVerifyTrust-validated browser PID.
    std::uint64_t m_Seq = 0;                     ///< Monotonic sequence; consume-once per new seq.
    std::chrono::steady_clock::time_point m_At;  ///< When the report was recorded (freshness TTL).
};

/**
 * @class BrowserBridge
 * @brief Bounded named-pipe server that receives extension click and
 *        navigation reports.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * Listens on the per-process pipe `\\.\pipe\seal-fill-<hex>`, where `<hex>` is
 * the SHA-256 of a key generated at each start (M7), so a pipe name learned in
 * a previous run leads nowhere. After the handshake, framed JSON messages are
 * decoded into the in-memory verdict map that @ref BrowserBridgeProbe reads at
 * fill time, or into the latest @ref NavSnapshot that StagingController polls.
 *
 * @par Threading
 * The accept loop owns a jthread. Each accepted connection is handed to its own
 * worker thread, which runs the gates and the handshake before any payload is
 * parsed, while the acceptor keeps listening - so several browsers are served
 * at once. At most 8 workers live at a time; a connection over that cap is
 * dropped. The class is non-copyable and non-movable, and FillController owns
 * one instance for its whole lifetime.
 *
 * @par Inbound report flow
 * @verbatim
 * content.js         classify clicked field; emit
 *                    {v,x,y,tag,url_host,secure,visit,url_path}
 *    | chrome.runtime.sendMessage
 *    v
 * background.js      own-id check; SHA-256(url_path)->url_path_hash (raw path dropped)
 *    | connectNative("com.seal.fill")
 *    v
 * seal-browser.exe   dumb stdio<->pipe relay (no parsing)
 *    | named pipe  \\.\pipe\seal-fill-<hex>   hex = SHA-256(per-start key)  [M7]
 *    | frame = uint32 length (native LE) + JSON, <= 4096 bytes
 *    v
 * BrowserBridge      per-conn gates: pin peer -> signer [M6] -> browser ancestor -> nonce echo,
 *                    then parseBridgeMessage, split by kind:
 *                      |- click -> verdict map keyed by (browserPid,qx,qy)  [BrowserBridgeProbe]
 *                      '- nav   -> single NavSnapshot slot + per-PID visit token
 *                                  [takeNavSince -> StagingController]
 * @endverbatim
 *
 * ## :material-shield-lock: Hardening Mitigations
 *
 * The bridge is seal's highest-risk attack surface: same-user malware that
 * reaches the pipe could poison the verdict map. Each connection worker applies
 * these checks in order, and a failure at any gate disconnects the peer before
 * a byte of its JSON is read.
 *
 * - **Pipe DACL** - only the current user SID gets read/write plus sync on the
 *   pipe. Authenticated Users and Administrators get no ACE, so cross-user
 *   attacks stop at the OS layer.
 * - **Pinned peer handle** - the client PID from `GetNamedPipeClientProcessId`
 *   is opened once (`ProcessPin.hpp`), and every later check uses that handle
 *   instead of resolving the PID again. The pipe's client PID is then read a
 *   second time and must still equal the pinned one, which rejects a PID
 *   recycled inside the read-then-open gap (`reason=pin_failed`,
 *   `reason=peer_pid_changed`).
 * - **M6: Signer identity match** - the peer binary path comes from the pinned
 *   handle, `WinVerifyTrust` runs with whole-chain revocation against the OS
 *   cache, and the peer's SPKI thumbprint must equal seal.exe's, so a cert
 *   renewal that keeps the key still matches but a key-rotation reissue does not.
 * - **An ancestor must be a known signed browser** - the chain above the relay
 *   process (`CreateToolhelp32Snapshot`, at most 6 hops, stepping only through
 *   allow-listed cmd.exe / powershell.exe / pwsh.exe / conhost.exe) must reach
 *   an image with a known browser name that passes `WinVerifyTrust` and is
 *   signed by that browser's vendor. A hop created later than its own child is
 *   rejected as a recycled PID link. Malware that launches seal-browser.exe
 *   with its own stdin therefore fails: no ancestor of it is a browser.
 * - **Fresh nonce per accept** - once the ancestor gate passes, the bridge
 *   sends a framed hello with a per-connection random nonce and requires that
 *   exact frame back byte for byte. It is a framing and replay sanity check,
 *   not authentication, so it carries no M-number. The per-start key that
 *   derives the pipe name (M7) is never transmitted.
 * - **M5: Bridge-alone short-circuit prohibition** - enforced in
 *   `FusionDecider`, not here. A Tier-1 hit from the bridge probe alone cannot
 *   decide a fill; another Tier-1 probe must agree.
 * - **Browser-PID-keyed map** - entries are indexed by the resolved browser
 *   ancestor PID, not the relay process's own PID. The wire schema carries no
 *   `browser_pid` field, so a lying peer cannot pick the key.
 * - **Bounded JSON parser** - hand-rolled and flat: it rejects payloads over
 *   4 KB, nested values, unknown or duplicate keys, and any value outside the
 *   kind-selected schema. It allocates no `seal::secure_string` and no
 *   DPAPIGuard; `BridgeFuzzTest.ParsedStructHasNoSecureStringMember` pins the
 *   parser's string output fields to plain `std::string` at compile time.
 * - **M8: Panic-mode disable** - `disable()` drops the map, closes the pipe,
 *   and refuses further inserts and lookups until `enable()` is called. The
 *   chip's right-click toggle wires to this.
 *
 * @par Mitigation index (M2-M9; M numbers a bridge threat-model mitigation; no M1 gate exists)
 * | Tag |                            Mitigation                            | Where         |
 * |-----|------------------------------------------------------------------|---------------|
 * |  M2 | Report only via chrome.runtime.sendMessage (no page postMessage) | content.js    |
 * |  M3 |                 Trusted events only (e.isTrusted)                | content.js    |
 * |  M4 |                          Top frame only                          | content.js    |
 * |  M5 |   Bridge not solely decisive; needs a 2nd on-disk Tier-1 probe   | FusionDecider |
 * |  M6 |        Peer signer identity match (WinVerifyTrust + SPKI)        | BrowserBridge |
 * |  M7 |       Per-run pipe-name rotation (SHA-256 of per-start key)      | BrowserBridge |
 * |  M8 |            Panic-mode disable (drop map, close pipe)             | BrowserBridge |
 * |  M9 |             Only user-visible click targets reported             | content.js    |
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
 *     Stopped --> Listening : start() / enable()
 *     Listening --> Gating : peer connects (own worker thread)
 *     Listening --> Listening : worker cap reached, connection dropped
 *     Gating --> Listening : a gate fails
 *     Gating --> Serving : signer + browser ancestor + nonce echo ok
 *     Serving --> Listening : peer disconnects
 *     Listening --> Stopped : stop() / disable()
 *     Serving --> Stopped : stop() / disable()
 * ```
 *
 * Listening continues while workers run, so Gating and Serving can each hold
 * several connections at once.
 *
 * @note `enable()` after a `disable()` regenerates the pipe-name key and the
 *       per-connection nonce state, so any pipe name or nonce leaked earlier is
 *       already invalid.
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
     * Generates a fresh 32-byte key with @c BCryptGenRandom, derives the
     * pipe-name suffix from its SHA-256 hash, builds the per-user DACL,
     * pre-creates the first pipe instance so the extension's first connect
     * cannot miss, and spawns the accept jthread. Idempotent: returns true
     * without doing anything when the bridge already runs.
     *
     * @return true on success. false when the bridge is panic-disabled, when
     *         RNG, hashing or DACL construction failed, when the pipe could not
     *         be created, or - with @c SEAL_REQUIRE_SIGNED_PEER compiled in -
     *         when this binary is unsigned. Treat failure as a warning, not a
     *         fatal error: the other probes still detect fields without it.
     *
     * @note Panic-disable is not cleared here. Call @ref enable to resume; it
     *       starts the pipe itself.
     */
    bool start();

    /**
     * @brief Stop the accept thread and close the pipe. Safe if already stopped.
     *
     * Blocking, and the single synchronisation point for full teardown. It
     * signals the accept jthread's stop token and joins it. The acceptor polls
     * that token every 200 ms, then cancels the pending overlapped I/O of every
     * connection worker with `CancelIoEx`, joins them, and closes their pipe
     * handles; a worker parked in a read notices within about 1 s.
     *
     * @par State after stop
     * Per-browser connected counts reset, so @ref isPeerConnected reports false.
     * The pending navigation snapshot survives; only @ref disable clears it. The
     * navigation sequence counter is monotonic for the process lifetime and
     * neither call resets it, so a consumer caching its last seen sequence
     * cannot be handed a stale snapshot after a restart.
     *
     * @note This clears neither the verdict map nor the per-PID visit tokens
     *       directly. Joining the workers runs each connection's disconnect
     *       bookkeeping, which drops the entries and the visit token of a
     *       browser whose last connection closes, so both end up empty.
     */
    void stop();

    /// @brief Whether the accept thread is currently running.
    bool isRunning() const noexcept;

    /**
     * @brief Whether peer signer authentication is active (this binary is signed).
     *
     * The expected identity is read once in the constructor. An empty identity
     * means the binary is unsigned, untrusted or revoked, and the M6 signer gate
     * then accepts any peer - the dev-mode degradation in verifySignerMatches
     * (BrowserBridge.cpp). The UI shows a warning so a user running an unsigned
     * build knows peer authentication is off. A build compiled with
     * @c SEAL_REQUIRE_SIGNED_PEER refuses to start the bridge in this state
     * instead of degrading.
     *
     * @return true when this binary carries an Authenticode signer identity.
     */
    bool isPeerAuthEnforced() const noexcept;

    /**
     * @brief Panic-mode disable: drop all state and refuse further activity.
     *
     * Sets the disabled flag, performs a full @ref stop, then clears the verdict
     * map, the per-browser connection counts, the pending navigation snapshot
     * and the per-PID visit tokens. Afterwards @ref lookup, @ref takeNavSince
     * and @ref currentVisit return @c std::nullopt, @ref sendFillUsername
     * returns false, incoming messages are discarded, and no new connection is
     * accepted until @ref enable is called.
     *
     * Blocking: it inherits @ref stop's join of the accept and worker threads.
     * Reached from the chip's right-click M8 toggle in BridgeSettings.qml via
     * FillController::disableBridge.
     */
    void disable();

    /**
     * @brief Re-enable after disable(). No-op when not disabled.
     *
     * Recovers from a panic-mode disable by restarting the accept thread on a
     * fresh key, which invalidates any nonce or pipe-name suffix issued before.
     * The restart result is not reported: on failure the bridge is enabled but
     * not running, which @ref isRunning reflects.
     *
     * @note From the peer's perspective this is a fresh start. The extension
     *       sees a port-closed event and reconnects on the new pipe name once
     *       its reconnect timer fires.
     */
    void enable();

    /// @brief Whether the bridge is in panic-mode disable state.
    bool isDisabled() const noexcept;

    /**
     * @brief Look up a recent extension report for the click site.
     *
     * Scans the bounded in-memory map and returns the freshest unexpired entry
     * whose key (browser PID plus quantised x/y) is within Chebyshev distance
     * @c kLookupToleranceRawPx of the query point. The tolerance covers natural
     * click variance on a typical 40 px input field, so a within-pixel match is
     * not required.
     *
     * @par Bucket geometry
     * Raw coordinates are quantised to 4 px buckets (an arithmetic shift by 2,
     * so negative coordinates floor too). A bucket's representative point is its
     * origin plus 2 px, and a query matches within a 48 px Chebyshev radius of
     * that point:
     * @f[
     *   q(v) = \left\lfloor v / 4 \right\rfloor, \qquad \hat{v} = 4\,q(v) + 2
     * @f]
     * @f[
     *   \text{match} \iff \max\bigl(|\hat{x} - x|,\ |\hat{y} - y|\bigr) \le 48
     * @f]
     *
     * @par Threading
     * Callable from any thread, in practice the GUI thread, while workers
     * insert. It takes a shared lock and returns a copy of the entry, so the
     * result stays valid after the map changes. It never prunes.
     *
     * @param browserPid Owner PID of the focused window at click time.
     * @param screenPoint Screen-space click coordinates, raw (unquantised).
     * @return A populated @ref BridgeEntry when an unexpired entry exists within
     *         the tolerance; @c std::nullopt when the bridge is panic-disabled
     *         or no such entry exists.
     */
    std::optional<BridgeEntry> lookup(DWORD browserPid, POINT screenPoint) const noexcept;

    /**
     * @brief Consume the latest navigation snapshot if it is newer than seen.
     *
     * Returns the most recent @ref NavSnapshot once per navigation: the caller
     * threads a @p lastSeenSeq it owns, and the snapshot comes back only when
     * its sequence exceeds that cursor, which then advances. Returns
     * @c std::nullopt when the bridge is panic-disabled (M8), when nothing new
     * arrived, or when the snapshot is older than the 10 s freshness window - in
     * that last case @p lastSeenSeq still advances, so a stale snapshot is
     * examined once and then skipped.
     *
     * One snapshot slot serves all browsers, so a navigation can be overwritten
     * before any caller consumes it. A caller may miss a navigation, but never
     * sees one twice.
     *
     * The snapshot is returned unfiltered: a report from an insecure page is
     * stored and handed back, so a caller that auto-arms must test
     * @ref NavSnapshot::m_Secure itself.
     *
     * @par Threading
     * Called on the GUI thread by StagingController's poll, while bridge worker
     * threads write the snapshot under a dedicated mutex. It holds that mutex
     * briefly and never blocks meaningfully.
     *
     * @param lastSeenSeq In/out cursor: the last sequence this caller consumed.
     *                    Each caller owns its own; the bridge does not track who
     *                    has consumed what.
     * @return A fresh, not-yet-seen snapshot, or @c std::nullopt.
     */
    std::optional<NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq) const;

    /**
     * @brief The per-document visit token of the page now loaded in a browser
     *        process, if known.
     *
     * Returns the visit token from the most recent navigation report for
     * @p browserPid - the identity of the document on screen. The click-fill
     * gate compares it against the token stored on a cached @ref BridgeEntry: a
     * mismatch means the entry belongs to another document, such as a
     * focus-click that survived a navigation or tab switch, and cannot authorize
     * a fill.
     *
     * This does not consume the snapshot, unlike @ref takeNavSince. It can be
     * queried repeatedly, has no freshness window, and is kept per browser PID
     * instead of in the single shared slot. The entry is dropped when that
     * browser's last connection closes.
     *
     * @param browserPid The validated browser PID to query.
     * @return The current document token, or @c std::nullopt when the bridge is
     *         disabled, no navigation has been seen for @p browserPid, or the
     *         last report carried no token.
     */
    std::optional<std::string> currentVisit(DWORD browserPid) const;

    /**
     * @brief Push a username-injection directive to a connected browser peer.
     *
     * The only reverse-channel write (bridge -> extension) besides the
     * handshake. Sends a framed
     * `{"v":1,"kind":"fill_username","url_host","visit","username"}` message to
     * the authenticated peer serving @p browserPid. It only routes to that
     * already-gated connection and frames the bytes; the release decision
     * belongs to the caller.
     *
     * @pre FillController has decrypted the username just in time and confirmed
     *      a strict domain match.
     *
     * @par Threading
     * Called on the GUI thread while a worker thread reads the same full-duplex
     * pipe. The write takes the connection's write mutex, which the worker also
     * holds when it marks that connection dead.
     *
     * @par Secret handling
     * The frame is built in one pre-reserved buffer, so no intermediate string
     * holding the plaintext username is reallocated away unwiped. Both the
     * escaped username and the finished frame are zeroed before returning.
     *
     * @param browserPid   The validated browser PID whose peer to send to.
     * @param host         The page host, echoed so the content script can
     *                     re-verify its own location before injecting.
     * @param visit        Per-document visit token, echoed so the content script
     *                     can reject a same-host different-document route. An
     *                     empty token fails the call instead of injecting into
     *                     an untagged document.
     * @param usernameUtf8 The plaintext username (UTF-8). Copied into the wire
     *                     frame; the caller and this method wipe their copies.
     * @return true when a framed directive was written to a live peer. false
     *         when the bridge is disabled (M8), @p visit is empty, no peer is
     *         connected for @p browserPid, that peer already marked itself dead,
     *         or the write failed.
     */
    bool sendFillUsername(DWORD browserPid,
                          const std::string& host,
                          const std::string& visit,
                          const std::string& usernameUtf8);

    /**
     * @brief Whether the pipe currently has an accepted peer (handshake done).
     *
     * False between starts, while the accept loop waits for a connection, and
     * after a peer disconnects. The diagnose dry-run reports it, so "no relay
     * process connected" is distinguishable from "connected but no report for
     * this click", and the chip indicator picks the green or red pulse colour.
     *
     * @return true when a peer of any browser is currently connected.
     */
    bool isPeerConnected() const noexcept;

    /**
     * @brief Whether a peer launched by a specific browser is connected.
     *
     * There is one named-pipe instance per connected relay process, so
     * distinct browsers can be connected at the same time. The launching
     * browser is the ancestor that @c WinVerifyTrust validated during the
     * accept handshake, never the peer's self-report, so this cannot be
     * spoofed. Drives the per-browser status dots in the footer.
     *
     * @param kind The browser to query.
     * @return true when at least one connected peer was launched by @p kind.
     */
    bool isPeerConnected(seal::signer::BrowserKind kind) const noexcept;

    /**
     * @brief Current size of the in-memory verdict map.
     *
     * Diagnostic only: the count is exposed, the contents are not. The diagnose
     * dry-run uses it to tell "peer connected but map empty" from "no peer at
     * all". Takes a shared lock and is callable from any thread.
     *
     * @return Number of entries the map holds, including entries whose 30 s TTL
     *         has elapsed. Expiry is lazy, so an expired entry stays counted
     *         until the next insert or browser disconnect prunes it.
     */
    std::size_t mapEntryCount() const noexcept;

#ifdef SEAL_BRIDGE_TEST_HOOKS
    /**
     * @brief Test-only hook: parse a single message in isolation.
     *
     * tests/test_bridge_fuzz.cpp feeds malformed input through it without
     * standing up a real pipe. Not compiled in release builds.
     *
     * @param payload Raw JSON payload as it would arrive on the pipe.
     * @param out May be null. On success it receives the verdict, the TTL
     *            deadline and the host. The visit token is not copied, unlike
     *            the live insert path, so @ref BridgeEntry::m_Visit is left untouched.
     * @return true when the payload parsed cleanly and the tag mapped to an
     *         insertable verdict. A nav report returns false: its tag defaults
     *         to Other, which never inserts.
     *
     * @note The hook covers only parsing and the tag-to-verdict mapping. It
     *       omits the live path's panic-disable check and its `secure` check, so
     *       a click report with `secure:0` returns true here although the bridge
     *       would drop it (`reason=insecure_click`).
     */
    bool testParseMessage(std::string_view payload, BridgeEntry* out);
#endif

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
