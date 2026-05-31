#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <QtCore/QString>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>

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
    QString m_UrlHost;  ///< Validated host name (no full URL ever crosses the pipe).
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
 * ## :material-shield-lock: Hardening Mitigations
 *
 * The bridge is the highest-risk attack surface in seal: same-user
 * malware that can connect to the pipe can poison the verdict map and
 * potentially bypass the URL-binding gate. The accept loop applies the
 * following checks in order; failure at any gate disconnects the peer
 * before a single byte of its JSON is read.
 *
 * - **Pipe DACL** -- only the current user SID gets RWX + SYNC on the
 *   pipe (Authenticated Users and Administrators are explicitly NOT
 *   granted). Cross-user attacks are blocked at the OS layer.
 * - **M6: Signer identity match** -- the peer binary path resolves via
 *   `GetNamedPipeClientProcessId`, then `WinVerifyTrust` with whole-
 *   chain revocation against the OS cache, and finally its SPKI
 *   thumbprint must equal seal.exe's. SPKI (not CN, not serial) binds
 *   to the publisher's public key, so cert renewals with the same key
 *   still match but a key-rotation reissue after a compromise does not.
 * - **M7: Fresh nonce per accept** -- after the peer is identity-
 *   matched, the bridge sends a per-connection random nonce and
 *   requires it back verbatim. The persistent HMAC key (used only in
 *   the pipe name) is never transmitted.
 * - **Parent process must be a known signed browser** -- the host's
 *   parent (via `CreateToolhelp32Snapshot`, walking through cmd.exe /
 *   powershell.exe hops) must (a) match a known browser image name and
 *   (b) pass `WinVerifyTrust`. Closes the "puppet a signed host" hole:
 *   same-user malware launching seal-browser.exe with attacker-
 *   controlled stdin still fails because its parent isn't a browser.
 * - **M5: Bridge-alone short-circuit prohibition** -- enforced in
 *   `FusionDecider`, not here. A Tier-1 hit from the bridge probe
 *   alone cannot decide a fill; another Tier-1 probe must agree.
 * - **Browser-PID-keyed map** -- entries are indexed by the resolved
 *   parent (browser) PID, not the host's own PID. There is no in-band
 *   `browser_pid` claim from the peer; the wire schema omits the
 *   field entirely so a lying peer cannot poison the map with a wrong
 *   key.
 * - **Bounded JSON parser** -- hand-rolled recursive-descent, rejects
 *   messages > 4 KB, nesting depth > 4, unknown / duplicate keys, or
 *   any value outside the six-field schema. Never allocates a
 *   `seal::secure_string` / DPAPIGuard (a test-only counter asserts
 *   zero such allocations across the fuzz corpus).
 * - **M8: Panic-mode disable** -- `disable()` drops the map, closes
 *   the pipe, and refuses further inserts/lookups until `enable()` is
 *   called. The chip's right-click toggle wires to this.
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
     *         non-fatal warning -- field detection still works without the
     *         bridge via the other probes.
     */
    bool start();

    /**
     * @brief Stop the accept thread and close the pipe. Safe if already stopped.
     *
     * Signals the jthread's stop token, cancels any pending overlapped I/O
     * on the pipe via `CancelIoEx`, joins the thread, and closes the
     * handle. The map is NOT cleared -- use @ref disable() for that.
     */
    void stop();

    /// @brief Whether the accept thread is currently running.
    bool isRunning() const noexcept;

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
     * @param browserPid Owner PID of the focused window at click time.
     * @param screenPoint Screen-space click coordinates.
     * @return A populated @ref BridgeEntry when a fresh entry exists within a
     *         small jitter tolerance; @c std::nullopt otherwise.
     */
    std::optional<BridgeEntry> lookup(DWORD browserPid, POINT screenPoint) const noexcept;

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
     * Diagnostic only -- the contents are not exposed via this API; only the
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
