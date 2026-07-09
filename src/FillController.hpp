#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>
#include <QTimer>

#include <windows.h>
#include <atomic>
#include <vector>

#include "BrowserBridge.hpp"
#include "BrowserBridgeProbe.hpp"
#include "CredentialSession.hpp"
#include "Cryptography.hpp"
#include "FusionDecider.hpp"
#include "ImeStateProbe.hpp"
#include "Probe.hpp"
#include "UiaIsPasswordProbe.hpp"
#include "UiaMetadataProbe.hpp"
#include "Vault.hpp"
#include "Win32StyleProbe.hpp"

namespace seal
{

/**
 * @class FillController
 * @brief Manages credential auto-fill via global Windows input hooks.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Implements a two-phase auto-fill workflow: the user arms the controller
 * for a specific vault record, then Ctrl+Clicks in an external application
 * to type credentials via synthesized keystrokes (SendInput).
 *
 * ## :material-state-machine: State Machine
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart LR
 *     classDef idle fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
 *     classDef armed fill:#1e4a3a,stroke:#22c55e,color:#e2e8f0
 *     classDef typing fill:#4a3520,stroke:#f59e0b,color:#e2e8f0
 *
 *     Idle([Idle]):::idle
 *     A([Armed]):::armed
 *     T([Typing]):::typing
 *
 *     Idle -->|arm| A
 *     A -->|Ctrl+Click| T
 *     A -->|Esc / timeout| Idle
 *     T -->|one field typed| A
 *     T -->|both fields typed| Idle
 *     T -->|error| Idle
 * ```
 *
 * - **Idle** - no hooks installed, waiting for arm().
 * - **Armed** - hooks active, waiting for Ctrl+Click. UIA probing auto-detects
 *   whether the clicked field is a password input; either credential field can
 *   be typed in any order. Bit flags track which fields have been filled.
 * - **Typing** - keystrokes being sent, hooks still installed.
 *
 * Two auxiliary modes reuse the same hook machinery and timeout:
 * - **AutoArmed** - staged on navigation (armAuto()); a plain (no-Ctrl) click
 *   into a bridge-classified login field completes the fill through the
 *   fail-closed auto gates. Placed by StagingController, never by the user.
 * - **Diagnose** - like Armed, but a Ctrl+Click runs the probe pipeline as a
 *   dry run (no decrypt, no keystrokes) and emits diagnoseCompleted with the
 *   per-probe verdict. Entered via armDiagnose().
 *
 * ## Complete state machine (ASCII)
 *
 * The Mermaid above shows only the manual Ctrl+Click lane; the full machine
 * has five states across three entry points. @ref State::Typing is transient -
 * it always resolves back to its lane's armed state or to @ref State::Idle.
 *
 * @verbatim
 *  MANUAL    Idle --arm()--> Armed
 *            Armed --Ctrl+Click--> Typing
 *            Typing --one field typed (manual)--> Armed     (2-field flow)
 *            Typing --both fields typed--> Idle
 *
 *  AUTO      Idle --armAuto()--> AutoArmed         (staged by StagingController)
 *            AutoArmed --plain click--> Typing
 *            Typing --weak fusion / non-password--> AutoArmed   (retry)
 *            Typing --password typed--> Idle
 *
 *  DIAGNOSE  Idle --armDiagnose()--> Diagnose
 *            Diagnose --Ctrl+Click--> [dry-run probes] --> Idle
 *
 *  CANCEL    Esc:     Armed | AutoArmed | Diagnose         --> Idle
 *            timeout: Armed | Diagnose  (30 s, Auto has none) --> Idle
 * @endverbatim
 *
 * ## :material-keyboard: Modifier Keys
 *
 * While armed, the user can override which field gets typed:
 * - **Ctrl+Click** - type whichever field the state expects (username or password)
 * - **Ctrl+Shift+Click** - force type password regardless of state
 * - **Ctrl+Alt+Click** - force type username regardless of state
 * - **Esc** - cancel and remove hooks
 *
 * @par Gesture map
 * | Gesture          | Field typed                                             |
 * |------------------|---------------------------------------------------------|
 * | Ctrl+Click       | Auto: the probe pipeline decides (username vs password) |
 * | Ctrl+Shift+Click | Password (forced, overrides detection)                  |
 * | Ctrl+Alt+Click   | Username (forced, overrides detection)                  |
 * | Esc              | Cancel the fill and remove hooks                        |
 *
 * ## :material-format-list-bulleted: Properties
 *
 * - **isArmed** (bool) - true when in Armed state
 * - **fillStatusText** (QString) - human-readable status for the UI
 * - **countdownSeconds** (int) - seconds remaining before auto-cancel
 *
 * ## :material-signal: Signals
 *
 * - **armedChanged** - armed state toggled on/off
 * - **fillStatusTextChanged** - status text updated
 * - **countdownSecondsChanged** - countdown tick or reset
 * - **fillCompleted**(statusMessage) - both credentials typed successfully
 * - **fillError**(errorMessage) - decrypt or keystroke failure
 * - **fillCancelled** - user pressed Esc or timeout expired
 *
 * @note Only one FillController can be active at a time (singleton hook via s_instance).
 *       The low-level hooks run on the thread that installed them, so all state
 *       mutations are queued back to the Qt event loop via QMetaObject::invokeMethod.
 */
class FillController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isArmed READ isArmed NOTIFY armedChanged)
    Q_PROPERTY(QString fillStatusText READ fillStatusText NOTIFY fillStatusTextChanged)
    Q_PROPERTY(int countdownSeconds READ countdownSeconds NOTIFY countdownSecondsChanged)

public:
    /// @enum State
    /// @brief Fill controller state machine states.
    enum class State
    {
        Idle,       ///< No hooks, waiting for arm() or armDiagnose().
        Armed,      ///< Hooks active, waiting for Ctrl+Click to type either field.
        Typing,     ///< Keystrokes being sent to target window.
        Diagnose,   ///< Hooks active, waiting for Ctrl+Click to dry-run probes only.
        AutoArmed,  ///< Staged on navigation; a plain (no-Ctrl) click completes the fill.
    };
    Q_ENUM(State)

    /// @brief Construct the controller and wire up the timeout timer.
    explicit FillController(QObject* parent = nullptr);

    /// @brief Destructor. Cancels any active fill and removes hooks.
    ~FillController() override;

    /// @brief Check whether hooks are installed and waiting for user click.
    bool isArmed() const;

    /// @brief Get the current human-readable status text for UI display.
    QString fillStatusText() const;

    /// @brief Get seconds remaining before the fill operation auto-cancels.
    int countdownSeconds() const;

    /// @brief Get the current state machine state.
    State state() const;

    /**
     * @brief Arm the controller for a specific vault record.
     *
     * Installs global WH_MOUSE_LL and WH_KEYBOARD_LL hooks and transitions
     * to Armed. The controller borrows a pointer to the records vector and a
     * reference to the credential session (caller must keep them alive until
     * fill completes or is cancelled). The master key stays DPAPI-protected
     * while armed; performType() opens a scoped session.unlock() only around
     * the on-demand decrypt, so plaintext exists for the decrypt instant.
     *
     * A generation counter snapshot is taken at arm-time and validated before
     * every pointer dereference in performType(). If the owner mutates the
     * records between arm() and the actual fill, the stale generation causes
     * the fill to cancel safely instead of dereferencing potentially-invalid
     * pointers.
     *
     * If the controller is already armed (e.g. the user selected a different
     * record), the previous session is cancelled and hooks are reinstalled
     * for the new record.
     *
     * @param recordIndex     Index into the records vector
     * @param records         Reference to the vault records (must outlive the fill)
     * @param session         Credential session that owns the master key; performType()
     *                        unlocks it only for the decrypt (must outlive the fill)
     * @param ownerGeneration Monotonic counter owned by the caller; incremented on every
     *                        records/password mutation.
     * @return `true` if hooks were installed and arming succeeded.
     */
    [[nodiscard]] bool arm(int recordIndex,
                           const std::vector<seal::VaultRecord>& records,
                           seal::CredentialSession& session,
                           const uint64_t& ownerGeneration);

    /**
     * @brief Arm the controller for zero-gesture staged auto-fill.
     *
     * Identical borrowing / generation-snapshot / hook-install semantics to
     * @ref arm, but transitions to @ref State::AutoArmed. In that state a
     * plain left click (NO Ctrl) into a bridge-classified login field
     * completes the fill through the fail-closed auto gates (tiered host
     * match, dual-PID foreground check, on-disk-corroborated fusion). The
     * click is never swallowed, so it focuses the field normally; a click
     * that isn't on a classified login field is a silent no-op.
     *
     * Called by StagingController when a navigation report uniquely matched a
     * record. Same parameters as @ref arm.
     * @return true if hooks installed and auto-arming succeeded.
     */
    [[nodiscard]] bool armAuto(int recordIndex,
                               const std::vector<seal::VaultRecord>& records,
                               seal::CredentialSession& session,
                               const uint64_t& ownerGeneration);

    /**
     * @brief Consume the latest bridge navigation snapshot (GUI-thread poll).
     *
     * Thin passthrough to @ref BrowserBridge::takeNavSince so StagingController
     * (which does not own the bridge) can poll it. Returns nullopt when the
     * bridge is disabled, nothing new arrived, or the snapshot aged out.
     *
     * @param lastSeenSeq In/out cursor owned by the caller.
     */
    std::optional<seal::NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq);

    /**
     * @brief Decrypt a record's username and push it to the browser for
     *        zero-click DOM injection by the extension.
     *
     * The higher-risk half of staged auto-fill (the username value crosses into
     * the browser). Host-bound via
     * @ref seal::url::platformMatchesHostForSecretRelease, the same strict
     * matcher the selector and the password click-gate use: a record must store
     * a real domain/URL before any browser credential value is released.
     * Decryption is JIT in a tight unlock() window here (StagingController stays
     * decrypt-free); the plaintext UTF-8 copy is wiped after the reverse-channel
     * send.
     *
     * @param recordIndex Record to read.
     * @param records     Borrowed vault records (must outlive the call).
     * @param session     Borrowed session; unlocked only for the decrypt.
     * @param host        The navigated host (strict-matched, echoed to the peer).
     * @param visit       The per-document visit token to bind browser injection.
     * @param browserPid  The validated browser PID whose peer receives it.
     * @return true iff the directive was written to a live peer - the signal
     *         StagingController uses to latch its once-per-visit guarantee
     *         (a failed send may be retried on a later nav of the same visit).
     */
    [[nodiscard]] bool injectUsername(int recordIndex,
                                      const std::vector<seal::VaultRecord>& records,
                                      seal::CredentialSession& session,
                                      const std::string& host,
                                      const std::string& visit,
                                      DWORD browserPid);

    /**
     * @brief Arm the controller in dry-run "diagnose" mode.
     *
     * Like @ref arm but without binding a credential. Installs the same
     * global mouse + keyboard hooks; on the next Ctrl+Click, runs the
     * full probe pipeline (browser bridge + Win32 + UIA + IME), fuses
     * the verdict, and emits @ref diagnoseCompleted with a human-
     * readable summary. No decryption, no SendInput; safe to use on
     * arbitrary fields including those that don't belong to seal.
     *
     * Intended for testing the browser extension end-to-end: arm
     * diagnose mode, switch to the browser, Ctrl+Click any input field,
     * and read the per-probe verdict to confirm the bridge fired.
     *
     * Esc or the @ref FILL_TIMEOUT_SECONDS timeout cancels with
     * @ref diagnoseCancelled.
     *
     * @return true if hooks installed and diagnose mode is active.
     */
    [[nodiscard]] bool armDiagnose();

    /**
     * @brief Cancel the current fill operation and remove all hooks.
     *
     * Safe to call from any state; no-op if already Idle.
     * Emits fillCancelled (or diagnoseCancelled when in Diagnose state).
     */
    Q_INVOKABLE void cancel();

    /**
     * @brief Panic mode - disable the browser bridge (M8).
     *
     * Drops the pipe handle, refuses further messages, and clears the in-memory
     * bridge map. Safe to call from any state. Re-enable with enableBridge().
     */
    Q_INVOKABLE void disableBridge();

    /**
     * @brief Re-enable the browser bridge after a previous disableBridge() call.
     *
     * If currently armed and the bridge was previously stopped, attempts to
     * restart it on a fresh token; old tokens are invalidated.
     */
    Q_INVOKABLE void enableBridge();

    /**
     * @brief Whether the bridge is currently enabled (not in panic mode).
     */
    bool isBridgeEnabled() const;

    /**
     * @brief Whether the bridge enforces peer signer authentication.
     *
     * False when this binary is unsigned (the M6 signer gate then accepts any
     * peer). Fixed at startup from the running binary's Authenticode identity;
     * surfaced by the UI so an unsigned build shows a "peer auth disabled"
     * warning. See @ref BrowserBridge::isPeerAuthEnforced.
     */
    bool isBridgePeerAuthEnforced() const;

    /**
     * @brief Whether any browser-companion native messaging host is currently
     * connected to the bridge (handshake complete, port open). Used by AppViewModel
     * to drive the chip's aggregate "actually working" visual.
     */
    bool isBridgePeerConnected() const;

    /**
     * @brief Whether a Chrome-launched companion host is currently connected.
     * Drives the per-browser Chrome status dot in the footer.
     */
    bool isBridgeChromeConnected() const;

    /**
     * @brief Whether a Brave-launched companion host is currently connected.
     * Drives the per-browser Brave status dot in the footer.
     */
    bool isBridgeBraveConnected() const;

signals:
    void armedChanged();             ///< Armed state toggled on or off.
    void fillStatusTextChanged();    ///< Status text updated.
    void countdownSecondsChanged();  ///< Countdown tick or reset.

    /**
     * @brief Both credentials were typed successfully.
     * @param statusMessage Summary for the status bar (e.g. "Filled credentials for 'GitHub'").
     */
    void fillCompleted(const QString& statusMessage);

    /**
     * @brief A decrypt or keystroke error occurred during fill.
     * @param errorMessage Description of the failure.
     */
    void fillError(const QString& errorMessage);

    /// @brief Fill was cancelled by user (Esc) or timeout.
    void fillCancelled();

    /**
     * @brief Dry-run probe completed; @p summary is a multi-line human-
     * readable breakdown of per-probe verdicts (one line per probe with
     * verdict + confidence + evidence).
     */
    void diagnoseCompleted(const QString& summary);

    /// @brief Dry-run probe was cancelled (Esc or timeout) before any click.
    void diagnoseCancelled();

private slots:
    /// @brief Called every second while armed; decrements countdown and auto-cancels at zero.
    void onTimeoutTick();

    /**
     * @brief Queued from the mouse hook; decrypts and types the pending credential field.
     *
     * Waits for the Ctrl key to be released (up to 2 s), performs on-demand
     * AES-256-GCM decryption of the selected record, sends keystrokes via
     * `SendInput`, and immediately wipes the plaintext. After typing the
     * username, remains Armed for the password; after both fields are typed, tears down
     * hooks and emits fillCompleted.
     */
    void performType();

    /**
     * @brief Queued from the mouse hook on a plain click while AutoArmed.
     *
     * The zero-gesture completion path. Validates a strict, fail-closed gate
     * set BEFORE any decrypt: a fresh bridge entry for this click must exist
     * (proving the click hit a classified login field), its host must bind to
     * the staged record under the tiered @ref seal::url::platformMatchesHost, the
     * foreground and click windows must both belong to the bridge-validated
     * browser PID, and the fused verdict must be on-disk corroborated
     * (@ref FusionOutcome). Any failure aborts without producing plaintext.
     * On success it types via the shared @ref decryptAndTypeField.
     */
    void performTypeAuto();

    /**
     * @brief Queued from the mouse hook when in Diagnose state. Runs the
     * probe pipeline at the captured click point, builds a multi-line
     * summary string, emits @ref diagnoseCompleted, and returns to Idle.
     * Never decrypts a credential or sends keystrokes.
     */
    void performDiagnose();

private:
    /**
     * @brief Shared body of @ref arm / @ref armAuto. @p targetState is
     *        State::Armed (manual Ctrl+Click) or State::AutoArmed (staged).
     */
    [[nodiscard]] bool armInternal(int recordIndex,
                                   const std::vector<seal::VaultRecord>& records,
                                   seal::CredentialSession& session,
                                   const uint64_t& ownerGeneration,
                                   State targetState);

    /// @brief Install global low-level mouse and keyboard hooks.
    void installHooks();

    /// @brief Remove hooks and clear the singleton pointer.
    void removeHooks();

    /**
     * @brief Transition to a new state, update status text, and emit armedChanged if needed.
     * @param newState Target state
     */
    void transitionTo(State newState);

    /// @brief Rebuild m_StatusText based on the current state.
    void updateStatusText();

    /// @brief Low-level mouse hook callback (runs on the hook thread).
    static LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    /// @brief Low-level keyboard hook callback (runs on the hook thread).
    static LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    /// @brief Singleton - only one controller can own the global hooks at a time.
    static std::atomic<FillController*> s_instance;

    /// @brief Which credential field to type next.
    enum class TypeTarget
    {
        Username,
        Password,
        Auto,  ///< Let UIA probing decide at fill time.
    };

    /// @brief Bit flags tracking which credential fields have been typed.
    enum TypedFieldFlags : uint8_t
    {
        TypedNone = 0,
        TypedUsername = 1 << 0,
        TypedPassword = 1 << 1,
        TypedBoth = TypedUsername | TypedPassword,
    };

    /**
     * @brief Run the probe registry against a click point and fuse results.
     *
     * Builds a `seal::ProbeContext`, invokes each registered probe in
     * Tier-1 order (cheap, decisive signals first), then Tier-2 (broader
     * heuristics), and combines the resulting `ProbeResult`s via
     * `seal::FusionDecider`. Logs one `event=fill.decide` summary line
     * via `logFill` with per-probe verdict, confidence, and evidence so
     * weight tuning can be telemetry-driven.
     *
     * @param x Screen-space X (raw mouse hook output).
     * @param y Screen-space Y.
     * @return The fused verdict; `Verdict::Unknown` means the caller should
     *         fall through to the existing sequential fallback.
     */
    seal::Verdict runProbeRegistry(LONG x, LONG y);

    /**
     * @brief Same probe run as @ref runProbeRegistry but returns the full
     *        @ref FusionOutcome (verdict + provenance flags). The auto path
     *        gates a secret release on the corroboration flags; @ref
     *        runProbeRegistry delegates here and returns only the verdict.
     */
    seal::FusionOutcome runProbeRegistryDetailed(LONG x, LONG y);

    /**
     * @brief Decrypt the record's selected field and type it via SendInput.
     *
     * The single decrypt+type site shared by @ref performType (manual) and
     * @ref performTypeAuto. Opens a scoped @c session.unlock() only around the
     * on-demand decrypt, types the field, cleanses immediately, then either
     * completes - tears down hooks and emits fillCompleted - when both fields
     * have been typed or the fill is an auto (staged) one, or (manual mode, one
     * field still pending) resets the countdown and stays Armed for the other
     * field's Ctrl+Click. Callers must have already validated the record and
     * (for auto) the fail-closed gates.
     */
    void decryptAndTypeField(const seal::VaultRecord& record, TypeTarget target);

    std::atomic<State> m_State{State::Idle};  ///< Current state machine state.
    int m_RecordIndex = -1;                   ///< Index of the armed vault record.
    const std::vector<seal::VaultRecord>* m_Records =
        nullptr;  ///< Borrowed pointer to vault records.
    seal::CredentialSession* m_Session =
        nullptr;  ///< Borrowed session; unlocked only for the on-demand decrypt.

    const uint64_t* m_OwnerGeneration = nullptr;  ///< Points to owner's generation counter.
    uint64_t m_SnapshotGeneration = 0;  ///< Generation at arm() time; mismatch means stale.

    HHOOK m_MouseHook = nullptr;     ///< WH_MOUSE_LL hook handle.
    HHOOK m_KeyboardHook = nullptr;  ///< WH_KEYBOARD_LL hook handle.

    QTimer m_TimeoutTimer;                                      ///< 1-second tick for countdown.
    int m_RemainingSeconds = 0;                                 ///< Seconds until auto-cancel.
    QString m_StatusText;                                       ///< Human-readable status for QML.
    std::atomic<TypeTarget> m_PendingTarget{TypeTarget::Auto};  ///< Field to type on next click.

    std::atomic<LONG> m_ClickX{0};  ///< Screen X captured in mouseHookProc.
    std::atomic<LONG> m_ClickY{0};  ///< Screen Y captured in mouseHookProc.

    uint8_t m_TypedFields = TypedNone;  ///< Which fields have been typed so far.

    std::atomic<bool> m_AutoMode{false};  ///< True while staged via navigation (AutoArmed path).
    std::atomic<bool> m_AutoFillInFlight{
        false};  ///< Single-flight guard: one auto completion at a time.

    // BrowserBridge MUST be declared before BrowserBridgeProbe because the
    // probe holds a non-owning pointer initialised from m_BrowserBridge.
    seal::BrowserBridge m_BrowserBridge;
    seal::BrowserBridgeProbe m_BrowserBridgeProbe{&m_BrowserBridge};
    seal::Win32StyleProbe m_Win32StyleProbe;   ///< Tier-1 native ES_PASSWORD probe (stateless).
    seal::UiaIsPasswordProbe m_UiaIsPassword;  ///< Tier-1 UIA IsPassword/MSAA probe (caches UIA).
    seal::UiaMetadataProbe
        m_UiaMetadata;  ///< Tier-2 UIA metadata + form-context probe (caches UIA).
    seal::ImeStateProbe m_ImeStateProbe;  ///< Tier-2 IME context weak signal (stateless).
    seal::FusionDecider m_FusionDecider;  ///< Fuses ProbeResults into a Verdict.

    static constexpr int FILL_TIMEOUT_SECONDS = 30;  ///< Max seconds to wait for user click.
};

}  // namespace seal

#endif  // USE_QT_UI
