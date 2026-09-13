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
 * @brief Release armed credentials through global Windows input hooks.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Manual mode types either field on Ctrl+Click and completes after both fields.
 * Auto mode types the password once on a plain click; it has no timeout.
 * Diagnose mode runs probes without decrypting or typing.
 *
 * One controller owns the global hooks. Callbacks run on the installing GUI
 * thread, update atomics, and queue work outside the OS hook dispatcher.
 * Ctrl-held clicks do not start auto fills. Probes and keystroke delivery run on
 * the GUI thread; a blocking provider or typing call delays cancellation processing.
 *
 * ### :material-transit-connection-variant: Manual fill states
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
 * | Gesture          | Effect                                               |
 * |------------------|------------------------------------------------------|
 * | Ctrl+click       | Type the field the probe pipeline detects            |
 * | Ctrl+shift+Click | Type the password (forced, overrides detection)      |
 * | Ctrl+alt+Click   | Type the username (forced, overrides detection)      |
 * | Esc              | Cancel and remove hooks (Armed, AutoArmed, Diagnose) |
 */
class FillController : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isArmed READ isArmed NOTIFY armedChanged)
    Q_PROPERTY(QString fillStatusText READ fillStatusText NOTIFY fillStatusTextChanged)
    Q_PROPERTY(int countdownSeconds READ countdownSeconds NOTIFY countdownSecondsChanged)

public:
    /**
     * @enum State
     * @brief Fill controller state machine states.
     * @author Alex (<https://github.com/lextpf>)
     */
    enum class State
    {
        Idle,       ///< No hooks, waiting for arm(), armAuto() or armDiagnose().
        Armed,      ///< Hooks active, waiting for Ctrl+Click to type either field.
        Typing,     ///< Keystrokes being sent to target window.
        Diagnose,   ///< Hooks active, waiting for Ctrl+Click to dry-run probes only.
        AutoArmed,  ///< Staged on navigation; a plain (no-ctrl) click completes the fill.
    };
    Q_ENUM(State)

    /**
     * @fn FillController(QObject* parent = nullptr)
     * @brief Construct the controller and wire up the timeout timer.
     * @author Alex (<https://github.com/lextpf>)
     */
    explicit FillController(QObject* parent = nullptr);

    /**
     * @fn ~FillController()
     * @brief Cancel any active fill, remove hooks, and stop the bridge.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~FillController() override;

    /**
     * @fn bool isArmed() const
     * @brief Whether a credential is bound and waiting for the completing click.
     * @author Alex (<https://github.com/lextpf>)
     *
     * True in `State::Armed` and `State::AutoArmed` only. Diagnose
     * installs hooks but binds no credential, so it reads false, as does
     * `State::Typing`.
     */
    bool isArmed() const;

    /**
     * @fn QString fillStatusText() const
     * @brief Status line for the UI.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Empty while Idle.
     */
    QString fillStatusText() const;

    /**
     * @fn int countdownSeconds() const
     * @brief Report seconds remaining before manual or diagnosis timeout.
     * @author Alex (<https://github.com/lextpf>)
     *
     * AutoArmed never expires; its value stays at `FILL_TIMEOUT_SECONDS`.
     */
    int countdownSeconds() const;

    /**
     * @fn State state() const
     * @brief The current state machine state.
     * @author Alex (<https://github.com/lextpf>)
     */
    State state() const;

    /**
     * @fn bool arm(int recordIndex, const std::vector<seal::VaultRecord>& records,
     *     seal::CredentialSession& session, const uint64_t& ownerGeneration)
     * @brief Install hooks for a manual fill of one record.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Records, session, and generation counter are borrowed and must outlive the fill.
     * The master key stays DPAPI-protected except during on-demand decrypt.
     * A changed generation cancels before decrypt. Re-arming first cancels the live
     * session and emits fillCancelled.
     *
     * @param recordIndex Checked on the completing click; an invalid index still arms.
     * @param ownerGeneration Must increase on every records or password change.
     * @return True if both hooks installed. Failure removes partial hooks, clears records
     *         and session pointers, emits fillError, and stays Idle. The generation
     *         pointer remains set but is unread while Idle.
     * @pre Call on the GUI thread.
     */
    [[nodiscard]] bool arm(int recordIndex,
                           const std::vector<seal::VaultRecord>& records,
                           seal::CredentialSession& session,
                           const uint64_t& ownerGeneration);

    /**
     * @fn bool armAuto(int recordIndex, const std::vector<seal::VaultRecord>& records,
     *     seal::CredentialSession& session, const uint64_t& ownerGeneration)
     * @brief Install hooks for one staged password fill.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses the borrowing and failure contract of arm. Plain clicks pass through for
     * normal focus; unclassified clicks leave AutoArmed unchanged. Successful typing,
     * esc, or re-staging ends the arm; no timeout applies.
     *
     * @see performTypeAuto
     */
    [[nodiscard]] bool armAuto(int recordIndex,
                               const std::vector<seal::VaultRecord>& records,
                               seal::CredentialSession& session,
                               const uint64_t& ownerGeneration);

    /**
     * @fn std::optional<seal::NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq)
     * @brief Poll one unseen navigation without changing fill state.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param lastSeenSeq Caller-owned cursor; advances when a snapshot is consumed.
     * @return `std::nullopt` if disabled, expired, or no newer snapshot exists.
     * @pre Call on the GUI thread.
     * @see BrowserBridge::takeNavSince
     */
    std::optional<seal::NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq);

    /**
     * @fn bool injectUsername(int recordIndex, const std::vector<seal::VaultRecord>& records,
     *     seal::CredentialSession& session, const std::string& host, const std::string& visit,
     *     DWORD browserPid)
     * @brief Send a host-bound username to the browser for DOM injection.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Requires a strict domain/URL match and a non-empty visit token. Decrypts inside
     * a scoped session unlock and wipes the transient UTF-8 copy after sending.
     * Does not read or change fill state.
     *
     * @param records Borrowed for this call.
     * @param session Borrowed for this call; unlocked only for decrypt.
     * @param browserPid Validated browser whose live peer receives the directive.
     * @return True if a live peer received the directive, allowing the caller to latch
     *         this visit. False without signals for invalid/deleted records, missing
     *         visit, host mismatch, disabled bridge, unlock/decrypt failure, empty
     *         username, or failed send. Failed sends may be retried.
     */
    [[nodiscard]] bool injectUsername(int recordIndex,
                                      const std::vector<seal::VaultRecord>& records,
                                      seal::CredentialSession& session,
                                      const std::string& host,
                                      const std::string& visit,
                                      DWORD browserPid);

    /**
     * @fn bool armDiagnose()
     * @brief Run the probe pipeline on the next Ctrl+Click without decrypt or typing.
     * @author Alex (<https://github.com/lextpf>)
     *
     * isArmed remains false. Completion emits diagnoseCompleted with probe results.
     * Esc or timeout emits diagnoseCancelled.
     *
     * @return True if both hooks installed; otherwise emits fillError and stays Idle.
     */
    [[nodiscard]] bool armDiagnose();

    /**
     * @fn void cancel()
     * @brief Remove hooks and clear borrowed state.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op in Idle. Stops the timer and returns to Idle without stopping the bridge.
     * Emits diagnoseCancelled for Diagnose, otherwise fillCancelled.
     */
    Q_INVOKABLE void cancel();

    /**
     * @fn void disableBridge()
     * @brief Disable the bridge and clear reports and visit tokens.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Does not cancel armed fills; auto completion requires a live bridge entry.
     * Blocks the GUI thread while bridge threads join.
     *
     * @see BrowserBridge::disable
     */
    Q_INVOKABLE void disableBridge();

    /**
     * @fn void enableBridge()
     * @brief Enable and start the bridge in any fill state.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Restarting rotates the pipe name. Eager startup avoids extension reconnect
     * backoff on the first click.
     *
     * @see BrowserBridge::enable
     */
    Q_INVOKABLE void enableBridge();

    /**
     * @fn bool isBridgeEnabled() const
     * @brief Whether the bridge is enabled, that is not in panic mode.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isBridgeEnabled() const;

    /**
     * @fn bool isBridgePeerAuthEnforced() const
     * @brief Report whether the startup signer identity enables peer authentication.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Unsigned builds return false and accept any peer signer.
     *
     * @see BrowserBridge::isPeerAuthEnforced
     */
    bool isBridgePeerAuthEnforced() const;

    /**
     * @fn bool isBridgePeerConnected() const
     * @brief Report whether any relay has completed the pipe handshake.
     * @author Alex (<https://github.com/lextpf>)
     *
     * BrowserBridge is not a QObject, so BridgeViewModel polls this at 1 Hz and
     * turns level changes into its aggregate `bridgePeerConnected` property.
     */
    bool isBridgePeerConnected() const;

    /**
     * @fn bool isBridgeBrowserConnected(seal::signer::BrowserKind kind) const
     * @brief Whether a peer launched by kind is currently connected.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The per-browser source of truth: BridgeViewModel builds its `browsers`
     * model from this, which drives the status dots in the UI.
     *
     * @param kind Browser identity established by the bridge signer walk.
     */
    bool isBridgeBrowserConnected(seal::signer::BrowserKind kind) const;

    /**
     * @fn bool isBridgeChromeConnected() const
     * @brief Report whether a Chrome-launched relay process is connected.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses the same peer state as `isBridgeBrowserConnected`.
     */
    bool isBridgeChromeConnected() const;

    /**
     * @fn bool isBridgeBraveConnected() const
     * @brief Report whether a Brave-launched relay process is connected.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses the same peer state as `isBridgeBrowserConnected`.
     */
    bool isBridgeBraveConnected() const;

signals:
    /**
     * @fn void armedChanged()
     * @brief Notify a change in whether a credential is waiting for a click.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Entering Typing from Armed emits this signal because `isArmed()` becomes false.
     * Returning to Armed emits it again; transitions between unarmed states stay silent.
     */
    void armedChanged();
    /**
     * @fn void fillStatusTextChanged()
     * @brief Notify a changed status message.
     * @author Alex (<https://github.com/lextpf>)
     */
    void fillStatusTextChanged();

    /**
     * @fn void countdownSecondsChanged()
     * @brief Notify a countdown tick or reset.
     * @author Alex (<https://github.com/lextpf>)
     */
    void countdownSecondsChanged();

    /**
     * @fn void fillCompleted(const QString& statusMessage)
     * @brief The fill finished and the controller is back in Idle.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Manual mode emits this once both fields are typed. AutoArmed mode is
     * one-click-one-fill, so it emits after the password alone.
     *
     * @param statusMessage Summary for the status bar (e.g. "Filled credentials for 'GitHub'").
     */
    void fillCompleted(const QString& statusMessage);

    /**
     * @fn void fillError(const QString& errorMessage)
     * @brief A fill attempt failed and the controller cancelled back to Idle.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Covers hook-install failure, a refused release gate (focus stolen on the manual
     * path; site mismatch or changed document on the staged path), a stale
     * generation or record, unlock or decrypt failure, and `SendInput` failure.
     * Every emission except the hook-install one is followed by `cancel`, so
     * `fillCancelled` follows on the same turn.
     *
     * @param errorMessage Description of the failure, shown to the user verbatim.
     */
    void fillError(const QString& errorMessage);

    /**
     * @fn void fillCancelled()
     * @brief Notify cancellation of an active credential fill.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Covers Escape, manual timeout, re-arming, and errors after arming succeeds.
     * Hook-install failure emits only `fillError`; diagnosis uses `diagnoseCancelled`.
     */
    void fillCancelled();

    /**
     * @fn void diagnoseCompleted(const QString& summary)
     * @brief Dry-run probe completed.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param summary Multi-line breakdown, one line per probe with its verdict,
     *                confidence and evidence.
     */
    void diagnoseCompleted(const QString& summary);

    /**
     * @fn void diagnoseCancelled()
     * @brief Dry-run probe was cancelled (esc or timeout) before any click.
     * @author Alex (<https://github.com/lextpf>)
     */
    void diagnoseCancelled();

private slots:
    /**
     * @fn void onTimeoutTick()
     * @brief Decrement the countdown and cancel when it reaches zero.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Only Armed and Diagnose consume timeout ticks; AutoArmed never expires.
     */
    void onTimeoutTick();

    /**
     * @fn void performType()
     * @brief Validate and type the pending manual field on the GUI thread.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Enters Typing, then waits for ctrl release at 20 ms intervals for up to 2 s
     * to avoid shortcuts. Typing proceeds after 2 s even if Ctrl remains held.
     * Cancellation during the wait ends the run silently.
     * Click and foreground PIDs must match and be non-zero. Modifiers override fusion;
     * Unknown uses the remaining field, starting with username. Generation and record
     * checks precede decrypt.
     *
     * The record choice and the Ctrl+Click authorize the release. No bridge entry,
     * host, or visit token is checked, so a browser fills like any other target and
     * the companion extension is optional. The fused verdict only selects the field.
     * Refusal emits fillError and cancels before decrypt.
     *
     * @see decryptAndTypeField
     */
    void performType();

    /**
     * @fn void performTypeAuto()
     * @brief Validate a staged password click before any decrypt.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Allows one completion at a time. Polls every 20 ms for up to 400 ms while the
     * extension report reaches the bridge. Both visit tokens must be non-empty.
     *
     * The URL gate uses platformMatchesHostForSecretRelease; bare labels cannot
     * release credentials. A retry preserves the arm and emits no fillError.
     * Corroboration and field-kind retries occur after entering Typing, so they emit
     * armedChanged twice and reset the countdown.
     *
     * On success, decryptAndTypeField types the password. Username injection uses
     * the reverse channel.
     *
     * | Gate           | Requirement                                  | On failure          |
     * |----------------|----------------------------------------------|---------------------|
     * | Classification | Fresh bridge entry for the click point       | Stay AutoArmed      |
     * | Foreground     | Click PID and foreground PID equal, non-zero | Stay AutoArmed      |
     * | Record         | Index in range, session live, not deleted    | Cancel + error      |
     * | URL            | Strict secret-release host match             | Cancel + error      |
     * | Visit          | Entry token equals the browser's current one | Cancel + error      |
     * | Generation     | Owner counter unchanged since arming         | Cancel + error      |
     * | Corroboration  | Tier-1 short circuit and bridge corroborated | Return to AutoArmed |
     * | Field kind     | Fused verdict is Password                    | Return to AutoArmed |
     */
    void performTypeAuto();

    /**
     * @fn void performDiagnose()
     * @brief Emit probe results and return to Idle without decrypt or keystrokes.
     * @author Alex (<https://github.com/lextpf>)
     *
     * If only the bridge probe is Unknown while a peer is connected, retry the whole
     * pipeline after a blocking 75 ms GUI-thread wait for the extension report.
     */
    void performDiagnose();

private:
    /**
     * @fn bool armInternal(int recordIndex, const std::vector<seal::VaultRecord>& records,
     *     seal::CredentialSession& session, const uint64_t& ownerGeneration, State targetState)
     * @brief Initialize borrowed fill state and install hooks.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cancels a live session first. Starts the bridge unless disabled and starts the
     * 1 s timer; AutoArmed ignores timer ticks.
     *
     * @param targetState Only Armed or AutoArmed is valid.
     * @return True if both hooks installed.
     */
    [[nodiscard]] bool armInternal(int recordIndex,
                                   const std::vector<seal::VaultRecord>& records,
                                   seal::CredentialSession& session,
                                   const uint64_t& ownerGeneration,
                                   State targetState);

    /**
     * @fn void installHooks()
     * @brief Install the desktop-wide WH_MOUSE_LL and WH_KEYBOARD_LL hooks.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Failure is not reported here: the caller inspects `m_MouseHook` and
     * `m_KeyboardHook`, because either one can fail on its own.
     */
    void installHooks();

    /**
     * @fn void removeHooks()
     * @brief Remove both hooks and clear the shared callback target.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Safe when hooks are absent; callbacks then have no controller to dereference.
     */
    void removeHooks();

    /**
     * @fn void transitionTo(State newState)
     * @brief Change state and refresh the status text.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Emits armedChanged only if isArmed changes.
     */
    void transitionTo(State newState);

    /**
     * @fn void updateStatusText()
     * @brief Refresh the status text from the state and completed fields.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Emits `fillStatusTextChanged` only when the text changes.
     */
    void updateStatusText();

    /**
     * @fn LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
     * @brief Capture left-button-down and queue the selected fill path.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Runs in the installing thread's OS hook dispatcher. Updates atomics and queues
     * work without synchronous controller calls. Shift selects password and wins over
     * alt, which selects username.
     *
     * Ctrl+Click is swallowed in Armed and Diagnose. Plain AutoArmed clicks pass
     * through for focus; injected clicks are ignored to prevent SendInput from
     * releasing a staged secret. Other cases call CallNextHookEx.
     */
    static LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    /**
     * @fn LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
     * @brief Queue cancellation for Escape while waiting for a click.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses the thread rules of `mouseHookProc`. Handled Escape events are swallowed.
     * Escape passes through during Typing and cannot interrupt keystroke delivery.
     */
    static LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    /**
     * @brief Sole controller allowed to own global hooks.
     *
     * Callbacks load once per invocation. The hook cleanup clears this pointer without an
     * ownership check, so a second controller would invalidate the first one's hooks.
     */
    static std::atomic<FillController*> s_instance;

    /**
     * @enum TypeTarget
     * @brief Which credential field to type next.
     * @author Alex (<https://github.com/lextpf>)
     */
    enum class TypeTarget
    {
        Username,  ///< Forced by Ctrl+Alt+Click, or resolved from a Username verdict.
        Password,  ///< Forced by Ctrl+Shift+Click, or resolved from a Password verdict.
        Auto,      ///< Let the probe pipeline decide at fill time.
    };

    /**
     * @enum TypedFieldFlags
     * @brief Bit flags tracking which credential fields have been typed.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Only manual mode accumulates both; auto mode disarms after the password.
     */
    enum TypedFieldFlags : uint8_t
    {
        TypedNone = 0,                              ///< Nothing typed yet.
        TypedUsername = 1 << 0,                     ///< Username has been typed.
        TypedPassword = 1 << 1,                     ///< Password has been typed.
        TypedBoth = TypedUsername | TypedPassword,  ///< Manual completion condition.
    };

    /**
     * @fn seal::Verdict runProbeRegistry(LONG x, LONG y)
     * @brief Fuse probes and discard release provenance.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param x Raw screen pixels.
     * @param y Raw screen pixels.
     * @return Unknown if no probe is decisive.
     * @warning Staged auto release must use runProbeRegistryDetailed.
     */
    seal::Verdict runProbeRegistry(LONG x, LONG y);

    /**
     * @fn seal::FusionOutcome runProbeRegistryDetailed(LONG x, LONG y)
     * @brief Fuse all probes with an advisory 300 ms pass deadline.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Runs bridge, Win32 style, UIA IsPassword, UIA metadata, then IME state.
     * Logs verdict, corroboration, confidence, and sanitized evidence. The deadline
     * does not interrupt provider calls or skip later probes.
     *
     * @param x Raw screen pixels.
     * @param y Raw screen pixels.
     * @return Verdict and provenance; auto release requires both provenance flags.
     */
    seal::FusionOutcome runProbeRegistryDetailed(LONG x, LONG y);

    /**
     * @fn void decryptAndTypeField(const seal::VaultRecord& record, TypeTarget target)
     * @brief Decrypt and type a validated field through SendInput.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Unlocks the session only for decrypt, then cleanses plaintext and trims the
     * working set. Auto mode completes after one field; manual mode re-arms with a
     * reset countdown until both fields are typed. Every exit clears m_AutoFillInFlight.
     *
     * @param target Resolved field; every value except Username selects password.
     * @pre Caller validated record, generation, and all applicable release gates.
     * @post Failure emits fillError and cancels to Idle. Completion removes hooks,
     *       clears borrowed records/session pointers, and emits fillCompleted.
     */
    void decryptAndTypeField(const seal::VaultRecord& record, TypeTarget target);

    std::atomic<State> m_State{State::Idle};  ///< Current state machine state.
    int m_RecordIndex = -1;                   ///< Index of the armed vault record.
    const std::vector<seal::VaultRecord>* m_Records =
        nullptr;  ///< Borrowed pointer to vault records.
    seal::CredentialSession* m_Session =
        nullptr;  ///< Borrowed session; unlocked only for the on-demand decrypt.

    /**
     * Borrowed generation counter, read only during an active fill. Successful
     * completion and hook-install failure can leave it set while Idle; cancel clears it.
     */
    const uint64_t* m_OwnerGeneration = nullptr;
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

    // Declare the bridge before its borrowing probe so the probe is destroyed first.

    /**
     * Owned named-pipe server that the browser relay process connects to. Started
     * lazily by `armInternal`, `armDiagnose` and `enableBridge`; stopped
     * only by the destructor and by `disableBridge`, so it outlives any single fill.
     */
    seal::BrowserBridge m_BrowserBridge;
    /**
     * Tier-1 probe reading the click map of `m_BrowserBridge`, which it
     * borrows by pointer. Rule M5 lets it short-circuit fusion only with an agreeing
     * on-disk probe.
     */
    seal::BrowserBridgeProbe m_BrowserBridgeProbe{&m_BrowserBridge};
    seal::Win32StyleProbe m_Win32StyleProbe;   ///< Tier-1 native ES_PASSWORD probe (stateless).
    seal::UiaIsPasswordProbe m_UiaIsPassword;  ///< Tier-1 UIA IsPassword/MSAA probe (caches UIA).
    seal::UiaMetadataProbe
        m_UiaMetadata;  ///< Tier-2 UIA metadata + form-context probe (caches UIA).
    seal::ImeStateProbe m_ImeStateProbe;  ///< Tier-2 IME context weak signal (stateless).
    seal::FusionDecider m_FusionDecider;  ///< Fuses ProbeResults into a Verdict.

    /**
     * Seconds the controller waits for the completing click before it
     * auto-cancels. It applies to `State::Armed` and `State::Diagnose`
     * only; see `onTimeoutTick`.
     */
    static constexpr int FILL_TIMEOUT_SECONDS = 30;
};

}  // namespace seal

#endif  // USE_QT_UI
