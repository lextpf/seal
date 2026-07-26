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
 * @author Fable 5 (https://github.com/claude)
 * @ingroup FillController
 *
 * Auto-fill runs in two phases: the caller arms the controller for one vault
 * record, then a click in an external application releases the credential as
 * synthesised keystrokes (`SendInput`). Arming installs desktop-wide mouse and
 * keyboard hooks; the completing click decides which field is typed.
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
 * - **Armed** - hooks active, waiting for Ctrl+Click. The probe pipeline
 *   detects whether the clicked field is a password input; either field can be
 *   typed in any order, and bit flags track which ones are done.
 * - **Typing** - keystrokes being sent, hooks still installed.
 *
 * Two more entry points reuse the same hook machinery:
 * - **AutoArmed** - staged on navigation by StagingController (armAuto()),
 *   never by the user. A plain click (no Ctrl) into a bridge-classified login
 *   field completes the fill through the fail-closed auto gates. It has no
 *   timeout: only Esc, a re-stage, or the fill itself ends it.
 * - **Diagnose** - armDiagnose() installs the same hooks and shares the Armed
 *   timeout, but a Ctrl+Click only dry-runs the probe pipeline (no decrypt, no
 *   keystrokes) and emits diagnoseCompleted with the per-probe verdict.
 *
 * ## Complete state machine (ASCII)
 *
 * The Mermaid diagram covers the manual Ctrl+Click path only. The full machine
 * has five states across three entry points; @ref State::Typing is transient
 * and always resolves back to its path's armed state or to @ref State::Idle.
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
 * A modifier overrides which field gets typed. Modifiers apply to
 * @ref State::Armed only: while AutoArmed a Ctrl-held click is passed straight
 * through and starts nothing.
 *
 * | Gesture          | Effect                                                |
 * |------------------|-------------------------------------------------------|
 * | Ctrl+Click       | Type the field the probe pipeline detects             |
 * | Ctrl+Shift+Click | Type the password (forced, overrides detection)       |
 * | Ctrl+Alt+Click   | Type the username (forced, overrides detection)       |
 * | Esc              | Cancel and remove hooks (Armed, AutoArmed, Diagnose)  |
 *
 * ## :material-format-list-bulleted: Properties
 *
 * - **isArmed** (bool) - true in Armed and AutoArmed only
 * - **fillStatusText** (QString) - status line for the UI
 * - **countdownSeconds** (int) - seconds before auto-cancel; it ticks in Armed
 *   and Diagnose only, so AutoArmed holds it at 30
 *
 * ## :material-signal: Signals
 *
 * - **armedChanged**, **fillStatusTextChanged**, **countdownSecondsChanged** -
 *   property notifications
 * - **fillCompleted**(statusMessage) - both fields typed in manual mode, the
 *   password alone in AutoArmed mode
 * - **fillError**(errorMessage) - hook install, gate, decrypt or keystroke failure
 * - **fillCancelled** - Esc, timeout, or a re-arm over a live session
 *
 * @note One controller at a time owns the global hooks (@ref s_instance). The
 *       low-level hooks run on the installing thread, which is the GUI thread
 *       here, so the callbacks write only their atomics and queue the fill work
 *       instead of running it inside the OS hook dispatcher.
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
        Idle,       ///< No hooks, waiting for arm(), armAuto() or armDiagnose().
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

    /// @brief Whether a credential is bound and waiting for the completing click.
    /// True in @ref State::Armed and @ref State::AutoArmed only. Diagnose
    /// installs hooks but binds no credential, so it reads false, as does
    /// @ref State::Typing.
    bool isArmed() const;

    /// @brief Status line for the UI. Empty while Idle.
    QString fillStatusText() const;

    /// @brief Seconds left before auto-cancel. It counts down in Armed and
    /// Diagnose only; AutoArmed never expires, so the value stays at its
    /// arm-time @ref FILL_TIMEOUT_SECONDS.
    int countdownSeconds() const;

    /// @brief The current state machine state.
    State state() const;

    /**
     * @brief Arm the controller for one vault record (manual Ctrl+Click path).
     *
     * Installs the global mouse and keyboard hooks and enters
     * @ref State::Armed. The completing Ctrl+Click decrypts and types one
     * field; manual mode stays armed until both fields are typed.
     *
     * @par Borrowing
     * The records vector, the session and the generation counter are borrowed
     * by pointer and must outlive the fill. The master key stays
     * DPAPI-protected for the whole armed window: @ref decryptAndTypeField
     * opens a scoped @c session.unlock() around the on-demand decrypt alone.
     *
     * @par Staleness
     * A generation snapshot is taken at arm time. When the owner mutates the
     * records before the completing click, the fill cancels instead of typing a
     * credential the index no longer names. Both fill paths check it before any
     * decrypt: @ref performType before it touches the borrowed vector,
     * @ref performTypeAuto later in its gate order.
     *
     * @par Re-arming
     * When the controller is not Idle - a different record was selected, or a
     * navigation re-staged - @ref cancel runs first, so a live session emits
     * @ref fillCancelled before the new arm. This keeps the manual and auto
     * paths mutually exclusive.
     *
     * @param recordIndex     Index into @p records. Not range-checked here; an
     *                        out-of-range index still arms and then fails with
     *                        @ref fillError on the completing click.
     * @param records         Vault records, borrowed by pointer.
     * @param session         Owns the master key; unlocked only for the decrypt.
     * @param ownerGeneration Owner's monotonic mutation counter, borrowed by
     *                        pointer; it rises on every records/password change.
     * @return `true` when both hooks installed. On failure it removes the
     *         partial hooks, clears the borrowed records and session pointers,
     *         emits @ref fillError and stays Idle. It emits no
     *         @ref fillCancelled and leaves the generation pointer set; no path
     *         reads it while Idle.
     *
     * @pre Call on the GUI thread; the timeout timer and the signals live there.
     */
    [[nodiscard]] bool arm(int recordIndex,
                           const std::vector<seal::VaultRecord>& records,
                           seal::CredentialSession& session,
                           const uint64_t& ownerGeneration);

    /**
     * @brief Arm the controller for zero-gesture staged auto-fill.
     *
     * Same borrowing, generation snapshot and hook install as @ref arm, but it
     * enters @ref State::AutoArmed. There a plain left click (no Ctrl) into a
     * bridge-classified login field completes the fill through the fail-closed
     * gates listed on @ref performTypeAuto. The click is never swallowed, so
     * the field takes focus normally; a click that misses a classified login
     * field is a silent no-op that leaves the controller AutoArmed.
     *
     * This path releases only the password, and at most once: the fill tears
     * the hooks down after the first successful type. It never times out -
     * @ref onTimeoutTick ignores this state - so only Esc, a re-stage or a
     * completed fill returns it to Idle.
     *
     * Called by StagingController when a navigation report uniquely matched a
     * record and that page carries a password field. Parameters as @ref arm.
     * @return true when both hooks installed; a failure behaves like a failed
     *         @ref arm.
     */
    [[nodiscard]] bool armAuto(int recordIndex,
                               const std::vector<seal::VaultRecord>& records,
                               seal::CredentialSession& session,
                               const uint64_t& ownerGeneration);

    /**
     * @brief Consume the latest bridge navigation snapshot (GUI-thread poll).
     *
     * Passthrough to @ref BrowserBridge::takeNavSince so StagingController,
     * which does not own the bridge, can poll it. The snapshot is consumed: a
     * navigation is returned once, then @p lastSeenSeq advances past it. This
     * does not touch the fill state machine and is legal in any state.
     *
     * @param lastSeenSeq In/out cursor owned by the caller.
     * @return The one unseen snapshot, or nullopt when the bridge is disabled,
     *         nothing new arrived, or the snapshot aged out.
     */
    std::optional<seal::NavSnapshot> takeNavSince(std::uint64_t& lastSeenSeq);

    /**
     * @brief Decrypt a record's username and push it to the browser for
     *        zero-click DOM injection by the extension.
     *
     * The higher-risk half of staged auto-fill: the username value crosses into
     * the browser. Host-bound through
     * @ref seal::url::platformMatchesHostForSecretRelease, the same strict
     * matcher the selector and the password click-gate use, so a record must
     * store a real domain or URL before any browser credential is released.
     * The decrypt happens in a tight unlock() window here, keeping
     * StagingController decrypt-free; the transient plaintext UTF-8 copy is
     * wiped after the reverse-channel send.
     *
     * Independent of the fill state machine: it neither reads nor changes
     * @ref state, so it works while Idle and does not consume the staged
     * password click.
     *
     * @param recordIndex Record to read; out of range returns false.
     * @param records     Borrowed vault records, must outlive the call.
     * @param session     Borrowed session; unlocked only for the decrypt.
     * @param host        Navigated host, strict-matched and echoed to the peer.
     * @param visit       Per-document visit token that binds the injection. An
     *                    empty token returns false; an untokened page is never fed.
     * @param browserPid  Validated browser PID whose peer receives the directive.
     * @return true only when the directive reached a live peer.
     *         StagingController latches its once-per-visit guarantee on this, so
     *         a failed send may be retried on a later navigation of the same
     *         visit. It returns false, emitting no signal, when the index is out
     *         of range, the record is soft-deleted, @p visit is empty, the host
     *         does not strict-match, the bridge is disabled, the unlock or
     *         decrypt fails, the decrypted username is empty, or no peer serves
     *         @p browserPid.
     */
    [[nodiscard]] bool injectUsername(int recordIndex,
                                      const std::vector<seal::VaultRecord>& records,
                                      seal::CredentialSession& session,
                                      const std::string& host,
                                      const std::string& visit,
                                      DWORD browserPid);

    /**
     * @brief Arm the controller in dry-run diagnose mode.
     *
     * Like @ref arm but it binds no credential. It installs the same mouse and
     * keyboard hooks; the next Ctrl+Click runs the full probe pipeline (browser
     * bridge, Win32, UIA, IME), fuses the verdict and emits
     * @ref diagnoseCompleted with a readable summary. No decrypt and no
     * keystrokes, so it is safe on any field, including fields owned by other
     * applications.
     *
     * Use it to test the browser extension end to end: arm diagnose, switch to
     * the browser, Ctrl+Click an input field, read the per-probe verdict to
     * confirm the bridge fired.
     *
     * Esc or the @ref FILL_TIMEOUT_SECONDS timeout cancels with
     * @ref diagnoseCancelled. @ref isArmed stays false throughout, so a UI that
     * only watches the armed property does not see diagnose mode.
     *
     * @return true when both hooks installed. On failure it emits
     *         @ref fillError, not @ref diagnoseCancelled, and stays Idle.
     */
    [[nodiscard]] bool armDiagnose();

    /**
     * @brief Cancel the current fill and remove all hooks.
     *
     * Safe from any state; a no-op while Idle. It stops the timer, removes the
     * hooks, clears the borrowed records, session and generation pointers and
     * the typed-field flags, then returns to Idle. It does not stop the browser
     * bridge; only @ref disableBridge does that.
     *
     * It emits @ref diagnoseCancelled when the previous state was
     * @ref State::Diagnose, otherwise @ref fillCancelled. A diagnose run that
     * already reached @ref performDiagnose is back in Idle, so cancelling after
     * it emits nothing.
     */
    Q_INVOKABLE void cancel();

    /**
     * @brief Panic mode: disable the browser bridge (M8).
     *
     * Closes the pipe handle, refuses further messages, and clears the
     * in-memory click map, the pending navigation snapshot and the per-process
     * visit tokens. Safe from any state. It does not cancel an armed fill, but
     * a staged auto-fill can no longer complete, because its gates need a live
     * bridge entry. Re-enable with @ref enableBridge.
     *
     * It blocks the GUI thread while it joins the bridge acceptor and its
     * connection workers: the acceptor polls its stop token every 200 ms, and a
     * worker parked in a read can take up to its 1 s stop poll to see the stop
     * request. See @ref BrowserBridge::disable.
     */
    Q_INVOKABLE void disableBridge();

    /**
     * @brief Clear panic mode and make sure the bridge pipe is listening.
     *
     * Clearing the disabled flag restarts the accept thread on a freshly
     * generated pipe-name secret, so the pipe name rotates (M7) and a peer that
     * still holds the previous name cannot reconnect; see
     * @ref BrowserBridge::enable. It then starts the pipe server whenever it is
     * not already running, in any fill state, and even if the bridge was never
     * disabled.
     *
     * Starting eagerly matters: the extension opens its native-messaging port
     * at browser load, so a missing pipe pushes its reconnect into exponential
     * backoff (tens of seconds) and the first Ctrl+Click finds no peer.
     */
    Q_INVOKABLE void enableBridge();

    /// @brief Whether the bridge is enabled, that is not in panic mode.
    bool isBridgeEnabled() const;

    /**
     * @brief Whether the bridge enforces peer signer authentication.
     *
     * False when this binary is unsigned; the M6 signer gate then accepts any
     * peer. Fixed at startup from the running binary's Authenticode identity
     * and surfaced by the UI, so an unsigned build shows a "peer auth disabled"
     * warning. See @ref BrowserBridge::isPeerAuthEnforced.
     */
    bool isBridgePeerAuthEnforced() const;

    /**
     * @brief Whether any relay process (`seal-browser.exe`) is connected to the
     *        bridge, with the pipe handshake complete.
     *
     * BrowserBridge is not a QObject, so BridgeViewModel polls this at 1 Hz and
     * turns level changes into its aggregate `bridgePeerConnected` property.
     * The three accessors below share that poll.
     */
    bool isBridgePeerConnected() const;

    /**
     * @brief Whether a peer launched by @p kind is currently connected.
     *
     * The per-browser source of truth: BridgeViewModel builds its `browsers`
     * model from this, which drives the status dots in the UI.
     *
     * @param kind Browser identity established by the bridge signer walk.
     */
    bool isBridgeBrowserConnected(seal::signer::BrowserKind kind) const;

    /// @brief Whether a Chrome-launched relay process is connected.
    /// Fixed-browser shorthand for @ref isBridgeBrowserConnected; it backs the
    /// `bridgeChromeConnected` property, which no QML file binds today.
    bool isBridgeChromeConnected() const;

    /// @brief Whether a Brave-launched relay process is connected.
    /// Fixed-browser shorthand for @ref isBridgeBrowserConnected; it backs the
    /// `bridgeBraveConnected` property, which no QML file binds today.
    bool isBridgeBraveConnected() const;

signals:
    /// @brief The armed/disarmed boundary was crossed. Moves that keep
    /// @ref isArmed the same (Armed to Typing to Armed) stay silent, so QML
    /// bindings are not woken for states that look identical to the front end.
    void armedChanged();
    void fillStatusTextChanged();    ///< Status text updated.
    void countdownSecondsChanged();  ///< Countdown tick or reset.

    /**
     * @brief The fill finished and the controller is back in Idle.
     *
     * Manual mode emits this once both fields are typed. AutoArmed mode is
     * one-click-one-fill, so it emits after the password alone.
     *
     * @param statusMessage Summary for the status bar (e.g. "Filled credentials for 'GitHub'").
     */
    void fillCompleted(const QString& statusMessage);

    /**
     * @brief A fill attempt failed and the controller cancelled back to Idle.
     *
     * Covers hook-install failure, a refused release gate (site mismatch,
     * changed document, unconfirmed password field, focus stolen), a stale
     * generation or record, unlock or decrypt failure, and `SendInput` failure.
     * Every emission except the hook-install one is followed by @ref cancel, so
     * @ref fillCancelled follows on the same turn.
     *
     * @param errorMessage Description of the failure, shown to the user verbatim.
     */
    void fillError(const QString& errorMessage);

    /// @brief The bound fill ended without completing: Esc, the Armed timeout,
    /// a re-arm over a live session, or any @ref fillError path.
    void fillCancelled();

    /**
     * @brief Dry-run probe completed.
     * @param summary Multi-line breakdown, one line per probe with its verdict,
     *                confidence and evidence.
     */
    void diagnoseCompleted(const QString& summary);

    /// @brief Dry-run probe was cancelled (Esc or timeout) before any click.
    void diagnoseCancelled();

private slots:
    /// @brief One-second tick. It decrements the countdown and auto-cancels at
    /// zero, but only in @ref State::Armed and @ref State::Diagnose; every
    /// other state returns at once, which is why AutoArmed never expires.
    void onTimeoutTick();

    /**
     * @brief Queued from the mouse hook; decrypts and types the pending field.
     *
     * Enters @ref State::Typing at once, then polls at 20 ms until Ctrl is
     * released (2 s cap for a stuck key), because keystrokes sent while Ctrl is
     * down register as shortcuts. A @ref cancel during that poll ends the run
     * silently.
     *
     * @par Order after the poll
     * The clicked window and the foreground window must belong to the same
     * non-zero process. The target field is then resolved: Shift or Alt was
     * already resolved in the hook, otherwise the fused probe verdict decides,
     * and an Unknown verdict falls back to whichever field is still untyped
     * (username when neither is). Next the generation and the record are
     * re-validated, then the browser gates run.
     *
     * @par Browser gates
     * They apply only when a bridge entry exists for the click point: its host
     * must strict-match the record, the entry must not contradict the document
     * now loaded, and a password release must also be Tier-1 short-circuited
     * and bridge-corroborated. The document check blocks only when the
     * browser's current visit token is known and differs from the entry's, so
     * an untagged click falls back to the host check alone - the fail-open
     * contract of @ref seal::visitAuthorizes. @ref performTypeAuto applies the
     * fail-closed form of the same gate and requires both tokens to be present
     * and equal. A click into a known browser image with no bridge entry is
     * refused outright; any other target carries no URL context and fills
     * without these gates. Every refusal emits @ref fillError and cancels,
     * always before the decrypt.
     *
     * Typing is delegated to @ref decryptAndTypeField, which stays Armed for
     * the second field and only then completes.
     */
    void performType();

    /**
     * @brief Queued from the mouse hook on a plain click while AutoArmed.
     *
     * The zero-gesture completion path, and the only one that releases a secret
     * without a modifier. A single-flight flag makes overlapping clicks a
     * no-op. The click report travels browser to service worker to host to
     * pipe, so the bridge entry is usually absent at click time: this polls for
     * it at 20 ms for up to 400 ms before failing closed.
     *
     * Every gate runs before any decrypt, so a refusal never produces plaintext.
     *
     * @par Release gates, in order
     * | Gate           | Requirement                                    | On failure          |
     * |----------------|------------------------------------------------|---------------------|
     * | classification | fresh bridge entry for the click point         | stay AutoArmed      |
     * | foreground     | click PID and foreground PID equal, non-zero   | stay AutoArmed      |
     * | record         | index in range, session live, not deleted      | cancel + error      |
     * | URL            | strict secret-release host match (see below)   | cancel + error      |
     * | visit          | entry token equals the browser's current one   | cancel + error      |
     * | generation     | owner counter unchanged since arming           | cancel + error      |
     * | corroboration  | Tier-1 short circuit and bridge corroborated   | return to AutoArmed |
     * | field kind     | fused verdict is Password                      | return to AutoArmed |
     *
     * The last two gates run after the controller has entered
     * @ref State::Typing, so a refusal there emits @ref armedChanged twice,
     * shows the Typing status briefly, and restarts the countdown before the
     * AutoArmed prompt returns.
     *
     * The URL gate uses @ref seal::url::platformMatchesHostForSecretRelease,
     * not the tiered @ref seal::url::platformMatchesHost, so a record whose
     * platform is a bare label such as "PayPal" never auto-releases. "Stay
     * AutoArmed" and "return to AutoArmed" release no secret, emit no
     * @ref fillError, and keep the arm live for a later click; "cancel"
     * disarms after a @ref fillError.
     *
     * On success it types the password through @ref decryptAndTypeField; the
     * username half is the extension DOM injection (@ref injectUsername).
     */
    void performTypeAuto();

    /**
     * @brief Queued from the mouse hook while in @ref State::Diagnose.
     *
     * Runs the probe pipeline at the captured click point, builds a multi-line
     * summary, emits @ref diagnoseCompleted and returns to Idle. It never
     * decrypts a credential and never sends keystrokes.
     *
     * When the bridge probe alone reads Unknown while a peer is connected, the
     * whole pipeline re-runs once after a 75 ms blocking `Sleep` on the GUI
     * thread. Only the bridge probe rides the async extension path, so a
     * just-woken service worker can land its report after the Ctrl+Click; the
     * fill path absorbs that in its Ctrl-release poll, diagnose has no such
     * wait of its own.
     */
    void performDiagnose();

private:
    /**
     * @brief Shared body of @ref arm and @ref armAuto.
     *
     * In order: cancel any live session, record the borrowed pointers and the
     * generation snapshot, reset the countdown, pending target and typed-field
     * flags, start the bridge unless it is running or disabled, claim the
     * `s_instance` singleton, install the hooks, then start the 1 s timeout
     * timer. That timer also runs in @ref State::AutoArmed, where
     * `onTimeoutTick` discards every tick.
     *
     * `m_AutoMode` follows @p targetState, which is what makes
     * `decryptAndTypeField` disarm after one field instead of two.
     *
     * @param targetState @ref State::Armed (manual Ctrl+Click) or
     *                    @ref State::AutoArmed (staged). No other value is valid.
     * @return true when both hooks installed.
     */
    [[nodiscard]] bool armInternal(int recordIndex,
                                   const std::vector<seal::VaultRecord>& records,
                                   seal::CredentialSession& session,
                                   const uint64_t& ownerGeneration,
                                   State targetState);

    /// @brief Install the desktop-wide WH_MOUSE_LL and WH_KEYBOARD_LL hooks.
    /// Failure is not reported here: the caller inspects @ref m_MouseHook and
    /// @ref m_KeyboardHook, because either one can fail on its own.
    void installHooks();

    /// @brief Remove both hooks and clear @ref s_instance so an in-flight hook
    /// callback cannot dereference a dead controller. Safe when not installed.
    void removeHooks();

    /**
     * @brief Move to @p newState and refresh the status text.
     *
     * @ref armedChanged is emitted only when @ref isArmed differs before and
     * after, so Armed to Typing to Armed is silent for QML.
     */
    void transitionTo(State newState);

    /// @brief Rebuild @ref m_StatusText from the current state and
    /// @ref m_TypedFields, emitting @ref fillStatusTextChanged only on a change.
    void updateStatusText();

    /**
     * @brief Low-level mouse hook callback; reacts to left-button-down only.
     *
     * Runs on the installing thread inside the OS hook dispatcher, so it keeps
     * its work minimal: it reads @ref m_State, stores the click point and the
     * resolved @ref TypeTarget in the atomics, then queues @ref performType,
     * @ref performTypeAuto or @ref performDiagnose over a queued connection.
     * Shift selects `Password`, Alt selects `Username`, any other modifier
     * state selects `Auto`, and Shift wins when both are held. It writes no
     * other controller state and calls no controller method synchronously; the
     * only other synchronous work is a category log.
     *
     * @par Click disposal
     * A Ctrl+Click while Armed or Diagnose is swallowed (returns 1) so the
     * target application never activates the control under the cursor. A plain
     * click while AutoArmed is passed on instead, so the field still takes
     * focus; an injected click (`LLMHF_INJECTED` or `LLMHF_LOWER_IL_INJECTED`)
     * is ignored on that path, because a local process must not release a
     * staged secret with `SendInput`. Every other case falls through to
     * `CallNextHookEx`.
     */
    static LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    /// @brief Low-level keyboard hook callback (same thread rules as
    /// @ref mouseHookProc). It handles Esc alone, and only while Armed,
    /// AutoArmed or Diagnose; Esc during Typing is passed through, so it cannot
    /// interrupt an in-flight keystroke run. A handled Esc queues @ref cancel
    /// and is swallowed (returns 1).
    static LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam);

    /**
     * @brief Singleton: one controller at a time owns the global hooks.
     *
     * The hook callbacks load it once per invocation, because a concurrent @ref cancel can
     * null it between loads. Both arm paths store this pointer and @ref removeHooks clears it
     * with no ownership check, so a second instance would take over the first one's hooks;
     * the composition root (QmlMain.cpp) constructs exactly one FillController.
     */
    static std::atomic<FillController*> s_instance;

    /// @enum TypeTarget
    /// @brief Which credential field to type next.
    enum class TypeTarget
    {
        Username,  ///< Forced by Ctrl+Alt+Click, or resolved from a Username verdict.
        Password,  ///< Forced by Ctrl+Shift+Click, or resolved from a Password verdict.
        Auto,      ///< Let the probe pipeline decide at fill time.
    };

    /// @enum TypedFieldFlags
    /// @brief Bit flags tracking which credential fields have been typed.
    /// Only manual mode accumulates both; auto mode disarms after the password.
    enum TypedFieldFlags : uint8_t
    {
        TypedNone = 0,                              ///< Nothing typed yet.
        TypedUsername = 1 << 0,                     ///< Username has been typed.
        TypedPassword = 1 << 1,                     ///< Password has been typed.
        TypedBoth = TypedUsername | TypedPassword,  ///< Manual completion condition.
    };

    /**
     * @brief Run the probe registry against a click point and fuse the results.
     *
     * Keeps the verdict of @ref runProbeRegistryDetailed and drops the
     * provenance flags, for callers where a bare Password/Username/Unknown
     * answer is enough. No call site uses it today: both fill paths need the
     * flags, and @ref performDiagnose builds its own pass.
     *
     * @warning A secret release must use the detailed form.
     *
     * @param x Screen-space X (raw mouse hook output).
     * @param y Screen-space Y.
     * @return The fused verdict. `Verdict::Unknown` means no probe was
     *         decisive and the caller must pick a default itself.
     */
    seal::Verdict runProbeRegistry(LONG x, LONG y);

    /**
     * @brief Run every probe against a click point and fuse the results.
     *
     * Builds a `seal::ProbeContext` from the point (target window and its
     * process id resolved with `WindowFromPoint`), gives the whole pass a
     * 300 ms deadline, then runs the five probes in a fixed order - bridge,
     * Win32 style, UIA IsPassword, UIA metadata, IME state - and fuses them
     * with `seal::FusionDecider::decideDetailed`. The probes are member
     * objects, so the UIA ones keep their cached automation state between calls.
     *
     * Each call logs one `event=fill.decide` line to `logFill` carrying the
     * fused verdict, the corroboration flag, and every probe's verdict,
     * confidence and sanitised evidence, so weight tuning is telemetry-driven.
     *
     * @param x Screen-space X (raw mouse hook output).
     * @param y Screen-space Y.
     * @return The verdict plus the @ref FusionOutcome provenance flags. The
     *         auto path releases a secret only when both flags are set, which
     *         is why the detailed form exists.
     */
    seal::FusionOutcome runProbeRegistryDetailed(LONG x, LONG y);

    /**
     * @brief Decrypt the record's selected field and type it via `SendInput`.
     *
     * The single decrypt-and-type site, shared by @ref performType (manual) and
     * @ref performTypeAuto. It opens a scoped `session.unlock()` around the
     * on-demand decrypt alone, types the field with `seal::typeSecret` and no
     * pre-typing delay, then cleanses the plaintext and trims the working set.
     *
     * @par Completion
     * It completes - stops the timer, tears down the hooks, clears the borrowed
     * records and session pointers, returns to Idle and emits
     * @ref fillCompleted - when both fields have been typed or @ref m_AutoMode
     * is set. In manual mode with one field still pending it instead resets the
     * countdown and returns to @ref State::Armed for the other field's
     * Ctrl+Click. Every exit path clears @ref m_AutoFillInFlight, which is what
     * lets the auto path take a later click after a refused one.
     *
     * @param record Already-validated record.
     * @param target The resolved field to type. @ref TypeTarget::Auto must have
     *               been resolved by the caller: anything other than
     *               @ref TypeTarget::Username types the password.
     *
     * @pre The caller validated the record, the generation and, for the auto
     *      path, every release gate. This function applies no gate of its own.
     * @post On failure it emits @ref fillError and cancels, so the controller
     *       is Idle whatever happened.
     */
    void decryptAndTypeField(const seal::VaultRecord& record, TypeTarget target);

    std::atomic<State> m_State{State::Idle};  ///< Current state machine state.
    int m_RecordIndex = -1;                   ///< Index of the armed vault record.
    const std::vector<seal::VaultRecord>* m_Records =
        nullptr;  ///< Borrowed pointer to vault records.
    seal::CredentialSession* m_Session =
        nullptr;  ///< Borrowed session; unlocked only for the on-demand decrypt.

    /// Points to the owner's generation counter; null while Idle, and a null
    /// pointer makes the fill paths skip the staleness check entirely.
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

    // Declaration order is load-bearing: members destruct in reverse
    // declaration order, so the probe - declared after the bridge - dies while
    // the bridge it borrows is still alive. Moving m_BrowserBridge below the
    // probe still compiles and silently breaks that ownership rule.

    /// Owned named-pipe server that the browser relay process connects to. Started
    /// lazily by @ref armInternal, @ref armDiagnose and @ref enableBridge; stopped
    /// only by the destructor and by @ref disableBridge, so it outlives any single fill.
    seal::BrowserBridge m_BrowserBridge;
    /// Tier-1 probe reading the click map of @ref m_BrowserBridge, which it
    /// borrows by pointer. Rule M5 forbids it from deciding a fill alone.
    seal::BrowserBridgeProbe m_BrowserBridgeProbe{&m_BrowserBridge};
    seal::Win32StyleProbe m_Win32StyleProbe;   ///< Tier-1 native ES_PASSWORD probe (stateless).
    seal::UiaIsPasswordProbe m_UiaIsPassword;  ///< Tier-1 UIA IsPassword/MSAA probe (caches UIA).
    seal::UiaMetadataProbe
        m_UiaMetadata;  ///< Tier-2 UIA metadata + form-context probe (caches UIA).
    seal::ImeStateProbe m_ImeStateProbe;  ///< Tier-2 IME context weak signal (stateless).
    seal::FusionDecider m_FusionDecider;  ///< Fuses ProbeResults into a Verdict.

    /// Seconds the controller waits for the completing click before it
    /// auto-cancels. It applies to @ref State::Armed and @ref State::Diagnose
    /// only; see @ref onTimeoutTick.
    static constexpr int FILL_TIMEOUT_SECONDS = 30;
};

}  // namespace seal

#endif  // USE_QT_UI
