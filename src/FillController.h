#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>
#include <QTimer>

#include <UIAutomation.h>
#include <windows.h>
#include <atomic>
#include <vector>

#include "Cryptography.h"
#include "Vault.h"

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
 * ## :material-keyboard: Modifier Keys
 *
 * While armed, the user can override which field gets typed:
 * - **Ctrl+Click** - type whichever field the state expects (username or password)
 * - **Ctrl+Shift+Click** - force type password regardless of state
 * - **Ctrl+Alt+Click** - force type username regardless of state
 * - **Esc** - cancel and remove hooks
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
        Idle,    ///< No hooks, waiting for arm().
        Armed,   ///< Hooks active, waiting for Ctrl+Click to type either field.
        Typing,  ///< Keystrokes being sent to target window.
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
     * to Armed. The controller borrows pointers to the records vector
     * and master password (caller must keep them alive until fill completes
     * or is cancelled).
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
     * @param masterPw        Master password for on-demand decryption (must outlive the fill)
     * @param ownerGeneration Monotonic counter owned by the caller; incremented on every
     *                        records/password mutation.
     * @return `true` if hooks were installed and arming succeeded.
     */
    [[nodiscard]] bool arm(
        int recordIndex,
        const std::vector<seal::VaultRecord>& records,
        const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw,
        const uint64_t& ownerGeneration);

    /**
     * @brief Cancel the current fill operation and remove all hooks.
     *
     * Safe to call from any state; no-op if already Idle.
     * Emits fillCancelled.
     */
    Q_INVOKABLE void cancel();

signals:
    void armedChanged();             ///< Armed state toggled on or off.
    void fillStatusTextChanged();    ///< Status text updated.
    void countdownSecondsChanged();  ///< Countdown tick or reset.

    /// @brief Both credentials were typed successfully.
    /// @param statusMessage Summary for the status bar (e.g. "Filled credentials for 'GitHub'").
    void fillCompleted(const QString& statusMessage);

    /// @brief A decrypt or keystroke error occurred during fill.
    /// @param errorMessage Description of the failure.
    void fillError(const QString& errorMessage);

    /// @brief Fill was cancelled by user (Esc) or timeout.
    void fillCancelled();

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

private:
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

    /// @brief Probe the UIA element at screen (x, y) for the IsPassword property.
    /// @return +1 if IsPassword=TRUE, 0 if IsPassword=FALSE, -1 on probe failure.
    int probeIsPassword(LONG x, LONG y);

    std::atomic<State> m_State{State::Idle};  ///< Current state machine state.
    int m_RecordIndex = -1;                   ///< Index of the armed vault record.
    const std::vector<seal::VaultRecord>* m_Records =
        nullptr;  ///< Borrowed pointer to vault records.
    const seal::basic_secure_string<wchar_t,
                                    seal::locked_allocator<wchar_t>>* m_MasterPw =
        nullptr;  ///< Borrowed pointer to master password.

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
    IUIAutomation* m_UIA = nullptr;     ///< Cached UI Automation client; lazy-init in arm().

    static constexpr int FILL_TIMEOUT_SECONDS = 30;  ///< Max seconds to wait for user click.
};

}  // namespace seal

#endif  // USE_QT_UI
