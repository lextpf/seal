#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>

#include "CredentialWorkspace.hpp"
#include "IFillControl.hpp"
#include "IPasswordGate.hpp"
#include "IUiFeedback.hpp"

namespace seal
{

class AsyncRunner;
class FillController;

/**
 * @class TypeController
 * @brief QML-facing auto-type surface that drives the borrowed FillController
 *        engine and owns the typing worker.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Exposes the auto-fill state (armed, status, countdown) as Q_PROPERTY values
 * and the typing commands as Q_INVOKABLE methods, so QML binds to a dedicated
 * `Fill` context property rather than the broad application view model. The
 * three properties are pure relays: they read the engine and re-emit its change
 * signals, so this class holds no fill state of its own.
 *
 * It implements seal::IFillControl so the application view model can arm and
 * cancel the engine through a narrow seam without referencing FillController
 * directly. The master key is cloned on the GUI thread inside a tight
 * `unlock()` window; the worker thread touches only that snapshot and cleanses
 * it on exit, so it never reads the workspace off-thread.
 *
 * @par Two separate typing paths
 * Neither path shares typing state with the other, but each refuses to start
 * while the other runs: the immediate path returns early when the engine is
 * armed, and the engine path returns early while the busy flag is set.
 * - typeLogin() / typePassword() - the immediate path. A 3 s countdown, then a
 *   worker types into whatever window happens to be focused. No hooks, no
 *   click, no field detection, no site binding. No `qml/` file calls either
 *   method today, so this path is API surface rather than a reachable gesture.
 * - armFor() - the engine path. Global hooks are installed and the user picks
 *   the field by clicking it, so the engine's probe and URL-binding gates apply.
 *
 * @warning Every reference member is borrowed from the composition root and
 *          must outlive this object. Call every public method on the GUI
 *          thread; only the typing worker body runs off it.
 */
class TypeController : public QObject, public seal::IFillControl
{
    Q_OBJECT

    Q_PROPERTY(bool isFillArmed READ isFillArmed NOTIFY fillArmedChanged)
    Q_PROPERTY(QString fillStatusText READ fillStatusText NOTIFY fillStatusTextChanged)
    Q_PROPERTY(
        int fillCountdownSeconds READ fillCountdownSeconds NOTIFY fillCountdownSecondsChanged)

public:
    /**
     * @brief Construct the controller and relay the engine's fill signals.
     *
     * The engine's armed, status and countdown signals pass straight through to
     * this object's own. Its outcome signals map onto the status sink: a
     * completed or cancelled fill only writes a status line, while
     * seal::FillController::fillError also emits @ref errorOccurred and
     * restores, raises and activates every top-level window. Staying minimised
     * on success keeps focus in the application that was just filled.
     *
     * The engine is shared with seal::StagingController, so these handlers also
     * run for the staged zero-gesture path, which this object never arms. A staged
     * refusal that emits seal::FillController::fillError therefore raises and
     * activates the seal windows over the browser the user is typing in. Staged
     * gates that keep the engine armed emit nothing and stay invisible.
     *
     * @param workspace   Qt-free core that owns the records and the session.
     * @param ui          Status sink for busy, countdown and status feedback.
     * @param gate        Defers arming until the master password is set.
     * @param engine      Fill engine owned by the composition root, borrowed here.
     * @param asyncRunner Runs the typing worker off the GUI thread.
     * @param parent      Optional QObject parent.
     */
    TypeController(seal::CredentialWorkspace& workspace,
                   seal::IUiFeedback& ui,
                   seal::IPasswordGate& gate,
                   seal::FillController& engine,
                   seal::AsyncRunner& asyncRunner,
                   QObject* parent = nullptr);

    /// @brief Whether a credential is bound and waiting for the completing
    /// click. Relays seal::FillController::isArmed, so it stays false during a
    /// diagnose dry run even though hooks are installed then.
    bool isFillArmed() const;

    /// @brief The auto-fill status message. Empty while the engine is idle.
    QString fillStatusText() const;

    /// @brief Seconds remaining before auto-fill times out. It counts down in
    /// the manual and diagnose states only; a staged arm holds the value.
    int fillCountdownSeconds() const;

    /**
     * @brief Auto-type the full login sequence into the focused window.
     *
     * A 3-second countdown gives the user time to focus the target field. A
     * worker then decrypts the credential on demand, types the username via
     * synthesised keystrokes (`SendInput`), sends Tab, and types the password.
     *
     * @verbatim
     *   t = 0      3 s countdown (QTimer, 1 s ticks) - focus the target field
     *   t = 3 s    type username      (SendInput UNICODE)
     *              wait 200 ms        (field registers the username)
     *              Tab down + up      (SendInput VK_TAB - advance focus)
     *              wait 100 ms        (focus settles on the password field)
     *              type password      (SendInput UNICODE)
     * @endverbatim
     *
     * typePassword() shares the 3 s countdown but types the password only, with
     * no username and no Tab.
     *
     * @warning There is no field detection and no site binding here: the
     *          keystrokes go to whatever window holds focus when the countdown
     *          ends. There is also no soft-delete check, so a record that
     *          deleteAccount() hid is still typed until saveVault() erases it.
     *          Use armFor() when the target must be verified.
     *
     * The call is dropped without feedback when @p index is out of range, when
     * a background operation is busy, or when the fill engine is armed. Without
     * the master password the whole call is enqueued on the password gate and
     * replayed unchanged, so all three checks run again at that later point.
     *
     * @param index Record index into the workspace record vector, as returned by
     *              VaultListModel::recordIndexForRow() - not a filtered row.
     */
    Q_INVOKABLE void typeLogin(int index);

    /**
     * @brief Auto-type only the password into the focused window.
     *
     * Decrypts the credential on demand and types the password field via
     * synthesised keystrokes (`SendInput`). Unlike typeLogin() it types no
     * username and sends no Tab key. Same 3 s countdown, same password-gate
     * deferral, the same range, busy and armed refusals, and the same warning:
     * no field detection, no site binding and no soft-delete check.
     *
     * @param index Record index into the workspace record vector, as returned by
     *              VaultListModel::recordIndexForRow() - not a filtered row.
     */
    Q_INVOKABLE void typePassword(int index);

    /**
     * @brief Cancel an active auto-fill operation.
     *
     * Removes the global hooks and resets the fill engine to idle.
     * Unconditional: unlike cancelIfArmed() it also ends a diagnose dry run. It
     * does not stop a countdown the immediate typing path has already started.
     */
    Q_INVOKABLE void cancelFill();

    /**
     * @brief Arm auto-fill hooks for one credential (seal::IFillControl).
     *
     * Self-gating: when the master password is not yet set the arm is deferred
     * through the password gate, otherwise the engine arms at once. It installs
     * global mouse and keyboard hooks; each Ctrl+Click in an external window
     * then runs the probe pipeline on the field under the cursor and types
     * whichever credential fits, in either order, until both are filled.
     * Ctrl+Shift+Click forces the password and Ctrl+Alt+Click forces the
     * username when the detection needs overriding.
     *
     * @par Side effect
     * A successful arm minimises every visible top-level window so the target
     * application is reachable, and the status line becomes the Ctrl+Click
     * prompt. The window is restored only if the fill later fails.
     *
     * Ignored without feedback when @p recordIndex is out of range or a
     * background operation is already busy. The deferred continuation re-enters
     * at doArm(), not here, so the password gate is consulted once per request.
     *
     * @param recordIndex Position in the full record list, not the filtered row.
     */
    void armFor(int recordIndex) override;

    /**
     * @brief Cancel any active auto-fill operation (seal::IFillControl).
     *
     * A no-op unless seal::FillController::isArmed is true, so it cancels the
     * manual and staged paths but leaves a diagnose dry run alone. Use
     * cancelFill() to cancel unconditionally.
     */
    void cancelIfArmed() override;

signals:
    void fillArmedChanged();             ///< Auto-fill armed state toggled.
    void fillStatusTextChanged();        ///< Auto-fill status message updated.
    void fillCountdownSecondsChanged();  ///< Auto-fill countdown tick.

    /**
     * @brief A fill error occurred that should be shown to the user.
     * @param title   Dialog title.
     * @param message Error description.
     */
    void errorOccurred(const QString& title, const QString& message);

private:
    /// @brief Typing mode for scheduleTypingAction.
    enum class TypingMode
    {
        Login,    ///< Username, Tab, then password.
        Password  ///< Password only; no username and no Tab.
    };

    /**
     * @brief Start a 3-second countdown, then run a typing action.
     *
     * Shared implementation of typeLogin() and typePassword(). It sets the busy
     * flag immediately, which is what keeps a second request out for the whole
     * countdown; the worker's completion callback or one of the two late aborts
     * clears it again.
     *
     * At the end of the countdown it snapshots the record and clones the master
     * password inside a GUI-thread `unlock()` window, then hands both to the
     * worker, so the worker never reads the workspace. The clone lives in locked
     * memory behind a shared_ptr, because the async runner decay-copies the work
     * body, and the worker cleanses it on exit.
     *
     * Two late aborts clear busy and type nothing: the record index no longer
     * being in range when the countdown ends, and a failed session unlock.
     *
     * @pre The caller already checked the busy flag; this function asserts it.
     *
     * @param index Record index to type.
     * @param mode  Whether to type login (username, Tab, password) or password only.
     * @param label Status label, for example "Login" or "Password".
     */
    void scheduleTypingAction(int index, TypingMode mode, const QString& label);

    /**
     * @brief Arm the engine for @p recordIndex once the password is available.
     *
     * Validates the index, ignores the request while busy, logs the arm, and
     * arms the engine against the workspace records, session and generation. A
     * successful arm writes the Ctrl+Click prompt to the status sink and
     * minimises every visible top-level window; a refused arm logs
     * `reason=controller_rejected` and changes no UI state.
     *
     * @param recordIndex Position in the full record list, not the filtered row.
     */
    void doArm(int recordIndex);

    seal::CredentialWorkspace& m_Workspace;  ///< Qt-free core: records, session.
    seal::IUiFeedback& m_Ui;                 ///< Status/busy/countdown sink.
    seal::IPasswordGate& m_Gate;             ///< Defers arming until password set.
    seal::FillController& m_Engine;          ///< Borrowed auto-fill engine.
    seal::AsyncRunner& m_Async;              ///< Runs the typing sequence on a worker thread.
};

}  // namespace seal

#endif  // USE_QT_UI
