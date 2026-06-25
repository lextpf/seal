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
 * @brief QML-facing auto-type/fill surface that drives the borrowed
 *        FillController engine and owns the typing worker.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Exposes the auto-fill state (armed/status/countdown) as Q_PROPERTY values
 * and the typing commands as Q_INVOKABLE methods, so QML binds to a dedicated
 * `Fill` context property rather than the broad application ViewModel.
 *
 * Implements seal::IFillControl so the application ViewModel can arm/cancel
 * the engine through a narrow seam without referencing the FillController
 * directly. The master key is cloned on the GUI thread inside a tight
 * `unlock()` window; the worker thread only ever touches the snapshot and
 * cleanses it on exit, so it never reaches into the workspace off-thread.
 */
class TypeController : public QObject, public seal::IFillControl
{
    Q_OBJECT

    Q_PROPERTY(bool isFillArmed READ isFillArmed NOTIFY fillArmedChanged)
    Q_PROPERTY(QString fillStatusText READ fillStatusText NOTIFY fillStatusTextChanged)
    Q_PROPERTY(
        int fillCountdownSeconds READ fillCountdownSeconds NOTIFY fillCountdownSecondsChanged)

public:
    /// @brief Construct the controller and relay the engine's fill signals.
    /// @param workspace    Injected Qt-free core that owns records and session.
    /// @param ui           Status sink for busy/countdown/status feedback.
    /// @param gate         Password gate used to defer arming until the password is set.
    /// @param engine       Borrowed fill engine owned by the composition root.
    /// @param asyncRunner  Async runner (held for future worker migration).
    /// @param parent       Optional QObject parent.
    TypeController(seal::CredentialWorkspace& workspace,
                   seal::IUiFeedback& ui,
                   seal::IPasswordGate& gate,
                   seal::FillController& engine,
                   seal::AsyncRunner& asyncRunner,
                   QObject* parent = nullptr);

    /// @brief Check whether the auto-fill hooks are armed.
    bool isFillArmed() const;

    /// @brief Get the current auto-fill status message.
    QString fillStatusText() const;

    /// @brief Get seconds remaining before auto-fill times out.
    int fillCountdownSeconds() const;

    /**
     * @brief Auto-type the full login sequence into the focused window.
     *
     * Decrypts the credential on demand, types the username via synthesised
     * keystrokes (`SendInput`), sends a Tab key to advance focus, then types
     * the password. A 3-second countdown gives the user time to focus the
     * target field before typing begins.
     *
     * @param index Row index of the record.
     */
    Q_INVOKABLE void typeLogin(int index);

    /**
     * @brief Auto-type only the password for a credential into the focused window.
     *
     * Decrypts the credential on demand and types the password field via
     * synthesised keystrokes (`SendInput`). Unlike typeLogin(), this does not
     * type the username or send a Tab key.
     *
     * @param index Row index of the record.
     */
    Q_INVOKABLE void typePassword(int index);

    /**
     * @brief Cancel an active auto-fill operation.
     *
     * Removes global hooks and resets the fill engine to idle.
     */
    Q_INVOKABLE void cancelFill();

    /**
     * @brief Arm auto-fill hooks for a specific credential (IFillControl).
     *
     * Self-gating: defers the arm via the password gate if the master password
     * is not yet set, otherwise arms the engine immediately. Installs global
     * mouse and keyboard hooks; the user then Ctrl+Clicks in an external window
     * to type the username, and Ctrl+Clicks again for the password.
     *
     * @param recordIndex Row index of the credential to fill.
     */
    void armFor(int recordIndex) override;

    /**
     * @brief Cancel any active auto-fill operation (IFillControl).
     *
     * No-op when the engine is not armed.
     */
    void cancelIfArmed() override;

signals:
    void fillArmedChanged();             ///< Auto-fill armed state toggled.
    void fillStatusTextChanged();        ///< Auto-fill status message updated.
    void fillCountdownSecondsChanged();  ///< Auto-fill countdown tick.

    /// @brief A fill error occurred that should be shown to the user.
    /// @param title   Dialog title.
    /// @param message Error description.
    void errorOccurred(const QString& title, const QString& message);

private:
    /// @brief Typing mode for scheduleTypingAction.
    enum class TypingMode
    {
        Login,
        Password
    };

    /**
     * @brief Start a 3-second countdown, then execute a typing action.
     *
     * Shared implementation for typeLogin() and typePassword(). Snapshots the
     * target record and master password into the worker thread's captures so
     * the worker never touches shared state.
     *
     * @param index Record index to type.
     * @param mode  Whether to type login (user+tab+pass) or password only.
     * @param label Status label (e.g. "Login" or "Password").
     */
    void scheduleTypingAction(int index, TypingMode mode, const QString& label);

    /**
     * @brief Arm the engine for @p recordIndex once the password is available.
     *
     * Validates the index, ignores the request while busy, logs the arm, and
     * arms the engine against the workspace records/session/generation.
     *
     * @param recordIndex Row index of the credential to fill.
     */
    void doArm(int recordIndex);

    seal::CredentialWorkspace& m_Workspace;  ///< Qt-free core: records, session.
    seal::IUiFeedback& m_Ui;                 ///< Status/busy/countdown sink.
    seal::IPasswordGate& m_Gate;             ///< Defers arming until password set.
    seal::FillController& m_Engine;          ///< Borrowed auto-fill engine.
    seal::AsyncRunner& m_Async;              ///< Async runner (held for future worker migration).
};

}  // namespace seal

#endif  // USE_QT_UI
