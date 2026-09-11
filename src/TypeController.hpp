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
 * @brief Expose fill state and typing commands through the Fill QML context property.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Properties relay FillController state. Immediate typing snapshots the record and
 * key on the GUI thread; workers never read the workspace and cleanse their key copy.
 *
 * | Path                     | Target checks                                   |
 * |--------------------------|-------------------------------------------------|
 * | typeLogin / typePassword | 3 s countdown; current focus; no binding checks |
 * | armFor                   | Click-selected field; engine probes and binding |
 *
 * Immediate typing refuses an armed engine; engine arming refuses busy state.
 * Once submitted, immediate typing runs to completion without cancellation. Destroying
 * this controller suppresses result delivery but does not stop that worker.
 *
 * @pre Borrowed collaborators outlive this object. Call methods on the GUI thread.
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
     * @fn TypeController(seal::CredentialWorkspace& workspace, seal::IUiFeedback& ui,
     *     seal::IPasswordGate& gate, seal::FillController& engine, seal::AsyncRunner& asyncRunner,
     *     QObject* parent = nullptr)
     * @brief Relay engine state and outcomes to QML and the status sink.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Success and cancellation keep seal minimized. Fill errors restore and activate
     * all top-level windows, including errors from StagingController's shared engine.
     */
    TypeController(seal::CredentialWorkspace& workspace,
                   seal::IUiFeedback& ui,
                   seal::IPasswordGate& gate,
                   seal::FillController& engine,
                   seal::AsyncRunner& asyncRunner,
                   QObject* parent = nullptr);

    /**
     * @fn bool isFillArmed() const
     * @brief False during diagnosis even though input hooks are installed.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isFillArmed() const;

    /**
     * @fn QString fillStatusText() const
     * @brief Empty while the engine is idle.
     * @author Alex (<https://github.com/lextpf>)
     */
    QString fillStatusText() const;

    /**
     * @fn int fillCountdownSeconds() const
     * @brief Seconds; manual and diagnosis count down, staged arms hold the value.
     * @author Alex (<https://github.com/lextpf>)
     */
    int fillCountdownSeconds() const;

    /**
     * @fn void typeLogin(int index)
     * @brief Type a login after a countdown using a worker snapshot.
     * @author Alex (<https://github.com/lextpf>)
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
     * Invalid index, busy state or an armed engine makes this a silent no-op. A missing
     * password defers the entire call and repeats those checks.
     *
     * @param index Full workspace record index, not a filtered row.
     * @warning No field, host or soft-delete checks. Keystrokes go to current focus;
     *          use `armFor()` when the target requires verification.
     */
    Q_INVOKABLE void typeLogin(int index);

    /**
     * @fn void typePassword(int index)
     * @brief Type only the password after the shared gate and countdown.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param index Full workspace record index.
     * @warning The same unchecked-target and soft-delete behavior as `typeLogin()` applies.
     */
    Q_INVOKABLE void typePassword(int index);

    /**
     * @fn void cancelFill()
     * @brief Remove fill hooks, including diagnosis; leave an immediate typing countdown running.
     * @author Alex (<https://github.com/lextpf>)
     */
    Q_INVOKABLE void cancelFill();

    /**
     * @fn void armFor(int recordIndex)
     * @brief Arm Ctrl+Click filling after password gating and minimize visible windows.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Ctrl+Shift+Click forces password; Ctrl+Alt+Click forces username. Restore occurs
     * only on fill error. Invalid index or busy state is ignored; deferred arming
     * re-enters `doArm()` without repeating the password gate.
     *
     * @param recordIndex Full workspace record index.
     */
    void armFor(int recordIndex) override;

    /**
     * @fn void cancelIfArmed()
     * @brief Cancel only manual/staged arms; use cancelFill() to also cancel diagnosis.
     * @author Alex (<https://github.com/lextpf>)
     */
    void cancelIfArmed() override;

signals:
    void fillArmedChanged();
    void fillStatusTextChanged();
    void fillCountdownSecondsChanged();

    void errorOccurred(const QString& title, const QString& message);

private:
    enum class TypingMode
    {
        Login,    ///< Username, Tab, then password.
        Password  ///< Password only; no username and no Tab.
    };

    /**
     * @fn void scheduleTypingAction(int index, TypingMode mode, const QString& label)
     * @brief Hold busy through a 3 s countdown and the typing worker.
     * @author Alex (<https://github.com/lextpf>)
     *
     * After countdown, copy the record and clone the key in a GUI-thread access window.
     * The copyable worker holds its key in shared locked memory and cleanses it on exit.
     * Invalidated index or failed unlock aborts and clears busy; completion also clears it.
     *
     * @pre The caller has checked busy state.
     */
    void scheduleTypingAction(int index, TypingMode mode, const QString& label);

    /**
     * @fn void doArm(int recordIndex)
     * @brief Validate and arm against workspace records, session and generation.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Invalid index or busy state does nothing. Success updates status and minimizes
     * windows; rejection logs `reason=controller_rejected` without changing UI state.
     */
    void doArm(int recordIndex);

    seal::CredentialWorkspace& m_Workspace;
    seal::IUiFeedback& m_Ui;
    seal::IPasswordGate& m_Gate;
    seal::FillController& m_Engine;  ///< Borrowed auto-fill engine.
    seal::AsyncRunner& m_Async;
};

}  // namespace seal

#endif  // USE_QT_UI
