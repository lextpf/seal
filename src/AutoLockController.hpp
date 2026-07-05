#pragma once

#ifdef USE_QT_UI

#include <QtCore/QAbstractNativeEventFilter>
#include <QtCore/QByteArray>
#include <QtCore/QElapsedTimer>
#include <QtCore/QObject>
#include <QtCore/QTimer>

namespace seal
{

/**
 * @class AutoLockController
 * @brief Requests a vault lock after user idle time or Windows session lock.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Owned by AppViewModel (the BridgeViewModel owned-collaborator pattern).
 * Two triggers, both emitting lockRequested():
 *
 * - **Idle**: an application-wide event filter stamps the last user
 *   activity (keys, mouse buttons, wheel, mouse move, focus-in); a coarse 30 s
 *   QTimer compares the elapsed idle time against the configured
 *   timeout (QSettings `security/autoLockSecs`, default 300, 0 = off).
 * - **Session lock**: WTSRegisterSessionNotification +
 *   WM_WTSSESSION_CHANGE / WTS_SESSION_LOCK via a native event filter
 *   (QSettings `security/lockOnSessionLock`, default true).
 *
 * Holds **no secret material**: the owner decides what "lock" means
 * (AppViewModel connects lockRequested to its existing lockVault()).
 *
 * @par Trigger flow
 * @verbatim
 *   user input                          Windows session
 *   (key/mouse/wheel/focus-in)          lock event
 *        |                                   |
 *        | eventFilter() stamps              | WM_WTSSESSION_CHANGE
 *        v m_LastActivityMs                  v (wParam == WTS_SESSION_LOCK)
 *   m_PollTimer (30 s) -> onPollTick    nativeEventFilter()
 *        | ShouldAutoLock(idle >=            | if m_LockOnSessionLock
 *        v   m_TimeoutSecs) ?                v
 *   emit lockRequested(...)  ------.   .---  emit lockRequested(...)
 *                                  |   |
 *                                  v   v
 *                        AppViewModel::lockVault()  (owner-connected)
 * @endverbatim
 *
 * @par Settings (QSettings)
 * | Key                          | Default | Meaning                             |
 * |------------------------------|---------|-------------------------------------|
 * | `security/autoLockSecs`      | `300`   | Idle timeout (seconds); `0` = off   |
 * | `security/lockOnSessionLock` | `true`  | Lock when Windows locks the session |
 *
 * @see AppViewModel, AutoLockPolicy.hpp
 */
class AutoLockController : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    /**
     * @brief Install the activity filter + native filter and start the poll.
     * @param parent Owning QObject (typically the AppViewModel).
     */
    explicit AutoLockController(QObject* parent = nullptr);

    /// @brief Unregister session notifications and remove filters.
    ~AutoLockController() override;

    /**
     * @brief App-level activity filter; stamps the idle clock.
     * @param watched Watched object; forwarded to the base filter, not inspected here.
     * @param event   The event; input events reset the idle timer.
     * @return Always the base-class result (never consumes events).
     */
    bool eventFilter(QObject* watched, QEvent* event) override;

    /**
     * @brief Native filter; catches WM_WTSSESSION_CHANGE session locks.
     * @param eventType Platform event type identifier (unused).
     * @param message   The native MSG pointer.
     * @param result    Optional result out-param (unused).
     * @return Always `false` (the message is never consumed).
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

signals:
    /**
     * @brief The vault should lock now.
     * @param reason Status-bar text describing the trigger.
     */
    void lockRequested(const QString& reason);

private slots:
    /**
     * @brief Coarse 30 s tick: evaluates ShouldAutoLock and lazily
     *        registers the WTS session notification once a window exists.
     */
    void onPollTick();

private:
    /// @brief Try WTSRegisterSessionNotification on the first top-level window.
    void tryRegisterSessionNotification();

    QTimer m_PollTimer;               ///< Coarse idle poll (30 s).
    QElapsedTimer m_Clock;            ///< Monotonic activity clock.
    qint64 m_LastActivityMs = 0;      ///< Last user input timestamp.
    int m_TimeoutSecs = 300;          ///< security/autoLockSecs (0 = off).
    bool m_LockOnSessionLock = true;  ///< security/lockOnSessionLock.
    bool m_WtsRegistered = false;     ///< Session notification active.
    void* m_WtsHwnd = nullptr;        ///< HWND used for registration.
};

}  // namespace seal

#endif  // USE_QT_UI
