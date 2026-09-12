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
 * @brief Request a vault lock on application idle or Windows session lock.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * The owner decides whether a key needs clearing. Settings are read once at
 * construction; activity in other applications does not reset idle time.
 *
 * | QSettings key                | Default | Effect                      |
 * |------------------------------|---------|-----------------------------|
 * | `security/autoLockSecs`      | 300     | Idle seconds; <= 0 disables |
 * | `security/lockOnSessionLock` | True    | React to WTS_SESSION_LOCK   |
 *
 * The coarse 30 s poll can delay idle locking by one interval. Session notification
 * also waits for a poll and a top-level window, so early session locks are missed.
 * Idle requests reset the activity timestamp; every session-lock message emits.
 *
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
 * @see AutoLockPolicy.hpp
 */
class AutoLockController : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    /**
     * @fn AutoLockController(QObject* parent = nullptr)
     * @brief Install application filters and start the 30 s poll; settings gate callbacks.
     * @author Alex (<https://github.com/lextpf>)
     */
    explicit AutoLockController(QObject* parent = nullptr);

    /**
     * @fn ~AutoLockController()
     * @brief Unregister WTS notifications and remove filters while the application exists.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~AutoLockController() override;

    /**
     * @fn bool eventFilter(QObject* watched, QEvent* event)
     * @brief Reset idle time on key/mouse press, mouse move, wheel or focus-in.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Programmatic focus changes count. Events pass through to the base filter.
     */
    bool eventFilter(QObject* watched, QEvent* event) override;

    /**
     * @fn bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result)
     * @brief Emit only for WTS_SESSION_LOCK when enabled; never consume the message.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Null messages are ignored.
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

signals:
    /**
     * @fn void lockRequested(const QString& reason)
     * @brief Request locking without checking whether a vault is unlocked.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param reason Display-ready idle or session-lock status.
     */
    void lockRequested(const QString& reason);

private slots:
    /**
     * @fn void onPollTick()
     * @brief Check idle time and register WTS; reset activity before emitting an idle lock.
     * @author Alex (<https://github.com/lextpf>)
     */
    void onPollTick();

private:
    /**
     * @fn void tryRegisterSessionNotification()
     * @brief Retry registration until a top-level window exists and WTS accepts it.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Skip when disabled or registered. `winId()` realizes the native window;
     * NOTIFY_FOR_THIS_SESSION restricts notifications to the current session.
     */
    void tryRegisterSessionNotification();

    QTimer m_PollTimer;     ///< Coarse idle poll (30 s, repeating).
    QElapsedTimer m_Clock;  ///< Monotonic activity clock, started in the constructor.
    /// Monotonic milliseconds at activity or the last idle-lock request.
    qint64 m_LastActivityMs = 0;
    int m_TimeoutSecs = 300;          ///< Security/autoLockSecs, read once (<= 0 = off).
    bool m_LockOnSessionLock = true;  ///< Security/lockOnSessionLock, read once.
    bool m_WtsRegistered = false;     ///< Session notification active.
    /// Borrowed HWND; registration ends with the window, which may die before this object.
    void* m_WtsHwnd = nullptr;
};

}  // namespace seal

#endif  // USE_QT_UI
