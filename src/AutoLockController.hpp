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
 * Created by AppViewModel as a QObject child and never exposed to QML. Two
 * triggers emit lockRequested():
 *
 * - **Idle**: an application-wide event filter stamps the last user activity
 *   (key press, mouse press, wheel, mouse move, focus-in); a coarse 30 s
 *   QTimer compares the elapsed idle time against `security/autoLockSecs`.
 * - **Session lock**: WTSRegisterSessionNotification plus
 *   WM_WTSSESSION_CHANGE / WTS_SESSION_LOCK through a native event filter,
 *   gated by `security/lockOnSessionLock`.
 *
 * This class holds no secret material; the owner decides what "lock" means.
 * AppViewModel connects lockRequested to lockVault() and ignores the request
 * when no master password is held.
 *
 * @par Timing and granularity
 * Both settings are read once in the constructor, so a settings change takes
 * effect on the next start. The idle poll is coarse: a lock fires up to 30 s
 * after the timeout expires.
 *
 * Session notification is registered lazily on a poll tick, because a top-level
 * window must exist first; a session lock in the first 30 s after construction
 * is missed. When `security/lockOnSessionLock` is false, registration never runs
 * and the native filter drops every message.
 *
 * @par Idle is application-scoped
 * Only events delivered to this application count as activity, so the timeout
 * expires while the user works elsewhere and seal sits in the background. That
 * is intended: it bounds how long the master key stays in memory unattended.
 *
 * @par Repeat suppression
 * onPollTick() re-stamps the activity clock when an idle lock fires, so one
 * idle period produces one lockRequested() instead of one per tick. Session
 * locks are not suppressed: every WTS_SESSION_LOCK message emits.
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
 * | `security/autoLockSecs`      | `300`   | Idle timeout (seconds); `<= 0` = off |
 * | `security/lockOnSessionLock` | `true`  | Lock when Windows locks the session |
 *
 * @see AppViewModel, AutoLockPolicy.hpp
 */
class AutoLockController : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

public:
    /**
     * @brief Read the settings, install both filters, and start the 30 s poll.
     *
     * Starts the monotonic activity clock and installs the event filter and the
     * native event filter on the QCoreApplication instance. Both filters are
     * installed unconditionally; the settings only gate what the callbacks do.
     *
     * @param parent Owning QObject (typically the AppViewModel).
     */
    explicit AutoLockController(QObject* parent = nullptr);

    /**
     * @brief Unregister the session notification and remove both filters.
     *
     * Unregistration is skipped when registration never succeeded; otherwise it
     * usually runs against a dead window handle, which is harmless and left
     * unchecked. The filters are removed only while a QCoreApplication instance
     * still exists, so destruction after the application object is gone is safe.
     */
    ~AutoLockController() override;

    /**
     * @brief App-level activity filter; stamps the idle clock.
     *
     * Runs for every event of every object in the application, so it stays a
     * type switch and a single timestamp write. A programmatic focus change
     * counts as activity, because FocusIn is not distinguished from a click.
     *
     * @param watched Forwarded to the base filter, never inspected here.
     * @param event   Key press, mouse press, mouse move, wheel and focus-in
     *                reset the idle timer; every other type is ignored.
     * @return Always the base-class result (never consumes events).
     */
    bool eventFilter(QObject* watched, QEvent* event) override;

    /**
     * @brief Native filter; catches WM_WTSSESSION_CHANGE session locks.
     *
     * Returns at once when `security/lockOnSessionLock` is false. A null
     * @p message is tolerated. Only WTS_SESSION_LOCK emits; unlock, logon and
     * remote-session transitions are ignored.
     *
     * @param eventType Platform event type identifier (unused).
     * @param message   The native `MSG*` for this Windows message.
     * @param result    Optional result out-param (unused).
     * @return Always `false` (the message is never consumed).
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

signals:
    /**
     * @brief The vault should lock now.
     *
     * Emitted from the poll tick (idle) or from the native filter (session
     * lock). The controller never checks whether a vault is open, so the owner
     * has to ignore the request when nothing is unlocked.
     *
     * @param reason Ready-to-show status-bar text naming the trigger, either
     *               "Vault locked (idle timeout)" or
     *               "Vault locked (Windows session locked)".
     */
    void lockRequested(const QString& reason);

private slots:
    /**
     * @brief Coarse 30 s tick: evaluates ShouldAutoLock and lazily
     *        registers the WTS session notification once a window exists.
     *
     * When @ref seal::ShouldAutoLock reports an idle lock, the activity clock is
     * re-stamped before the signal is emitted, which keeps one idle period to
     * one lockRequested().
     */
    void onPollTick();

private:
    /**
     * @brief Try WTSRegisterSessionNotification on the first top-level window.
     *
     * A no-op once registered, and a no-op while `security/lockOnSessionLock`
     * is false. Otherwise retried on every tick until a top-level window exists
     * and the call succeeds; a failed call leaves @ref m_WtsRegistered false.
     * Reading winId() realises the native window. Registration is
     * NOTIFY_FOR_THIS_SESSION, so only the user's own session transitions
     * arrive.
     */
    void tryRegisterSessionNotification();

    QTimer m_PollTimer;     ///< Coarse idle poll (30 s, repeating).
    QElapsedTimer m_Clock;  ///< Monotonic activity clock, started in the constructor.
    /// Milliseconds on @ref m_Clock at the last user input; also re-stamped
    /// when an idle lock fires, to suppress a per-tick repeat.
    qint64 m_LastActivityMs = 0;
    int m_TimeoutSecs = 300;          ///< security/autoLockSecs, read once (<= 0 = off).
    bool m_LockOnSessionLock = true;  ///< security/lockOnSessionLock, read once.
    bool m_WtsRegistered = false;     ///< Session notification active.
    /// Borrowed HWND of the first top-level window; not owned. RunQMLMode
    /// destroys the QML engine, and with it that window, before this
    /// controller, so the destructor usually unregisters a dead handle. The
    /// registration dies with the window, so the result is not checked.
    void* m_WtsHwnd = nullptr;
};

}  // namespace seal

#endif  // USE_QT_UI
