#include "AutoLockController.hpp"

#ifdef USE_QT_UI

#include "AutoLockPolicy.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"

#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QSettings>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <windows.h>

#include <wtsapi32.h>

namespace seal
{

AutoLockController::AutoLockController(QObject* parent)
    : QObject(parent)
{
    QSettings settings;
    m_TimeoutSecs = settings.value(QStringLiteral("security/autoLockSecs"), 300).toInt();
    m_LockOnSessionLock =
        settings.value(QStringLiteral("security/lockOnSessionLock"), true).toBool();

    m_Clock.start();
    m_LastActivityMs = m_Clock.elapsed();

    QCoreApplication::instance()->installEventFilter(this);
    QCoreApplication::instance()->installNativeEventFilter(this);

    connect(&m_PollTimer, &QTimer::timeout, this, &AutoLockController::onPollTick);
    m_PollTimer.setInterval(30000);
    m_PollTimer.start();

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=security.autolock.init",
                                "result=ok",
                                seal::diag::kv("timeout_secs", m_TimeoutSecs),
                                seal::diag::kv("lock_on_session", m_LockOnSessionLock)}));
}

AutoLockController::~AutoLockController()
{
    if (m_WtsRegistered && m_WtsHwnd != nullptr)
    {
        WTSUnRegisterSessionNotification(static_cast<HWND>(m_WtsHwnd));
    }
    if (QCoreApplication::instance() != nullptr)
    {
        QCoreApplication::instance()->removeNativeEventFilter(this);
        QCoreApplication::instance()->removeEventFilter(this);
    }
}

bool AutoLockController::eventFilter(QObject* watched, QEvent* event)
{
    switch (event->type())
    {
        case QEvent::KeyPress:
        case QEvent::MouseButtonPress:
        case QEvent::MouseMove:
        case QEvent::Wheel:
        case QEvent::FocusIn:
            m_LastActivityMs = m_Clock.elapsed();
            break;
        default:
            break;
    }
    return QObject::eventFilter(watched, event);
}

bool AutoLockController::nativeEventFilter(const QByteArray& eventType,
                                           void* message,
                                           qintptr* result)
{
    Q_UNUSED(eventType);
    Q_UNUSED(result);
    if (!m_LockOnSessionLock)
    {
        return false;
    }
    MSG* msg = static_cast<MSG*>(message);
    if (msg != nullptr && msg->message == WM_WTSSESSION_CHANGE && msg->wParam == WTS_SESSION_LOCK)
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=security.autolock.trigger", "result=ok", "reason=session_lock"}));
        emit lockRequested(QStringLiteral("Vault locked (Windows session locked)"));
    }
    return false;
}

void AutoLockController::onPollTick()
{
    tryRegisterSessionNotification();

    if (seal::ShouldAutoLock(m_LastActivityMs, m_Clock.elapsed(), m_TimeoutSecs))
    {
        // Re-stamp so a no-op lock (already locked) doesn't re-fire each tick.
        m_LastActivityMs = m_Clock.elapsed();
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=security.autolock.trigger", "result=ok", "reason=idle_timeout"}));
        emit lockRequested(QStringLiteral("Vault locked (idle timeout)"));
    }
}

void AutoLockController::tryRegisterSessionNotification()
{
    if (m_WtsRegistered || !m_LockOnSessionLock)
    {
        return;
    }
    const auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
    {
        return;
    }
    HWND hwnd = reinterpret_cast<HWND>(windows.first()->winId());
    if (WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION))
    {
        m_WtsRegistered = true;
        m_WtsHwnd = hwnd;
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=security.autolock.wts_register", "result=ok"}));
    }
}

}  // namespace seal

#endif  // USE_QT_UI
