#ifdef USE_QT_UI

#include "WindowController.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"
#include "WindowChrome.hpp"

#include <QtGui/QGuiApplication>
#include <QtGui/QScreen>
#include <QtGui/QWindow>

#include <algorithm>

#include <windows.h>

namespace seal
{

WindowController::WindowController(QObject* parent)
    : QObject(parent)
{
    refreshReduceMotion();
    QGuiApplication::instance()->installNativeEventFilter(this);
}

WindowController::~WindowController()
{
    if (auto* app = QGuiApplication::instance())
    {
        app->removeNativeEventFilter(this);
    }
}

bool WindowController::isAlwaysOnTop() const
{
    return m_AlwaysOnTop;
}

bool WindowController::isCompact() const
{
    return m_Compact;
}

bool WindowController::reduceMotion() const
{
    return m_ReduceMotion;
}

bool WindowController::nativeEventFilter(const QByteArray& eventType,
                                         void* message,
                                         qintptr* /*result*/)
{
    if (eventType == "windows_generic_MSG")
    {
        const MSG* msg = static_cast<const MSG*>(message);
        if (msg->message == WM_SETTINGCHANGE)
        {
            refreshReduceMotion();
        }
    }
    return false;
}

void WindowController::refreshReduceMotion()
{
    BOOL animate = TRUE;
    if (!SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animate, 0))
    {
        return;
    }

    const bool reduce = !animate;
    if (reduce == m_ReduceMotion)
    {
        return;
    }

    m_ReduceMotion = reduce;
    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=window.reduce_motion.change", seal::diag::kv("state", m_ReduceMotion)}));
    emit reduceMotionChanged();
}

void WindowController::updateWindowTheme(bool dark)
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
    {
        return;
    }

    HWND hwnd = (HWND)windows.first()->winId();
    if (!hwnd)
    {
        return;
    }

    seal::InstallWindowChrome(hwnd);
    seal::ApplyWindowTheme(hwnd, dark);
}

void WindowController::startWindowDrag()
{
    auto windows = QGuiApplication::topLevelWindows();
    if (!windows.isEmpty())
    {
        windows.first()->startSystemMove();
    }
}

void WindowController::toggleAlwaysOnTop()
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
    {
        return;
    }

    HWND hwnd = (HWND)windows.first()->winId();
    m_AlwaysOnTop = !m_AlwaysOnTop;
    SetWindowPos(
        hwnd, m_AlwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=window.always_on_top.toggle", seal::diag::kv("state", m_AlwaysOnTop)}));
    emit alwaysOnTopChanged();
}

void WindowController::toggleCompact()
{
    // kCompactHeight / kNormalMinimumHeight are mirrored by the minimumHeight
    // binding in qml/Main.qml, and kWorkAreaInset by its
    // fitInitialWindowToScreen(). Keep both sides in step.
    static constexpr int kCompactHeight = 272;
    static constexpr int kNormalMinimumHeight = 480;
    static constexpr int kDefaultNormalWidth = 1600;
    static constexpr int kDefaultNormalHeight = 690;
    static constexpr int kWorkAreaInset = 64;

    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
    {
        return;
    }

    QWindow* win = windows.first();
    m_Compact = !m_Compact;

    if (m_Compact)
    {
        // Save the size so leaving compact can restore it. Only the height
        // collapses; the chosen width is kept as it is.
        m_NormalWidth = win->width();
        m_NormalHeight = win->height();
        win->setMinimumHeight(kCompactHeight);
        win->resize(win->width(), kCompactHeight);
    }
    else
    {
        // Restore the saved size, clamped to the current monitor's work area,
        // which also re-fits a strip dragged onto a smaller monitor.
        win->setMinimumHeight(kNormalMinimumHeight);
        int restoreWidth = m_NormalWidth > 0 ? m_NormalWidth : kDefaultNormalWidth;
        int restoreHeight = m_NormalHeight > 0 ? m_NormalHeight : kDefaultNormalHeight;
        if (QScreen* screen = win->screen())
        {
            const QSize available = screen->availableGeometry().size();
            restoreWidth = std::min(
                restoreWidth, std::max(win->minimumWidth(), available.width() - kWorkAreaInset));
            restoreHeight = std::min(
                restoreHeight, std::max(kNormalMinimumHeight, available.height() - kWorkAreaInset));
        }
        win->resize(restoreWidth, restoreHeight);
    }

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=window.compact.toggle",
                                seal::diag::kv("state", m_Compact),
                                seal::diag::kv("width", win->width()),
                                seal::diag::kv("height", win->height())}));
    emit compactChanged();
}

}  // namespace seal

#endif  // USE_QT_UI
