#ifdef USE_QT_UI

#include "WindowController.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"
#include "WindowChrome.hpp"

#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <windows.h>

namespace seal
{

WindowController::WindowController(QObject* parent)
    : QObject(parent)
{
}

bool WindowController::isAlwaysOnTop() const
{
    return m_AlwaysOnTop;
}

bool WindowController::isCompact() const
{
    return m_Compact;
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
        windows.first()->startSystemMove();
}

void WindowController::toggleAlwaysOnTop()
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
        return;

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
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
        return;

    QWindow* win = windows.first();
    m_Compact = !m_Compact;

    if (m_Compact)
    {
        // Save the current dimensions so we can restore them when leaving
        // compact mode, preserving whatever size the user had chosen.
        m_NormalWidth = win->width();
        m_NormalHeight = win->height();
        win->setMinimumHeight(272);
        win->resize(win->width(), 272);
    }
    else
    {
        // Restore saved dimensions, falling back to default size if none
        // were captured (e.g. app launched directly into compact mode).
        win->setMinimumHeight(540);
        win->resize(m_NormalWidth > 0 ? m_NormalWidth : 1420,
                    m_NormalHeight > 0 ? m_NormalHeight : 690);
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
