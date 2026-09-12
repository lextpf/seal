#ifdef USE_QT_UI

#include "WindowChrome.hpp"

#include <QtCore/QCoreApplication>

#include <dwmapi.h>
#include <windowsx.h>

namespace seal
{

bool TitleBarFilter::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result)
{
    if (eventType != "windows_generic_MSG")
    {
        return false;
    }
    auto* msg = static_cast<MSG*>(message);
    if (!m_Hwnd || msg->hwnd != m_Hwnd)
    {
        return false;
    }

    switch (msg->message)
    {
        case WM_NCCALCSIZE:
        {
            // claim client area for both wParam forms; the FALSE path otherwise leaves
            // a visible pixel. maximized bounds use the work area to avoid the taskbar.
            if (IsZoomed(msg->hwnd))
            {
                HMONITOR mon = MonitorFromWindow(msg->hwnd, MONITOR_DEFAULTTONEAREST);
                MONITORINFO mi{};
                mi.cbSize = sizeof(mi);
                if (GetMonitorInfoW(mon, &mi))
                {
                    if (msg->wParam == TRUE)
                    {
                        auto* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(msg->lParam);
                        params->rgrc[0] = mi.rcWork;
                    }
                    else
                    {
                        auto* rect = reinterpret_cast<RECT*>(msg->lParam);
                        *rect = mi.rcWork;
                    }
                }
            }
            *result = 0;
            return true;
        }
        case WM_NCACTIVATE:
        {
            *result = TRUE;
            return true;
        }
        case WM_NCPAINT:
        {
            *result = 0;
            return true;
        }
        case WM_NCHITTEST:
        {
            // QML owns caption controls; handle only resize bands.
            POINT pt;
            pt.x = GET_X_LPARAM(msg->lParam);
            pt.y = GET_Y_LPARAM(msg->lParam);
            RECT rc;
            GetWindowRect(msg->hwnd, &rc);

            if (!IsZoomed(msg->hwnd))
            {
                // use window DPI; system DPI gives incorrect bands on mixed-DPI monitors.
                const UINT windowDpi = GetDpiForWindow(msg->hwnd);
                const UINT dpi = windowDpi > 0 ? windowDpi : USER_DEFAULT_SCREEN_DPI;
                const int paddedBorder = GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
                const int frameX = GetSystemMetricsForDpi(SM_CXSIZEFRAME, dpi) + paddedBorder;
                const int frameY = GetSystemMetricsForDpi(SM_CYSIZEFRAME, dpi) + paddedBorder;
                // test corners before sides so corner resize cursors win.
                if (pt.y < rc.top + frameY)
                {
                    if (pt.x < rc.left + frameX)
                    {
                        *result = HTTOPLEFT;
                        return true;
                    }
                    if (pt.x >= rc.right - frameX)
                    {
                        *result = HTTOPRIGHT;
                        return true;
                    }
                    *result = HTTOP;
                    return true;
                }
                if (pt.y >= rc.bottom - frameY)
                {
                    if (pt.x < rc.left + frameX)
                    {
                        *result = HTBOTTOMLEFT;
                        return true;
                    }
                    if (pt.x >= rc.right - frameX)
                    {
                        *result = HTBOTTOMRIGHT;
                        return true;
                    }
                    *result = HTBOTTOM;
                    return true;
                }
                if (pt.x < rc.left + frameX)
                {
                    *result = HTLEFT;
                    return true;
                }
                if (pt.x >= rc.right - frameX)
                {
                    *result = HTRIGHT;
                    return true;
                }
            }

            // HTCLIENT routes dragging to QML; no native caption or maximize-button gestures.
            *result = HTCLIENT;
            return true;
        }
    }
    return false;
}

void InstallWindowChrome(HWND hwnd)
{
    // the guard is process-wide, so only the first HWND gets chrome.
    static bool installed = false;
    if (installed)
    {
        return;
    }

    // class icon changes affect every window created from this Qt class.
    SetClassLongPtr(hwnd, GCLP_HICON, 0);
    SetClassLongPtr(hwnd, GCLP_HICONSM, 0);
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, 0);
    SendMessage(hwnd, WM_SETICON, ICON_BIG, 0);

    // remove visible edges while retaining native resize/snap/min/max styles.
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    style &= ~static_cast<LONG_PTR>(WS_CAPTION);
    style |= static_cast<LONG_PTR>(WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
    SetWindowLongPtr(hwnd, GWL_STYLE, style);

    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    exStyle &= ~static_cast<LONG_PTR>(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME |
                                      WS_EX_WINDOWEDGE);
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle);

    // Qt borrows the filter; keep it alive for the process lifetime.
    auto* filter = new TitleBarFilter();
    filter->m_Hwnd = hwnd;
    QCoreApplication::instance()->installNativeEventFilter(filter);

    // negative margins extend DWM over the whole client area and preserve its shadow.
    MARGINS margins{-1, -1, -1, -1};
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    // disable the opaque system backdrop so window alpha exposes the desktop.
    static constexpr DWORD DWMWA_SYSTEMBACKDROP_TYPE = 38;  // Win11 22621+
    DWORD backdropNone = 1;                                 // DWMSBT_NONE
    DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdropNone, sizeof(backdropNone));

    static constexpr DWORD DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    DWORD cornerPref = 2;  // DWMWCP_ROUND
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cornerPref, sizeof(cornerPref));

    // recalculate the client rectangle through our filter.
    SetWindowPos(
        hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    installed = true;
}

void ApplyWindowTheme(HWND hwnd, bool dark)
{
    // older SDKs lack these ids; dark-mode id 19 is not attempted on older windows.
    static constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE = 20;  // Win10 18985+
    static constexpr DWORD DWMWA_BORDER_COLOR = 34;             // Win11 22000+
    static constexpr DWORD DWMWA_CAPTION_COLOR = 35;            // Win11 22000+
    static constexpr DWORD DWMWA_TEXT_COLOR = 36;               // Win11 22000+

    BOOL darkMode = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));

    // caption colors still affect shell previews.
    COLORREF captionColor = dark ? RGB(7, 8, 16) : RGB(248, 246, 242);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));

    COLORREF textColor = dark ? RGB(224, 230, 244) : RGB(30, 26, 18);
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));

    // DWMWA_COLOR_NONE removes the accent stroke. apply last because caption
    // attribute changes can reset the border color.
    COLORREF borderNone = 0xFFFFFFFE;
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &borderNone, sizeof(borderNone));
}

}  // namespace seal

#endif  // USE_QT_UI
