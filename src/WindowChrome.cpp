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
            // Claim the entire window as client area on both NCCALCSIZE
            // paths. The wParam==FALSE branch matters: letting DefWindowProc
            // handle it leaves a 1px visible frame around the chrome.
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
            // Suppress the default active/inactive NC border repaint.
            *result = TRUE;
            return true;
        }
        case WM_NCPAINT:
        {
            // Suppress NC painting -- our client covers the whole window.
            *result = 0;
            return true;
        }
        case WM_NCHITTEST:
        {
            // QML draws caption buttons; we only handle resize borders.
            POINT pt;
            pt.x = GET_X_LPARAM(msg->lParam);
            pt.y = GET_Y_LPARAM(msg->lParam);
            RECT rc;
            GetWindowRect(msg->hwnd, &rc);

            // Resize borders (only when not maximized).
            if (!IsZoomed(msg->hwnd))
            {
                // Raw 92 == SM_CXPADDEDBORDERWIDTH (some old SDKs miss it).
                int frame = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(92);
                // Top strip first (corners win), then bottom, then sides.
                // The returned HT* code drives the resize cursor + edge.
                if (pt.y < rc.top + frame)
                {
                    if (pt.x < rc.left + frame)
                    {
                        *result = HTTOPLEFT;
                        return true;
                    }
                    if (pt.x >= rc.right - frame)
                    {
                        *result = HTTOPRIGHT;
                        return true;
                    }
                    *result = HTTOP;
                    return true;
                }
                if (pt.y >= rc.bottom - frame)
                {
                    if (pt.x < rc.left + frame)
                    {
                        *result = HTBOTTOMLEFT;
                        return true;
                    }
                    if (pt.x >= rc.right - frame)
                    {
                        *result = HTBOTTOMRIGHT;
                        return true;
                    }
                    *result = HTBOTTOM;
                    return true;
                }
                if (pt.x < rc.left + frame)
                {
                    *result = HTLEFT;
                    return true;
                }
                if (pt.x >= rc.right - frame)
                {
                    *result = HTRIGHT;
                    return true;
                }
            }

            // Everything else is client; QML drags via startSystemMove().
            *result = HTCLIENT;
            return true;
        }
    }
    return false;
}

void InstallWindowChrome(HWND hwnd)
{
    // Idempotent: once per process lifetime.
    static bool installed = false;
    if (installed)
    {
        return;
    }

    // Remove window icon from the title bar.
    SetClassLongPtr(hwnd, GCLP_HICON, 0);
    SetClassLongPtr(hwnd, GCLP_HICONSM, 0);
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, 0);
    SendMessage(hwnd, WM_SETICON, ICON_BIG, 0);

    // Drop native caption/border so Windows stops drawing the last visible
    // frame pixel; keep WS_THICKFRAME etc. for resize/snap/min/max semantics.
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    style &= ~static_cast<LONG_PTR>(WS_CAPTION);
    style |= static_cast<LONG_PTR>(WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
    SetWindowLongPtr(hwnd, GWL_STYLE, style);

    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    exStyle &= ~static_cast<LONG_PTR>(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME |
                                      WS_EX_WINDOWEDGE);
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle);

    auto* filter = new TitleBarFilter();
    filter->m_Hwnd = hwnd;
    QCoreApplication::instance()->installNativeEventFilter(filter);

    // Extend the DWM frame into the client area so shadow + caption
    // buttons paint over our content. {-1,-1,-1,-1} = whole window.
    MARGINS margins{-1, -1, -1, -1};
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    // No system backdrop -- prevents accent/glass bleeding through the
    // rounded-corner clip region.
    static constexpr DWORD DWMWA_SYSTEMBACKDROP_TYPE = 38;
    DWORD backdropNone = 1;  // DWMSBT_NONE
    DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdropNone, sizeof(backdropNone));

    // Request DWM rounded corners.
    static constexpr DWORD DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    DWORD cornerPref = 2;  // DWMWCP_ROUND
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cornerPref, sizeof(cornerPref));

    // Force a frame recalc so WM_NCCALCSIZE runs with our handler.
    SetWindowPos(
        hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    installed = true;
}

void ApplyWindowTheme(HWND hwnd, bool dark)
{
    // Win10/11 DWM attribute IDs not always present in older SDK headers;
    // declared here so we can build against older SDKs.
    static constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE = 20;  // Win10 1903+
    static constexpr DWORD DWMWA_CAPTION_COLOR = 34;            // Win11 22000+
    static constexpr DWORD DWMWA_BORDER_COLOR = 35;             // Win11 22000+
    static constexpr DWORD DWMWA_TEXT_COLOR = 36;               // Win11 22000+

    BOOL darkMode = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));

    // Suppress the 1px DWM accent stroke so client content paints flush to
    // the edge; shadow + rounded corners are separate attributes.
    // 0xFFFFFFFE = DWMWA_COLOR_NONE.
    COLORREF borderNone = 0xFFFFFFFE;
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &borderNone, sizeof(borderNone));

    // Caption color still feeds taskbar thumbnails and alt-tab previews.
    COLORREF captionColor = dark ? RGB(7, 8, 16) : RGB(248, 246, 242);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));

    COLORREF textColor = dark ? RGB(224, 230, 244) : RGB(30, 26, 18);
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));
}

}  // namespace seal

#endif  // USE_QT_UI
