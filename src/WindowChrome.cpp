#ifdef USE_QT_UI

#include "WindowChrome.h"

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
            // Claim the entire window as client area on both NCCALCSIZE paths.
            // Some frame recalculations arrive with wParam == FALSE; letting
            // DefWindowProc handle those leaves a 1px visible frame around the
            // custom chrome.
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
            // Prevent the default handler from repainting an active/inactive
            // non-client border over our edge-to-edge client surface.
            *result = TRUE;
            return true;
        }
        case WM_NCPAINT:
        {
            // Suppress all non-client painting to eliminate the 1px
            // DWM border. The client area covers the full window so
            // there is nothing legitimate to paint in the NC region.
            *result = 0;
            return true;
        }
        case WM_NCHITTEST:
        {
            // Custom title bar: all caption buttons are QML-driven,
            // so we only handle resize borders here.
            POINT pt;
            pt.x = GET_X_LPARAM(msg->lParam);
            pt.y = GET_Y_LPARAM(msg->lParam);
            RECT rc;
            GetWindowRect(msg->hwnd, &rc);

            // Resize borders (only when not maximized).
            if (!IsZoomed(msg->hwnd))
            {
                // SM_CXPADDEDBORDERWIDTH (index 92) adds the extra padding
                // Windows uses around resizable frames. We use the raw
                // integer 92 because some older SDK headers don't define the
                // SM_CXPADDEDBORDERWIDTH constant.
                int frame = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(92);
                // Walk the edges: check top strip first (corners have
                // priority), then bottom strip, then left/right. The
                // returned HT* codes tell Windows which resize cursor to
                // show and which edge the user is dragging.
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

            // Everything else is client area; QML handles window dragging
            // via startSystemMove() from the header bar.
            *result = HTCLIENT;
            return true;
        }
    }
    return false;
}

void InstallWindowChrome(HWND hwnd)
{
    // Idempotent: only install once per process lifetime.
    static bool installed = false;
    if (installed)
    {
        return;
    }

    // Remove window icon from title bar
    SetClassLongPtr(hwnd, GCLP_HICON, 0);
    SetClassLongPtr(hwnd, GCLP_HICONSM, 0);
    SendMessage(hwnd, WM_SETICON, ICON_SMALL, 0);
    SendMessage(hwnd, WM_SETICON, ICON_BIG, 0);

    // Strip the native caption/border styles so Windows stops reserving and
    // drawing the last visible frame pixel, while keeping the thick frame and
    // system menu bits needed for resize, snap, minimize/maximize semantics.
    LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
    style &= ~static_cast<LONG_PTR>(WS_CAPTION);
    style |= static_cast<LONG_PTR>(WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
    SetWindowLongPtr(hwnd, GWL_STYLE, style);

    LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
    exStyle &= ~static_cast<LONG_PTR>(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_DLGMODALFRAME |
                                      WS_EX_WINDOWEDGE);
    SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle);

    // Install native event filter for custom title bar
    auto* filter = new TitleBarFilter();
    filter->m_Hwnd = hwnd;
    QCoreApplication::instance()->installNativeEventFilter(filter);

    // Extend the DWM frame into the client area so the system draws its
    // shadow and caption buttons over our content.
    // {-1,-1,-1,-1} means "extend to the entire window" - DWM will
    // render its glass/shadow over the full client surface.
    MARGINS margins{-1, -1, -1, -1};
    DwmExtendFrameIntoClientArea(hwnd, &margins);

    // Disable the system backdrop so no accent/glass color bleeds through
    // the rounded corner pixels where DWM clips the client area.
    static constexpr DWORD DWMWA_SYSTEMBACKDROP_TYPE = 38;
    DWORD backdropNone = 1;  // DWMSBT_NONE
    DwmSetWindowAttribute(hwnd, DWMWA_SYSTEMBACKDROP_TYPE, &backdropNone, sizeof(backdropNone));

    // Request rounded window corners from the DWM compositor.
    static constexpr DWORD DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    DWORD cornerPref = 2;  // DWMWCP_ROUND
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cornerPref, sizeof(cornerPref));

    // Force a frame recalculation so WM_NCCALCSIZE runs with our handler.
    SetWindowPos(
        hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

    installed = true;
}

void ApplyWindowTheme(HWND hwnd, bool dark)
{
    // These DWM attribute IDs were introduced in Windows 10/11 but aren't
    // always in the SDK headers. Defining them as constants lets us build
    // with older SDKs while still using the newer personalization APIs.
    static constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE = 20;  // Win10 1903+
    static constexpr DWORD DWMWA_CAPTION_COLOR = 34;            // Win11 22000+
    static constexpr DWORD DWMWA_BORDER_COLOR = 35;             // Win11 22000+
    static constexpr DWORD DWMWA_TEXT_COLOR = 36;               // Win11 22000+

    BOOL darkMode = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));

    // Suppress the 1px DWM accent stroke so client-area content (e.g. caption
    // button hover highlights) paints flush to the window edge. The window
    // shadow and rounded corners remain intact -- they are separate DWM
    // attributes. The sentinel 0xFFFFFFFE is DWMWA_COLOR_NONE.
    COLORREF borderNone = 0xFFFFFFFE;
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &borderNone, sizeof(borderNone));

    // Caption color still feeds the taskbar thumbnail and alt-tab preview
    // even though our client area covers the whole window.
    COLORREF captionColor = dark ? RGB(7, 8, 16) : RGB(248, 246, 242);
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));

    COLORREF textColor = dark ? RGB(224, 230, 244) : RGB(30, 26, 18);
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));
}

}  // namespace seal

#endif  // USE_QT_UI
