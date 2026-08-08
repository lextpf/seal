#pragma once

#ifdef USE_QT_UI

#include <QtCore/QAbstractNativeEventFilter>

#include <windows.h>

namespace seal
{

/**
 * @class TitleBarFilter
 * @brief Native event filter that extends the client area into the title bar.
 * @author Alex (https://github.com/lextpf)
 * @ingroup WindowChrome
 *
 * Intercepts Win32 messages before Qt sees them, so QML can draw the whole
 * title bar while resize, snap and the DWM shadow stay native.
 *
 * @par Ownership
 * `InstallWindowChrome` is the only construction site: it heap-allocates one
 * instance, sets `m_Hwnd`, and installs it on `QCoreApplication`. Qt takes no
 * ownership and nothing removes or deletes the filter, so the instance lives for
 * the whole process. Qt routes every window's messages through it, so
 * `nativeEventFilter` re-checks `m_Hwnd` on entry.
 *
 * @note Qt runs the filter on the GUI thread. The class holds no lock and needs
 * none.
 *
 * @see InstallWindowChrome, ApplyWindowTheme
 */
class TitleBarFilter : public QAbstractNativeEventFilter
{
public:
    /// Native window handle the filter acts on. Messages for any other window
    /// are ignored, and a null handle makes the filter inert.
    HWND m_Hwnd = nullptr;

    /**
     * @brief Handle the non-client Win32 messages that realize the custom frame.
     *
     * Messages for any window other than `m_Hwnd` fall through to Qt untouched.
     *
     * @par Non-client message handling
     * | Message       | Action                                  | `*result` |
     * |---------------|-----------------------------------------|-----------|
     * | WM_NCCALCSIZE | Claim the whole window as client area   | 0         |
     * | WM_NCACTIVATE | Suppress active/inactive border repaint | TRUE      |
     * | WM_NCPAINT    | Suppress non-client painting            | 0         |
     * | WM_NCHITTEST  | Report resize-border / client zones     | HT* code  |
     *
     * @par Client area
     * WM_NCCALCSIZE writes 0 (no `WVR_*` bits) on both the `wParam == TRUE` and
     * the `wParam == FALSE` path, so the client area becomes the proposed
     * rectangle. While maximized it first rewrites that rectangle to the monitor
     * work area, which keeps the frame off the taskbar. A failed
     * `GetMonitorInfoW` leaves the rectangle untouched.
     *
     * @par Resize bands
     * When not maximized, WM_NCHITTEST measures the bands at the window's own
     * DPI (`GetSystemMetricsForDpi`), so they stay correct across mixed-DPI
     * monitors. Below, `fx` is `SM_CXSIZEFRAME + SM_CXPADDEDBORDER` and `fy` is
     * `SM_CYSIZEFRAME + SM_CXPADDEDBORDER`; a `GetDpiForWindow` of 0 falls back
     * to 96 DPI. Hit point and window rectangle are in screen coordinates.
     * @verbatim
     *                x < left+fx                     x >= right-fx
     *                +---------+---------------------+---------+
     *     y < top+fy | TOPLEFT |        HTTOP        | TOPRIGHT|
     *                +---------+---------------------+---------+
     *                | HTLEFT  |       HTCLIENT      | HTRIGHT |
     *                +---------+---------------------+---------+
     * y >= bottom-fy | BTMLEFT |       HTBOTTOM      | BTMRIGHT|
     *                +---------+---------------------+---------+
     * @endverbatim
     * The top strip is tested before the bottom and both before the sides, so
     * corners win over edges. While maximized every point is HTCLIENT. The filter
     * answers every remaining point with HTCLIENT and still returns `true`, so
     * Windows delivers the next press to Qt as an ordinary client-area mouse
     * message. QML then starts the move through `WindowVM.startWindowDrag()`,
     * which calls `QWindow::startSystemMove()`.
     *
     * @warning HTCAPTION and HTMAXBUTTON are never reported, so the shell gives
     * this window no caption double-click maximize, no right-click system menu
     * and no Snap Layouts flyout. QML must supply those gestures itself.
     *
     * @param eventType Qt platform tag; only `"windows_generic_MSG"` is inspected.
     * @param message   Points to a Win32 `MSG` owned by Qt, valid for this call only.
     * @param result    Receives the message result; written only when the return
     *                  value is `true`.
     * @return `true` when the message was handled and @p result is authoritative.
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;
};

/**
 * @brief One-time setup of the frameless window: styles, filter, DWM frame,
 * rounded corners.
 * @ingroup WindowChrome
 *
 * Runs at most once per process: a function-local `static` flag latches on the
 * first call, so a later call is a no-op even when @p hwnd names a different
 * window. Only the first window passed here gets the custom chrome.
 *
 * @par What the first call does
 * - Clears the class icons with `SetClassLongPtr` (`GCLP_HICON` and
 *   `GCLP_HICONSM`), which affects every window Qt creates from that class, then
 *   clears this window's own small and large icons with WM_SETICON.
 * - Clears `WS_CAPTION` and the `WS_EX_*` edge styles; forces on
 *   `WS_THICKFRAME`, `WS_SYSMENU`, `WS_MINIMIZEBOX` and `WS_MAXIMIZEBOX` so
 *   resize, snap, minimize and maximize stay native.
 * - Installs a `TitleBarFilter` bound to @p hwnd.
 * - Extends the DWM frame over the whole client area (`MARGINS{-1,-1,-1,-1}`)
 *   so the drop shadow survives.
 * - Sets DWMWA_SYSTEMBACKDROP_TYPE (38) to DWMSBT_NONE (1), so accent and glass
 *   do not bleed through the rounded-corner clip.
 * - Sets DWMWA_WINDOW_CORNER_PREFERENCE (33) to DWMWCP_ROUND (2).
 * - Forces `SWP_FRAMECHANGED` so WM_NCCALCSIZE re-runs through the new filter.
 *
 * @pre A `QCoreApplication` instance exists; the function dereferences
 *      `QCoreApplication::instance()` without a null check. Call it on the GUI
 *      thread with a valid window handle.
 *
 * @note Every Win32 and DWM result is discarded, so an invalid handle fails
 * silently and still latches the guard.
 * @note Nothing removes or deletes the filter; it lives for the process
 * lifetime on purpose.
 * @note Theme colors are not applied here. Call `ApplyWindowTheme` for those.
 *
 * @param hwnd Native window handle for the application's main window.
 */
void InstallWindowChrome(HWND hwnd);

/**
 * @brief Apply DWM dark or light window theme attributes.
 * @ingroup WindowChrome
 *
 * Writes four attributes in a fixed order: immersive dark mode, caption color,
 * text color, border color. The border goes last, because writing a caption
 * attribute makes Windows recompute the frame color and would undo an earlier
 * border write.
 *
 * @par DWM theme colors (COLORREF built with RGB, shown as #RRGGBB)
 * | Element | DWM attribute (id)       | Dark    | Light   |
 * |---------|--------------------------|---------|---------|
 * | Caption | DWMWA_CAPTION_COLOR (35) | #070810 | #f8f6f2 |
 * | Text    | DWMWA_TEXT_COLOR (36)    | #e0e6f4 | #1e1a12 |
 * | Border  | DWMWA_BORDER_COLOR (34)  | none    | none    |
 *
 * The border is DWMWA_COLOR_NONE (0xFFFFFFFE) in both themes, which drops the
 * 1px accent stroke; DWMWA_USE_IMMERSIVE_DARK_MODE (20) follows @p dark.
 *
 * @par Where the colors show
 * `InstallWindowChrome` removes `WS_CAPTION` and `TitleBarFilter` suppresses
 * non-client painting, so these colors reach only the surfaces the shell still
 * draws itself: taskbar thumbnails and alt-tab previews. They are literals here,
 * not read from the QML `Theme` singleton, so the two can drift apart.
 *
 * @note Every `DwmSetWindowAttribute` result is discarded. Attribute 20
 * (immersive dark mode) is honoured from Windows 10 build 18985 on; builds 17763
 * to 18362 used id 19, so those systems apply nothing at all. Attributes 34, 35
 * and 36 need Windows 11 build 22000 or newer. Every call returns normally on
 * every version.
 * @note This function does not install the custom chrome. Callers that need
 * both use `WindowController::updateWindowTheme`.
 *
 * @param hwnd Native window handle.
 * @param dark `true` for dark theme, `false` for light.
 */
void ApplyWindowTheme(HWND hwnd, bool dark);

}  // namespace seal

#endif  // USE_QT_UI
