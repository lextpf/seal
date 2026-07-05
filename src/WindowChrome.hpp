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
 * Intercepts Win32 messages before Qt sees them, allowing a fully custom
 * title bar (drawn in QML) while still supporting native window chrome
 * behaviors like resizing, snapping, and DWM shadows.
 */
class TitleBarFilter : public QAbstractNativeEventFilter
{
public:
    HWND m_Hwnd = nullptr;  ///< Native window handle to filter events for.

    /**
     * @brief Handle the non-client Win32 messages that realize the custom frame.
     *
     * Only messages targeting @ref m_Hwnd are intercepted; everything else
     * falls through to Qt. Claims the whole window as client area
     * (WM_NCCALCSIZE), suppresses the default non-client border paint
     * (WM_NCACTIVATE / WM_NCPAINT), and reports resize-border hit zones
     * (WM_NCHITTEST).
     *
     * @par Non-client message handling
     * | Message       | Action                                  | `*result` |
     * |---------------|-----------------------------------------|-----------|
     * | WM_NCCALCSIZE | Claim the whole window as client area   | 0         |
     * | WM_NCACTIVATE | Suppress active/inactive border repaint | TRUE      |
     * | WM_NCPAINT    | Suppress non-client painting            | 0         |
     * | WM_NCHITTEST  | Report resize-border / caption zones    | HT* code  |
     *
     * When not maximized, WM_NCHITTEST maps a point to a resize zone using a
     * border `SM_CXSIZEFRAME + SM_CXPADDEDBORDERWIDTH` (metric 92) px wide (`f`
     * below), tested top strip first so corners win over edges. When maximized,
     * every point is HTCLIENT and WM_NCCALCSIZE clamps the client to the
     * monitor work area.
     * @verbatim
     *      x < left+f                     x >= right-f
     *   +---------+------------------------------+---------+  y < top+f
     *   | TOPLEFT |            HTTOP             | TOPRIGHT|
     *   +---------+------------------------------+---------+
     *   | HTLEFT  |           HTCLIENT           | HTRIGHT |
     *   +---------+------------------------------+---------+  y >= bottom-f
     *   | BTMLEFT |           HTBOTTOM           | BTMRIGHT|
     *   +---------+------------------------------+---------+
     * @endverbatim
     * HTCLIENT points fall through to Qt; QML drags them via startSystemMove().
     *
     * @return `true` when the message was handled and @p result is authoritative.
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;
};

/**
 * @brief One-time setup: install TitleBarFilter, extend DWM frame, round corners.
 *
 * Idempotent - calling multiple times is safe. On the first call, removes the
 * window icon, installs the native event filter, extends the DWM frame into the
 * client area, requests rounded corners, and forces a frame recalculation.
 *
 * @param hwnd Native window handle for the application's main window.
 */
void InstallWindowChrome(HWND hwnd);

/**
 * @brief Apply DWM dark or light window theme attributes.
 *
 * Sets the immersive dark-mode flag, suppresses the 1px DWM border stroke
 * (border color set to none), and sets the caption and text colors on the
 * given window handle. The caption color closely tracks the QML Theme's
 * bgDeep background and the text color its textPrimary foreground, so taskbar
 * thumbnails and alt-tab previews blend in.
 *
 * @par DWM theme colors (COLORREF from RGB)
 * | Element | DWM attribute (id)       | Dark    | Light   |
 * |---------|--------------------------|---------|---------|
 * | Caption | DWMWA_CAPTION_COLOR (34) | #070810 | #f8f6f2 |
 * | Text    | DWMWA_TEXT_COLOR (36)    | #e0e6f4 | #1e1a12 |
 * | Border  | DWMWA_BORDER_COLOR (35)  | none    | none    |
 *
 * The border is set to DWMWA_COLOR_NONE (0xFFFFFFFE) in both themes to drop
 * the 1px accent stroke; DWMWA_USE_IMMERSIVE_DARK_MODE (20) follows @p dark.
 *
 * @param hwnd Native window handle.
 * @param dark `true` for dark theme, `false` for light.
 */
void ApplyWindowTheme(HWND hwnd, bool dark);

}  // namespace seal

#endif  // USE_QT_UI
