#pragma once

#ifdef USE_QT_UI

#include <QtCore/QAbstractNativeEventFilter>

#include <windows.h>

namespace seal
{

/**
 * @class TitleBarFilter
 * @brief extend Qt client rendering over native window chrome.
 * @author Alex (https://github.com/lextpf)
 * @ingroup WindowChrome
 *
 * InstallWindowChrome installs one process-lifetime filter. Qt borrows it and
 * dispatches on the GUI thread; only the bound HWND is handled.
 */
class TitleBarFilter : public QAbstractNativeEventFilter
{
public:
    /// borrowed target HWND; null makes the filter inert.
    HWND m_Hwnd = nullptr;

    /**
     * @brief handle non-client messages for the bound window.
     *
     * | message       | action                             | result   |
     * |---------------|------------------------------------|----------|
     * | WM_NCCALCSIZE | claim client area                  | 0        |
     * | WM_NCACTIVATE | suppress border activation repaint | TRUE     |
     * | WM_NCPAINT    | suppress non-client paint          | 0        |
     * | WM_NCHITTEST  | return resize/client zone          | HT* code |
     *
     * WM_NCCALCSIZE handles both wParam forms. maximized windows use the monitor work
     * area; failed monitor queries leave the proposed rectangle unchanged.
     *
     * resize bands use window DPI, falling back to 96. fx = SM_CXSIZEFRAME +
     * SM_CXPADDEDBORDER; fy = SM_CYSIZEFRAME + SM_CXPADDEDBORDER. coordinates are screen pixels.
     *
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
     *
     * corners win over edges. maximized windows and all remaining points return
     * HTCLIENT; QML must start dragging itself. HTCAPTION/HTMAXBUTTON are never
     * returned, so native caption double-click, system menu and Snap Layouts are absent.
     *
     * @param eventType only `windows_generic_MSG` is inspected.
     * @param message borrowed MSG, valid for this call.
     * @param result written only when returning true.
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;
};

/**
 * @brief install chrome for the first window passed in the process.
 * @ingroup WindowChrome
 *
 * clears class/window icons and native caption/edge styles; retains native resize,
 * snap and min/max behavior. installs the process-lifetime filter, extends DWM
 * over the client area, disables the opaque backdrop, requests rounded corners
 * and recalculates the frame. class icon changes affect other windows of that class.
 *
 * Win32/DWM failures are ignored and still latch the one-time guard.
 *
 * @pre a QCoreApplication exists; call on the GUI thread with a valid HWND.
 * @see ApplyWindowTheme
 */
void InstallWindowChrome(HWND hwnd);

/**
 * @brief set DWM colors for shell previews.
 * @ingroup WindowChrome
 *
 * write dark mode, caption, text, then border. caption attributes recompute frame
 * color, so the border override must be last. QML Theme colors are independent.
 *
 * | element | DWM attribute            | dark    | light   |
 * |---------|--------------------------|---------|---------|
 * | caption | DWMWA_CAPTION_COLOR (35) | #070810 | #f8f6f2 |
 * | text    | DWMWA_TEXT_COLOR (36)    | #e0e6f4 | #1e1a12 |
 * | border  | DWMWA_BORDER_COLOR (34)  | none    | none    |
 *
 * DWMWA_COLOR_NONE (0xFFFFFFFE) removes the accent border. failures are ignored:
 * attribute 20 needs windows 10 build 18985; color attributes need windows 11
 * build 22000. older dark-mode attribute 19 is not attempted.
 *
 * @note does not install chrome; `WindowController::updateWindowTheme()` does both.
 */
void ApplyWindowTheme(HWND hwnd, bool dark);

}  // namespace seal

#endif  // USE_QT_UI
