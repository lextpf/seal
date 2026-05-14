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

    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;
};

/**
 * @brief One-time setup: install TitleBarFilter, extend DWM frame, round corners.
 * @author Alex (https://github.com/lextpf)
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
 * @author Alex (https://github.com/lextpf)
 *
 * Sets the immersive dark mode flag, border color, caption color, and text
 * color on the given window handle. Colors match the QML Theme's bgDeep
 * values for seamless integration.
 *
 * @param hwnd Native window handle.
 * @param dark `true` for dark theme, `false` for light.
 */
void ApplyWindowTheme(HWND hwnd, bool dark);

}  // namespace seal

#endif  // USE_QT_UI
