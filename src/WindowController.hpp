#pragma once

#ifdef USE_QT_UI

#include <QObject>

namespace seal
{

/**
 * @class WindowController
 * @brief Manages window chrome operations: theme, drag, always-on-top, compact mode.
 * @author Alex (https://github.com/lextpf)
 * @ingroup WindowController
 *
 * Extracted from Backend to isolate window management from vault/crypto logic.
 * Backend owns this controller and relays its signals to QML.
 *
 * @see Backend, WindowChrome
 */
class WindowController : public QObject
{
    Q_OBJECT

public:
    explicit WindowController(QObject* parent = nullptr);

    /// @brief Check whether the window is pinned above other windows.
    bool isAlwaysOnTop() const;

    /// @brief Check whether the window is in compact (minimal strip) mode.
    bool isCompact() const;

    /// @brief Apply DWM dark or light window theme and update the custom title bar.
    /// @param dark `true` for dark theme, `false` for light.
    void updateWindowTheme(bool dark);

    /// @brief Initiate a native window drag via `startSystemMove()`.
    void startWindowDrag();

    /// @brief Toggle always-on-top (HWND_TOPMOST / HWND_NOTOPMOST).
    void toggleAlwaysOnTop();

    /// @brief Toggle compact mode (shrinks window to a minimal strip).
    void toggleCompact();

signals:
    void alwaysOnTopChanged();  ///< Always-on-top toggled.
    void compactChanged();      ///< Compact mode toggled.

private:
    bool m_AlwaysOnTop = false;  ///< Window pinned above others.
    bool m_Compact = false;      ///< Compact mode active.
    int m_NormalWidth = 0;       ///< Saved width before compact.
    int m_NormalHeight = 0;      ///< Saved height before compact.
};

}  // namespace seal

#endif  // USE_QT_UI
