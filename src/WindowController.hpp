#pragma once

#ifdef USE_QT_UI

#include <QAbstractNativeEventFilter>
#include <QObject>

namespace seal
{

/**
 * @class WindowController
 * @brief Manages window chrome operations: theme, drag, always-on-top, compact mode.
 * @author Alex (https://github.com/lextpf)
 * @ingroup WindowController
 *
 * Extracted from AppViewModel to isolate window management from vault/crypto logic.
 * AppViewModel owns this controller and relays its signals to QML.
 *
 * Also surfaces the OS "Show animations in Windows" preference
 * (SPI_GETCLIENTAREAANIMATION) as `reduceMotion`, refreshed on
 * WM_SETTINGCHANGE, so QML can gate flashes and large motion.
 *
 * @see AppViewModel, WindowChrome
 */
class WindowController : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

    Q_PROPERTY(bool isAlwaysOnTop READ isAlwaysOnTop NOTIFY alwaysOnTopChanged)
    Q_PROPERTY(bool isCompact READ isCompact NOTIFY compactChanged)
    Q_PROPERTY(bool reduceMotion READ reduceMotion NOTIFY reduceMotionChanged)

public:
    /// @brief Read the initial animation preference and install a native event filter.
    explicit WindowController(QObject* parent = nullptr);

    /// @brief Remove the installed native event filter.
    ~WindowController() override;

    /// @brief Check whether the window is pinned above other windows.
    bool isAlwaysOnTop() const;

    /// @brief Check whether the window is in compact (minimal strip) mode.
    bool isCompact() const;

    /**
     * @brief Whether the OS asks apps to minimize animation ("Show animations in
     * Windows" turned off).
     *
     * QML gates flashes and large motion on this preference; it is refreshed
     * live whenever a WM_SETTINGCHANGE arrives.
     */
    bool reduceMotion() const;

    /// @brief Watches WM_SETTINGCHANGE to re-read the animation preference live.
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

    /**
     * @brief Apply the DWM dark or light window theme.
     *
     * Ensures the custom title-bar chrome is installed first (idempotent), then
     * applies the immersive dark/light attributes.
     *
     * @param dark `true` for dark theme, `false` for light.
     */
    Q_INVOKABLE void updateWindowTheme(bool dark);

    /// @brief Initiate a native window drag via `startSystemMove()`.
    Q_INVOKABLE void startWindowDrag();

    /// @brief Toggle always-on-top (HWND_TOPMOST / HWND_NOTOPMOST).
    Q_INVOKABLE void toggleAlwaysOnTop();

    /**
     * @brief Toggle compact mode (shrinks window to a minimal strip).
     *
     * @par Compact vs. normal geometry
     * | State   | Min height | Size applied                          |
     * |---------|------------|---------------------------------------|
     * | Compact | 272        | current width x 272                   |
     * | Normal  | 540        | restored WxH, else 1420 x 690 default |
     *
     * Entering compact saves the current width/height so exiting can restore
     * them; a window launched directly into compact restores to 1420 x 690.
     */
    Q_INVOKABLE void toggleCompact();

signals:
    void alwaysOnTopChanged();   ///< Always-on-top toggled.
    void compactChanged();       ///< Compact mode toggled.
    void reduceMotionChanged();  ///< OS animation preference changed.

private:
    /// @brief Re-read SPI_GETCLIENTAREAANIMATION; emits on change.
    void refreshReduceMotion();

    bool m_AlwaysOnTop = false;   ///< Window pinned above others.
    bool m_Compact = false;       ///< Compact mode active.
    bool m_ReduceMotion = false;  ///< OS asks apps to minimize animation.
    int m_NormalWidth = 0;        ///< Saved width before compact.
    int m_NormalHeight = 0;       ///< Saved height before compact.
};

}  // namespace seal

#endif  // USE_QT_UI
