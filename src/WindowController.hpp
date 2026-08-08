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
 * Keeps window management out of the vault and crypto logic. `RunQMLMode`
 * builds one instance on the stack and registers it as the `WindowVM` QML
 * context property, so QML reaches these properties and methods directly.
 * `AppViewModel` neither owns this object nor relays its signals.
 *
 * Also surfaces the operating-system "Show animations in Windows" preference
 * (SPI_GETCLIENTAREAANIMATION) as `reduceMotion`, refreshed on
 * WM_SETTINGCHANGE, so QML can gate flashes and large motion.
 *
 * @par Target window
 * No window handle is stored. Every method that acts on the window re-reads
 * `QGuiApplication::topLevelWindows().first()`, so the controller survives
 * window recreation. With no top-level window yet, those methods return without
 * changing state and without emitting a signal; the toggles test the list
 * before they flip their flag.
 *
 * @note Not thread-safe and not reentrant. Construct, call and destroy it on
 * the GUI thread only.
 *
 * @see AppViewModel, WindowChrome, RunQMLMode
 */
class WindowController : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

    Q_PROPERTY(bool isAlwaysOnTop READ isAlwaysOnTop NOTIFY alwaysOnTopChanged)
    Q_PROPERTY(bool isCompact READ isCompact NOTIFY compactChanged)
    Q_PROPERTY(bool reduceMotion READ reduceMotion NOTIFY reduceMotionChanged)

public:
    /**
     * @brief Read the initial animation preference and install this object as a
     * native event filter on the application.
     *
     * @pre A `QGuiApplication` instance already exists. The constructor
     *      dereferences it without a null check.
     * @param parent Owning QObject, or null when the controller lives on the
     *               stack (the composition root does that).
     */
    explicit WindowController(QObject* parent = nullptr);

    /**
     * @brief Remove the installed native event filter.
     *
     * When the application object is already gone the destructor does nothing,
     * so destruction order against `QGuiApplication` does not matter.
     */
    ~WindowController() override;

    /**
     * @brief Check whether the window is pinned above other windows.
     *
     * Reports the flag that `toggleAlwaysOnTop` maintains, not the live
     * `WS_EX_TOPMOST` bit; the two diverge if anything else re-orders the
     * window. Starts `false` and is not persisted between runs.
     */
    bool isAlwaysOnTop() const;

    /**
     * @brief Check whether the window is in compact (minimal strip) mode.
     *
     * Reports the flag that `toggleCompact` maintains. Starts `false` and is
     * not persisted between runs.
     */
    bool isCompact() const;

    /**
     * @brief Whether the OS asks apps to minimize animation ("Show animations in
     * Windows" turned off).
     *
     * The value is the negation of the OS animate flag and stays `false` when
     * the preference cannot be read.
     */
    bool reduceMotion() const;

    /**
     * @brief Watch WM_SETTINGCHANGE to re-read the animation preference live.
     *
     * The constructor installs this filter on the application, so it sees every
     * window's messages. It triggers a re-read and consumes nothing.
     *
     * @param eventType Qt platform tag; only `"windows_generic_MSG"` is inspected.
     * @param message   Points to a Win32 `MSG` owned by Qt.
     * @param result    Unused and left untouched.
     * @return Always `false`, so the message continues on to Qt.
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

    /**
     * @brief Apply the DWM dark or light window theme.
     *
     * Calls `InstallWindowChrome` first so the custom frame exists before the
     * theme attributes land. That call latches after the first window, so later
     * invocations change only the theme attributes. Returns without effect when
     * `winId()` yields no handle.
     *
     * @note Emits no signal, so every theme change must re-invoke it. QML does
     * this once at startup and again on each `Theme.dark` change.
     *
     * @param dark `true` for dark theme, `false` for light.
     */
    Q_INVOKABLE void updateWindowTheme(bool dark);

    /**
     * @brief Initiate a native window drag via `startSystemMove()`.
     *
     * Call it from a press handler while the button is still down; the shell
     * then owns the drag and QML receives no further mouse events for it.
     * Needed because `TitleBarFilter` reports the caption area as HTCLIENT, not
     * HTCAPTION.
     */
    Q_INVOKABLE void startWindowDrag();

    /**
     * @brief Toggle always-on-top (HWND_TOPMOST / HWND_NOTOPMOST).
     *
     * Flips the cached flag, calls `SetWindowPos` with `SWP_NOMOVE |
     * SWP_NOSIZE`, logs the new state, and emits `alwaysOnTopChanged`. The
     * flag flips even when `SetWindowPos` fails, so the property can disagree
     * with the real z-order.
     */
    Q_INVOKABLE void toggleAlwaysOnTop();

    /**
     * @brief Toggle compact mode (shrinks window to a minimal strip).
     *
     * @par Compact vs. normal geometry
     * | State   | Min height | Size applied                                   |
     * |---------|------------|------------------------------------------------|
     * | Compact | 272        | current width x 272                            |
     * | Normal  | 480        | saved width x height, clamped (see below)      |
     *
     * Entering compact saves the current width and height, then changes only the
     * height. Leaving compact restores the saved pair, or 1600 x 690 when a
     * saved value is not positive. Minimum width is never touched. The mode
     * starts as normal, so the first toggle always enters compact and stores
     * both values; 1600 x 690 is a defensive fallback.
     *
     * @par Restore clamp
     * When the window reports a screen, the restore is clamped against that
     * screen's available geometry with a 64 px inset per axis, which also
     * re-fits a strip dragged onto a smaller monitor. With no screen the saved
     * size is applied unclamped.
     *
     * For stored size @f$ w_{saved} @f$, @f$ h_{saved} @f$, available geometry
     * @f$ w_{avail} @f$, @f$ h_{avail} @f$ and the window's own minimum width
     * @f$ w_{min} @f$:
     * @f[
     *   w = \min\bigl(w_{saved},\; \max(w_{min},\; w_{avail} - 64)\bigr), \qquad
     *   h = \min\bigl(h_{saved},\; \max(480,\; h_{avail} - 64)\bigr)
     * @f]
     *
     * @note `qml/Main.qml` repeats these numbers: its `minimumHeight` binding
     * mirrors 272 / 480 and `fitInitialWindowToScreen()` mirrors the 64 px
     * inset. Changing one side requires changing the other.
     */
    Q_INVOKABLE void toggleCompact();

signals:
    void alwaysOnTopChanged();   ///< Emitted after `toggleAlwaysOnTop` flips the pin.
    void compactChanged();       ///< Emitted after `toggleCompact` resizes the window.
    void reduceMotionChanged();  ///< Emitted only when the OS preference really changed.

private:
    /**
     * @brief Re-read SPI_GETCLIENTAREAANIMATION; emits on change.
     *
     * `reduceMotion` is the negation of the OS animate flag. A failed
     * `SystemParametersInfoW` keeps the cached value; neither that nor an
     * unchanged value emits, so a WM_SETTINGCHANGE storm costs one system call
     * per message.
     */
    void refreshReduceMotion();

    bool m_AlwaysOnTop = false;   ///< Window pinned above others.
    bool m_Compact = false;       ///< Compact mode active.
    bool m_ReduceMotion = false;  ///< OS asks apps to minimize animation.
    /// Width saved when compact mode was entered. Stays 0 until the first
    /// toggle; a non-positive value selects the 1600 px restore fallback.
    int m_NormalWidth = 0;
    /// Height saved when compact mode was entered. Stays 0 until the first
    /// toggle; a non-positive value selects the 690 px restore fallback.
    int m_NormalHeight = 0;
};

}  // namespace seal

#endif  // USE_QT_UI
