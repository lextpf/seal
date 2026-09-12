#pragma once

#ifdef USE_QT_UI

#include <QAbstractNativeEventFilter>
#include <QObject>

namespace seal
{

/**
 * @class WindowController
 * @brief expose native window operations through the WindowVM QML context property.
 * @author Alex (https://github.com/lextpf)
 * @ingroup WindowController
 *
 * window operations use the first current top-level window; with none they leave
 * state unchanged and emit nothing. WM_SETTINGCHANGE refreshes the OS animation
 * preference used by `reduceMotion`.
 *
 * @pre construct, call and destroy on the GUI thread; not reentrant.
 */
class WindowController : public QObject, public QAbstractNativeEventFilter
{
    Q_OBJECT

    Q_PROPERTY(bool isAlwaysOnTop READ isAlwaysOnTop NOTIFY alwaysOnTopChanged)
    Q_PROPERTY(bool isCompact READ isCompact NOTIFY compactChanged)
    Q_PROPERTY(bool reduceMotion READ reduceMotion NOTIFY reduceMotionChanged)

public:
    /**
     * @brief read animation preference and install the native filter.
     *
     * @pre a QGuiApplication exists.
     */
    explicit WindowController(QObject* parent = nullptr);

    /// remove the native filter if the application still exists.
    ~WindowController() override;

    /// cached toggle state; external z-order changes are not observed. not persisted.
    bool isAlwaysOnTop() const;

    /// starts false; not persisted.
    bool isCompact() const;

    /// negates the OS animation flag; defaults to false if the initial read fails.
    bool reduceMotion() const;

    /**
     * @brief refresh animation preference on WM_SETTINGCHANGE without consuming messages.
     *
     * only `windows_generic_MSG` is inspected; `result` is untouched.
     */
    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

    /**
     * @brief install chrome once, then apply theme attributes on every call.
     *
     * no-op without a native handle. emits no signal; callers repeat it on theme changes.
     */
    Q_INVOKABLE void updateWindowTheme(bool dark);

    /// call during a mouse press; the shell owns subsequent drag events.
    Q_INVOKABLE void startWindowDrag();

    /// cached state flips even if SetWindowPos fails and can differ from actual z-order.
    Q_INVOKABLE void toggleAlwaysOnTop();

    /**
     * @brief save normal geometry on entry and restore it on exit.
     *
     * | mode    | minimum height | size                                  |
     * |---------|----------------|---------------------------------------|
     * | compact | 272            | keep width; set height to 272         |
     * | normal  | 480            | saved size, clamped to current screen |
     *
     * dimensions are logical pixels. non-positive saved dimensions use 1600x690.
     * minimum width is unchanged. with no screen, restoration is unclamped; otherwise:
     *
     * $$
     *   w = \min\bigl(w_{saved},\; \max(w_{min},\; w_{avail} - 64)\bigr), \qquad
     *   h = \min\bigl(h_{saved},\; \max(480,\; h_{avail} - 64)\bigr)
     * $$
     *
     * keep 272/480 heights and the 64 px inset synchronized with qml/Main.qml.
     */
    Q_INVOKABLE void toggleCompact();

signals:
    void alwaysOnTopChanged();
    void compactChanged();
    void reduceMotionChanged();

private:
    /// keep cached state on read failure; emit only on change.
    void refreshReduceMotion();

    bool m_AlwaysOnTop = false;
    bool m_Compact = false;
    bool m_ReduceMotion = false;  ///< OS asks apps to minimize animation.
    /// saved logical pixels; <= 0 selects the 1600 px fallback.
    int m_NormalWidth = 0;
    /// saved logical pixels; <= 0 selects the 690 px fallback.
    int m_NormalHeight = 0;
};

}  // namespace seal

#endif  // USE_QT_UI
