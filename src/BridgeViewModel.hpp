#pragma once

#ifdef USE_QT_UI

#include <QObject>
#include <QString>
#include <QTimer>

namespace seal
{

class FillController;

/**
 * @class BridgeViewModel
 * @brief ViewModel collaborator that owns the browser-companion bridge
 *        presentation and control surface.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Extracted from @ref AppViewModel to keep the QML bridge concern (M8 panic-mode
 * toggle, per-browser connected-state indicators, native-messaging host
 * install/uninstall, and the diagnose dry-run) in one cohesive object,
 * following the same owned-collaborator pattern as @ref FillController and
 * @ref WindowController.
 *
 * Holds **no secret material**: it only reads the bridge connection atomics
 * exposed by @ref FillController, persists the enable/disable preference via
 * `QSettings`, and relays human-readable status / info / error strings.
 * Registered as the `Bridge` QML context property in `RunQMLMode` so QML
 * binds `Bridge.*` directly; status messages are forwarded to
 * `AppViewModel`'s `IUiFeedback::setStatus` via a connect in the
 * composition root.
 *
 * @see AppViewModel, FillController
 */
class BridgeViewModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(
        bool bridgeEnabled READ bridgeEnabled WRITE setBridgeEnabled NOTIFY bridgeEnabledChanged)
    Q_PROPERTY(bool bridgePeerConnected READ bridgePeerConnected NOTIFY bridgePeerConnectedChanged)
    Q_PROPERTY(
        bool bridgeChromeConnected READ bridgeChromeConnected NOTIFY bridgeChromeConnectedChanged)
    Q_PROPERTY(
        bool bridgeBraveConnected READ bridgeBraveConnected NOTIFY bridgeBraveConnectedChanged)
    Q_PROPERTY(QString bridgeStatusText READ bridgeStatusText NOTIFY bridgeStatusTextChanged)
    Q_PROPERTY(bool autoStageEnabled READ autoStageEnabled WRITE setAutoStageEnabled NOTIFY
                   autoStageEnabledChanged)
    Q_PROPERTY(bool bridgePeerAuthEnforced READ bridgePeerAuthEnforced CONSTANT)

public:
    /**
     * @brief Construct the ViewModel, restore the persisted enable state, and
     *        start the 1 Hz peer-connected poll.
     * @param fillController Borrowed (non-owning) controller that owns the
     *        actual BrowserBridge; must outlive this presenter.
     * @param parent QObject parent (typically the owning AppViewModel).
     */
    explicit BridgeViewModel(FillController* fillController, QObject* parent = nullptr);

    /// @brief Whether the browser bridge is enabled (M8 panic-mode off).
    bool bridgeEnabled() const;

    /**
     * @brief Whether peer signer authentication is active (this binary is signed).
     *        False in an unsigned build, where the M6 signer gate accepts any
     *        peer; the settings panel shows a warning when this is false.
     */
    bool bridgePeerAuthEnforced() const;

    /// @brief Whether any browser-companion peer is currently connected.
    bool bridgePeerConnected() const;

    /// @brief Whether a Chrome-launched companion peer is connected.
    bool bridgeChromeConnected() const;

    /// @brief Whether a Brave-launched companion peer is connected.
    bool bridgeBraveConnected() const;

    /// @brief Human-readable bridge status for the settings panel.
    QString bridgeStatusText() const;

    /**
     * @brief Toggle the browser bridge on/off (M8 panic mode) and persist it.
     * @param enabled true to allow extension reports, false to disable.
     */
    Q_INVOKABLE void setBridgeEnabled(bool enabled);

    /// @brief Whether zero-gesture staged auto-fill is enabled (default false).
    bool autoStageEnabled() const;

    /**
     * @brief Enable/disable staged auto-fill and persist it. The actual
     *        staging behaviour lives in StagingController, wired to this
     *        property's change signal in the composition root.
     * @param enabled true to auto-arm on matching navigation.
     */
    Q_INVOKABLE void setAutoStageEnabled(bool enabled);

    /// @brief Install the browser-companion native-messaging manifest (HKCU).
    Q_INVOKABLE void runInstallBrowserExtension();

    /// @brief Remove the browser-companion native-messaging manifest (HKCU).
    Q_INVOKABLE void runUninstallBrowserExtension();

    /// @brief Arm the FillController in dry-run "diagnose" mode.
    Q_INVOKABLE void runBridgeDiagnose();

signals:
    void bridgeEnabledChanged();          ///< Browser bridge enabled/disabled.
    void bridgePeerConnectedChanged();    ///< Any-bridge-peer connect/disconnect edge.
    void bridgeChromeConnectedChanged();  ///< Chrome-peer connect/disconnect edge.
    void bridgeBraveConnectedChanged();   ///< Brave-peer connect/disconnect edge.
    void bridgeStatusTextChanged();       ///< Bridge status text updated.
    void autoStageEnabledChanged();       ///< Staged auto-fill toggled on/off.

    /// @brief Diagnose dry-run finished; @p summary holds the per-probe breakdown.
    void bridgeDiagnoseReady(const QString& summary);

    /// @brief Diagnose dry-run was cancelled (Esc or timeout).
    void bridgeDiagnoseCancelled();

    /// @brief An informational message should be shown to the user.
    void infoMessage(const QString& title, const QString& message);

    /// @brief An error occurred that should be shown to the user.
    void errorOccurred(const QString& title, const QString& message);

    /// @brief A status-bar message that the owning AppViewModel should display.
    void statusMessage(const QString& text);

private:
    FillController* m_FillController = nullptr;  ///< Borrowed controller owning the BrowserBridge.

    QTimer m_BridgePeerPoll;             ///< Polls bridge peer-connected state (1 Hz).
    bool m_LastPeerConnected = false;    ///< Last observed any-peer level, for edge detection.
    bool m_LastChromeConnected = false;  ///< Last observed Chrome-peer level, for edge detection.
    bool m_LastBraveConnected = false;   ///< Last observed Brave-peer level, for edge detection.
    QString m_BridgeStatusText;          ///< Last bridge action result for QML.
};

}  // namespace seal

#endif  // USE_QT_UI
