#pragma once

#ifdef USE_QT_UI

#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantList>

#include <vector>

namespace seal
{

class FillController;

/**
 * @class BridgeViewModel
 * @brief ViewModel collaborator that owns the browser-companion bridge
 *        presentation and control surface.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup ViewModel
 *
 * Carries one QML concern: the M8 panic-mode toggle, the per-browser
 * connected-state indicators, native-messaging host install and uninstall, and
 * the diagnose dry-run. This is the same one-concern-per-context-property split
 * @ref WindowController uses.
 *
 * Holds no secret material: it reads the bridge connection atomics exposed by
 * @ref FillController, persists `bridge/enabled` and `bridge/autostage` via
 * `QSettings`, and relays human-readable status, info and error strings. It is
 * the `Bridge` QML context property, bound in `RunQMLMode`; status messages
 * reach `AppViewModel`'s `IUiFeedback::setStatus` through a connect made in the
 * composition root.
 *
 * @par Lifetime
 * `RunQMLMode` builds this on the stack beside the @ref FillController it
 * borrows, with no QObject parent. It is not a child of @ref AppViewModel; the
 * two are linked only by signal connections made in the composition root.
 *
 * @par Polled state
 * `BrowserBridge` is not a QObject, so a 1 Hz timer samples it and turns level
 * changes into signals: a per-browser connect edge emits @ref browsersChanged,
 * and the Chrome, Brave and any-peer levels each emit their own signal. QML
 * draws the per-browser dots from @ref browsers; @ref bridgePeerConnected,
 * @ref bridgeChromeConnected and @ref bridgeBraveConnected are convenience
 * properties that no `qml/` file binds today.
 *
 * @par Installed-browser detection
 * Probed at construction and again after @ref runInstallBrowserExtension, never
 * polled. A browser installed while seal runs appears in @ref browsers only
 * after the next manifest install or a restart.
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
    Q_PROPERTY(QVariantList browsers READ browsers NOTIFY browsersChanged)
    Q_PROPERTY(QString bridgeStatusText READ bridgeStatusText NOTIFY bridgeStatusTextChanged)
    Q_PROPERTY(bool autoStageEnabled READ autoStageEnabled WRITE setAutoStageEnabled NOTIFY
                   autoStageEnabledChanged)
    Q_PROPERTY(bool bridgePeerAuthEnforced READ bridgePeerAuthEnforced CONSTANT)

public:
    /**
     * @brief Construct the ViewModel, apply the persisted enable state, and
     *        start the 1 Hz peer-connected poll.
     *
     * Applying the state is not passive. `bridge/enabled` defaults to true, and
     * enabling opens the native-messaging pipe at once rather than on first
     * arm, so an extension launched with the browser connects immediately. A
     * pipe left closed until arm time drops the extension into its reconnect
     * backoff (doubling, capped at 5 s) and then its 30 s recovery alarm, so
     * the first fill can wait tens of seconds.
     *
     * The constructor also subscribes to the FillController diagnose signals
     * and seeds the connected and installed caches that the poll compares
     * against.
     *
     * @pre @p fillController is not null; it is dereferenced during
     *      construction and on every property read.
     * @param fillController Borrowed controller that owns the BrowserBridge;
     *        must outlive this object.
     * @param parent QObject parent, or nullptr. The composition root passes
     *        nothing and keeps the object on the stack.
     */
    explicit BridgeViewModel(FillController* fillController, QObject* parent = nullptr);

    /**
     * @brief Whether the browser bridge is enabled (M8 panic-mode off).
     *
     * Read live from the FillController, not from `QSettings`. The stored
     * preference is only the value replayed at the next start.
     */
    bool bridgeEnabled() const;

    /**
     * @brief Whether peer signer authentication is active (this binary is signed).
     *
     * False in an unsigned build, where the M6 signer gate accepts any peer; the
     * browser-chip row in the status footer (qml/BridgeSettings.qml) then shows
     * an amber unsigned-build warning. The value is fixed at startup from the
     * running binary's Authenticode identity, so the QML property is `CONSTANT`
     * and emits no change signal.
     */
    bool bridgePeerAuthEnforced() const;

    /// @brief Whether any browser-companion peer is currently connected.
    bool bridgePeerConnected() const;

    /// @brief Whether a Chrome-launched companion peer is connected.
    bool bridgeChromeConnected() const;

    /// @brief Whether a Brave-launched companion peer is connected.
    bool bridgeBraveConnected() const;

    /**
     * @brief Installed Chromium-family browsers and live connection state.
     *
     * Each row holds only non-secret presentation metadata: `label`, `key`,
     * `icon`, `iconPath`, `iconAvailable`, `extensionsPage`, `installed` and
     * `connected`.
     *
     * Gecko entries are skipped, because seal ships no Gecko native-messaging
     * manifest. A Chromium entry is listed when it is detected as installed or
     * is connected right now, so a portable copy that install detection misses
     * still appears once its peer connects.
     *
     * - `installed` comes from the cache refreshed at construction and after
     *   @ref runInstallBrowserExtension.
     * - `connected` is read live from the FillController.
     * - `iconAvailable` probes the compiled-in resource, so it is false in a
     *   build made with an empty `assets/` tree.
     *
     * @return A freshly built list; the rows are rebuilt on every read, so bind
     *         it in QML rather than calling it in a loop.
     */
    QVariantList browsers() const;

    /// @brief Human-readable result of the last companion install or uninstall.
    /// Shown as the tooltip of the header Setup button (`qml/HeaderBar.qml`).
    /// Empty until one of those two commands runs.
    QString bridgeStatusText() const;

    /**
     * @brief Toggle the browser bridge on/off (M8 panic mode) and persist it.
     *
     * Takes effect at once: enabling opens the native-messaging pipe, disabling
     * closes it and drops any connected peer. The comparison is against the
     * live FillController state, so a call that matches it returns without
     * writing `QSettings` and without emitting @ref bridgeEnabledChanged.
     *
     * @param enabled true to allow extension reports, false to disable them.
     */
    Q_INVOKABLE void setBridgeEnabled(bool enabled);

    /**
     * @brief Whether zero-gesture staged auto-fill is enabled (default false).
     *
     * Reads `bridge/autostage` from `QSettings` on every call, with no cached
     * copy, so each call returns the stored value. Only @ref setAutoStageEnabled
     * emits @ref autoStageEnabledChanged, so a write through any other path
     * updates the stored value but re-evaluates no QML binding and does not
     * notify StagingController. A new writer must emit that signal itself.
     */
    bool autoStageEnabled() const;

    /**
     * @brief Enable/disable staged auto-fill and persist it.
     *
     * This setter writes `bridge/autostage` and emits
     * @ref autoStageEnabledChanged, nothing more. The staging behaviour lives
     * in StagingController, which is not a QML context property and is attached
     * to that signal in the composition root; without that connection the
     * toggle changes nothing. A call that matches the stored value returns
     * without writing and without emitting.
     *
     * @param enabled true to auto-arm on matching navigation.
     */
    Q_INVOKABLE void setAutoStageEnabled(bool enabled);

    /**
     * @brief Install the browser-companion native-messaging manifest (HKCU).
     *
     * Writes the manifest and the per-browser HKCU registry values, refreshes
     * the installed-browser cache (emitting @ref browsersChanged when a flag
     * moved), and stores the human-readable outcome in @ref bridgeStatusText.
     * Emits @ref infoMessage on success and @ref errorOccurred on failure, with
     * the same message text in both cases. Runs synchronously on the GUI
     * thread.
     */
    Q_INVOKABLE void runInstallBrowserExtension();

    /**
     * @brief Remove the browser-companion native-messaging manifest (HKCU).
     *
     * Mirrors @ref runInstallBrowserExtension for the registry values and the
     * status text, but does not re-probe installed browsers: removing the
     * manifest does not uninstall a browser, so the `installed` flags in
     * @ref browsers stay valid. The generated manifest file on disk is kept.
     */
    Q_INVOKABLE void runUninstallBrowserExtension();

    /**
     * @brief Arm the FillController in dry-run "diagnose" mode.
     *
     * Diagnose reads no credential, so it skips the password gate and works
     * with a locked vault. On success it emits @ref statusMessage with the
     * prompt, and the user has one `FillController::FILL_TIMEOUT_SECONDS`
     * window (30 s) to Ctrl+Click a field. The per-probe report then arrives as
     * @ref bridgeDiagnoseReady, or @ref bridgeDiagnoseCancelled on Esc or
     * timeout. When the input hooks cannot be installed, the method emits
     * @ref errorOccurred and returns without arming.
     */
    Q_INVOKABLE void runBridgeDiagnose();

signals:
    void bridgeEnabledChanged();          ///< Browser bridge enabled/disabled.
    void bridgePeerConnectedChanged();    ///< Any-bridge-peer connect/disconnect edge.
    void bridgeChromeConnectedChanged();  ///< Chrome-peer connect/disconnect edge.
    void bridgeBraveConnectedChanged();   ///< Brave-peer connect/disconnect edge.
    void browsersChanged();               ///< Browser list/install/connect state changed.
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
    /**
     * @brief Re-probe the registry and disk for installed Chromium browsers.
     *
     * Updates @ref m_InstalledBrowsers in place. Gecko kinds are skipped and
     * keep their initial false. This helper emits nothing; the caller decides
     * whether to emit @ref browsersChanged.
     *
     * @return true when at least one entry changed value.
     */
    bool refreshInstalledBrowsers();

    FillController* m_FillController = nullptr;  ///< Borrowed controller owning the BrowserBridge.

    QTimer m_BridgePeerPoll;           ///< Polls bridge peer-connected state (1 Hz).
    bool m_LastPeerConnected = false;  ///< Last observed any-peer level, for edge detection.
    /// Last observed Chrome level. Duplicates one m_LastBrowserConnected slot, because the
    /// Chrome and Brave convenience properties need their own edge signal.
    bool m_LastChromeConnected = false;
    /// Last observed Brave level; same duplication as m_LastChromeConnected.
    bool m_LastBraveConnected = false;
    /// Per-BrowserKind connected level, indexed by the BrowserKind value; sized to
    /// BrowserKind::Count in the constructor.
    std::vector<bool> m_LastBrowserConnected;
    /// Per-BrowserKind installed flag, same indexing. Only Chromium kinds are probed.
    std::vector<bool> m_InstalledBrowsers;
    QString m_BridgeStatusText;  ///< Last install/uninstall result text for QML.
};

}  // namespace seal

#endif  // USE_QT_UI
