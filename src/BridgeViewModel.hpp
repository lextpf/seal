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
 * @brief Expose non-secret browser bridge controls as the Bridge QML context property.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Poll connection atomics at 1 Hz and emit changes. Installed-browser detection
 * runs only at construction and after manifest installation. QSettings persists
 * `bridge/enabled` and `bridge/autostage`; RunQMLMode connects status to AppViewModel.
 *
 * @pre The borrowed FillController outlives this object.
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
     * @fn BridgeViewModel(FillController* fillController, QObject* parent = nullptr)
     * @brief Restore bridge enablement, connect diagnosis signals and start connection polling.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Enablement defaults to true and opens the pipe immediately so browser startup
     * does not enter reconnect backoff.
     *
     * @param fillController Non-null borrowed controller; must outlive this object.
     */
    explicit BridgeViewModel(FillController* fillController, QObject* parent = nullptr);

    /**
     * @fn bool bridgeEnabled() const
     * @brief Live engine state; the persisted preference is replayed at startup.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool bridgeEnabled() const;

    /**
     * @fn bool bridgePeerAuthEnforced() const
     * @brief Report whether the bridge requires a matching peer signer.
     * @author Alex (<https://github.com/lextpf>)
     *
     * An unavailable or untrusted application signer disables peer-signer matching
     * in development builds. SEAL_REQUIRE_SIGNED_PEER then prevents bridge startup.
     * Process pinning and trusted browser ancestry checks still apply.
     *
     * @return True when the application cached a trusted, non-empty signer identity.
     */
    bool bridgePeerAuthEnforced() const;

    bool bridgePeerConnected() const;

    bool bridgeChromeConnected() const;

    bool bridgeBraveConnected() const;

    /**
     * @fn QVariantList browsers() const
     * @brief Build a list of installed or connected Chromium browsers.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Rows contain `label`, `key`, `icon`, `iconPath`, `iconAvailable`, `extensionsPage`,
     * `installed` and `connected`. Connected portable browsers remain visible even
     * when installation detection misses them. Gecko has no supported manifest.
     *
     * Installed state is cached; connections and icon availability are read live.
     * Missing bundled assets make `iconAvailable` false. Each read rebuilds the list.
     */
    QVariantList browsers() const;

    /**
     * @fn QString bridgeStatusText() const
     * @brief Last install/uninstall result; empty before either command runs.
     * @author Alex (<https://github.com/lextpf>)
     */
    QString bridgeStatusText() const;

    /**
     * @fn void setBridgeEnabled(bool enabled)
     * @brief Persist enablement and open or close the pipe immediately.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Disabling disconnects peers. Matching live state makes this a no-op.
     */
    Q_INVOKABLE void setBridgeEnabled(bool enabled);

    /**
     * @fn bool autoStageEnabled() const
     * @brief Read bridge/autostage from QSettings on every call; default false.
     * @author Alex (<https://github.com/lextpf>)
     *
     * External settings writes emit no signal. Use `setAutoStageEnabled()` to update
     * QML bindings and StagingController.
     */
    bool autoStageEnabled() const;

    /**
     * @fn void setAutoStageEnabled(bool enabled)
     * @brief Persist staging preference and emit only when it changes.
     * @author Alex (<https://github.com/lextpf>)
     *
     * RunQMLMode must connect the signal to StagingController for it to take effect.
     */
    Q_INVOKABLE void setAutoStageEnabled(bool enabled);

    /**
     * @fn void runInstallBrowserExtension()
     * @brief Write the manifest and HKCU registrations on the GUI thread.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Refresh installed browsers and status. Success emits `infoMessage`; failure
     * emits `errorOccurred`.
     */
    Q_INVOKABLE void runInstallBrowserExtension();

    /**
     * @fn void runUninstallBrowserExtension()
     * @brief Remove HKCU registrations and report status; keep the manifest file.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Browser installation state is unchanged, so its cache is not refreshed.
     */
    Q_INVOKABLE void runUninstallBrowserExtension();

    /**
     * @fn void runBridgeDiagnose()
     * @brief Diagnose a Ctrl+Click within 30 s without accessing credentials.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Works while locked. Emits the probe report on completion, cancellation on
     * Escape/timeout, or `errorOccurred` when hooks cannot be installed.
     */
    Q_INVOKABLE void runBridgeDiagnose();

signals:
    void bridgeEnabledChanged();
    void bridgePeerConnectedChanged();
    void bridgeChromeConnectedChanged();
    void bridgeBraveConnectedChanged();
    void browsersChanged();
    void bridgeStatusTextChanged();
    void autoStageEnabledChanged();

    /**
     * @fn void bridgeDiagnoseReady(const QString& summary)
     * @brief Per-probe report from the dry run.
     * @author Alex (<https://github.com/lextpf>)
     */
    void bridgeDiagnoseReady(const QString& summary);

    /**
     * @fn void bridgeDiagnoseCancelled()
     * @brief Escape or timeout ended diagnosis.
     * @author Alex (<https://github.com/lextpf>)
     */
    void bridgeDiagnoseCancelled();

    void infoMessage(const QString& title, const QString& message);

    void errorOccurred(const QString& title, const QString& message);

    void statusMessage(const QString& text);

private:
    /**
     * @fn bool refreshInstalledBrowsers()
     * @brief Refresh Chromium installation flags without emitting signals.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return True if any flag changed.
     */
    bool refreshInstalledBrowsers();

    FillController* m_FillController = nullptr;  ///< Borrowed controller owning the BrowserBridge.

    QTimer m_BridgePeerPoll;           ///< Polls bridge peer-connected state (1 Hz).
    bool m_LastPeerConnected = false;  ///< Last observed any-peer level, for edge detection.
    /// Separate edge cache for the Chrome convenience property.
    bool m_LastChromeConnected = false;
    /// Separate edge cache for Brave.
    bool m_LastBraveConnected = false;
    /// Indexed by BrowserKind; sized to BrowserKind::Count.
    std::vector<bool> m_LastBrowserConnected;
    /// Same indexing; only Chromium installation is probed.
    std::vector<bool> m_InstalledBrowsers;
    QString m_BridgeStatusText;
};

}  // namespace seal

#endif  // USE_QT_UI
