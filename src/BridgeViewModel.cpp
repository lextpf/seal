#ifdef USE_QT_UI

#include "BridgeViewModel.hpp"

#include "CliModes.hpp"
#include "FillController.hpp"

#include <QtCore/QSettings>
#include <QtCore/QString>

#include <string>

namespace seal
{

BridgeViewModel::BridgeViewModel(FillController* fillController, QObject* parent)
    : QObject(parent),
      m_FillController(fillController)
{
    // Diagnose dry-run: forward the summary up to QML. No DPAPI re-protect
    // is needed because diagnose never touches the master password.
    connect(m_FillController,
            &FillController::diagnoseCompleted,
            this,
            [this](const QString& summary)
            {
                emit statusMessage(QStringLiteral("Bridge diagnose complete"));
                emit bridgeDiagnoseReady(summary);
            });
    connect(m_FillController,
            &FillController::diagnoseCancelled,
            this,
            [this]()
            {
                emit statusMessage(QStringLiteral("Bridge diagnose cancelled"));
                emit bridgeDiagnoseCancelled();
            });

    // Restore persisted bridge enablement (M8; default true, QSettings ->
    // HKCU\Software\seal\seal via QmlMain). enableBridge() starts the pipe
    // immediately (not only on arm) so the extension can connect at launch,
    // else its reconnect backoff can stall the first fill by ~60 s.
    QSettings settings;
    const bool bridgeEnabledPref = settings.value("bridge/enabled", true).toBool();
    if (bridgeEnabledPref)
    {
        m_FillController->enableBridge();
    }
    else
    {
        m_FillController->disableBridge();
    }

    // BrowserBridge isn't a QObject, so poll per-browser connected state at 1 Hz
    // and convert level changes into *Changed signals. QML dots turn green only
    // after a real handshake, though atomics flip immediately on connect/disconnect;
    // aggregate bridgePeerConnected (chrome||brave) kept for existing bindings.
    m_LastPeerConnected = m_FillController->isBridgePeerConnected();
    m_LastChromeConnected = m_FillController->isBridgeChromeConnected();
    m_LastBraveConnected = m_FillController->isBridgeBraveConnected();
    m_BridgePeerPoll.setInterval(1000);
    connect(&m_BridgePeerPoll,
            &QTimer::timeout,
            this,
            [this]()
            {
                const bool chrome = m_FillController->isBridgeChromeConnected();
                if (chrome != m_LastChromeConnected)
                {
                    m_LastChromeConnected = chrome;
                    emit bridgeChromeConnectedChanged();
                }
                const bool brave = m_FillController->isBridgeBraveConnected();
                if (brave != m_LastBraveConnected)
                {
                    m_LastBraveConnected = brave;
                    emit bridgeBraveConnectedChanged();
                }
                const bool any = m_FillController->isBridgePeerConnected();
                if (any != m_LastPeerConnected)
                {
                    m_LastPeerConnected = any;
                    emit bridgePeerConnectedChanged();
                }
            });
    m_BridgePeerPoll.start();
}

bool BridgeViewModel::bridgeEnabled() const
{
    return m_FillController->isBridgeEnabled();
}

bool BridgeViewModel::bridgePeerAuthEnforced() const
{
    return m_FillController->isBridgePeerAuthEnforced();
}

bool BridgeViewModel::bridgePeerConnected() const
{
    return m_FillController->isBridgePeerConnected();
}

bool BridgeViewModel::bridgeChromeConnected() const
{
    return m_FillController->isBridgeChromeConnected();
}

bool BridgeViewModel::bridgeBraveConnected() const
{
    return m_FillController->isBridgeBraveConnected();
}

void BridgeViewModel::setBridgeEnabled(bool enabled)
{
    const bool was = m_FillController->isBridgeEnabled();
    if (was == enabled)
    {
        return;
    }
    if (enabled)
    {
        m_FillController->enableBridge();
    }
    else
    {
        m_FillController->disableBridge();
    }

    // Persist preference - QSettings resolves to HKCU\Software\seal\seal
    // (org/app names set in QmlMain).
    QSettings settings;
    settings.setValue("bridge/enabled", enabled);

    emit bridgeEnabledChanged();
}

QString BridgeViewModel::bridgeStatusText() const
{
    return m_BridgeStatusText;
}

bool BridgeViewModel::autoStageEnabled() const
{
    // Default false: zero-gesture staged auto-fill is opt-in. QSettings
    // resolves to HKCU\Software\seal\seal. StagingController reads the same
    // key for its initial state and follows this property's change signal.
    const QSettings settings;
    return settings.value("bridge/autostage", false).toBool();
}

void BridgeViewModel::setAutoStageEnabled(bool enabled)
{
    if (autoStageEnabled() == enabled)
    {
        return;
    }
    QSettings settings;
    settings.setValue("bridge/autostage", enabled);
    emit autoStageEnabledChanged();
}

void BridgeViewModel::runInstallBrowserExtension()
{
    std::string message;
    const int rc = seal::installBrowserExtensionInternal(&message);
    m_BridgeStatusText = QString::fromStdString(message);
    emit bridgeStatusTextChanged();
    if (rc == 0)
    {
        emit infoMessage(QStringLiteral("Browser companion"), m_BridgeStatusText);
    }
    else
    {
        emit errorOccurred(QStringLiteral("Browser companion"), m_BridgeStatusText);
    }
}

void BridgeViewModel::runUninstallBrowserExtension()
{
    std::string message;
    const int rc = seal::uninstallBrowserExtensionInternal(&message);
    m_BridgeStatusText = QString::fromStdString(message);
    emit bridgeStatusTextChanged();
    if (rc == 0)
    {
        emit infoMessage(QStringLiteral("Browser companion"), m_BridgeStatusText);
    }
    else
    {
        emit errorOccurred(QStringLiteral("Browser companion"), m_BridgeStatusText);
    }
}

void BridgeViewModel::runBridgeDiagnose()
{
    // Diagnose never touches the master password, so deliberately skip
    // any password gate - user can run this with a locked vault.
    if (!m_FillController->armDiagnose())
    {
        emit errorOccurred(QStringLiteral("Bridge diagnose"),
                           QStringLiteral("Failed to install input hooks"));
        return;
    }
    emit statusMessage(QStringLiteral("Ctrl+Click any field to test field detection (30s)"));
}

}  // namespace seal

#endif  // USE_QT_UI
