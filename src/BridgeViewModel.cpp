#ifdef USE_QT_UI

#include "BridgeViewModel.hpp"

#include "CliModes.hpp"
#include "FillController.hpp"
#include "SignerUtils.hpp"

#include <QtCore/QFile>
#include <QtCore/QSettings>
#include <QtCore/QString>
#include <QtCore/QVariantMap>

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
    // HKCU\Software\seal\seal via QmlMain). enableBridge() starts the pipe at
    // once, not only on arm, so the extension can connect at launch. A closed
    // pipe drops the extension into its reconnect backoff (doubling, capped at
    // 5 s) and, once its service worker suspends, into the 30 s recovery alarm.
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

    // BrowserBridge is not a QObject, so poll per-browser connected state at
    // 1 Hz and convert level changes into *Changed signals. A QML dot turns
    // green only after an authenticated handshake.
    const std::size_t browserKindCount = static_cast<std::size_t>(seal::signer::BrowserKind::Count);
    m_LastBrowserConnected.assign(browserKindCount, false);
    m_InstalledBrowsers.assign(browserKindCount, false);
    refreshInstalledBrowsers();
    for (const auto& browser : seal::signer::kBrowserMetadata)
    {
        const std::size_t index = static_cast<std::size_t>(browser.m_Kind);
        m_LastBrowserConnected[index] = m_FillController->isBridgeBrowserConnected(browser.m_Kind);
    }
    m_LastPeerConnected = m_FillController->isBridgePeerConnected();
    m_LastChromeConnected = m_FillController->isBridgeChromeConnected();
    m_LastBraveConnected = m_FillController->isBridgeBraveConnected();
    m_BridgePeerPoll.setInterval(1000);
    connect(&m_BridgePeerPoll,
            &QTimer::timeout,
            this,
            [this]()
            {
                bool browserChanged = false;
                for (const auto& browser : seal::signer::kBrowserMetadata)
                {
                    const std::size_t index = static_cast<std::size_t>(browser.m_Kind);
                    const bool connected =
                        m_FillController->isBridgeBrowserConnected(browser.m_Kind);
                    if (connected != m_LastBrowserConnected[index])
                    {
                        m_LastBrowserConnected[index] = connected;
                        browserChanged = true;
                    }
                }
                if (browserChanged)
                {
                    emit browsersChanged();
                }

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

QVariantList BridgeViewModel::browsers() const
{
    // Chromium kinds only - seal ships no Gecko native-messaging manifest. A
    // row is emitted when the browser was detected as installed or has a live
    // peer, so a portable copy that install detection misses still shows up
    // once it connects. Rebuilt on every read; QML binds it, nothing caches it.
    QVariantList result;
    for (const auto& browser : seal::signer::kBrowserMetadata)
    {
        if (browser.m_EngineFamily != seal::signer::BrowserEngineFamily::Chromium)
        {
            continue;
        }

        const std::size_t index = static_cast<std::size_t>(browser.m_Kind);
        const bool connected = m_FillController->isBridgeBrowserConnected(browser.m_Kind);
        const bool installed = index < m_InstalledBrowsers.size() && m_InstalledBrowsers[index];
        if (!installed && !connected)
        {
            continue;
        }

        const QString icon =
            QString::fromUtf8(browser.m_BrandIconToken.data(), browser.m_BrandIconToken.size());
        const QString iconPath = QStringLiteral("qrc:/qt/qml/seal/assets/brands/%1.svg").arg(icon);
        const QString resourcePath = QStringLiteral(":/qt/qml/seal/assets/brands/%1.svg").arg(icon);

        QVariantMap row;
        row.insert(QStringLiteral("label"),
                   QString::fromUtf8(browser.m_DisplayName.data(), browser.m_DisplayName.size()));
        row.insert(QStringLiteral("key"),
                   QString::fromUtf8(browser.m_Token.data(), browser.m_Token.size()));
        row.insert(QStringLiteral("icon"), icon);
        row.insert(QStringLiteral("iconPath"), iconPath);
        row.insert(QStringLiteral("iconAvailable"), QFile::exists(resourcePath));
        row.insert(
            QStringLiteral("extensionsPage"),
            QString::fromUtf8(browser.m_ExtensionsPage.data(), browser.m_ExtensionsPage.size()));
        row.insert(QStringLiteral("installed"), installed);
        row.insert(QStringLiteral("connected"), connected);
        result.push_back(row);
    }
    return result;
}

bool BridgeViewModel::refreshInstalledBrowsers()
{
    // Registry and disk probe, so it stays off the 1 Hz poll. Gecko kinds keep
    // their initial false. Returns whether anything moved; the caller decides
    // whether to emit browsersChanged.
    bool changed = false;
    for (const auto& browser : seal::signer::kBrowserMetadata)
    {
        if (browser.m_EngineFamily != seal::signer::BrowserEngineFamily::Chromium)
        {
            continue;
        }
        const std::size_t index = static_cast<std::size_t>(browser.m_Kind);
        const bool installed = seal::isBrowserInstalled(browser.m_Kind);
        if (index >= m_InstalledBrowsers.size())
        {
            continue;
        }
        if (m_InstalledBrowsers[index] != installed)
        {
            m_InstalledBrowsers[index] = installed;
            changed = true;
        }
    }
    return changed;
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
    seal::BrowserExtensionInstallReport report;
    const int rc = seal::installBrowserExtensionInternal(&message, &report);
    m_BridgeStatusText = QString::fromStdString(message);
    emit bridgeStatusTextChanged();
    if (refreshInstalledBrowsers())
    {
        emit browsersChanged();
    }
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
    // No refreshInstalledBrowsers() here on purpose: removing the manifest
    // does not uninstall the browser, so the installed flags stay valid.
    std::string message;
    seal::BrowserExtensionUninstallReport report;
    const int rc = seal::uninstallBrowserExtensionInternal(&message, &report);
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
    // Diagnose never touches the master password, so it skips any password
    // gate; the user can run it with a locked vault.
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
