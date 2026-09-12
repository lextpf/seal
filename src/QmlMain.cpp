#ifdef USE_QT_UI

#include "QmlMain.hpp"
#include "AppViewModel.hpp"
#include "AsyncRunner.hpp"
#include "BridgeViewModel.hpp"
#include "CliPanelViewModel.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FillController.hpp"
#include "IUiFeedback.hpp"
#include "Logging.hpp"
#include "StagingController.hpp"
#include "TypeController.hpp"
#include "WindowController.hpp"

#include <QtCore/QCoreApplication>
#include <QtGui/QGuiApplication>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtQuick/QQuickWindow>
#include <QtQuickControls2/QQuickStyle>

int RunQMLMode(int argc, char* argv[])
{
    // Basic lets Theme.qml control the palette.
    QQuickStyle::setStyle("Basic");

    // Request an alpha buffer before the platform window is created.
    QQuickWindow::setDefaultAlphaBuffer(true);

    QGuiApplication app(argc, argv);

    app.setApplicationName("seal");
    app.setOrganizationName("seal");
    qCInfo(logApp).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.startup.begin", "mode=gui"}));
    if (seal::Cryptography::isRemoteSession())
    {
        qCCritical(logApp).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=app.environment.remote_session",
                                    "result=fail",
                                    "reason=remote_session_detected"}));
    }

    // Construct owners before borrowers; reverse stack destruction preserves workspace pointers.
    seal::CredentialWorkspace workspace;
    seal::AsyncRunner async;
    seal::FillController fillEngine;
    seal::AppViewModel appViewModel(workspace, async);
    // AppViewModel supplies both feedback and password gating.
    seal::TypeController fill(workspace, appViewModel, appViewModel, fillEngine, async);
    appViewModel.setFillControl(&fill);
    // Bridge borrows fillEngine and reports status through AppViewModel.
    seal::BridgeViewModel bridge(&fillEngine);
    // Staging borrows earlier owners and stays outside the QML context.
    seal::StagingController staging(workspace, fillEngine, appViewModel);
    seal::WindowController window;
    // CLI dies before its borrowed workspace, feedback, password gate and fill controller.
    seal::CliPanelViewModel cli(workspace, appViewModel, appViewModel, fill);
    appViewModel.setCliPanel(&cli);
    // Detach borrowed pointers as their targets die before AppViewModel.
    QObject::connect(&fill,
                     &QObject::destroyed,
                     &appViewModel,
                     [&appViewModel] { appViewModel.setFillControl(nullptr); });
    QObject::connect(&cli,
                     &QObject::destroyed,
                     &appViewModel,
                     [&appViewModel] { appViewModel.setCliPanel(nullptr); });
    // Route QR worker results to the active CLI panel.
    QObject::connect(&cli,
                     &seal::CliPanelViewModel::qrCaptureRequested,
                     &appViewModel,
                     &seal::AppViewModel::requestQrCapture);
    QObject::connect(&bridge,
                     &seal::BridgeViewModel::statusMessage,
                     &appViewModel,
                     [p = static_cast<seal::IUiFeedback*>(&appViewModel)](const QString& t)
                     { p->setStatus(t); });
    // Bridge exposes the staging preference; staged arms update row highlighting.
    QObject::connect(&staging,
                     &seal::StagingController::autoArmedForRecord,
                     &appViewModel,
                     &seal::AppViewModel::onAutoArmed);
    QObject::connect(&bridge,
                     &seal::BridgeViewModel::autoStageEnabledChanged,
                     &staging,
                     [&staging, &bridge] { staging.setEnabled(bridge.autoStageEnabled()); });
    // Merge fill errors into the shared QML dialog channel.
    QObject::connect(&fill,
                     &seal::TypeController::errorOccurred,
                     &appViewModel,
                     &seal::AppViewModel::errorOccurred);
    QQmlApplicationEngine engine;
    // Queue failure exit so QML construction can finish unwinding.
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        [] { QCoreApplication::exit(1); },
        Qt::QueuedConnection);

    engine.rootContext()->setContextProperty("AppViewModel", &appViewModel);
    engine.rootContext()->setContextProperty("Fill", &fill);
    engine.rootContext()->setContextProperty("Bridge", &bridge);
    engine.rootContext()->setContextProperty("WindowVM", &window);
    engine.rootContext()->setContextProperty("Cli", &cli);
    engine.loadFromModule("seal", "Main");

    if (engine.rootObjects().isEmpty())
    {
        qCCritical(logApp).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=app.qml.load.fail", "result=fail", "reason=no_root_objects"}));
        return 1;
    }

    qCInfo(logApp).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.qml.load.ok", "result=ok"}));
    return app.exec();
}

#endif  // USE_QT_UI
