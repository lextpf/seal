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
    // "Basic" is the non-native Quick Controls style, so Theme.qml's palette
    // takes full effect regardless of the OS look and feel.
    QQuickStyle::setStyle("Basic");

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

    // CredentialWorkspace is the Qt-free core (records, session, vault path);
    // AsyncRunner and FillController are QObjects. All three are constructed
    // before every ViewModel and outlive them, so the pointers borrowed from the
    // workspace stay valid for the whole UI session: by VaultListModel through
    // AppViewModel, and by FillController through TypeController::armFor.
    seal::CredentialWorkspace workspace;
    seal::AsyncRunner async;
    seal::FillController fillEngine;
    seal::AppViewModel appViewModel(workspace, async);
    // TypeController owns the auto-type surface (the "Fill" context property) and
    // drives the borrowed fillEngine. appViewModel is both its status sink
    // (IUiFeedback) and its password gate (IPasswordGate) for deferred arming.
    seal::TypeController fill(workspace, appViewModel, appViewModel, fillEngine, async);
    appViewModel.setFillControl(&fill);
    // Bridge borrows fillEngine, which is declared earlier and therefore
    // outlives it, and routes its status messages through appViewModel's
    // IUiFeedback::setStatus so the shared footer updates.
    seal::BridgeViewModel bridge(&fillEngine);
    // Zero-gesture staged auto-fill. An owned collaborator, not a context
    // property: it polls the bridge's nav snapshot and auto-arms fillEngine on a
    // unique host match. Borrows workspace, fillEngine and appViewModel, all
    // declared earlier, so they outlive it.
    seal::StagingController staging(workspace, fillEngine, appViewModel);
    seal::WindowController window;
    // The embedded-CLI surface (the "Cli" context property). Declared last so it
    // destructs first: it borrows workspace, appViewModel (as IUiFeedback +
    // IPasswordGate), and fill (as IFillControl), all of which must outlive it.
    seal::CliPanelViewModel cli(workspace, appViewModel, appViewModel, fill);
    appViewModel.setCliPanel(&cli);
    // Detach the borrowed seams when their owners are destroyed. fill and cli
    // are declared after appViewModel, so they destruct first; nulling the
    // pointers here keeps ~AppViewModel's cleanup() from dereferencing a freed
    // TypeController or CliPanelViewModel.
    QObject::connect(&fill,
                     &QObject::destroyed,
                     &appViewModel,
                     [&appViewModel] { appViewModel.setFillControl(nullptr); });
    QObject::connect(&cli,
                     &QObject::destroyed,
                     &appViewModel,
                     [&appViewModel] { appViewModel.setCliPanel(nullptr); });
    // The :qr builtin runs on AppViewModel's QR worker; its result routes back
    // into the CLI transcript when the panel is in CLI mode.
    QObject::connect(&cli,
                     &seal::CliPanelViewModel::qrCaptureRequested,
                     &appViewModel,
                     &seal::AppViewModel::requestQrCapture);
    QObject::connect(&bridge,
                     &seal::BridgeViewModel::statusMessage,
                     &appViewModel,
                     [p = static_cast<seal::IUiFeedback*>(&appViewModel)](const QString& t)
                     { p->setStatus(t); });
    // Staged auto-fill: highlight the auto-armed record and follow the
    // Bridge.autoStageEnabled master switch. StagingController is not exposed to
    // QML, so the toggle rides the Bridge context property.
    QObject::connect(&staging,
                     &seal::StagingController::autoArmedForRecord,
                     &appViewModel,
                     &seal::AppViewModel::onAutoArmed);
    QObject::connect(&bridge,
                     &seal::BridgeViewModel::autoStageEnabledChanged,
                     &staging,
                     [&staging, &bridge] { staging.setEnabled(bridge.autoStageEnabled()); });
    // Route TypeController fill errors into the same error dialog as
    // AppViewModel's vault errors, so QML keeps a single Connections target.
    QObject::connect(&fill,
                     &seal::TypeController::errorOccurred,
                     &appViewModel,
                     &seal::AppViewModel::errorOccurred);
    QQmlApplicationEngine engine;
    // Abort on QML construction failure (a Main.qml type error, for example)
    // instead of leaving an empty window. QueuedConnection defers exit(1) until
    // control returns to the event loop, so the engine finishes unwinding.
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
