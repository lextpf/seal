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
#include "TypeController.hpp"
#include "WindowController.hpp"

#include <QtCore/QCoreApplication>
#include <QtGui/QGuiApplication>
#include <QtGui/QScreen>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtQuick/QQuickWindow>
#include <QtQuickControls2/QQuickStyle>

#include <algorithm>

// DPI-aware text scale factor. Baseline 1920 px = 1.0. Above 1920 px we
// apply only a fraction of the excess (text-only boost), so buttons +
// layout don't double on a 4K display. Clamped to [kMinScale, kMaxScale]
// for extreme displays.
static qreal computeUiScale()
{
    static constexpr qreal kBaselineWidth = 1920.0;
    static constexpr qreal kTextBoostFactor = 0.45;
    static constexpr qreal kMinScale = 1.0;
    static constexpr qreal kMaxScale = 1.5;

    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen)
        return kMinScale;

    const qreal physicalWidth =
        static_cast<qreal>(screen->size().width()) * screen->devicePixelRatio();
    if (physicalWidth <= kBaselineWidth)
        return kMinScale;

    const qreal rawScale = physicalWidth / kBaselineWidth;
    const qreal textScale = 1.0 + (rawScale - 1.0) * kTextBoostFactor;
    return std::clamp(textScale, kMinScale, kMaxScale);
}

int RunQMLMode(int argc, char* argv[])
{
    // "Basic" is the non-native Quick Controls style; lets Theme.qml's
    // palette take full effect regardless of OS look-and-feel.
    QQuickStyle::setStyle("Basic");

    QGuiApplication app(argc, argv);

    app.setApplicationName("seal");
    app.setOrganizationName("seal");
    const qreal uiScale = computeUiScale();
    qCInfo(logApp).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=app.startup.begin", "mode=gui", seal::diag::kv("ui_scale", uiScale, 2)}));
    if (seal::Cryptography::isRemoteSession())
    {
        qCCritical(logApp).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=app.environment.remote_session",
                                    "result=fail",
                                    "reason=remote_session_detected"}));
    }

    // The Qt-free core (records, session, vault path) is constructed before the
    // ViewModel and outlives it, so the borrowed pointers AppViewModel hands to
    // VaultListModel / FillController stay valid for the whole UI session.
    seal::CredentialWorkspace workspace;
    seal::AsyncRunner async;
    seal::FillController fillEngine;
    seal::AppViewModel appViewModel(workspace, async);
    // TypeController owns the auto-type surface (the "Fill" context property) and
    // drives the borrowed fillEngine. appViewModel serves as both the status sink
    // (IUiFeedback) and the password gate (IPasswordGate) for deferred arming.
    seal::TypeController fill(workspace, appViewModel, appViewModel, fillEngine, async);
    appViewModel.setFillControl(&fill);
    // Bridge borrows fillEngine (must outlive it) and routes its status messages
    // through appViewModel's IUiFeedback::setStatus so the shared footer updates.
    seal::BridgeViewModel bridge(&fillEngine);
    seal::WindowController window;
    // The embedded-CLI surface (the "Cli" context property). Declared last so it
    // destructs first: it borrows workspace, appViewModel (as IUiFeedback +
    // IPasswordGate), and fill (as IFillControl), all of which must outlive it.
    seal::CliPanelViewModel cli(workspace, appViewModel, appViewModel, fill);
    appViewModel.setCliPanel(&cli);
    // Detach the borrowed seams when their owners are destroyed. fill/cli are
    // declared after appViewModel, so they destruct first; nulling the pointers
    // here ensures ~AppViewModel's cleanup() never dereferences a freed
    // TypeController / CliPanelViewModel (teardown use-after-free fix).
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
    // Surface the TypeController's fill errors through the same error dialog that
    // AppViewModel's vault errors use, so the QML Connections target stays single.
    QObject::connect(&fill,
                     &seal::TypeController::errorOccurred,
                     &appViewModel,
                     &seal::AppViewModel::errorOccurred);
    QQmlApplicationEngine engine;
    // Abort on QML construction failure (e.g. Main.qml syntax error)
    // instead of leaving an empty window. QueuedConnection runs the slot
    // after the engine finishes its current frame.
    QObject::connect(
        &engine,
        &QQmlApplicationEngine::objectCreationFailed,
        &app,
        [] { QCoreApplication::exit(1); },
        Qt::QueuedConnection);

    engine.rootContext()->setContextProperty("UiScale", uiScale);  // DPI-aware text scale factor
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
