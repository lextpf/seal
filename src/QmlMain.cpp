#ifdef USE_QT_UI

#include "QmlMain.hpp"
#include "Backend.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"

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

    seal::Backend backend;
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

    engine.rootContext()->setContextProperty("UiScale", uiScale);   // DPI-aware text scale factor
    engine.rootContext()->setContextProperty("Backend", &backend);  // vault + crypto operations
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
