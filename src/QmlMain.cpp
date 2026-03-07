#ifdef USE_QT_UI

#include "QmlMain.h"
#include "Backend.h"
#include "Cryptography.h"
#include "Logging.h"

#include <QtCore/QCoreApplication>
#include <QtGui/QGuiApplication>
#include <QtGui/QScreen>
#include <QtQml/QQmlApplicationEngine>
#include <QtQml/QQmlContext>
#include <QtQuick/QQuickWindow>
#include <QtQuickControls2/QQuickStyle>

#include <algorithm>

static qreal computeUiScale()
{
    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen)
        return 1.0;

    // Match the existing QWidget baseline: 1920 physical pixels = 1.0 scale.
    const qreal physicalWidth =
        static_cast<qreal>(screen->size().width()) * screen->devicePixelRatio();
    if (physicalWidth <= 1920.0)
        return 1.0;

    const qreal rawScale = physicalWidth / 1920.0;
    // Text-only boost: increase readability on 4K without resizing the whole layout.
    const qreal textScale = 1.0 + (rawScale - 1.0) * 0.45;
    return std::clamp(textScale, 1.0, 1.5);
}

int RunQMLMode(int argc, char* argv[])
{
    QQuickStyle::setStyle("Basic");  // non-native style so custom theming takes full effect

    QGuiApplication app(argc, argv);
    installSealMessageHandler();

    app.setApplicationName("seal");
    app.setOrganizationName("seal");
    const qreal uiScale = computeUiScale();
    qCInfo(logApp) << "startup: uiScale =" << uiScale;
    if (seal::Cryptography::isRemoteSession())
        qCCritical(logApp) << "running in a Remote Desktop session";

    seal::Backend backend;
    QQmlApplicationEngine engine;
    QObject::connect(  // abort on QML load failure instead of showing a blank window
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
        qCCritical(logApp) << "Failed to load QML - no root objects created";
        return 1;
    }

    qCInfo(logApp) << "QML loaded successfully";
    return app.exec();
}

#endif  // USE_QT_UI
