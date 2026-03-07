#ifdef USE_QT_UI

#include "Logging.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>

#include <cstdio>

Q_LOGGING_CATEGORY(logBackend, "seal.backend")
Q_LOGGING_CATEGORY(logVault, "seal.vault")
Q_LOGGING_CATEGORY(logCrypto, "seal.crypto")
Q_LOGGING_CATEGORY(logFill, "seal.fill")
Q_LOGGING_CATEGORY(logFile, "seal.file")
Q_LOGGING_CATEGORY(logApp, "seal.app")

static void sealMessageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg)
{
    const char* lvl = "???";
    switch (type)
    {
        case QtDebugMsg:
            lvl = "DBG";
            break;
        case QtInfoMsg:
            lvl = "INF";
            break;
        case QtWarningMsg:
            lvl = "WRN";
            break;
        case QtCriticalMsg:
            lvl = "ERR";
            break;
        case QtFatalMsg:
            lvl = "FTL";
            break;
    }

    const QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    const char* cat = ctx.category ? ctx.category : "default";

    const QByteArray line = QStringLiteral("[%1] [%2] [%3] %4\n")
                                .arg(timestamp, QLatin1String(lvl), QLatin1String(cat), msg)
                                .toUtf8();

    fwrite(line.constData(), 1, line.size(), stderr);
    fflush(stderr);

    if (type == QtFatalMsg)
        abort();
}

void installSealMessageHandler()
{
    qInstallMessageHandler(sealMessageHandler);
}

#endif  // USE_QT_UI
