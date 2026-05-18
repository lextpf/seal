#ifdef USE_QT_UI

#include "Logging.hpp"
#include "ConsoleStyle.hpp"
#include "Diagnostics.hpp"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

// Bare category strings (no "seal." prefix). Filters previously written
// as "seal.bridge.*" must drop the prefix.
Q_LOGGING_CATEGORY(logBackend, "backend")
Q_LOGGING_CATEGORY(logVault, "vault")
Q_LOGGING_CATEGORY(logCrypto, "crypto")
Q_LOGGING_CATEGORY(logFill, "fill")
Q_LOGGING_CATEGORY(logFile, "file")
Q_LOGGING_CATEGORY(logApp, "app")
Q_LOGGING_CATEGORY(logCamera, "camera")
Q_LOGGING_CATEGORY(logQr, "qr")
Q_LOGGING_CATEGORY(logBridge, "bridge")

// Qt message handler. Format: "[HH:mm:ss.zzz] [LVL] [cat] [tid=N] text"
// on stderr; fatal messages abort after printing.
static void sealMessageHandler(QtMsgType type, const QMessageLogContext& ctx, const QString& msg)
{
    const char* lvl = "???";
    seal::console::Tone tone = seal::console::Tone::Plain;
    switch (type)
    {
        case QtDebugMsg:
            lvl = "DBG";
            tone = seal::console::Tone::Debug;
            break;
        case QtInfoMsg:
            lvl = "INF";
            tone = seal::console::Tone::Info;
            break;
        case QtWarningMsg:
            lvl = "WRN";
            tone = seal::console::Tone::Warning;
            break;
        case QtCriticalMsg:
            lvl = "ERR";
            tone = seal::console::Tone::Error;
            break;
        case QtFatalMsg:
            lvl = "FTL";
            tone = seal::console::Tone::Error;
            break;
        default:
            break;
    }

    const QString timestamp = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    const char* cat = ctx.category ? ctx.category : "default";
    const DWORD threadId = GetCurrentThreadId();

    const QByteArray tsBytes = timestamp.toUtf8();
    const QByteArray tidBytes = QString::number(threadId).toUtf8();
    const QByteArray msgBytes = msg.toUtf8();

    const std::string safeMsg = seal::diag::sanitizeAscii(
        std::string_view(msgBytes.constData(), static_cast<size_t>(msgBytes.size())), 4096);

    const seal::console::LogSegments segs{
        std::string_view(tsBytes.constData(), static_cast<size_t>(tsBytes.size())),
        std::string_view(lvl),
        std::string_view(cat),
        std::string_view(tidBytes.constData(), static_cast<size_t>(tidBytes.size())),
        safeMsg};

    seal::console::writeLogLine(std::cerr, tone, segs);
    std::cerr.flush();

    if (type == QtFatalMsg)
        abort();
}

void installSealMessageHandler()
{
    qInstallMessageHandler(sealMessageHandler);
}

#endif  // USE_QT_UI
