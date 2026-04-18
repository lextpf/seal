#ifdef USE_QT_UI

#include "Logging.h"
#include "ConsoleStyle.h"
#include "Diagnostics.h"

#include <QtCore/QByteArray>
#include <QtCore/QDateTime>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <iostream>

Q_LOGGING_CATEGORY(logBackend, "seal.backend")
Q_LOGGING_CATEGORY(logVault, "seal.vault")
Q_LOGGING_CATEGORY(logCrypto, "seal.crypto")
Q_LOGGING_CATEGORY(logFill, "seal.fill")
Q_LOGGING_CATEGORY(logFile, "seal.file")
Q_LOGGING_CATEGORY(logApp, "seal.app")
Q_LOGGING_CATEGORY(logCamera, "seal.camera")
Q_LOGGING_CATEGORY(logQr, "seal.qr")

// Custom Qt message handler that replaces the default qDebug/qWarning output.
// Formats every Qt log message as
// "[HH:mm:ss.zzz] [LVL] [category] [tid=1234] text"
// and writes to stderr. Fatal messages abort immediately after printing.
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
