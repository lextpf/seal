#pragma once

#ifdef USE_QT_UI

#include <QtCore/QLoggingCategory>

#include "ConsoleStyle.hpp"

#include <initializer_list>
#include <string>

/**
 * @brief Qt diagnostic categories and stderr handler.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * available only with USE_QT_UI. category strings omit the `seal.` prefix.
 * call installSealMessageHandler() once at startup.
 */

Q_DECLARE_LOGGING_CATEGORY(logBackend)
Q_DECLARE_LOGGING_CATEGORY(logVault)
Q_DECLARE_LOGGING_CATEGORY(logCrypto)
Q_DECLARE_LOGGING_CATEGORY(logFill)
Q_DECLARE_LOGGING_CATEGORY(logFile)
Q_DECLARE_LOGGING_CATEGORY(logApp)
Q_DECLARE_LOGGING_CATEGORY(logCamera)
Q_DECLARE_LOGGING_CATEGORY(logQr)
Q_DECLARE_LOGGING_CATEGORY(logBridge)

/**
 * @brief route Qt messages to timestamped stderr lines.
 * @ingroup Logging
 *
 * the previous handler is discarded. timestamps use local wall time and are not monotonic.
 * bodies pass through sanitizeAscii() with a 4096-byte cap; empty bodies become `none`.
 * an absent category becomes `default`.
 *
 * the handler runs on the emitting thread and flushes stderr. concurrent lines can interleave.
 *
 * | Qt type         | token | effect             |
 * |-----------------|-------|--------------------|
 * | `QtDebugMsg`    | `DBG` |                    |
 * | `QtInfoMsg`     | `INF` |                    |
 * | `QtWarningMsg`  | `WRN` |                    |
 * | `QtCriticalMsg` | `ERR` |                    |
 * | `QtFatalMsg`    | `FTL` | abort after output |
 *
 * @code
 * [HH:mm:ss.zzz] [LVL] [cat]   [tid=N]    message
 * [12:34:56.789] [INF] [vault] [tid=4210] event=vault.load.ok result=ok
 * @endcode
 */
void installSealMessageHandler();

/**
 * @brief emit diagnostic fields at the severity selected by the tone.
 * @ingroup Logging
 *
 * empty fields are skipped and output uses `noquote()`.
 * message context points to Logging.cpp, not the caller.
 *
 * | tone             | Qt call      |
 * |------------------|--------------|
 * | `Debug`, `Plain` | `qCDebug`    |
 * | `Warning`        | `qCWarning`  |
 * | `Error`          | `qCCritical` |
 * | otherwise        | `qCInfo`     |
 */
void writeToneLine(const QLoggingCategory& category,
                   seal::console::Tone tone,
                   std::initializer_list<std::string> fields);

#endif  // USE_QT_UI
