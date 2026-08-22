#pragma once

#ifdef USE_QT_UI

#include <QtCore/QLoggingCategory>

#include "ConsoleStyle.hpp"

#include <initializer_list>
#include <string>

/**
 * @brief Qt logging categories and message handler for the seal application.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * Per-subsystem logging categories let a filter select one component
 * (e.g. `backend`, `vault`, `bridge`). Category strings are bare, without a
 * `seal.` prefix, because every log line in this process comes from seal. Emit
 * through Qt's `qCDebug` / `qCWarning` / `qCCritical` macros with the category
 * variable below.
 *
 * Call installSealMessageHandler() once at startup to route all
 * `qDebug` / `qWarning` / `qCritical` / `qFatal` output through one format
 * written to `stderr`.
 *
 * @warning The whole header is gated on `USE_QT_UI`, so the Qt-free test
 * binary neither declares the categories nor links the handler. Code that
 * must compile in both configurations cannot call into this file.
 *
 * @par Categories
 * | Variable     | String    | Subsystem                                |
 * |--------------|-----------|------------------------------------------|
 * | `logBackend` | `backend` | App ViewModel / QML bridge operations    |
 * | `logVault`   | `vault`   | Vault load, save, record mutations       |
 * | `logCrypto`  | `crypto`  | Encryption, decryption, key derivation   |
 * | `logFill`    | `fill`    | Auto-fill hook + keystroke injection     |
 * | `logFile`    | `file`    | File and directory I/O                   |
 * | `logApp`     | `app`     | Application lifecycle and general events |
 * | `logCamera`  | `camera`  | Camera enumeration, probing, selection   |
 * | `logQr`      | `qr`      | QR capture loop + frame decoding         |
 * | `logBridge`  | `bridge`  | BrowserBridge pipe + message validation  |
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
 * @brief Install the seal-specific Qt message handler.
 * @ingroup Logging
 *
 * Replaces the default Qt message handler with one that writes timestamped,
 * categorised lines to `stderr`. The timestamp is local wall-clock time, so it
 * is not monotonic across a clock change. Call it before or after QApplication
 * construction. A second call replaces the handler; the previous one is
 * discarded and cannot be restored.
 *
 * @par Message shaping
 * The body passes through seal::diag::sanitizeAscii() with a 4096-byte cap, so
 * non-ASCII text becomes `?`, a long line ends in `...`, and an empty body
 * prints as `none`. A message with no category is logged as `default`.
 *
 * @par Threading
 * The handler runs on the thread that emitted the message, renders the line
 * through `seal::console::writeLogLine` (per-segment colour) and flushes
 * `stderr` afterwards. Segments are written with several stream operations, so
 * lines emitted concurrently from different threads can interleave.
 *
 * @par Emitted line
 * @code
 * [HH:mm:ss.zzz] [LVL] [cat]   [tid=N]    message
 * [12:34:56.789] [INF] [vault] [tid=4210] event=vault.load.ok result=ok
 * @endcode
 *
 * @par Level tokens (QtMsgType -> LVL)
 * | QtMsgType        | LVL   | Notes                   |
 * |------------------|-------|-------------------------|
 * | `QtDebugMsg`     | `DBG` |                         |
 * | `QtInfoMsg`      | `INF` |                         |
 * | `QtWarningMsg`   | `WRN` |                         |
 * | `QtCriticalMsg`  | `ERR` |                         |
 * | `QtFatalMsg`     | `FTL` | aborts after printing   |
 *
 * @post Every later `qCDebug` / `qCWarning` / `qCCritical` / `qFatal` call is
 *       routed through the seal message handler.
 */
void installSealMessageHandler();

/**
 * @brief Emit a pre-joined diagnostic line to @p category at the Qt level that
 *        matches @p tone.
 * @ingroup Logging
 *
 * Shared Tone-to-qC dispatcher for the camera and QR sinks.
 *
 * @param category Target logging category (e.g. logCamera(), logQr()).
 * @param tone     Severity selector: Debug and Plain map to qCDebug, Warning to
 *                 qCWarning, Error to qCCritical, everything else to qCInfo.
 * @param fields   logfmt fields, joined via seal::diag::joinFields(). Empty
 *                 fields are dropped, so a conditional token can be passed
 *                 unconditionally.
 *
 * @note The line is emitted with `noquote()`, so no quotes are added. The
 *       QMessageLogger is built here, so the file, line and function in the
 *       message context name Logging.cpp rather than the caller.
 */
void writeToneLine(const QLoggingCategory& category,
                   seal::console::Tone tone,
                   std::initializer_list<std::string> fields);

#endif  // USE_QT_UI
