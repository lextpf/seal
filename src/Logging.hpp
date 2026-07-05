#pragma once

#ifdef USE_QT_UI

#include <QtCore/QLoggingCategory>

/**
 * @brief Qt logging categories and message handler for the seal application.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * Provides per-subsystem logging categories so messages can be filtered
 * by component (e.g. `backend`, `vault`, `bridge`). All categories use
 * Qt's `qCDebug` / `qCWarning` / `qCCritical` macros. Category strings
 * are bare (no `seal.` prefix) since every log line in this process is
 * by definition from seal.
 *
 * Call installSealMessageHandler() once at startup to redirect all
 * `qDebug` / `qWarning` / `qCritical` / `qFatal` output through a
 * unified format written to `stderr`.
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

Q_DECLARE_LOGGING_CATEGORY(logBackend)  // App ViewModel / QML bridge operations.
Q_DECLARE_LOGGING_CATEGORY(logVault)    // Vault load, save, and record mutations.
Q_DECLARE_LOGGING_CATEGORY(logCrypto)   // Encryption, decryption, and key derivation.
Q_DECLARE_LOGGING_CATEGORY(logFill)     // Auto-fill hook and keystroke injection.
Q_DECLARE_LOGGING_CATEGORY(logFile)     // File and directory I/O operations.
Q_DECLARE_LOGGING_CATEGORY(logApp)      // Application lifecycle and general events.
Q_DECLARE_LOGGING_CATEGORY(logCamera)   // Camera enumeration, probing, and selection.
Q_DECLARE_LOGGING_CATEGORY(logQr)       // QR capture loop and frame decoding.
Q_DECLARE_LOGGING_CATEGORY(logBridge)   // BrowserBridge named-pipe server and message validation.

/**
 * @brief Install the seal-specific Qt message handler.
 *
 * Replaces the default Qt message handler with one that writes
 * timestamped, categorised log lines to `stderr` in the format:
 * `[HH:mm:ss.zzz] [level] [category] [tid=threadId] message`. Thread-safe;
 * may be called before or after QApplication construction.
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
 * @post All subsequent `qCDebug` / `qCWarning` / `qCCritical` / `qFatal`
 *       calls are routed through the seal message handler.
 *
 * @see logBackend, logVault, logCrypto, logFill, logFile, logApp, logCamera,
 *      logQr, logBridge
 */
void installSealMessageHandler();

#endif  // USE_QT_UI
