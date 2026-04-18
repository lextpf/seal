#pragma once

#ifdef USE_QT_UI

#include <QtCore/QLoggingCategory>

/**
 * @brief Qt logging categories and message handler for the seal application.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Logging
 *
 * Provides per-subsystem logging categories so messages can be filtered
 * by component (e.g. `seal.backend`, `seal.vault`). All categories use
 * Qt's `qCDebug` / `qCWarning` / `qCCritical` macros.
 *
 * Call installSealMessageHandler() once at startup to redirect all
 * `qDebug` / `qWarning` / `qCritical` / `qFatal` output through a
 * unified format written to `stderr`.
 */

Q_DECLARE_LOGGING_CATEGORY(logBackend)  // Backend / QML bridge operations.
Q_DECLARE_LOGGING_CATEGORY(logVault)    // Vault load, save, and record mutations.
Q_DECLARE_LOGGING_CATEGORY(logCrypto)   // Encryption, decryption, and key derivation.
Q_DECLARE_LOGGING_CATEGORY(logFill)     // Auto-fill hook and keystroke injection.
Q_DECLARE_LOGGING_CATEGORY(logFile)     // File and directory I/O operations.
Q_DECLARE_LOGGING_CATEGORY(logApp)      // Application lifecycle and general events.
Q_DECLARE_LOGGING_CATEGORY(logCamera)   // Camera enumeration, probing, and selection.
Q_DECLARE_LOGGING_CATEGORY(logQr)       // QR capture loop and frame decoding.

/**
 * @brief Install the seal-specific Qt message handler.
 *
 * Replaces the default Qt message handler with one that writes
 * timestamped, categorised log lines to `stderr` in the format:
 * `[HH:mm:ss.zzz] [category] message`. Thread-safe;
 * may be called before or after QApplication construction.
 *
 * @post All subsequent `qCDebug` / `qCWarning` / `qCCritical` / `qFatal`
 *       calls are routed through the seal message handler.
 *
 * @see logBackend, logVault, logCrypto, logFill, logFile, logApp
 */
void installSealMessageHandler();

#endif  // USE_QT_UI
