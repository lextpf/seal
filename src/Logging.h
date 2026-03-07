#pragma once

#ifdef USE_QT_UI

#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(logBackend)
Q_DECLARE_LOGGING_CATEGORY(logVault)
Q_DECLARE_LOGGING_CATEGORY(logCrypto)
Q_DECLARE_LOGGING_CATEGORY(logFill)
Q_DECLARE_LOGGING_CATEGORY(logFile)
Q_DECLARE_LOGGING_CATEGORY(logApp)

void installSealMessageHandler();

#endif  // USE_QT_UI
