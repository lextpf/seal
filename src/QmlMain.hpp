#pragma once

#ifdef USE_QT_UI

/**
 * @brief Launch QML GUI mode for seal.
 *
 * Creates the QGuiApplication, registers the Backend and Theme
 * singletons with the QML engine, loads `Main.qml`, installs the
 * custom message handler, and enters the Qt event loop.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return Process exit code from `QGuiApplication::exec()`.
 *
 * @pre Security mitigations must be applied before calling this function
 *      (with `allowDynamicCode = true` for QML's V4 JIT engine).
 *
 * @see Backend, installSealMessageHandler
 */
int RunQMLMode(int argc, char* argv[]);

#endif  // USE_QT_UI
