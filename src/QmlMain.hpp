#pragma once

#ifdef USE_QT_UI

/**
 * @brief Launch QML GUI mode for seal (the composition root).
 * @author Alex (https://github.com/lextpf)
 * @ingroup GUI
 *
 * Creates the QGuiApplication, builds the long-lived core (the Qt-free
 * CredentialWorkspace, plus AsyncRunner and FillController, which are both
 * QObjects) and the ViewModels on the stack in dependency order, registers the
 * five ViewModel context properties (`AppViewModel`, `Fill`, `Bridge`,
 * `WindowVM`, `Cli`), loads the `seal` module's `Main.qml`, and enters the Qt
 * event loop. No DPI factor reaches QML: Qt applies platform scaling and
 * `Theme.px()` carries the design scale. No QML types are registered (no
 * `qmlRegister*` call, no `QML_ELEMENT`), so these five names are the whole
 * C++-to-QML surface; owned collaborators such as FillController and
 * StagingController stay unexposed.
 * The source-scan tests in `tests/test_ui_secret_boundaries.cpp` pin the set.
 *
 * @par Startup order
 * The Quick Controls style is pinned before the QGuiApplication exists and
 * cannot be changed afterwards, so that call comes first. Application and
 * organization names are both `seal`, which scopes every default-constructed
 * `QSettings` to the per-user `Software/seal/seal` registry key.
 *
 * @par Composition-root build order
 * @code
 * RunQMLMode(argc, argv):
 *   QQuickStyle::setStyle("Basic");   QGuiApplication app;
 *
 *   // 1. Core - constructed first, outlives every ViewModel below.
 *   CredentialWorkspace workspace;
 *   AsyncRunner         async;
 *   FillController      fillEngine;
 *
 *   // 2. ViewModels + collaborators in dependency order.
 *   //    Declared later => destructed earlier (borrowers die before owners).
 *   AppViewModel      appViewModel(workspace, async);  // hub  -> "AppViewModel"
 *   TypeController    fill(...);                       //      -> "Fill"
 *   BridgeViewModel   bridge(&fillEngine);             //      -> "Bridge"
 *   StagingController staging(...);   // owned collaborator, not a ctx property
 *   WindowController  window;                          //      -> "WindowVM"
 *   CliPanelViewModel cli(...);       // declared last, destructs first -> "Cli"
 *
 *   // 3. Engine after every ViewModel: the QML tree borrows the five context
 *   //    objects, so it must be destructed before them.
 *   QQmlApplicationEngine engine;
 *
 *   // 4. Register 5 context properties on the QML root context:
 *   //    AppViewModel, Fill, Bridge, WindowVM, Cli
 *   engine.loadFromModule("seal", "Main");
 *   return rootObjects.isEmpty() ? 1 : app.exec();     // empty => load.fail (1)
 * @endcode
 *
 * @par Cross-wiring done here
 * The stack objects know nothing about each other, so this function connects
 * them: destroying TypeController or CliPanelViewModel nulls the seam it lent
 * AppViewModel; TypeController fill errors and BridgeViewModel status messages
 * route into AppViewModel; the CLI `:qr` builtin drives AppViewModel's QR
 * worker; and the Bridge auto-stage toggle enables StagingController, whose
 * auto-arm highlights a row through AppViewModel.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return Process exit code from `QGuiApplication::exec()`, or 1 when the root
 *         object list is empty. A QML object-creation failure raised after the
 *         root exists also ends the loop with 1, through a queued
 *         `QCoreApplication::exit(1)`.
 *
 * @pre Security mitigations must be applied before calling this function
 *      (with `allowDynamicCode = true` for QML's V4 JIT engine).
 * @pre The structured Qt message handler (installSealMessageHandler) is
 *      installed by the caller in `main`, not here.
 *
 * @note `main` calls initializeSecurity() before this function and returns 1
 *       when SM_REMOTESESSION is set, so a remote session never reaches here
 *       on the normal GUI path. The check inside this function only writes a
 *       critical diagnostic line for a direct caller and does not block
 *       startup by itself.
 *
 * @see AppViewModel
 */
int RunQMLMode(int argc, char* argv[]);

#endif  // USE_QT_UI
