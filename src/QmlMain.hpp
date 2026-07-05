#pragma once

#ifdef USE_QT_UI

/**
 * @brief Launch QML GUI mode for seal (the composition root).
 *
 * Creates the QGuiApplication, computes a DPI-aware UI-scale factor, builds the
 * Qt-free core (CredentialWorkspace, AsyncRunner, FillController) and the
 * ViewModels on the stack in dependency order, registers the five ViewModel
 * context properties (`AppViewModel`, `Fill`, `Bridge`, `WindowVM`, `Cli`) plus
 * the `UiScale` factor, loads the `seal` module's `Main.qml`, and enters the Qt
 * event loop.
 *
 * @par Composition-root build order
 * @code
 * RunQMLMode(argc, argv):
 *   QQuickStyle::setStyle("Basic");   QGuiApplication app;
 *   uiScale = computeUiScale();                          // DPI-aware text factor
 *
 *   // 1. Qt-free core -- constructed first, outlives every ViewModel below.
 *   CredentialWorkspace workspace;
 *   AsyncRunner         async;
 *   FillController      fillEngine;
 *
 *   // 2. ViewModels + collaborators in dependency order.
 *   //    Declared later => destructed earlier (borrowers die before owners).
 *   AppViewModel      appViewModel(workspace, async);  // hub  -> "AppViewModel"
 *   TypeController    fill(...);                        //      -> "Fill"
 *   BridgeViewModel   bridge(&fillEngine);             //      -> "Bridge"
 *   StagingController staging(...);   // owned collaborator, NOT a ctx property
 *   WindowController  window;                          //      -> "WindowVM"
 *   CliPanelViewModel cli(...);       // declared last, destructs first -> "Cli"
 *
 *   // 3. Register 6 context properties on the QML root context:
 *   //    UiScale, AppViewModel, Fill, Bridge, WindowVM, Cli
 *   engine.loadFromModule("seal", "Main");
 *   return rootObjects.isEmpty() ? 1 : app.exec();     // empty => load.fail (1)
 * @endcode
 *
 * @par UI-scale factor
 * For physical width @f$ w = \text{screen.width} \times \text{devicePixelRatio} @f$,
 * the exposed `UiScale` is a text-only boost applied only above a 1920 px
 * baseline (@f$ w \le 1920 @f$ yields exactly 1.0):
 * @f[
 *   \text{UiScale} = \operatorname{clamp}\!\left(
 *       1 + \left(\frac{w}{1920} - 1\right)\cdot 0.45,\ 1.0,\ 1.5 \right),
 *   \quad w > 1920
 * @f]
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line argument strings.
 * @return Process exit code from `QGuiApplication::exec()`, or 1 if the QML root
 *         object fails to load.
 *
 * @pre Security mitigations must be applied before calling this function
 *      (with `allowDynamicCode = true` for QML's V4 JIT engine).
 * @pre The structured Qt message handler (installSealMessageHandler) is
 *      installed by the caller in `main`, not here.
 *
 * @see AppViewModel
 */
int RunQMLMode(int argc, char* argv[]);

#endif  // USE_QT_UI
