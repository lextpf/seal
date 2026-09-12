#pragma once

#ifdef USE_QT_UI

/**
 * @fn int RunQMLMode(int argc, char** argv)
 * @brief Compose the GUI and run its Qt event loop.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup GUI
 *
 * Owners precede borrowers on the stack; the QML engine must be destroyed first.
 * The five context properties are the complete C++ to QML surface. No QML types
 * are registered. `WindowVM` avoids QtQuick's `Window` name.
 *
 * ### :material-transit-connection-variant: Destruction order
 *
 * Destroy objects in reverse construction order so each borrower releases its
 * references while its owners remain valid.
 *
 * ```mermaid
 * flowchart LR
 *     QML["QML engine"] --> Borrowers
 *     Borrowers["CLI, window, staging,<br/>bridge, typing controller"] --> AppViewModel
 *     AppViewModel --> Core["Fill engine, AsyncRunner,<br/>credential workspace"]
 * ```
 *
 * `Basic` style must be set before QGuiApplication. Organization/application names
 * scope QSettings to `Software/seal/seal`. Qt handles DPI; Theme handles design scale.
 * Destruction connections detach the fill and CLI pointers borrowed by AppViewModel.
 *
 * @return Qt event-loop result, or 1 on QML creation failure.
 * @pre The caller installs the message handler and security mitigations with
 *      `allowDynamicCode = true` for QML's JIT.
 * @note The caller rejects remote sessions. The check here only logs a diagnostic.
 */
int RunQMLMode(int argc, char* argv[]);

#endif  // USE_QT_UI
