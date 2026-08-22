#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>

#include "CredentialWorkspace.hpp"
#include "IFillControl.hpp"
#include "IPasswordGate.hpp"
#include "IUiFeedback.hpp"

namespace seal
{

/**
 * @class CliPanelViewModel
 * @brief QML-facing ViewModel for the embedded interactive CLI panel.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Holds the whole embedded-terminal concern in one object: CLI mode toggle,
 * command dispatch, transcript ownership and trim policy, and QR-into-CLI
 * routing. `RunQMLMode` registers it as the `Cli` QML context property.
 *
 * @par Collaborators
 * It reaches everything else through injected seams: vault state via
 * @ref CredentialWorkspace, password-requiring commands via
 * @ref IPasswordGate, auto-fill via @ref IFillControl. All CLI feedback goes to
 * the transcript (cliOutputText), so this class needs no error or info dialog
 * channel: the injected @ref IUiFeedback is stored but is currently unused.
 *
 * @see AppViewModel, CredentialWorkspace
 */
class CliPanelViewModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isCliMode READ isCliMode NOTIFY cliModeChanged)
    Q_PROPERTY(QString cliOutputText READ cliOutputText NOTIFY cliOutputTextChanged)

public:
    /**
     * @brief Construct the CLI panel ViewModel over the shared seams.
     *
     * All four references are borrowed and must outlive this object.
     *
     * @param ws     Qt-free core that owns the records and the session.
     * @param ui     Status feedback sink. Stored but currently unused.
     * @param gate   Defers commands that need the master password.
     * @param fill   Auto-fill control used by the `:fill` builtin.
     * @param parent Optional QObject parent.
     */
    CliPanelViewModel(seal::CredentialWorkspace& ws,
                      seal::IUiFeedback& ui,
                      seal::IPasswordGate& gate,
                      seal::IFillControl& fill,
                      QObject* parent = nullptr);

    /// @brief Check whether the CLI panel is active.
    bool isCliMode() const;

    /// @brief Full CLI transcript text for the embedded terminal view.
    QString cliOutputText() const;

    /**
     * @brief Execute a command in the embedded CLI panel.
     *
     * The input is tried against each form in order; @ref HandleCliBuiltin owns
     * the built-in command set.
     *
     * @verbatim
     *   input (trimmed, then echoed to the transcript)
     *     |-- built-in command?    -> handled, return             (no master password)
     *     |== master-password gate: defer via IPasswordGate if the password is unset ==
     *     |-- directory path?      -> encrypt / decrypt the whole folder tree
     *     |-- existing file?       -> encrypt file (or decrypt a .seal)
     *     |-- hex token(s)?        -> decrypt -> clipboard
     *     |-- base64 ciphertext?   -> decrypt -> clipboard
     *     `-- otherwise plain text -> encrypt -> emit hex + base64
     * @endverbatim
     *
     * The directory branch is recursive and works in place.
     * @ref CliDispatchDirectory walks the whole subtree, replaces each file with
     * its transformed copy, deletes the source, and asks for no confirmation. It
     * skips `*.exe`, entries named `seal`, and reparse points.
     *
     * While the master password is unset, a command that needs it is deferred
     * through the password gate. The gate raises the password dialog and, once
     * the password arrives, re-runs this method with the same argument, echo
     * line included, so a deferred command appears twice in the transcript.
     *
     * @par Two forms of the input
     * The path branches use a sanitised copy: quotes stripped, control
     * characters (below 0x20, plus 0x7F) removed, and trailing separators
     * dropped so `GetFileAttributesA` accepts a non-root folder path. A bare
     * drive root such as `C:\` keeps its separator.
     *
     * The hex, base64 and plaintext branches use the trimmed input unchanged,
     * so quoting a secret changes what gets encrypted.
     *
     * @note The path branches are ANSI-only. The command is converted to UTF-8
     *       and passed to the -A Win32 APIs, which decode it in the process
     *       code page. A path with characters outside that code page fails both
     *       existence tests and falls through to the plaintext branch, where it
     *       is encrypted as text.
     *
     * @param command Command text entered by the user. An empty or
     *        whitespace-only string returns immediately, with no echo.
     *
     * @warning The dispatch below the gate runs to completion on the GUI thread: no
     *          AsyncRunner, no loading overlay, no cancel. Each packet or file costs
     *          one scrypt derivation (64 MiB), so the window stays unresponsive for
     *          the whole operation, and the directory branch pays that cost once per
     *          file in the tree. One CredentialSession::Access window spans the
     *          dispatch, so the master key is plaintext throughout.
     *
     * @note Any exception raised below the gate is caught and appended as an
     *       `Error: <what>` transcript line; it is never propagated to QML.
     */
    Q_INVOKABLE void executeCliCommand(const QString& command);

    /**
     * @brief Toggle CLI mode (replaces vault UI with embedded terminal).
     *
     * The first activation also appends the four-line welcome banner. The
     * banner appears once per object lifetime, so later toggles only flip the
     * flag and emit cliModeChanged().
     */
    Q_INVOKABLE void toggleCliMode();

    /**
     * @brief Route a successful QR capture into the CLI transcript.
     *
     * Copies the captured text to the clipboard with the default 6-second
     * scrub and appends `(QR captured) ****  [copied]`, one asterisk per
     * captured character. The text itself never enters the transcript.
     * AppViewModel's QR completion path calls this when isCliMode() is true.
     */
    void handleQrResult(const QString& text);

    /**
     * @brief Route a failed/cancelled QR capture into the CLI transcript.
     *
     * Appends a plain transcript line; nothing was captured, so nothing is
     * copied to the clipboard. AppViewModel's QR completion path calls this
     * when isCliMode() is true.
     */
    void handleQrFailure();

signals:
    void cliModeChanged();        ///< CLI mode toggled.
    void cliOutputTextChanged();  ///< CLI transcript text updated (line appended or cleared).

    /**
     * @brief The `:qr` builtin requested a webcam QR capture.
     *
     * The QR worker lives on AppViewModel. The composition root connects this
     * signal to AppViewModel::requestQrCapture, which runs the capture and
     * routes the result back through handleQrResult or handleQrFailure while
     * isCliMode() holds.
     */
    void qrCaptureRequested();

private:
    /**
     * @brief Append one line to the CLI transcript and notify QML.
     *
     * Owns the trim policy: past kCliMaxLines (500) the oldest lines are
     * dropped in one batch down to kCliTrimTarget (400). That bounds the
     * transcript in a long session and pays the split cost once per 100 lines
     * instead of once per append.
     *
     * Every call emits cliOutputTextChanged(), so the bound QML view rebuilds
     * on each line.
     *
     * @param line Output line, without a trailing newline. An empty line is
     *        kept, and is how the welcome banner ends with a blank row.
     */
    void appendCliOutput(const QString& line);

    /// @brief Clear the CLI transcript and notify QML.
    /// When the transcript is already empty the call returns without emitting
    /// cliOutputTextChanged().
    void clearCliOutput();

    seal::CredentialWorkspace& m_Workspace;  ///< Qt-free core: records, session.
    seal::IUiFeedback& m_Ui;                 ///< Status feedback sink; stored, never called.
    seal::IPasswordGate& m_Gate;             ///< Defers password-requiring commands.
    seal::IFillControl& m_Fill;              ///< Auto-fill control for the `:fill` builtin.

    bool m_CliMode = false;          ///< CLI panel active.
    bool m_CliWelcomeShown = false;  ///< Welcome banner shown once.
    QString m_CliOutputText;         ///< Accumulated CLI transcript (view binds read-only).
    int m_CliLineCount = 0;          ///< Lines in m_CliOutputText, for the trim policy.
};

}  // namespace seal

#endif  // USE_QT_UI
