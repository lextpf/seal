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
 * Extracted from @ref AppViewModel to keep the embedded-terminal concern
 * (CLI mode toggle, command dispatch, transcript ownership + trim policy,
 * and QR-into-CLI routing) in one cohesive object, registered as the `Cli`
 * QML context property in `RunQMLMode`.
 *
 * Collaborates exclusively through the seams: it reads/mutates vault state
 * via @ref CredentialWorkspace, gates password-requiring commands through
 * @ref IPasswordGate, arms auto-fill via @ref IFillControl, and reports
 * status via @ref IUiFeedback. CLI feedback is written to the transcript
 * (cliOutputText) rather than dialogs, so no error/info dialog channel is
 * needed.
 *
 * @see AppViewModel, CredentialWorkspace
 */
class CliPanelViewModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isCliMode READ isCliMode NOTIFY cliModeChanged)
    Q_PROPERTY(QString cliOutputText READ cliOutputText NOTIFY cliOutputTextChanged)

public:
    /// @brief Construct the CLI panel ViewModel over the shared seams.
    /// @param ws   Injected Qt-free core that owns records and session.
    /// @param ui   Status sink for status feedback.
    /// @param gate Password gate used to defer password-requiring commands.
    /// @param fill Auto-fill control used by the `:fill` builtin.
    /// @param parent Optional QObject parent.
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
     * Supported input types (tried in order):
     * - **Built-in commands**: `:help`, `:open`, `:copy`, `:clear`, `:cls`,
     *   `:gen [len]`, `:qr`, `:fill <index>`, `:hex`, `:unhex` (no password needed).
     * - **File/directory paths**: encrypt or decrypt based on `.seal` extension.
     * - **Hex tokens**: decrypt and copy to clipboard.
     * - **Base64 ciphertext**: decrypt and copy to clipboard.
     * - **Plain text**: encrypt and emit both hex and base64 output.
     *
     * Commands that require the master password trigger the password dialog
     * via the password gate if the password is not yet set.
     *
     * @param command The command string entered by the user.
     */
    Q_INVOKABLE void executeCliCommand(const QString& command);

    /// @brief Toggle CLI mode (replaces vault UI with embedded terminal).
    Q_INVOKABLE void toggleCliMode();

    /**
     * @brief Route a successful QR capture into the CLI transcript.
     *
     * Copies the captured text to the clipboard (TTL-scrubbed) and appends a
     * masked confirmation line. Called by AppViewModel's QR completion path
     * when isCliMode() is true.
     *
     * @param text The captured QR text.
     */
    void handleQrResult(const QString& text);

    /**
     * @brief Route a failed/cancelled QR capture into the CLI transcript.
     *
     * Appends a plain transcript line; nothing was captured, so nothing is
     * copied to the clipboard. Called by AppViewModel's QR completion path
     * when isCliMode() is true.
     */
    void handleQrFailure();

signals:
    void cliModeChanged();        ///< CLI mode toggled.
    void cliOutputTextChanged();  ///< CLI transcript text updated (line appended or cleared).

    /// @brief The `:qr` builtin requested a webcam QR capture.
    ///
    /// The QR worker lives on AppViewModel; the composition root connects this
    /// to AppViewModel::requestQrCapture so the capture runs there and routes
    /// its result back via handleQrResult / handleQrFailure when isCliMode().
    void qrCaptureRequested();

private:
    /**
     * @brief Append one line to the CLI transcript and notify QML.
     *
     * Owns the trim policy: past kCliMaxLines the oldest lines are dropped in
     * a batch down to kCliTrimTarget, so long sessions do not grow the
     * transcript unboundedly.
     *
     * @param line Output line (no trailing newline).
     */
    void appendCliOutput(const QString& line);

    /// @brief Clear the CLI transcript and notify QML.
    void clearCliOutput();

    seal::CredentialWorkspace& m_Workspace;  ///< Qt-free core: records, session.
    seal::IUiFeedback& m_Ui;                 ///< Status feedback sink.
    seal::IPasswordGate& m_Gate;             ///< Defers password-requiring commands.
    seal::IFillControl& m_Fill;              ///< Auto-fill control for the `:fill` builtin.

    bool m_CliMode = false;          ///< CLI panel active.
    bool m_CliWelcomeShown = false;  ///< Welcome banner shown once.
    QString m_CliOutputText;         ///< Accumulated CLI transcript (view binds read-only).
    int m_CliLineCount = 0;          ///< Lines in m_CliOutputText, for the trim policy.
};

}  // namespace seal

#endif  // USE_QT_UI
