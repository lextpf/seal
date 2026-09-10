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
 * @brief Own the embedded terminal transcript and expose it as Cli in QML.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Vault, password and fill operations use borrowed collaborators. Feedback stays
 * in the transcript; the stored IUiFeedback reference is unused.
 */
class CliPanelViewModel : public QObject
{
    Q_OBJECT

    Q_PROPERTY(bool isCliMode READ isCliMode NOTIFY cliModeChanged)
    Q_PROPERTY(QString cliOutputText READ cliOutputText NOTIFY cliOutputTextChanged)

public:
    /**
     * @fn CliPanelViewModel(seal::CredentialWorkspace& ws, seal::IUiFeedback& ui,
     *     seal::IPasswordGate& gate, seal::IFillControl& fill, QObject* parent = nullptr)
     * @brief All four collaborator references are borrowed and must outlive this object.
     * @author Alex (<https://github.com/lextpf>)
     */
    CliPanelViewModel(seal::CredentialWorkspace& ws,
                      seal::IUiFeedback& ui,
                      seal::IPasswordGate& gate,
                      seal::IFillControl& fill,
                      QObject* parent = nullptr);

    bool isCliMode() const;

    QString cliOutputText() const;

    /**
     * @fn void executeCliCommand(const QString& command)
     * @brief Dispatch terminal input in precedence order.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @verbatim
     *   Input (trimmed, then passed through CliEchoLine for a masked echo)
     *     |-- built-in command?    -> handled, return             (no master password)
     *     |== master-password gate: defer via IPasswordGate if the password is unset ==
     *     |-- directory path?      -> encrypt / decrypt the whole folder tree
     *     |-- existing file?       -> encrypt file (or decrypt a .seal)
     *     |-- hex token(s)?        -> decrypt -> clipboard
     *     |-- base64 ciphertext?   -> decrypt -> clipboard
     *     `-- otherwise plain text -> encrypt -> emit hex + base64
     * @endverbatim
     *
     * Path dispatch transforms files in place and deletes sources without confirmation.
     * It skips executables, `seal` entries and reparse points. Path input loses quotes,
     * control characters and trailing separators except drive-root separators.
     * Crypto input keeps its trimmed spelling, including quotes.
     *
     * Deferral repeats the masked echo after a password arrives. Empty input emits
     * nothing. Dispatch exceptions become transcript errors. Deferred input remains
     * captured as a QString until the password gate runs or discards the action.
     *
     * @warning Dispatch blocks the GUI without cancellation or a loading cover. One
     *          session access window spans all per-packet scrypt derivations.
     * @note Path dispatch passes UTF-8 to ANSI Win32 APIs. Unrepresentable paths can
     *       fail existence checks and fall through to plaintext encryption.
     */
    Q_INVOKABLE void executeCliCommand(const QString& command);

    /**
     * @fn void toggleCliMode()
     * @brief First activation adds the welcome banner; later toggles preserve the transcript.
     * @author Alex (<https://github.com/lextpf>)
     */
    Q_INVOKABLE void toggleCliMode();

    /**
     * @fn void handleQrResult(const QString& text)
     * @brief Copy QR text with a 6 s scrub; transcript output has one asterisk per character.
     * @author Alex (<https://github.com/lextpf>)
     */
    void handleQrResult(const QString& text);

    /**
     * @fn void handleQrFailure()
     * @brief Report failure or cancellation without changing the clipboard.
     * @author Alex (<https://github.com/lextpf>)
     */
    void handleQrFailure();

signals:
    void cliModeChanged();        ///< CLI mode toggled.
    void cliOutputTextChanged();  ///< CLI transcript text updated (line appended or cleared).

    /**
     * @fn void qrCaptureRequested()
     * @brief RunQMLMode routes this to AppViewModel capture, then routes its result back here.
     * @author Alex (<https://github.com/lextpf>)
     */
    void qrCaptureRequested();

private:
    /**
     * @fn void appendCliOutput(const QString& line)
     * @brief Append a line and emit a transcript change.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Above 500 lines, remove oldest lines down to 400 in one batch.
     *
     * @param line No trailing newline; empty lines are retained.
     */
    void appendCliOutput(const QString& line);

    /**
     * @fn void clearCliOutput()
     * @brief Emit only if the transcript was non-empty.
     * @author Alex (<https://github.com/lextpf>)
     */
    void clearCliOutput();

    seal::CredentialWorkspace& m_Workspace;
    seal::IUiFeedback& m_Ui;  ///< Status feedback sink; stored, never called.
    seal::IPasswordGate& m_Gate;
    seal::IFillControl& m_Fill;

    bool m_CliMode = false;          ///< CLI panel active.
    bool m_CliWelcomeShown = false;  ///< Welcome banner shown once.
    QString m_CliOutputText;         ///< Accumulated CLI transcript (view binds read-only).
    int m_CliLineCount = 0;          ///< Lines in m_CliOutputText, for the trim policy.
};

}  // namespace seal

#endif  // USE_QT_UI
