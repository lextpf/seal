#ifdef USE_QT_UI

#include "CliPanelViewModel.hpp"

#include "CliDispatch.hpp"
#include "CliHandler.hpp"
#include "Clipboard.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "Logging.hpp"
#include "Utils.hpp"

#include <QtCore/QString>
#include <QtCore/QStringList>

#include <algorithm>
#include <stdexcept>
#include <string>

namespace seal
{

// CLI transcript trim policy: cap memory growth during long sessions while
// keeping enough scrollback to stay useful.
namespace
{
constexpr int kCliMaxLines = 500;
constexpr int kCliTrimTarget = 400;
}  // namespace

CliPanelViewModel::CliPanelViewModel(seal::CredentialWorkspace& ws,
                                     seal::IUiFeedback& ui,
                                     seal::IPasswordGate& gate,
                                     seal::IFillControl& fill,
                                     QObject* parent)
    : QObject(parent),
      m_Workspace(ws),
      m_Ui(ui),
      m_Gate(gate),
      m_Fill(fill)
{
}

bool CliPanelViewModel::isCliMode() const
{
    return m_CliMode;
}

QString CliPanelViewModel::cliOutputText() const
{
    return m_CliOutputText;
}

void CliPanelViewModel::toggleCliMode()
{
    m_CliMode = !m_CliMode;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=cli.mode.toggle", seal::diag::kv("state", m_CliMode)}));
    emit cliModeChanged();

    if (m_CliMode && !m_CliWelcomeShown)
    {
        m_CliWelcomeShown = true;
        appendCliOutput(QStringLiteral("seal - Interactive Mode"));
        appendCliOutput(
            QStringLiteral("Commands: :help | :open | :copy | :clear | :gen | :fill | :cls | :qr"));
        appendCliOutput(
            QStringLiteral("Type text to encrypt, paste hex to decrypt, or enter a file path."));
        appendCliOutput(QString{});
    }
}

void CliPanelViewModel::appendCliOutput(const QString& line)
{
    if (!m_CliOutputText.isEmpty())
    {
        m_CliOutputText += QChar('\n');
    }
    m_CliOutputText += line;
    ++m_CliLineCount;

    // Trim oldest lines in batches to avoid an O(n) split on every append.
    if (m_CliLineCount > kCliMaxLines)
    {
        QStringList lines = m_CliOutputText.split(QChar('\n'));
        const int excess = static_cast<int>(lines.size()) - kCliTrimTarget;
        lines.erase(lines.begin(), lines.begin() + excess);
        m_CliOutputText = lines.join(QChar('\n'));
        m_CliLineCount = kCliTrimTarget;
    }
    emit cliOutputTextChanged();
}

void CliPanelViewModel::clearCliOutput()
{
    if (m_CliOutputText.isEmpty())
    {
        return;
    }
    m_CliOutputText.clear();
    m_CliLineCount = 0;
    emit cliOutputTextChanged();
}

void CliPanelViewModel::executeCliCommand(const QString& command)
{
    QString trimmed = command.trimmed();
    if (trimmed.isEmpty())
    {
        return;
    }

    std::string input = trimmed.toStdString();
    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=cli.command.begin", seal::diag::kv("input_len", input.size())}));

    // Echo the (masked) command into the transcript before any output.
    appendCliOutput(seal::CliEchoLine(trimmed));

    // --- Built-in commands (no password needed) ---
    seal::CliCallbacks cb;
    cb.output = [this](const QString& s) { appendCliOutput(s); };
    cb.clearOutput = [this]() { clearCliOutput(); };
    cb.requestQrCapture = [this]() { emit qrCaptureRequested(); };
    cb.armFill = [this](int i) { m_Fill.armFor(i); };
    cb.records = &m_Workspace.records();

    if (seal::HandleCliBuiltin(trimmed, cb))
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=cli.command.finish", "result=builtin"}));
        return;
    }

    // --- Password-requiring commands ---

    if (!m_Gate.ensurePassword([this, command]() { executeCliCommand(command); }))
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=cli.command.finish", "result=defer", "reason=password_required"}));
        return;
    }

    try
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            throw std::runtime_error("Could not access the master key.");
        }
        std::string stripped = seal::utils::stripQuotes(seal::utils::trim(input));

        // Strip control characters that may survive from clipboard paste.
        std::erase_if(stripped, [](unsigned char c) { return c < 32 || c == 127; });

        // Remove trailing path separators so GetFileAttributesA does not reject
        // non-root directory paths like "C:\folder\sub\".
        while (stripped.size() > 1 && (stripped.back() == '\\' || stripped.back() == '/') &&
               !(stripped.size() == 3 && stripped[1] == ':'))
        {
            stripped.pop_back();
        }

        seal::CliDispatchCallbacks dcb{.output = [this](const QString& s) { appendCliOutput(s); },
                                       .password = access.password()};

        // Priority 1: file or directory path
        if (seal::utils::isDirectoryA(stripped))
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=directory",
                                        seal::diag::pathSummary(stripped)}));
            seal::CliDispatchDirectory(stripped, dcb);
            return;
        }
        if (seal::utils::fileExistsA(stripped))
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=file",
                                        seal::diag::pathSummary(stripped)}));
            seal::CliDispatchFile(stripped, dcb);
            return;
        }

        // Priority 2: hex token -> decrypt
        auto hexTokens = seal::utils::extractHexTokens(input);
        if (!hexTokens.empty())
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=hex",
                                        seal::diag::kv("token_count", hexTokens.size())}));
            seal::CliDispatchHexTokens(input, dcb);
            return;
        }

        // Priority 2b: base64-encoded ciphertext -> decrypt
        if (seal::utils::isBase64(input) && seal::CliDispatchBase64(input, dcb))
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=base64",
                                        seal::diag::kv("input_len", input.size())}));
            return;
        }

        // Priority 3: plain text -> encrypt (show both hex and base64)
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=cli.command.finish",
                                    "result=dispatch",
                                    "route=encrypt",
                                    seal::diag::kv("input_len", input.size())}));
        seal::CliDispatchEncrypt(input, dcb);
    }
    catch (const std::exception& ex)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=cli.command.finish",
             "result=fail",
             seal::diag::kv("reason", seal::diag::reasonFromMessage(ex.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(ex.what())),
             seal::diag::kv("input_len", input.size())}));
        appendCliOutput(QString("Error: %1").arg(QString::fromUtf8(ex.what())));
    }
}

void CliPanelViewModel::handleQrResult(const QString& text)
{
    std::string narrow = text.toStdString();
    (void)seal::Clipboard::copyWithTTL(narrow);
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=cli.qr.capture.finish",
                                "result=ok",
                                seal::diag::kv("payload_len", text.size()),
                                "copied=true"}));
    seal::Cryptography::cleanseString(narrow);
    // Mask QR text in the CLI -- value lands on the clipboard (TTL-scrubbed).
    appendCliOutput(QString("(QR captured) %1  [copied]").arg(QString(text.size(), QChar('*'))));
}

void CliPanelViewModel::handleQrFailure()
{
    // Plain transcript line; nothing was captured, so nothing is copied to
    // the clipboard.
    appendCliOutput(QStringLiteral("(QR capture failed or cancelled)"));
}

}  // namespace seal

#endif  // USE_QT_UI
