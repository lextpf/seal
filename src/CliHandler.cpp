#ifdef USE_QT_UI

#include "CliHandler.h"
#include "Clipboard.h"
#include "Cryptography.h"
#include "PasswordGen.h"
#include "Utils.h"

#include <QtCore/QString>
#include <QtCore/QStringLiteral>

#include <algorithm>
#include <string>

namespace seal
{

bool HandleCliBuiltin(const QString& command, const CliCallbacks& cb)
{
    if (command == ":help" || command == ":h")
    {
        cb.output(QStringLiteral("Available commands:"));
        cb.output(QStringLiteral("  <text>        Encrypt text with AES-256-GCM, output hex"));
        cb.output(QStringLiteral("  <hex>         Decrypt hex token, copy to clipboard"));
        cb.output(QStringLiteral("  <path>        Encrypt/decrypt file"));
        cb.output(QStringLiteral("  :gen [len]    Generate random password (default 20)"));
        cb.output(QStringLiteral("  :fill <svc>   Arm fill for a service by name"));
        cb.output(QStringLiteral("  :qr           Scan QR code from webcam"));
        cb.output(QStringLiteral("  :hex <text>   Hex-encode text"));
        cb.output(QStringLiteral("  :unhex <hex>  Hex-decode to text"));
        cb.output(QStringLiteral("  :cls          Clear terminal output"));
        cb.output(QStringLiteral("  :open :edit   Open seal input file in Notepad"));
        cb.output(QStringLiteral("  :copy :clip   Copy seal file to clipboard"));
        cb.output(QStringLiteral("  :clear :none  Clear clipboard"));
        cb.output(QStringLiteral("  :help         Show this help"));
        return true;
    }

    if (command == ":open" || command == ":o" || command == ":edit")
    {
        bool ok = seal::openInputInNotepad();
        cb.output(ok ? QStringLiteral("(opened seal file in Notepad)")
                     : QStringLiteral("(failed to launch Notepad)"));
        return true;
    }

    if (command == ":copy" || command == ":clip" || command == ":copyfile" ||
        command == ":copyinput")
    {
        bool ok = seal::Clipboard::copyInputFile();
        cb.output(ok ? QStringLiteral("(fence copied to clipboard)")
                     : QStringLiteral("(failed to copy fence)"));
        return true;
    }

    if (command == ":clear" || command == ":none")
    {
        (void)seal::Clipboard::copyWithTTL("");
        cb.output(QStringLiteral("(clipboard cleared)"));
        return true;
    }

    if (command == ":cls" || command == ":clear-screen")
    {
        cb.clearOutput();
        return true;
    }

    if (command.startsWith(":gen"))
    {
        int length = 20;
        if (command.length() > 4)
        {
            bool ok = false;
            int parsed = command.mid(4).trimmed().toInt(&ok);
            if (ok)
            {
                length = std::clamp(parsed, 8, 128);
            }
        }

        auto password = seal::GeneratePassword(length);

        (void)seal::Clipboard::copyWithTTL(password.data(), password.size());

        cb.output(QString("%1  [copied]")
                      .arg(QString::fromUtf8(password.data(), static_cast<int>(password.size()))));

        seal::Cryptography::cleanseString(password);
        return true;
    }

    if (command == ":qr")
    {
        cb.output(QStringLiteral("(scanning QR code from webcam...)"));
        cb.requestQrCapture();
        return true;
    }

    if (command.startsWith(":fill"))
    {
        QString service = command.mid(5).trimmed();
        if (service.isEmpty())
        {
            cb.output(QStringLiteral("Usage: :fill <service>"));
            return true;
        }
        if (!cb.records || cb.records->empty())
        {
            cb.output(QStringLiteral("(no vault loaded)"));
            return true;
        }
        for (int i = 0; i < static_cast<int>(cb.records->size()); ++i)
        {
            if ((*cb.records)[i].deleted)
            {
                continue;
            }
            if (QString::fromStdString((*cb.records)[i].platform)
                    .compare(service, Qt::CaseInsensitive) == 0)
            {
                cb.output(QString("(arming fill for %1)")
                              .arg(QString::fromStdString((*cb.records)[i].platform)));
                cb.armFill(i);
                return true;
            }
        }
        cb.output(QString("(no account found for \"%1\")").arg(service));
        return true;
    }

    if (command.startsWith(":hex "))
    {
        std::string text = command.mid(5).toStdString();
        auto bytes = std::vector<unsigned char>(text.begin(), text.end());
        std::string hex = seal::utils::to_hex(std::span<const unsigned char>(bytes));
        (void)seal::Clipboard::copyWithTTL(hex);
        cb.output(QString("%1  [copied]").arg(QString::fromStdString(hex)));
        return true;
    }

    if (command.startsWith(":unhex "))
    {
        std::string hex = command.mid(7).toStdString();
        std::vector<unsigned char> bytes;
        if (seal::utils::from_hex(std::string_view{hex}, bytes))
        {
            std::string text(bytes.begin(), bytes.end());
            (void)seal::Clipboard::copyWithTTL(text);
            cb.output(QString("%1  [copied]").arg(QString::fromStdString(text)));
        }
        else
        {
            cb.output(QStringLiteral("(invalid hex)"));
        }
        return true;
    }

    // Command not handled - requires master password (crypto dispatch).
    return false;
}

}  // namespace seal

#endif  // USE_QT_UI
