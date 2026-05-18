#ifdef USE_QT_UI

#include "CliDispatch.hpp"

#include "Clipboard.hpp"
#include "FileOperations.hpp"
#include "Utils.hpp"

#include <QtCore/QString>

#include <windows.h>

#include <cstring>
#include <span>
#include <string>

namespace seal
{

void CliDispatchFile(const std::string& stripped, const CliDispatchCallbacks& cb)
{
    std::string target = stripped;

    std::string base = seal::utils::basenameA(target);
    if (seal::utils::endsWithCi(base, ".exe") || _stricmp(base.c_str(), "seal") == 0)
    {
        cb.output(QString("(skipped) %1").arg(QString::fromStdString(target)));
        return;
    }

    bool isSeal = seal::utils::endsWithCi(target, ".seal");
    if (isSeal)
    {
        std::string newName = seal::utils::strip_ext_ci(target, std::string_view{".seal"});
        bool ok = seal::FileOperations::decryptFileTo(target, newName, cb.password);
        if (ok)
        {
            DeleteFileA(target.c_str());
            cb.output(QString("(decrypted) %1 -> %2")
                          .arg(QString::fromStdString(target), QString::fromStdString(newName)));
        }
        else
        {
            cb.output(QString("(decrypt failed) %1").arg(QString::fromStdString(target)));
        }
    }
    else
    {
        std::string newName = seal::utils::add_ext(target, std::string_view{".seal"});
        bool ok = seal::FileOperations::encryptFileTo(target, newName, cb.password);
        if (ok)
        {
            DeleteFileA(target.c_str());
            cb.output(QString("(encrypted) %1 -> %2")
                          .arg(QString::fromStdString(target), QString::fromStdString(newName)));
        }
        else
        {
            cb.output(QString("(encrypt failed) %1").arg(QString::fromStdString(target)));
        }
    }
}

void CliDispatchHexTokens(const std::string& input, const CliDispatchCallbacks& cb)
{
    auto hexTokens = seal::utils::extractHexTokens(input);
    for (const auto& tok : hexTokens)
    {
        try
        {
            auto plain = seal::FileOperations::decryptLine(tok, cb.password);
            (void)seal::Clipboard::copyWithTTL(plain.view());
            // Mask plaintext in the output -- value lands on the
            // clipboard (TTL-scrubbed) so it doesn't accumulate in QML.
            cb.output(
                QString("%1  [copied]").arg(QString(static_cast<int>(plain.size()), QChar('*'))));
            seal::Cryptography::cleanseString(plain);
        }
        catch (const std::exception& ex)
        {
            cb.output(QString("(decrypt failed: %1)").arg(QString::fromUtf8(ex.what())));
        }
    }
}

bool CliDispatchBase64(const std::string& input, const CliDispatchCallbacks& cb)
{
    try
    {
        auto bytes = seal::utils::fromBase64(input);
        if (!bytes.empty())
        {
            auto plain = seal::Cryptography::decryptPacket(std::span<const unsigned char>(bytes),
                                                           cb.password);
            (void)seal::Clipboard::copyWithTTL(reinterpret_cast<const char*>(plain.data()),
                                               plain.size());
            // Mask plaintext -- value is on the clipboard.
            cb.output(
                QString("%1  [copied]").arg(QString(static_cast<int>(plain.size()), QChar('*'))));
            seal::Cryptography::cleanseString(plain);
            return true;
        }
    }
    catch (...)
    {
        // Not valid base64 ciphertext -- fall through to encrypt.
    }
    return false;
}

void CliDispatchDirectory(const std::string& dir, const CliDispatchCallbacks& cb)
{
    WIN32_FIND_DATAA fd{};
    std::string pattern = seal::utils::joinPath(dir, "*");
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        cb.output(QString("(dir) cannot list: %1").arg(QString::fromStdString(dir)));
        return;
    }

    int total = 0;

    do
    {
        const char* name = fd.cFileName;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
            continue;

        std::string full = seal::utils::joinPath(dir, name);

        if (seal::utils::endsWithCi(name, ".exe") || _stricmp(name, "seal") == 0)
        {
            cb.output(QString("(skipped) %1").arg(QString::fromStdString(full)));
            continue;
        }

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            CliDispatchDirectory(full, cb);
            continue;
        }

        ++total;
        CliDispatchFile(full, cb);

    } while (FindNextFileA(h, &fd));

    FindClose(h);

    cb.output(QString("[dir] %1: %2 files processed").arg(QString::fromStdString(dir)).arg(total));
}

void CliDispatchEncrypt(const std::string& input, const CliDispatchCallbacks& cb)
{
    std::string hex = seal::FileOperations::encryptLine(input, cb.password);
    // Hex -> raw bytes for base64.
    std::vector<unsigned char> raw;
    seal::utils::from_hex(std::string_view{hex}, raw);
    std::string b64 = seal::utils::toBase64(std::span<const unsigned char>(raw));
    cb.output(QString("(hex) %1").arg(QString::fromStdString(hex)));
    cb.output(QString("(b64) %1").arg(QString::fromStdString(b64)));
}

}  // namespace seal

#endif  // USE_QT_UI
