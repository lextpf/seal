#include "CliModes.h"

#include "Clipboard.h"
#include "Console.h"
#include "ConsoleStyle.h"
#include "Cryptography.h"
#include "Diagnostics.h"
#include "FileOperations.h"
#include "PasswordGen.h"
#include "ScopedDpapiUnprotect.h"
#include "Utils.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>

namespace
{
template <class GuardT>
using ScopedUnprotect = seal::ScopedDpapiUnprotect<GuardT>;

void writeCliDiag(seal::console::Tone tone, std::initializer_list<std::string> fields)
{
    seal::console::writeTagged(std::cerr, tone, "CLI", seal::diag::joinFields(fields));
}
}  // namespace

namespace seal
{

int HandleGenMode(int length)
{
    auto password = seal::GeneratePassword(length);

    std::cout << password.view() << "\n";

    (void)seal::Clipboard::copyWithTTL(password.data(), password.size());
    writeCliDiag(seal::console::Tone::Success,
                 {"event=cli.password.generate.finish",
                  "result=ok",
                  seal::diag::kv("length", password.size()),
                  "copied=true"});

    seal::Cryptography::cleanseString(password);
    return 0;
}

int HandleShredMode(const std::string& path)
{
    if (!seal::utils::fileExistsA(path))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.shred.finish",
                      "result=fail",
                      "reason=file_not_found",
                      seal::diag::pathSummary(path)});
        return 1;
    }

    const auto started = std::chrono::steady_clock::now();
    writeCliDiag(seal::console::Tone::Step,
                 {"event=cli.shred.begin", "result=start", seal::diag::pathSummary(path)});
    bool ok = seal::FileOperations::shredFile(path);
    if (ok)
    {
        writeCliDiag(seal::console::Tone::Success,
                     {"event=cli.shred.finish",
                      "result=ok",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(path)});
    }
    else
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.shred.finish",
                      "result=fail",
                      "reason=shred_failed",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(path)});
    }
    return ok ? 0 : 1;
}

int HandleHashMode(const std::string& path)
{
    if (!seal::utils::fileExistsA(path))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.hash.finish",
                      "result=fail",
                      "reason=file_not_found",
                      seal::diag::pathSummary(path)});
        return 1;
    }

    std::string hash = seal::FileOperations::hashFile(path);
    if (hash.empty())
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.hash.finish",
                      "result=fail",
                      "reason=hash_failed",
                      seal::diag::pathSummary(path)});
        return 1;
    }

    std::cout << hash << "  " << path << "\n";
    writeCliDiag(seal::console::Tone::Success,
                 {"event=cli.hash.finish",
                  "result=ok",
                  seal::diag::kv("digest_len", hash.size()),
                  seal::diag::pathSummary(path)});
    return 0;
}

int HandleVerifyMode(const std::string& path)
{
    if (!seal::utils::fileExistsA(path))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.verify.finish",
                      "result=fail",
                      "reason=file_not_found",
                      seal::diag::pathSummary(path)});
        return 1;
    }

    const auto started = std::chrono::steady_clock::now();
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);
        ScopedUnprotect<decltype(dpapi)> dpapiScope(dpapi);

        std::ifstream in(path, std::ios::binary);
        std::vector<unsigned char> blob((std::istreambuf_iterator<char>(in)),
                                        std::istreambuf_iterator<char>());
        in.close();

        // Verify the GCM tag without allocating a full plaintext buffer.
        // verifyPacket processes ciphertext in 64 KB chunks, keeping peak
        // memory at ~n (file blob) instead of ~2n (blob + plaintext).
        seal::Cryptography::verifyPacket(std::span<const unsigned char>(blob), password);
        seal::Cryptography::cleanseString(password);

        writeCliDiag(seal::console::Tone::Success,
                     {"event=cli.verify.finish",
                      "result=ok",
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(path)});
        return 0;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.verify.finish",
                      "result=fail",
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(path)});
        return 1;
    }
}

int HandleWipeMode()
{
    (void)seal::Clipboard::copyWithTTL("");
    seal::wipeConsoleBuffer();
    writeCliDiag(seal::console::Tone::Success,
                 {"event=cli.wipe.finish", "result=ok", "clipboard=true"});
    return 0;
}

int HandleFileEncrypt(const std::string& inputPath, const std::string& outputPath)
{
    if (!seal::utils::fileExistsA(inputPath))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.file_encrypt.finish",
                      "result=fail",
                      "reason=file_not_found",
                      seal::diag::pathSummary(inputPath)});
        return 1;
    }

    const std::string opId = seal::diag::nextOpId("cli_file_encrypt");
    const auto started = std::chrono::steady_clock::now();
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);
        ScopedUnprotect<decltype(dpapi)> dpapiScope(dpapi);

        // Encrypt to destination path (default: append .seal).
        // Source file is only deleted after the destination is fully written.
        std::string dest = outputPath.empty()
                               ? seal::utils::add_ext(inputPath, std::string_view{".seal"})
                               : outputPath;

        writeCliDiag(seal::console::Tone::Step,
                     {"event=cli.file_encrypt.begin",
                      "result=start",
                      seal::diag::kv("op", opId),
                      seal::diag::pathSummary(inputPath)});

        bool ok = seal::FileOperations::encryptFileTo(inputPath, dest, password);
        if (!ok)
        {
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.file_encrypt.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=encrypt_failed",
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                          seal::diag::pathSummary(inputPath)});
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        DeleteFileA(inputPath.c_str());
        writeCliDiag(seal::console::Tone::Success,
                     {"event=cli.file_encrypt.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(inputPath, "src"),
                      seal::diag::pathSummary(dest, "dst")});
        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.file_encrypt.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(inputPath)});
        return 1;
    }
}

int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath)
{
    if (!seal::utils::fileExistsA(inputPath))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.file_decrypt.finish",
                      "result=fail",
                      "reason=file_not_found",
                      seal::diag::pathSummary(inputPath)});
        return 1;
    }

    const std::string opId = seal::diag::nextOpId("cli_file_decrypt");
    const auto started = std::chrono::steady_clock::now();
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);
        ScopedUnprotect<decltype(dpapi)> dpapiScope(dpapi);

        // Decrypt to destination path (default: strip .seal extension).
        // Source file is only deleted after the destination is fully written.
        std::string dest = outputPath;
        if (dest.empty())
        {
            if (seal::utils::endsWithCi(inputPath, ".seal"))
                dest = seal::utils::strip_ext_ci(inputPath, std::string_view{".seal"});
            else
                dest = inputPath + ".decrypted";
        }

        writeCliDiag(seal::console::Tone::Step,
                     {"event=cli.file_decrypt.begin",
                      "result=start",
                      seal::diag::kv("op", opId),
                      seal::diag::pathSummary(inputPath)});

        bool ok = seal::FileOperations::decryptFileTo(inputPath, dest, password);
        if (!ok)
        {
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.file_decrypt.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=decrypt_failed",
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                          seal::diag::pathSummary(inputPath)});
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        DeleteFileA(inputPath.c_str());
        writeCliDiag(seal::console::Tone::Success,
                     {"event=cli.file_decrypt.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(inputPath, "src"),
                      seal::diag::pathSummary(dest, "dst")});
        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.file_decrypt.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(inputPath)});
        return 1;
    }
}

// String encrypt/decrypt mode: text in -> hex out, or hex in -> text out.
// Reads from the inline argument if provided, otherwise from stdin.
// Password prompt goes to stderr so piping works cleanly.
int HandleStringMode(bool encryptMode, const std::string& inlineData)
{
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);
        ScopedUnprotect<decltype(dpapi)> dpapiScope(dpapi);

        // Get input: inline argument or stdin
        std::string input = inlineData;
        if (input.empty())
        {
            input.assign(std::istreambuf_iterator<char>(std::cin),
                         std::istreambuf_iterator<char>());
            // Strip trailing newline from piped/pasted input
            while (!input.empty() && (input.back() == '\n' || input.back() == '\r'))
                input.pop_back();
        }

        if (input.empty())
        {
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.text.finish", "result=fail", "reason=no_input"});
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        if (encryptMode)
        {
            std::string hex = seal::FileOperations::encryptLine(input, password);
            std::vector<unsigned char> raw;
            if (!seal::utils::from_hex(std::string_view{hex}, raw))
            {
                writeCliDiag(seal::console::Tone::Error,
                             {"event=cli.text.finish",
                              "result=fail",
                              "mode=encrypt",
                              "reason=hex_roundtrip_failed"});
                seal::Cryptography::cleanseString(input, password, hex);
                return 1;
            }
            std::string b64 = seal::utils::toBase64(std::span<const unsigned char>(raw));
            std::cout << "(hex) " << hex << "\n";
            std::cout << "(b64) " << b64 << "\n";
            writeCliDiag(seal::console::Tone::Success,
                         {"event=cli.text.finish",
                          "result=ok",
                          "mode=encrypt",
                          seal::diag::kv("input_len", input.size()),
                          seal::diag::kv("hex_len", hex.size()),
                          seal::diag::kv("b64_len", b64.size())});
            seal::Cryptography::cleanseString(input);
        }
        else
        {
            // Auto-detect format: try hex first (stricter check -- even length
            // + all hex digits), then fall back to Base64.  Hex is checked
            // first because all hex characters are valid Base64 characters,
            // but the reverse is not true, making hex the more specific test.
            bool looksHex = (input.size() % 2 == 0) && input.size() >= 4 &&
                            std::all_of(input.begin(),
                                        input.end(),
                                        [](unsigned char c) { return std::isxdigit(c) != 0; });

            if (looksHex)
            {
                auto plain = seal::FileOperations::decryptLine(input, password);
                std::cout << std::string_view(plain.data(), plain.size()) << "\n";
                seal::Cryptography::cleanseString(plain);
            }
            else if (seal::utils::isBase64(input))
            {
                auto bytes = seal::utils::fromBase64(input);
                auto plain = seal::Cryptography::decryptPacket(
                    std::span<const unsigned char>(bytes), password);
                std::cout << std::string_view(reinterpret_cast<const char*>(plain.data()),
                                              plain.size())
                          << "\n";
                seal::Cryptography::cleanseString(plain);
            }
            else
            {
                writeCliDiag(seal::console::Tone::Error,
                             {"event=cli.text.finish",
                              "result=fail",
                              "mode=decrypt",
                              "reason=invalid_encoding",
                              seal::diag::kv("input_len", input.size())});
                seal::Cryptography::cleanseString(input, password);
                return 1;
            }
            writeCliDiag(seal::console::Tone::Success,
                         {"event=cli.text.finish",
                          "result=ok",
                          "mode=decrypt",
                          seal::diag::kv("input_len", input.size())});
            seal::Cryptography::cleanseString(input);
        }

        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.text.finish",
                      "result=fail",
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))});
        return 1;
    }
}

}  // namespace seal
