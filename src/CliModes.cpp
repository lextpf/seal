#include "CliModes.h"

#include "Clipboard.h"
#include "Console.h"
#include "Cryptography.h"
#include "FileOperations.h"
#include "PasswordGen.h"
#include "ScopedDpapiUnprotect.h"
#include "Utils.h"

#include <fstream>
#include <iostream>
#include <string>

namespace
{
template <class GuardT>
using ScopedUnprotect = seal::ScopedDpapiUnprotect<GuardT>;
}  // namespace

namespace seal
{

int HandleGenMode(int length)
{
    auto password = seal::GeneratePassword(length);

    std::cout << password.view() << "\n";

    (void)seal::Clipboard::copyWithTTL(password.data(), password.size());
    std::cerr << "(copied to clipboard)\n";

    seal::Cryptography::cleanseString(password);
    return 0;
}

int HandleShredMode(const std::string& path)
{
    if (!seal::utils::fileExistsA(path))
    {
        std::cerr << "Error: File not found: " << path << "\n";
        return 1;
    }

    std::cerr << "Shredding: " << path << " (3-pass overwrite + delete)...\n";
    bool ok = seal::FileOperations::shredFile(path);
    if (ok)
        std::cerr << "(shredded) " << path << "\n";
    else
        std::cerr << "Error: Failed to shred " << path << "\n";
    return ok ? 0 : 1;
}

int HandleHashMode(const std::string& path)
{
    if (!seal::utils::fileExistsA(path))
    {
        std::cerr << "Error: File not found: " << path << "\n";
        return 1;
    }

    std::string hash = seal::FileOperations::hashFile(path);
    if (hash.empty())
    {
        std::cerr << "Error: Failed to hash " << path << "\n";
        return 1;
    }

    std::cout << hash << "  " << path << "\n";
    return 0;
}

int HandleVerifyMode(const std::string& path)
{
    if (!seal::utils::fileExistsA(path))
    {
        std::cerr << "Error: File not found: " << path << "\n";
        return 1;
    }

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

        std::cerr << "(verified) " << path << " - password correct\n";
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "(failed) " << path << " - " << e.what() << "\n";
        return 1;
    }
}

int HandleWipeMode()
{
    (void)seal::Clipboard::copyWithTTL("");
    seal::wipeConsoleBuffer();
    std::cerr << "(wiped) clipboard and console buffer cleared\n";
    return 0;
}

int HandleFileEncrypt(const std::string& inputPath, const std::string& outputPath)
{
    if (!seal::utils::fileExistsA(inputPath))
    {
        std::cerr << "Error: File not found: " << inputPath << "\n";
        return 1;
    }

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

        bool ok = seal::FileOperations::encryptFileTo(inputPath, dest, password);
        if (!ok)
        {
            std::cerr << "Error: Encryption failed for " << inputPath << "\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        DeleteFileA(inputPath.c_str());
        std::cerr << "(encrypted) " << inputPath << " -> " << dest << "\n";
        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath)
{
    if (!seal::utils::fileExistsA(inputPath))
    {
        std::cerr << "Error: File not found: " << inputPath << "\n";
        return 1;
    }

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

        bool ok = seal::FileOperations::decryptFileTo(inputPath, dest, password);
        if (!ok)
        {
            std::cerr << "Error: Decryption failed for " << inputPath << "\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        DeleteFileA(inputPath.c_str());
        std::cerr << "(decrypted) " << inputPath << " -> " << dest << "\n";
        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
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
            std::cerr << "Error: No input provided\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        if (encryptMode)
        {
            std::string hex = seal::FileOperations::encryptLine(input, password);
            std::vector<unsigned char> raw;
            seal::utils::from_hex(std::string_view{hex}, raw);
            std::string b64 = seal::utils::toBase64(std::span<const unsigned char>(raw));
            std::cout << "(hex) " << hex << "\n";
            std::cout << "(b64) " << b64 << "\n";
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
                std::cerr << "Error: Input is neither valid hex nor Base64\n";
                seal::Cryptography::cleanseString(input, password);
                return 1;
            }
            seal::Cryptography::cleanseString(input);
        }

        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

}  // namespace seal
