/*  ============================================================================================  *
 *                                                            ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
 *                                                            ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
 *           ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
 *          :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
 *          +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
 *          +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
 *                 +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇
 *          #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
 *           ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
 *                                                            ⠀⠀⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 *
 *                                  << P A S S   M A N A G E R >>
 *
 *  ============================================================================================  *
 *
 *      A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *      providing on-demand credential management, directory encryption,
 *      webcam QR authentication, and global auto-fill.
 *
 *    ----------------------------------------------------------------------
 *
 *      Repository:   https://github.com/lextpf/seal
 *      License:      MIT
 */
#include "Clipboard.h"
#include "Console.h"
#include "Cryptography.h"
#include "FileOperations.h"
#include "ScopedDpapiUnprotect.h"
#include "Utils.h"
#include "Version.h"

#ifdef USE_QT_UI
#include <QtCore/QString>
#include "Vault.h"
#endif

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

// Forward declaration - implementation is in qmlmain.cpp
#ifdef USE_QT_UI
int RunQMLMode(int argc, char* argv[]);
#endif

// Parsed command-line options for mode dispatch.
struct ProgramOptions
{
    bool stringMode = false;
    bool encryptMode = false;
    bool decryptMode = false;
    std::string stringData;
    bool uiMode = false;
    bool cliMode = false;
    bool importMode = false;
    std::string importData;
    std::string importOutputPath;
    bool exportMode = false;
    std::string exportInputPath;
    std::string exportOutputPath;
    bool fileEncryptMode = false;
    bool fileDecryptMode = false;
    std::string fileInput;
    std::string fileOutput;
    bool genMode = false;
    int genLength = 20;
    bool shredMode = false;
    std::string shredPath;
    bool hashMode = false;
    std::string hashPath;
    bool verifyMode = false;
    std::string verifyPath;
    bool wipeMode = false;
};

// Alias for backwards compatibility with existing call sites in this file.
template <class GuardT>
using ScopedUnprotect = seal::ScopedDpapiUnprotect<GuardT>;

static void printHelp()
{
    std::cout << "seal " << SEAL_VERSION << " - AES-256-GCM Encryption Utility\n\n";
    std::cout << "Usage:\n";
    std::cout << "  seal <command> [args]\n";
    std::cout << "  seal [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  encrypt <file> [output]   Encrypt a file (output defaults to <file>.seal)\n";
    std::cout << "  decrypt <file> [output]   Decrypt a file (output defaults to original name)\n";
    std::cout << "  gen [length]              Generate a random password (default: 20)\n";
    std::cout << "  shred <file>              Securely delete a file (3-pass overwrite + remove)\n";
    std::cout << "  hash <file>               Compute SHA-256 hash of a file\n";
    std::cout << "  verify <file.seal>        Verify password for an encrypted file\n";
    std::cout << "  wipe                      Clear clipboard and console buffer\n";
    std::cout << "  import <data> [output]    Import credentials into a vault file\n";
    std::cout << "  export <input> [output]   Export vault to plaintext (re-importable format)\n\n";
    std::cout << "Options:\n";
    std::cout << "  -e, --text-encrypt [text] Encrypt a string, output hex\n";
    std::cout << "  -d, --text-decrypt [hex]  Decrypt a hex string, output plaintext\n";
    std::cout << "  -u, --ui                  Launch graphical user interface\n";
    std::cout << "  -c, --cli                 Launch command-line interactive mode\n";
    std::cout << "  -v, --version             Display version information\n";
    std::cout << "  -h, --help                Display this help message\n";
    std::cout << "  (no args)                 GUI mode (default)\n\n";
    std::cout << "Import format:\n";
    std::cout << "  <data> is comma-separated entries: plat:user:pass, plat:user:pass,...\n";
    std::cout << "  <data> can also be a path to a text file containing entries\n";
    std::cout << "  Use '-' as <data> to read entries from stdin (pipe or paste)\n";
    std::cout << "  [output] is the vault file path (default: .seal)\n\n";
    std::cout << "Export format:\n";
    std::cout << "  <input> is the vault file path (e.g. vault.seal)\n";
    std::cout << "  [output] is the plaintext output path (default: stdout)\n\n";
    std::cout << "Examples:\n";
    std::cout << "  seal encrypt secret.txt                  Produces secret.txt.seal\n";
    std::cout << "  seal decrypt secret.txt.seal             Produces secret.txt\n";
    std::cout << "  seal encrypt photo.png encrypted.seal    Custom output name\n";
    std::cout << "  seal decrypt encrypted.seal photo.png    Custom output name\n";
    std::cout << "  seal -e \"Hello World\"                    Encrypt string to hex\n";
    std::cout << "  seal -d <hex>                            Decrypt hex to plaintext\n";
    std::cout << "  echo \"Hello\" | seal -e                   Encrypt from stdin\n";
    std::cout << "  echo \"Hello\" | seal -e | seal -d         Round-trip via pipe\n";
    std::cout << "  seal gen                                 Random 20-char password\n";
    std::cout << "  seal gen 40                              Random 40-char password\n";
    std::cout << "  seal shred secret.txt                    Securely delete file\n";
    std::cout << "  seal hash document.pdf                   SHA-256 hash\n";
    std::cout << "  seal verify secret.txt.seal              Check password correctness\n";
    std::cout << "  seal wipe                                Clear clipboard + console\n";
    std::cout << "  seal import \"github:alice:pw123\"         Import to default .seal\n";
    std::cout << "  seal import entries.txt vault.seal       Import from file to vault\n";
    std::cout << "  seal import - vault.seal < entries.txt   Read entries from stdin\n";
    std::cout << "  seal export vault.seal                   Print credentials to stdout\n";
    std::cout << "  seal export vault.seal export.txt        Save credentials to file\n";
    std::cout << "  seal --ui                                Launch GUI mode\n";
    std::cout << "  seal --cli                               Launch interactive CLI\n";
}

static bool isOptionToken(const char* token)
{
    return token && token[0] == '-' && token[1] != '\0';
}

// Returns: -1 = parsed OK (continue), 0 = help shown (exit 0), 1 = error (exit 1)
static int parseArguments(int argc, char* argv[], ProgramOptions& opts)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-e" || arg == "--text-encrypt")
        {
            opts.stringMode = true;
            opts.encryptMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.stringData = argv[++i];
        }
        else if (arg == "-d" || arg == "--text-decrypt")
        {
            opts.stringMode = true;
            opts.decryptMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.stringData = argv[++i];
        }
        else if (arg == "-u" || arg == "--ui")
        {
            opts.uiMode = true;
        }
        else if (arg == "-c" || arg == "--cli")
        {
            opts.cliMode = true;
        }
        else if (arg == "--import" || arg == "import")
        {
            opts.importMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.importData = argv[++i];
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                    opts.importOutputPath = argv[++i];
                else
                    opts.importOutputPath = ".seal";
            }
            else
            {
                std::cerr << "Error: import requires at least one argument\n";
                std::cerr << "Usage: seal import \"plat:user:pass,...\" [output.seal]\n";
                return 1;
            }
        }
        else if (arg == "--export" || arg == "export")
        {
            opts.exportMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.exportInputPath = argv[++i];
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                    opts.exportOutputPath = argv[++i];
            }
            else
            {
                std::cerr << "Error: export requires a vault file argument\n";
                std::cerr << "Usage: seal export vault.seal [output.txt]\n";
                return 1;
            }
        }
        else if (arg == "encrypt")
        {
            opts.fileEncryptMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.fileInput = argv[++i];
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                    opts.fileOutput = argv[++i];
            }
            else
            {
                std::cerr << "Error: encrypt requires a file argument\n";
                std::cerr << "Usage: seal encrypt <file> [output]\n";
                return 1;
            }
        }
        else if (arg == "decrypt")
        {
            opts.fileDecryptMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.fileInput = argv[++i];
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                    opts.fileOutput = argv[++i];
            }
            else
            {
                std::cerr << "Error: decrypt requires a file argument\n";
                std::cerr << "Usage: seal decrypt <file> [output]\n";
                return 1;
            }
        }
        else if (arg == "gen")
        {
            opts.genMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                try
                {
                    opts.genLength = std::stoi(argv[++i]);
                }
                catch (...)
                {
                    opts.genLength = 20;
                }
            }
        }
        else if (arg == "shred")
        {
            opts.shredMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.shredPath = argv[++i];
            else
            {
                std::cerr << "Error: shred requires a file argument\n";
                std::cerr << "Usage: seal shred <file>\n";
                return 1;
            }
        }
        else if (arg == "hash")
        {
            opts.hashMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.hashPath = argv[++i];
            else
            {
                std::cerr << "Error: hash requires a file argument\n";
                std::cerr << "Usage: seal hash <file>\n";
                return 1;
            }
        }
        else if (arg == "verify")
        {
            opts.verifyMode = true;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.verifyPath = argv[++i];
            else
            {
                std::cerr << "Error: verify requires a file argument\n";
                std::cerr << "Usage: seal verify <file.seal>\n";
                return 1;
            }
        }
        else if (arg == "wipe")
        {
            opts.wipeMode = true;
        }
        else if (arg == "-v" || arg == "--version")
        {
            std::cout << "seal " << SEAL_VERSION << "\n";
            return 0;
        }
        else if (arg == "-h" || arg == "--help")
        {
            printHelp();
            return 0;
        }
        else
        {
            std::cerr << "Unknown option: " << arg << "\n";
            std::cerr << "Use -h or --help for usage information.\n";
            return 1;
        }
    }

    if (opts.uiMode && opts.cliMode)
    {
        std::cerr << "Error: Cannot specify both --ui and --cli\n";
        return 1;
    }
    if (opts.encryptMode && opts.decryptMode)
    {
        std::cerr << "Error: Cannot specify both -e and -d\n";
        return 1;
    }
    if (opts.importMode && opts.stringMode)
    {
        std::cerr << "Error: Cannot combine import with -e/-d\n";
        return 1;
    }
    if (opts.exportMode && opts.stringMode)
    {
        std::cerr << "Error: Cannot combine export with -e/-d\n";
        return 1;
    }
    if (opts.exportMode && opts.importMode)
    {
        std::cerr << "Error: Cannot combine export with import\n";
        return 1;
    }
    if ((opts.fileEncryptMode || opts.fileDecryptMode) &&
        (opts.stringMode || opts.importMode || opts.exportMode))
    {
        std::cerr << "Error: Cannot combine encrypt/decrypt with other modes\n";
        return 1;
    }
    if (opts.fileEncryptMode && opts.fileDecryptMode)
    {
        std::cerr << "Error: Cannot specify both encrypt and decrypt\n";
        return 1;
    }
    return -1;
}

// Apply all process-wide security mitigations in dependency order.
// Returns 0 on success, 1 if a critical mitigation fails.
static int initializeSecurity(bool allowDynamicCode)
{
    // Order matters: debugger check first (fail fast before any secrets load),
    // then process mitigations (CFG, DEP, ASLR, dynamic-code policy), then
    // heap/access hardening, and finally memory-lock privilege which is needed
    // before any secure_string allocations touch VirtualLock.
    seal::Cryptography::detectDebugger();

    if (!seal::Cryptography::setSecureProcessMitigations(allowDynamicCode))
        return 1;
    if (seal::Cryptography::isRemoteSession())
        return 1;

    seal::Cryptography::hardenHeap();
    seal::Cryptography::hardenProcessAccess();
    seal::Cryptography::disableCrashDumps();
    if (!seal::Cryptography::tryEnableLockPrivilege())
    {
        const char* username = std::getenv("USERNAME");

        std::cerr << "\n!!! SECURITY WARNING !!!\n\n"
                  << "Failed to enable memory lock privilege (SE_LOCK_MEMORY_NAME).\n"
                  << "This application cannot securely protect sensitive data in memory.\n\n"
                  << "To fix this issue:\n"
                  << "  1. Open Group Policy Editor (gpedit.msc)\n"
                  << "  2. Go to \"Local Policies\" then \"User Rights Assignment\"\n"
                  << "  3. Add your account to \"Lock pages in memory\"\n"
                  << "  4. Reboot your system\n\n"
                  << "Current user: " << (username ? username : "Unknown") << "\n";
    }
    return 0;
}

#ifdef USE_QT_UI
static void loadImportDataFromFile(std::string& importData)
{
    std::string fileContent;

    if (importData == "-")
    {
        // Read from stdin - supports piping and paste (Ctrl+Z to end on Windows).
        fileContent.assign(std::istreambuf_iterator<char>(std::cin),
                           std::istreambuf_iterator<char>());
        std::cout << "Reading entries from stdin...\n";
    }
    else
    {
        std::ifstream testFile(importData);
        if (!testFile.good())
            return;

        fileContent.assign(std::istreambuf_iterator<char>(testFile),
                           std::istreambuf_iterator<char>());
        testFile.close();
        std::cout << "Reading entries from file...\n";
    }

    // Replace newlines with commas so entries can be one-per-line or comma-separated.
    std::replace_if(
        fileContent.begin(), fileContent.end(), [](char c) { return c == '\n' || c == '\r'; }, ',');
    importData = fileContent;
}

static int parseImportEntries(
    const std::string& importData,
    std::vector<std::tuple<std::string, std::string, std::string>>& entries)
{
    std::string remaining = importData;
    while (!remaining.empty())
    {
        size_t commaPos = remaining.find(',');
        std::string token =
            (commaPos != std::string::npos) ? remaining.substr(0, commaPos) : remaining;
        remaining = (commaPos != std::string::npos) ? remaining.substr(commaPos + 1) : "";

        token = seal::utils::trim(token);
        if (token.empty())
            continue;

        size_t firstColon = token.find(':');
        if (firstColon == std::string::npos)
        {
            std::cerr << "Error: Invalid entry (missing colon): " << token << "\n";
            std::cerr << "Expected format: platform:username:password\n";
            return 1;
        }
        size_t secondColon = token.find(':', firstColon + 1);
        if (secondColon == std::string::npos)
        {
            std::cerr << "Error: Invalid entry (missing second colon): " << token << "\n";
            std::cerr << "Expected format: platform:username:password\n";
            return 1;
        }

        std::string platform = seal::utils::trim(token.substr(0, firstColon));
        std::string user =
            seal::utils::trim(token.substr(firstColon + 1, secondColon - firstColon - 1));
        std::string pass = token.substr(secondColon + 1);

        if (platform.empty() || user.empty() || pass.empty())
        {
            std::cerr << "Error: Empty field in entry: " << token << "\n";
            return 1;
        }
        entries.emplace_back(platform, user, pass);
    }
    return 0;
}

static int handleImportMode(std::string& importData, const std::string& importOutputPath)
{
    loadImportDataFromFile(importData);

    std::vector<std::tuple<std::string, std::string, std::string>> entries;
    int rc = parseImportEntries(importData, entries);
    if (rc != 0)
        return rc;

    if (entries.empty())
    {
        std::cerr << "Error: No valid entries found in import data\n";
        return 1;
    }

    std::cout << "Importing " << entries.size() << " credential(s)...\n";

    seal::basic_secure_string<wchar_t> masterPassword;
    try
    {
        masterPassword = seal::readPasswordConsole();
    }
    catch (...)
    {
        std::cerr << "Error: Failed to read master password\n";
        return 1;
    }
    // DPAPIGuard wraps the master password with CryptProtectMemory while idle.
    // unprotect() decrypts it in-place for the encryption loop; reprotect()
    // (or destructor) re-encrypts it so the plaintext key is short-lived.
    seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> importDpapi(&masterPassword);

    std::vector<seal::VaultRecord> records;
    records.reserve(entries.size());
    try
    {
        ScopedUnprotect dpapiScope(importDpapi);
        for (const auto& [platform, user, pass] : entries)
        {
            auto secUser = seal::utils::utf8ToSecureWide(user);
            auto secPass = seal::utils::utf8ToSecureWide(pass);
            records.push_back(seal::encryptCredential(platform, secUser, secPass, masterPassword));
            // Wipe the wide copies immediately; the encrypted VaultRecord now owns the data.
            seal::Cryptography::cleanseString(secUser, secPass);
        }

        QString outputPath = QString::fromUtf8(importOutputPath.c_str());
        if (!outputPath.endsWith(".seal", Qt::CaseInsensitive))
            outputPath += ".seal";

        // Cleanse the original plaintext entry strings now that every credential
        // has been encrypted into a VaultRecord. This limits the plaintext lifetime.
        for (auto& [p, u, pw] : entries)
            seal::Cryptography::cleanseString(p, u, pw);

        if (seal::saveVaultV2(outputPath, records, masterPassword))
        {
            std::cout << "Successfully saved " << records.size() << " credential(s) to "
                      << outputPath.toStdString() << "\n";
            seal::Cryptography::cleanseString(masterPassword);
            return 0;
        }
        std::cerr << "Error: Failed to save vault file\n";
        seal::Cryptography::cleanseString(masterPassword);
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        seal::Cryptography::cleanseString(masterPassword);
    }
    return 1;
}

static int handleExportMode(const std::string& inputPath, const std::string& outputPath)
{
    QString vaultPath = QString::fromUtf8(inputPath.c_str());
    if (!vaultPath.endsWith(".seal", Qt::CaseInsensitive))
        vaultPath += ".seal";

    seal::basic_secure_string<wchar_t> masterPassword;
    try
    {
        masterPassword = seal::readPasswordConsole();
    }
    catch (...)
    {
        std::cerr << "Error: Failed to read master password\n";
        return 1;
    }
    seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> exportDpapi(&masterPassword);

    std::vector<seal::VaultRecord> records;
    try
    {
        ScopedUnprotect dpapiScope(exportDpapi);
        records = seal::loadVaultIndex(vaultPath, masterPassword);
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        seal::Cryptography::cleanseString(masterPassword);
        return 1;
    }

    if (records.empty())
    {
        std::cerr << "Vault is empty, nothing to export.\n";
        seal::Cryptography::cleanseString(masterPassword);
        return 0;
    }

    // Build one comma-separated export string in the same format that --import accepts.
    // SECURITY: fail immediately on the first decryption error. If we kept going,
    // the number of successful decryptions before the error would leak how many
    // records the vault contains (side-channel on wrong password).
    // Pre-reserve to reduce intermediate reallocation copies of plaintext on
    // the heap. Each record is roughly ~80 chars (platform:user:pass + comma).
    std::string exportData;
    exportData.reserve(records.size() * 80);
    size_t exportedCount = 0;
    try
    {
        ScopedUnprotect dpapiScope(exportDpapi);
        for (const auto& rec : records)
        {
            if (rec.deleted)
                continue;
            auto cred = seal::decryptCredentialOnDemand(rec, masterPassword);
            std::string user = seal::utils::secureWideToUtf8(cred.username);
            std::string pass = seal::utils::secureWideToUtf8(cred.password);
            std::string entry = rec.platform + ":" + user + ":" + pass;
            if (!exportData.empty())
                exportData.push_back(',');
            exportData += entry;
            ++exportedCount;
            seal::Cryptography::cleanseString(entry);
            seal::Cryptography::cleanseString(user, pass);
            cred.cleanse();
        }
    }
    catch (const std::exception&)
    {
        seal::Cryptography::cleanseString(exportData);
        seal::Cryptography::cleanseString(masterPassword);
        std::cerr << "Error: Decryption failed - wrong password or corrupted vault.\n";
        return 1;
    }
    seal::Cryptography::cleanseString(masterPassword);

    // Write to file or stdout.
    if (outputPath.empty())
    {
        std::cout << exportData;
    }
    else
    {
        std::ofstream out(outputPath);
        if (!out.good())
        {
            std::cerr << "Error: Could not open output file: " << outputPath << "\n";
            return 1;
        }
        out << exportData;
        out.close();
        std::cout << "Exported " << exportedCount << " credential(s) to " << outputPath << "\n";
    }

    seal::Cryptography::cleanseString(exportData);
    return 0;
}
#endif  // USE_QT_UI

static int handleGenMode(int length)
{
    length = std::clamp(length, 8, 128);

    static constexpr char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
    static constexpr int charsetLen = sizeof(charset) - 1;

    std::vector<unsigned char> buf(static_cast<size_t>(length));
    RAND_bytes(buf.data(), length);

    std::string password;
    password.reserve(static_cast<size_t>(length));
    for (int i = 0; i < length; ++i)
        password.push_back(charset[buf[static_cast<size_t>(i)] % charsetLen]);

    SecureZeroMemory(buf.data(), buf.size());
    std::cout << password << "\n";

    (void)seal::Clipboard::copyWithTTL(password);
    std::cerr << "(copied to clipboard)\n";

    seal::Cryptography::cleanseString(password);
    return 0;
}

static int handleShredMode(const std::string& path)
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

static int handleHashMode(const std::string& path)
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

static int handleVerifyMode(const std::string& path)
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

        // Attempt decryption - success means password is correct
        auto plain =
            seal::Cryptography::decryptPacket(std::span<const unsigned char>(blob), password);
        seal::Cryptography::cleanseString(plain);
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

static int handleWipeMode()
{
    (void)seal::Clipboard::copyWithTTL("");
    seal::wipeConsoleBuffer();
    std::cerr << "(wiped) clipboard and console buffer cleared\n";
    return 0;
}

static int handleFileEncrypt(const std::string& inputPath, const std::string& outputPath)
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

        bool ok = seal::FileOperations::encryptFileInPlace(inputPath, password);
        if (!ok)
        {
            std::cerr << "Error: Encryption failed for " << inputPath << "\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        // Rename to output path (default: append .seal)
        std::string dest = outputPath.empty()
                               ? seal::utils::add_ext(inputPath, std::string_view{".seal"})
                               : outputPath;

        if (!MoveFileExA(inputPath.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            std::cerr << "Error: Failed to rename " << inputPath << " -> " << dest << "\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

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

static int handleFileDecrypt(const std::string& inputPath, const std::string& outputPath)
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

        bool ok = seal::FileOperations::decryptFileInPlace(inputPath, password);
        if (!ok)
        {
            std::cerr << "Error: Decryption failed for " << inputPath << "\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        // Rename to output path (default: strip .seal extension)
        std::string dest = outputPath;
        if (dest.empty())
        {
            if (seal::utils::endsWithCi(inputPath, ".seal"))
                dest = seal::utils::strip_ext_ci(inputPath, std::string_view{".seal"});
            else
                dest = inputPath + ".decrypted";
        }

        if (!MoveFileExA(inputPath.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            std::cerr << "Error: Failed to rename " << inputPath << " -> " << dest << "\n";
            seal::Cryptography::cleanseString(password);
            return 1;
        }

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
static int handleStringMode(bool encryptMode, const std::string& inlineData)
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
            // Auto-detect hex vs base64 input
            if (seal::utils::isBase64(input))
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
                auto plain = seal::FileOperations::decryptLine(input, password);
                std::cout << std::string_view(plain.data(), plain.size()) << "\n";
                seal::Cryptography::cleanseString(plain);
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

// Process the "seal" input file (a text file named literally "seal" in the cwd).
// It contains paths/hex tokens, one per line, terminated by '?' or '!'.
// This runs once at startup as a batch before the interactive loop begins.
static void processSageFileBatch(seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>& dpapi,
                                 seal::basic_secure_string<wchar_t>& password)
{
    std::ifstream fin("seal");
    if (!fin)
        return;

    auto fileBatch = seal::readBulkLinesDualFrom(fin);
    const auto& flines = fileBatch.first;
    if (flines.empty())
        return;

    ScopedUnprotect dpapiScope(dpapi);
    seal::FileOperations::processBatch(flines, fileBatch.second, password);
    std::cout << "\n";
}

// Re-read the "seal" input file on Esc press. Only processes the file if it
// contains actual file/directory paths (not raw hex), acting as a quick
// re-encrypt/re-decrypt shortcut before exiting the interactive loop.
static bool handleEscSageFile(seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>& dpapi,
                              seal::basic_secure_string<wchar_t>& password)
{
    std::ifstream fin("seal");
    if (!fin)
        return false;

    auto fileBatch = seal::readBulkLinesDualFrom(fin);
    const auto& flines = fileBatch.first;
    if (flines.empty())
        return false;

    bool hasFiles = false;
    for (const auto& line : flines)
    {
        if (_stricmp(line.c_str(), ".") == 0 || seal::utils::isDirectoryA(line.c_str()) ||
            seal::utils::fileExistsA(line.c_str()))
        {
            hasFiles = true;
            break;
        }
    }
    if (hasFiles)
    {
        ScopedUnprotect dpapiScope(dpapi);
        seal::FileOperations::processBatch(flines, fileBatch.second, password);
    }
    return true;
}

static int handleCliMode()
{
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);

        // CLI startup sequence:
        // 1. Process the "seal" input file as an automatic batch (if present).
        // 2. Enter the interactive loop where the user types/pastes lines
        //    terminated by '?' (masked output) or '!' (uncensored output).
        // 3. On Esc, re-read the "seal" file one more time, then exit cleanly.
        processSageFileBatch(dpapi, password);

        std::cout << "+----------------------------------------- seal - Interactive Mode "
                     "-----------------------------------------+\n";
        std::cout << "|              Paste/type and finish with '?' (MASKED) or '!' (UNCENSORED) "
                     "Press Esc to exit.               |\n";
        std::cout << "|    Commands '.'= current dir | ':clip'= copy seal | ':open'= edit seal | "
                     "':none'= clear clipboard         |\n";
        std::cout << "+----------------------------------------------------------------------------"
                     "-------------------------------+\n";

        for (;;)
        {
            std::pair<std::vector<std::string>, bool> batch;
            if (!seal::readBulkLinesDualOrEsc(batch))
            {
                (void)handleEscSageFile(dpapi, password);
                return 0;
            }
            if (batch.first.empty())
                break;

            ScopedUnprotect dpapiScope(dpapi);
            seal::FileOperations::processBatch(batch.first, batch.second, password);
        }
        seal::Cryptography::cleanseString(password);
        seal::wipeConsoleBuffer();
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// Program entry point. Dispatches to one of several modes based on CLI args:
//   -e/--encrypt, -d/--decrypt  : stream encryption/decryption (stdin->stdout)
//   -u/--ui / no args           : Qt GUI mode (default)
//   --cli                       : interactive console mode
//   --import / --export          : vault import/export
//   -h/--help                   : usage information
int main(int argc, char* argv[])
{
    ProgramOptions opts;
    int rc = parseArguments(argc, argv, opts);
    if (rc >= 0)
        return rc;

    const bool useUIMode =
        opts.uiMode ||
        (!opts.cliMode && !opts.stringMode && !opts.fileEncryptMode && !opts.fileDecryptMode &&
         !opts.genMode && !opts.shredMode && !opts.hashMode && !opts.verifyMode && !opts.wipeMode);
    // Qt Quick's QML engine uses a JIT compiler (V4) that needs dynamic code
    // generation. CLI / import / export never load QML, so they can keep the
    // stricter PROCESS_MITIGATION_DYNAMIC_CODE_POLICY that blocks RWX pages.
    const bool allowDynamicCode = useUIMode && !opts.importMode && !opts.exportMode;

    rc = initializeSecurity(allowDynamicCode);
    if (rc != 0)
        return rc;

    if (opts.importMode)
    {
#ifdef USE_QT_UI
        return handleImportMode(opts.importData, opts.importOutputPath);
#else
        std::cerr << "Error: --import requires Qt UI support (USE_QT_UI).\n";
        std::cerr << "Please rebuild with USE_QT_UI enabled.\n";
        return 1;
#endif
    }

    if (opts.exportMode)
    {
#ifdef USE_QT_UI
        return handleExportMode(opts.exportInputPath, opts.exportOutputPath);
#else
        std::cerr << "Error: --export requires Qt UI support (USE_QT_UI).\n";
        std::cerr << "Please rebuild with USE_QT_UI enabled.\n";
        return 1;
#endif
    }

    if (opts.genMode)
        return handleGenMode(opts.genLength);

    if (opts.shredMode)
        return handleShredMode(opts.shredPath);

    if (opts.hashMode)
        return handleHashMode(opts.hashPath);

    if (opts.verifyMode)
        return handleVerifyMode(opts.verifyPath);

    if (opts.wipeMode)
        return handleWipeMode();

    if (opts.fileEncryptMode)
        return handleFileEncrypt(opts.fileInput, opts.fileOutput);

    if (opts.fileDecryptMode)
        return handleFileDecrypt(opts.fileInput, opts.fileOutput);

    if (opts.stringMode)
        return handleStringMode(opts.encryptMode, opts.stringData);

    if (useUIMode)
    {
#ifdef USE_QT_UI
        return RunQMLMode(argc, argv);
#else
        std::cerr << "Error: GUI mode requested but Qt UI support is not compiled in.\n";
        std::cerr << "Please rebuild with USE_QT_UI enabled or use --cli for CLI mode.\n";
        return 1;
#endif
    }

    return handleCliMode();
}
