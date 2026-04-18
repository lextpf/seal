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
#include "Version.h"

#ifdef USE_QT_UI
#include <QtCore/QString>
#include "Logging.h"
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

namespace
{

// Discriminated program mode.
enum class Mode
{
    Gui,
    Cli,
    TextEncrypt,
    TextDecrypt,
    FileEncrypt,
    FileDecrypt,
    Import,
    Export,
    Gen,
    Shred,
    Hash,
    Verify,
    Wipe
};

struct ProgramOptions
{
    Mode mode = Mode::Gui;
    bool modeExplicit = false;  // true once any mode flag is parsed
    std::string inputPath;      // primary path or import data
    std::string outputPath;     // secondary / destination path
    std::string stringData;     // inline text for -e/-d
    int genLength = 20;
};

void writeCliDiag(std::ostream& os,
                  seal::console::Tone tone,
                  std::string_view tag,
                  std::initializer_list<std::string> fields);

// Set the program mode, rejecting conflicts with any previously set mode.
static bool trySetMode(ProgramOptions& opts, Mode newMode)
{
    if (opts.modeExplicit)
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "ARGS",
                     {"event=cli.args.parse", "result=fail", "reason=multiple_modes"});
        return false;
    }
    opts.mode = newMode;
    opts.modeExplicit = true;
    return true;
}

// Alias for backwards compatibility with existing call sites in this file.
template <class GuardT>
using ScopedUnprotect = seal::ScopedDpapiUnprotect<GuardT>;

void writeCliDiag(std::ostream& os,
                  seal::console::Tone tone,
                  std::string_view tag,
                  std::initializer_list<std::string> fields)
{
    seal::console::writeTagged(os, tone, tag, seal::diag::joinFields(fields));
}

}  // namespace

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

// Parse a required path argument for a command. Returns false on missing arg.
static bool parseRequiredPath(
    int argc, char* argv[], int& i, ProgramOptions& opts, const char* cmdName, const char* usage)
{
    if (i + 1 < argc && !isOptionToken(argv[i + 1]))
    {
        opts.inputPath = argv[++i];
        if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            opts.outputPath = argv[++i];
        return true;
    }
    writeCliDiag(std::cerr,
                 seal::console::Tone::Error,
                 "ARGS",
                 {"event=cli.args.parse",
                  "result=fail",
                  seal::diag::kv("command", cmdName),
                  "reason=missing_file_argument"});
    writeCliDiag(std::cerr, seal::console::Tone::Info, "USAGE", {seal::diag::kv("syntax", usage)});
    return false;
}

// Returns: -1 = parsed OK (continue), 0 = help shown (exit 0), 1 = error (exit 1)
static int parseArguments(int argc, char* argv[], ProgramOptions& opts)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-e" || arg == "--text-encrypt")
        {
            if (!trySetMode(opts, Mode::TextEncrypt))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.stringData = argv[++i];
        }
        else if (arg == "-d" || arg == "--text-decrypt")
        {
            if (!trySetMode(opts, Mode::TextDecrypt))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                opts.stringData = argv[++i];
        }
        else if (arg == "-u" || arg == "--ui")
        {
            if (!trySetMode(opts, Mode::Gui))
                return 1;
        }
        else if (arg == "-c" || arg == "--cli")
        {
            if (!trySetMode(opts, Mode::Cli))
                return 1;
        }
        else if (arg == "--import" || arg == "import")
        {
            if (!trySetMode(opts, Mode::Import))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.inputPath = argv[++i];
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                    opts.outputPath = argv[++i];
                else
                    opts.outputPath = ".seal";
            }
            else
            {
                writeCliDiag(std::cerr,
                             seal::console::Tone::Error,
                             "ARGS",
                             {"event=cli.args.parse",
                              "result=fail",
                              "command=import",
                              "reason=missing_argument"});
                writeCliDiag(std::cerr,
                             seal::console::Tone::Info,
                             "USAGE",
                             {"syntax=seal_import_data_output.seal"});
                return 1;
            }
        }
        else if (arg == "--export" || arg == "export")
        {
            if (!trySetMode(opts, Mode::Export))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.inputPath = argv[++i];
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                    opts.outputPath = argv[++i];
            }
            else
            {
                writeCliDiag(std::cerr,
                             seal::console::Tone::Error,
                             "ARGS",
                             {"event=cli.args.parse",
                              "result=fail",
                              "command=export",
                              "reason=missing_argument"});
                writeCliDiag(std::cerr,
                             seal::console::Tone::Info,
                             "USAGE",
                             {"syntax=seal_export_vault.seal_output.txt"});
                return 1;
            }
        }
        else if (arg == "encrypt")
        {
            if (!trySetMode(opts, Mode::FileEncrypt))
                return 1;
            if (!parseRequiredPath(argc, argv, i, opts, "encrypt", "seal encrypt <file> [output]"))
                return 1;
        }
        else if (arg == "decrypt")
        {
            if (!trySetMode(opts, Mode::FileDecrypt))
                return 1;
            if (!parseRequiredPath(argc, argv, i, opts, "decrypt", "seal decrypt <file> [output]"))
                return 1;
        }
        else if (arg == "gen")
        {
            if (!trySetMode(opts, Mode::Gen))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                try
                {
                    opts.genLength = std::stoi(argv[++i]);
                }
                catch (...)
                {
                    writeCliDiag(std::cerr,
                                 seal::console::Tone::Warning,
                                 "ARGS",
                                 {"event=cli.args.parse",
                                  "result=warn",
                                  "command=gen",
                                  "reason=invalid_length",
                                  "fallback=20"});
                    opts.genLength = 20;
                }
            }
        }
        else if (arg == "shred")
        {
            if (!trySetMode(opts, Mode::Shred))
                return 1;
            if (!parseRequiredPath(argc, argv, i, opts, "shred", "seal shred <file>"))
                return 1;
        }
        else if (arg == "hash")
        {
            if (!trySetMode(opts, Mode::Hash))
                return 1;
            if (!parseRequiredPath(argc, argv, i, opts, "hash", "seal hash <file>"))
                return 1;
        }
        else if (arg == "verify")
        {
            if (!trySetMode(opts, Mode::Verify))
                return 1;
            if (!parseRequiredPath(argc, argv, i, opts, "verify", "seal verify <file.seal>"))
                return 1;
        }
        else if (arg == "wipe")
        {
            if (!trySetMode(opts, Mode::Wipe))
                return 1;
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
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "ARGS",
                         {"event=cli.args.parse",
                          "result=fail",
                          "reason=unknown_option",
                          seal::diag::kv("option", seal::diag::sanitizeAscii(arg))});
            writeCliDiag(std::cerr, seal::console::Tone::Info, "USAGE", {"hint=use_--help"});
            return 1;
        }
    }
    // No explicit validation block needed: trySetMode() rejects conflicts
    // at parse time, and the Mode enum makes invalid combinations impossible.
    return -1;
}

// Apply all process-wide security mitigations in dependency order.
// Returns 0 on success, 1 if a critical mitigation fails.
static int initializeSecurity(bool allowDynamicCode)
{
    // Order matters: Debugger check first (fail fast before any secrets load),
    // then process mitigations (Control Flow Guard, Data Execution Prevention,
    // Address Space Layout Randomization, dynamic-code policy), then
    // heap/access hardening, and finally memory-lock privilege which is needed
    // before any secure_string allocations touch VirtualLock.
    seal::Cryptography::detectDebugger();

    // Process mitigations are best-effort
    if (!seal::Cryptography::setSecureProcessMitigations(allowDynamicCode))
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Warning,
                     "SEC",
                     {"event=app.security.mitigations",
                      "result=partial",
                      "reason=best_effort_failed",
                      seal::diag::kv("allow_dynamic_code", allowDynamicCode)});
    }
    if (seal::Cryptography::isRemoteSession())
    {
        writeCliDiag(
            std::cerr,
            seal::console::Tone::Error,
            "SEC",
            {"event=app.security.environment", "result=fail", "reason=remote_session_detected"});
        return 1;
    }

    seal::Cryptography::hardenHeap();
    seal::Cryptography::hardenProcessAccess();
    seal::Cryptography::disableCrashDumps();
    if (!seal::Cryptography::tryEnableLockPrivilege())
    {
        writeCliDiag(
            std::cerr,
            seal::console::Tone::Error,
            "SEC",
            {"event=app.security.lock_pages", "result=warn", "reason=privilege_unavailable"});
        seal::console::writeLine(std::cerr,
                                 seal::console::Tone::Banner,
                                 "Lock pages in memory privilege is unavailable.");
        seal::console::writeLine(std::cerr,
                                 seal::console::Tone::Banner,
                                 "Open gpedit.msc, grant Lock pages in memory, then reboot.");
    }
    return 0;
}

#ifdef USE_QT_UI
static void loadImportDataFromFile(std::string& importData)
{
    std::string fileContent;
    const std::string sourcePath = importData;

    if (importData == "-")
    {
        // Read from stdin - supports piping and paste (Ctrl+Z to end on Windows).
        fileContent.assign(std::istreambuf_iterator<char>(std::cin),
                           std::istreambuf_iterator<char>());
        writeCliDiag(std::cerr,
                     seal::console::Tone::Step,
                     "IMPORT",
                     {"event=import.read.begin", "source=stdin"});
    }
    else
    {
        std::ifstream testFile(importData);
        if (!testFile.good())
            return;

        fileContent.assign(std::istreambuf_iterator<char>(testFile),
                           std::istreambuf_iterator<char>());
        testFile.close();
        writeCliDiag(
            std::cerr,
            seal::console::Tone::Step,
            "IMPORT",
            {"event=import.read.begin", "source=file", seal::diag::pathSummary(sourcePath)});
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
    size_t entryIndex = 0;
    while (!remaining.empty())
    {
        size_t commaPos = remaining.find(',');
        std::string token =
            (commaPos != std::string::npos) ? remaining.substr(0, commaPos) : remaining;
        remaining = (commaPos != std::string::npos) ? remaining.substr(commaPos + 1) : "";

        token = seal::utils::trim(token);
        if (token.empty())
            continue;
        ++entryIndex;

        size_t firstColon = token.find(':');
        if (firstColon == std::string::npos)
        {
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "IMPORT",
                         {"event=import.parse.finish",
                          "result=fail",
                          "reason=missing_first_colon",
                          seal::diag::kv("entry_index", entryIndex),
                          seal::diag::kv("token_len", token.size())});
            return 1;
        }
        size_t secondColon = token.find(':', firstColon + 1);
        if (secondColon == std::string::npos)
        {
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "IMPORT",
                         {"event=import.parse.finish",
                          "result=fail",
                          "reason=missing_second_colon",
                          seal::diag::kv("entry_index", entryIndex),
                          seal::diag::kv("token_len", token.size())});
            return 1;
        }

        // Reject entries with more than 2 colons: the format is strictly
        // platform:username:password, so 3+ colons means ambiguous field
        // boundaries that cannot be round-tripped through export/import.
        if (token.find(':', secondColon + 1) != std::string::npos)
        {
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "IMPORT",
                         {"event=import.parse.finish",
                          "result=fail",
                          "reason=too_many_colons",
                          seal::diag::kv("entry_index", entryIndex),
                          seal::diag::kv("token_len", token.size())});
            return 1;
        }

        std::string platform = seal::utils::trim(token.substr(0, firstColon));
        std::string user =
            seal::utils::trim(token.substr(firstColon + 1, secondColon - firstColon - 1));
        std::string pass = token.substr(secondColon + 1);

        if (platform.empty() || user.empty() || pass.empty())
        {
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "IMPORT",
                         {"event=import.parse.finish",
                          "result=fail",
                          "reason=empty_field",
                          seal::diag::kv("entry_index", entryIndex),
                          seal::diag::kv("token_len", token.size())});
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
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "IMPORT",
                     {"event=import.finish", "result=fail", "reason=no_valid_entries"});
        return 1;
    }

    const std::string opId = seal::diag::nextOpId("cli_import");
    writeCliDiag(std::cerr,
                 seal::console::Tone::Step,
                 "IMPORT",
                 {"event=import.begin",
                  "result=start",
                  seal::diag::kv("op", opId),
                  seal::diag::kv("entry_count", entries.size()),
                  seal::diag::pathSummary(importOutputPath)});

    seal::basic_secure_string<wchar_t> masterPassword;
    try
    {
        masterPassword = seal::readPasswordConsole();
    }
    catch (...)
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "IMPORT",
                     {"event=import.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=password_read_failed"});
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
            writeCliDiag(std::cerr,
                         seal::console::Tone::Success,
                         "IMPORT",
                         {"event=import.finish",
                          "result=ok",
                          seal::diag::kv("op", opId),
                          seal::diag::kv("record_count", records.size()),
                          seal::diag::pathSummary(outputPath.toUtf8().toStdString())});
            seal::Cryptography::cleanseString(masterPassword);
            return 0;
        }
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "IMPORT",
                     {"event=import.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=save_failed",
                      seal::diag::pathSummary(outputPath.toUtf8().toStdString())});
        seal::Cryptography::cleanseString(masterPassword);
        return 1;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "IMPORT",
                     {"event=import.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))});
        seal::Cryptography::cleanseString(masterPassword);
    }
    return 1;
}

static int handleExportMode(const std::string& inputPath, const std::string& outputPath)
{
    QString vaultPath = QString::fromUtf8(inputPath.c_str());
    if (!vaultPath.endsWith(".seal", Qt::CaseInsensitive))
        vaultPath += ".seal";

    const std::string opId = seal::diag::nextOpId("cli_export");
    writeCliDiag(
        std::cerr,
        seal::console::Tone::Step,
        "EXPORT",
        {"event=export.begin",
         "result=start",
         seal::diag::kv("op", opId),
         seal::diag::pathSummary(vaultPath.toUtf8().toStdString(), "src"),
         outputPath.empty() ? "dst_kind=stdout" : seal::diag::pathSummary(outputPath, "dst")});

    seal::basic_secure_string<wchar_t> masterPassword;
    try
    {
        masterPassword = seal::readPasswordConsole();
    }
    catch (...)
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "EXPORT",
                     {"event=export.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=password_read_failed"});
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
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "EXPORT",
                     {"event=export.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
                      seal::diag::pathSummary(vaultPath.toUtf8().toStdString(), "src")});
        seal::Cryptography::cleanseString(masterPassword);
        return 1;
    }

    if (records.empty())
    {
        writeCliDiag(
            std::cerr,
            seal::console::Tone::Info,
            "EXPORT",
            {"event=export.finish", "result=ok", seal::diag::kv("op", opId), "reason=empty_vault"});
        seal::Cryptography::cleanseString(masterPassword);
        return 0;
    }

    // Stream each credential directly to the output instead of accumulating
    // all plaintext in a heap buffer. This limits plaintext exposure to one
    // record at a time rather than the entire vault.
    std::ofstream outFile;
    std::ostream* out = &std::cout;
    if (!outputPath.empty())
    {
        outFile.open(outputPath);
        if (!outFile.good())
        {
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "EXPORT",
                         {"event=export.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=output_open_failed",
                          seal::diag::pathSummary(outputPath, "dst")});
            seal::Cryptography::cleanseString(masterPassword);
            return 1;
        }
        out = &outFile;
    }

    size_t exportedCount = 0;
    bool hasColonWarning = false;
    size_t recordIndex = 0;
    try
    {
        ScopedUnprotect dpapiScope(exportDpapi);
        for (const auto& rec : records)
        {
            ++recordIndex;
            if (rec.deleted)
            {
                continue;
            }
            // The export format is "platform:username:password" with exactly 2
            // colon delimiters. If platform or username contain ':', the output
            // cannot be round-tripped through --import because the parser splits
            // on the first two colons. Warn the user so they can fix the data.
            if (!hasColonWarning && (rec.platform.find(':') != std::string::npos))
            {
                writeCliDiag(std::cerr,
                             seal::console::Tone::Warning,
                             "EXPORT",
                             {"event=export.data.warn",
                              "result=warn",
                              "reason=platform_contains_colon",
                              seal::diag::kv("record_index", recordIndex),
                              seal::diag::kv("platform_len", rec.platform.size())});
                hasColonWarning = true;
            }
            auto cred = seal::decryptCredentialOnDemand(rec, masterPassword);
            std::string user = seal::utils::secureWideToUtf8(cred.username);
            std::string pass = seal::utils::secureWideToUtf8(cred.password);
            if (!hasColonWarning && user.find(':') != std::string::npos)
            {
                writeCliDiag(std::cerr,
                             seal::console::Tone::Warning,
                             "EXPORT",
                             {"event=export.data.warn",
                              "result=warn",
                              "reason=username_contains_colon",
                              seal::diag::kv("record_index", recordIndex),
                              seal::diag::kv("platform_len", rec.platform.size()),
                              seal::diag::kv("username_len", user.size())});
                hasColonWarning = true;
            }
            // Write directly to output, cleanse immediately. No intermediate
            // accumulation buffer means only one credential is in pageable
            // memory at any moment.
            if (exportedCount > 0)
                *out << ',';
            *out << rec.platform << ':' << user << ':' << pass;
            ++exportedCount;
            seal::Cryptography::cleanseString(user, pass);
            cred.cleanse();
        }
    }
    catch (const std::exception&)
    {
        seal::Cryptography::cleanseString(masterPassword);
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "EXPORT",
                     {"event=export.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=decrypt_failed"});
        return 1;
    }
    seal::Cryptography::cleanseString(masterPassword);

    if (!outputPath.empty())
    {
        outFile.close();
        writeCliDiag(std::cerr,
                     seal::console::Tone::Success,
                     "EXPORT",
                     {"event=export.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("record_count", exportedCount),
                      seal::diag::pathSummary(outputPath, "dst")});
    }
    return 0;
}
#endif  // USE_QT_UI

// Process the "seal" input file (a text file named literally "seal" in the cwd).
// It contains paths/hex tokens, one per line, terminated by '?' or '!'.
// This runs once at startup as a batch before the interactive loop begins.
static void processSealFileBatch(seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>& dpapi,
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
static bool handleEscSealFile(seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>& dpapi,
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
        processSealFileBatch(dpapi, password);

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
                (void)handleEscSealFile(dpapi, password);
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
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "CLI",
                     {"event=cli.interactive.finish",
                      "result=fail",
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                      seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))});
        return 1;
    }
    return 0;
}

// Program entry point. Dispatches to one of several modes based on CLI args:
//   -e/--encrypt, -d/--decrypt  : stream encryption/decryption (stdin->stdout)
//   -u/--ui / no args           : Qt GUI mode (default)
//   --cli                       : interactive console mode
//   --import / --export         : vault import/export
//   -h/--help                   : usage information
int main(int argc, char* argv[])
{
    ProgramOptions opts;
    int rc = parseArguments(argc, argv, opts);
    if (rc >= 0)
        return rc;

#ifdef USE_QT_UI
    // Route Qt log output through the structured seal handler before any
    // security-init code runs, so early qCInfo(logCrypto) calls emit the
    // same `[ts] [LVL] [cat] [tid=N]` format as the rest of the app.
    installSealMessageHandler();
#endif

    // Qt Quick's QML engine uses a JIT compiler (V4) that needs dynamic code
    // generation. Only GUI mode loads QML; all other modes can keep the
    // stricter PROCESS_MITIGATION_DYNAMIC_CODE_POLICY that blocks RWX pages.
    const bool allowDynamicCode = (opts.mode == Mode::Gui);

    rc = initializeSecurity(allowDynamicCode);
    if (rc != 0)
        return rc;

    // Set OpenCV environment variables while still single-threaded.
    // captureQrFromWebcam() runs on a worker thread and reads these via
    // std::getenv; setting them here avoids a data race on the process
    // environment block.
    _putenv_s("OPENCV_VIDEOIO_MSMF_ENABLE_HW_TRANSFORMS", "0");

    // RAII guard ensures the clipboard TTL thread is joined before static
    // destruction begins, preventing potential deadlock when DLLs unload.
    struct ClipboardShutdownGuard
    {
        ~ClipboardShutdownGuard() { seal::Clipboard::shutdown(); }
    } clipGuard;

    switch (opts.mode)
    {
        case Mode::Import:
#ifdef USE_QT_UI
            return handleImportMode(opts.inputPath, opts.outputPath);
#else
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "CLI",
                         {"event=cli.mode.dispatch",
                          "result=fail",
                          "command=import",
                          "reason=qt_ui_unavailable"});
            return 1;
#endif

        case Mode::Export:
#ifdef USE_QT_UI
            return handleExportMode(opts.inputPath, opts.outputPath);
#else
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "CLI",
                         {"event=cli.mode.dispatch",
                          "result=fail",
                          "command=export",
                          "reason=qt_ui_unavailable"});
            return 1;
#endif

        case Mode::Gen:
            return seal::HandleGenMode(opts.genLength);
        case Mode::Shred:
            return seal::HandleShredMode(opts.inputPath);
        case Mode::Hash:
            return seal::HandleHashMode(opts.inputPath);
        case Mode::Verify:
            return seal::HandleVerifyMode(opts.inputPath);
        case Mode::Wipe:
            return seal::HandleWipeMode();
        case Mode::FileEncrypt:
            return seal::HandleFileEncrypt(opts.inputPath, opts.outputPath);
        case Mode::FileDecrypt:
            return seal::HandleFileDecrypt(opts.inputPath, opts.outputPath);
        case Mode::TextEncrypt:
            return seal::HandleStringMode(true, opts.stringData);
        case Mode::TextDecrypt:
            return seal::HandleStringMode(false, opts.stringData);

        case Mode::Gui:
#ifdef USE_QT_UI
            return RunQMLMode(argc, argv);
#else
            writeCliDiag(std::cerr,
                         seal::console::Tone::Error,
                         "CLI",
                         {"event=cli.mode.dispatch",
                          "result=fail",
                          "command=gui",
                          "reason=qt_ui_unavailable"});
            return 1;
#endif

        case Mode::Cli:
            return handleCliMode();
    }
    return 1;
}
