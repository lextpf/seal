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
#include "CliModes.hpp"
#include "Clipboard.hpp"
#include "Console.hpp"
#include "ConsoleStyle.hpp"
#include "CredentialCsv.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "PasswordGen.hpp"
#include "ScopedDpapiUnprotect.hpp"
#include "Utils.hpp"
#include "Version.hpp"

#ifdef USE_QT_UI
#include <QtCore/QString>
#include "Logging.hpp"
#include "Vault.hpp"
#endif

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

// Forward declaration; definition is in QmlMain.cpp.
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
    Wipe,
    Rekey,
    List,
    Get,
    InstallBrowserExtension,
    UninstallBrowserExtension
};

struct ProgramOptions
{
    Mode mode = Mode::Gui;
    bool modeExplicit = false;  // true once any mode flag is parsed
    std::string inputPath;      // primary path or import data
    std::string outputPath;     // secondary / destination path
    std::string stringData;     // inline text for -e/-d
    int genLength = 20;
    std::string getField = "pass";  // get: pass | user | both
    bool getStdout = false;         // get: print to stdout instead of clipboard
    int getTtlSeconds = 6;          // get: clipboard scrub TTL
    std::string ioFormat = "auto";  // import: auto|seal|chrome ; export: seal|csv
    bool force = false;             // export: skip the plaintext confirmation
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
    std::cout
        << "  rekey <vault.seal>        Change the vault master password (atomic re-encrypt)\n";
    std::cout << "  list [vault]              List platform names in a vault\n";
    std::cout << "  get <platform> [vault]    Retrieve one credential (clipboard by default)\n";
    std::cout << "      --user|--pass|--both    Field selection (default: --pass)\n";
    std::cout << "      --stdout                Print raw value instead of clipboard\n";
    std::cout << "      --ttl <seconds>         Clipboard scrub delay (default 6)\n";
    std::cout << "  import <data> [output]    Import credentials into a vault file\n";
    std::cout << "  export <input> [output]   Export vault to plaintext (re-importable format)\n";
    std::cout
        << "  install-browser-extension   Register the browser companion native-messaging host\n";
    std::cout
        << "  uninstall-browser-extension Remove the browser companion native-messaging host\n\n";
    std::cout << "Options:\n";
    std::cout << "  -e, --text-encrypt [text] Encrypt a string, output hex\n";
    std::cout << "  -d, --text-decrypt [hex]  Decrypt a hex string, output plaintext\n";
    std::cout << "  -u, --ui                  Launch graphical user interface\n";
    std::cout << "  -c, --cli                 Launch command-line interactive mode\n";
    std::cout << "  -v, --version             Display version information\n";
    std::cout << "  -h, --help                Display this help message\n";
    std::cout << "  (no args)                 GUI mode (default)\n\n";
    std::cout << "  --format <fmt>            import: auto|seal|chrome   export: seal|csv\n";
    std::cout << "  --force                   export: skip the plaintext confirmation\n\n";
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
    std::cout << "  seal rekey vault.seal                    Rotate the master password\n";
    std::cout << "  seal list vault.seal                     Show stored platforms\n";
    std::cout << "  seal get github --stdout | clip          Pipe a password\n";
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
        else if (arg == "rekey")
        {
            if (!trySetMode(opts, Mode::Rekey))
                return 1;
            if (!parseRequiredPath(argc, argv, i, opts, "rekey", "seal rekey <vault.seal>"))
                return 1;
        }
        else if (arg == "list")
        {
            if (!trySetMode(opts, Mode::List))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.inputPath = argv[++i];
            }
        }
        else if (arg == "get")
        {
            if (!trySetMode(opts, Mode::Get))
                return 1;
            if (i + 1 < argc && !isOptionToken(argv[i + 1]))
            {
                opts.stringData = argv[++i];  // platform query
                if (i + 1 < argc && !isOptionToken(argv[i + 1]))
                {
                    opts.inputPath = argv[++i];  // optional vault path
                }
            }
            else
            {
                writeCliDiag(std::cerr,
                             seal::console::Tone::Error,
                             "ARGS",
                             {"event=cli.args.parse",
                              "result=fail",
                              "command=get",
                              "reason=missing_platform"});
                writeCliDiag(std::cerr,
                             seal::console::Tone::Info,
                             "USAGE",
                             {"syntax=seal_get_platform_[vault]_[--user|--pass|--both]_[--stdout]_["
                              "--ttl_s]"});
                return 1;
            }
        }
        else if (arg == "--user")
        {
            opts.getField = "user";
        }
        else if (arg == "--pass")
        {
            opts.getField = "pass";
        }
        else if (arg == "--both")
        {
            opts.getField = "both";
        }
        else if (arg == "--stdout")
        {
            opts.getStdout = true;
        }
        else if (arg == "--ttl")
        {
            if (i + 1 < argc)
            {
                try
                {
                    opts.getTtlSeconds = std::stoi(argv[++i]);
                }
                catch (...)
                {
                    opts.getTtlSeconds = 6;
                }
            }
        }
        else if (arg == "--format")
        {
            if (i + 1 < argc)
            {
                opts.ioFormat = argv[++i];
            }
        }
        else if (arg == "--force")
        {
            opts.force = true;
        }
        else if (arg == "install-browser-extension" || arg == "--install-browser-extension")
        {
            if (!trySetMode(opts, Mode::InstallBrowserExtension))
                return 1;
        }
        else if (arg == "uninstall-browser-extension" || arg == "--uninstall-browser-extension")
        {
            if (!trySetMode(opts, Mode::UninstallBrowserExtension))
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
    // No post-validation needed: trySetMode() rejects conflicts at parse time.
    return -1;
}

// Apply all process-wide security mitigations in dependency order.
// Returns 0 on success, 1 if a critical mitigation fails.
static int initializeSecurity(bool allowDynamicCode)
{
    // Order: debugger check first (fail fast before secrets load), process
    // mitigations (CFG/DEP/ASLR/dynamic-code), then heap/access hardening,
    // then SeLockMemoryPrivilege - required before any secure_string
    // allocation hits VirtualLock.
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

// Resolve <data> that names a file (or "-" for stdin) into raw content.
// No newline normalization here: the CSV path needs the raw line structure,
// and the legacy triple path normalizes for itself in handleImportMode.
static void readImportSource(std::string& importData)
{
    std::string fileContent;
    const std::string sourcePath = importData;

    if (importData == "-")
    {
        // Read from stdin: pipes + paste (Ctrl+Z to end on Windows).
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

        // Reject >2 colons: ambiguous field boundaries break round-trip
        // through export/import.
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

static int handleImportMode(std::string& importData,
                            const std::string& importOutputPath,
                            const std::string& format)
{
    readImportSource(importData);

    // Format selection: explicit --format wins; auto sniffs the header.
    std::string effectiveFormat = format;
    if (effectiveFormat == "auto")
    {
        const size_t eol = importData.find('\n');
        const std::string firstLine =
            (eol == std::string::npos) ? importData : importData.substr(0, eol);
        effectiveFormat = seal::csv::LooksLikeChromeCsv(firstLine) ? "chrome" : "seal";
    }

    std::vector<std::tuple<std::string, std::string, std::string>> entries;
    if (effectiveFormat == "chrome")
    {
        std::vector<seal::csv::Credential> csvCreds;
        seal::csv::Stats stats;
        if (!seal::csv::ParseChromeCsv(importData, csvCreds, stats))
        {
            writeCliDiag(
                std::cerr,
                seal::console::Tone::Error,
                "IMPORT",
                {"event=import.parse.finish", "result=fail", "format=chrome", "reason=bad_header"});
            return 1;
        }
        writeCliDiag(std::cerr,
                     seal::console::Tone::Step,
                     "IMPORT",
                     {"event=import.parse.finish",
                      "result=ok",
                      "format=chrome",
                      seal::diag::kv("imported", stats.imported),
                      seal::diag::kv("skipped_no_platform", stats.skippedNoPlatform),
                      seal::diag::kv("skipped_no_password", stats.skippedNoPassword),
                      seal::diag::kv("bad_rows", stats.badRows)});
        for (auto& c : csvCreds)
        {
            entries.emplace_back(
                std::move(c.platform), std::move(c.username), std::move(c.password));
        }
        seal::Cryptography::cleanseString(importData);
    }
    else if (effectiveFormat == "seal")
    {
        // Legacy plat:user:pass entries: newlines normalise to commas so
        // entries can be one-per-line or comma-separated.
        std::replace_if(
            importData.begin(),
            importData.end(),
            [](char c) { return c == '\n' || c == '\r'; },
            ',');
        int rc = parseImportEntries(importData, entries);
        if (rc != 0)
            return rc;
    }
    else
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "IMPORT",
                     {"event=import.parse.finish",
                      "result=fail",
                      "reason=unknown_format",
                      seal::diag::kv("format", seal::diag::sanitizeAscii(effectiveFormat))});
        return 1;
    }

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
    // DPAPIGuard keeps the master password CryptProtectMemory-encrypted
    // while idle. ScopedUnprotect decrypts in-place for the loop; reprotect
    // (or destructor) re-encrypts to minimise plaintext lifetime.
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
            // VaultRecord now owns the encrypted data; wipe the plaintext copies.
            seal::Cryptography::cleanseString(secUser, secPass);
        }

        std::string outputPath = importOutputPath;
        if (!seal::utils::endsWithCi(outputPath, ".seal"))
        {
            outputPath += ".seal";
        }

        // Original plaintext entries are now encrypted; wipe them.
        for (auto& [p, u, pw] : entries)
            seal::Cryptography::cleanseString(p, u, pw);

        if (seal::saveVault(std::filesystem::path{outputPath}, records, masterPassword))
        {
            writeCliDiag(std::cerr,
                         seal::console::Tone::Success,
                         "IMPORT",
                         {"event=import.finish",
                          "result=ok",
                          seal::diag::kv("op", opId),
                          seal::diag::kv("record_count", records.size()),
                          seal::diag::pathSummary(outputPath)});
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
                      seal::diag::pathSummary(outputPath)});
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

static int handleExportMode(const std::string& inputPath,
                            const std::string& outputPath,
                            const std::string& format,
                            bool force)
{
    std::string vaultPathStr = inputPath;
    if (!seal::utils::endsWithCi(vaultPathStr, ".seal"))
    {
        vaultPathStr += ".seal";
    }
    const std::filesystem::path vaultPath{vaultPathStr};

    const std::string opId = seal::diag::nextOpId("cli_export");
    writeCliDiag(
        std::cerr,
        seal::console::Tone::Step,
        "EXPORT",
        {"event=export.begin",
         "result=start",
         seal::diag::kv("op", opId),
         seal::diag::kv("format", format),
         seal::diag::pathSummary(vaultPathStr, "src"),
         outputPath.empty() ? "dst_kind=stdout" : seal::diag::pathSummary(outputPath, "dst")});

    if (format != "seal" && format != "csv")
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "EXPORT",
                     {"event=export.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=unknown_format"});
        return 1;
    }
    const bool csvFormat = (format == "csv");

    // Plaintext gate: every export emits secrets in the clear, so an
    // explicit confirmation (or --force for scripts) is required first --
    // before the password prompt, so a refusal costs nothing.
    const char* confirmPrompt = outputPath.empty()
                                    ? "Print ALL credentials in PLAINTEXT to this console?"
                                    : "Export ALL credentials in PLAINTEXT to a file?";
    if (!seal::console::ConfirmDestructive(force, std::cin, std::cerr, confirmPrompt))
    {
        writeCliDiag(std::cerr,
                     seal::console::Tone::Error,
                     "EXPORT",
                     {"event=export.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=not_confirmed"});
        return 1;
    }

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
                      seal::diag::pathSummary(vaultPathStr, "src")});
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

    // Stream credentials one at a time; never accumulate the whole vault
    // in a plaintext heap buffer.
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

    if (csvFormat)
    {
        *out << seal::csv::WriteCsvRow({"name", "url", "username", "password"});
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
            // Export format is platform:username:password (2 colons). If
            // platform or username contains ':', --import cannot round-trip.
            // Warn so the user can fix the data.
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
            // Write + cleanse per record so only one credential ever sits
            // in pageable memory.
            if (csvFormat)
            {
                *out << seal::csv::WriteCsvRow({rec.platform, "", user, pass});
            }
            else
            {
                if (exportedCount > 0)
                    *out << ',';
                *out << rec.platform << ':' << user << ':' << pass;
            }
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
        std::cerr << "Reminder: shred the plaintext once done:  seal shred " << outputPath << "\n";
    }
    return 0;
}

// Process the "seal" input file in cwd (paths/hex tokens, terminated by
// '?' or '!') as a startup batch before the interactive loop.
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

// Re-read "seal" on Esc. Only fires when the file contains real paths
// (not raw hex) - a quick re-encrypt/re-decrypt shortcut on exit.
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

        // CLI startup: 1. run the "seal" file as a startup batch (if present);
        // 2. interactive loop, lines end with '?' (masked) or '!' (uncensored);
        // 3. Esc re-runs "seal" once and exits cleanly.
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

// Entry point. Dispatches by mode: -e/-d stream encrypt/decrypt (stdin->stdout);
// -u / no args Qt GUI mode (default); --cli interactive console; --import/--export
// vault import/export; -h/--help usage.
int main(int argc, char* argv[])
{
    ProgramOptions opts;
    int rc = parseArguments(argc, argv, opts);
    if (rc >= 0)
        return rc;

#ifdef USE_QT_UI
    // Install the structured handler before any security-init log line so
    // early qCInfo(logCrypto) calls share the standard format.
    installSealMessageHandler();
#endif

    // Only GUI mode loads QML (V4 JIT needs RWX). Other modes keep the
    // stricter PROCESS_MITIGATION_DYNAMIC_CODE_POLICY.
    const bool allowDynamicCode = (opts.mode == Mode::Gui);

    rc = initializeSecurity(allowDynamicCode);
    if (rc != 0)
        return rc;

    // Set OpenCV env vars while still single-threaded; captureQrFromWebcam()
    // reads them via getenv on a worker thread, so this avoids racing on the
    // process environment block.
    _putenv_s("OPENCV_VIDEOIO_MSMF_ENABLE_HW_TRANSFORMS", "0");

    // RAII guard joins the clipboard TTL thread before static destruction,
    // avoiding a DLL-unload deadlock.
    struct ClipboardShutdownGuard
    {
        ~ClipboardShutdownGuard() { seal::Clipboard::shutdown(); }
    } clipGuard;

    switch (opts.mode)
    {
        case Mode::Import:
            return handleImportMode(opts.inputPath, opts.outputPath, opts.ioFormat);

        case Mode::Export:
            return handleExportMode(opts.inputPath,
                                    opts.outputPath,
                                    opts.ioFormat == "auto" ? "seal" : opts.ioFormat,
                                    opts.force);

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
        case Mode::Rekey:
            return seal::HandleRekeyMode(opts.inputPath);
        case Mode::List:
            return seal::HandleListMode(opts.inputPath);
        case Mode::Get:
            return seal::HandleGetMode(
                opts.stringData, opts.inputPath, opts.getField, opts.getStdout, opts.getTtlSeconds);
        case Mode::InstallBrowserExtension:
            return seal::HandleInstallBrowserExtensionMode();
        case Mode::UninstallBrowserExtension:
            return seal::HandleUninstallBrowserExtensionMode();
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
