/*  ============================================================================================  *
 *                                                            ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
 *                                                            ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
 *           ::::::::      :::      ::::::::  ::::::::::      ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
 *          :+:    :+:   :+: :+:   :+:    :+: :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
 *          +:+         +:+   +:+  +:+        +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
 *          +#++:++#++ +#++:++#++: :#:        +#++:++#        ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
 *                 +#+ +#+     +#+ +#+   +#+# +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇
 *          #+#    #+# #+#     #+# #+#    #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
 *           ########  ###     ###  ########  ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
 *                                                            ⠀⠀⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 *
 *                                  << P A S S   M A N A G E R >>
 *
 *  ============================================================================================  *
 *
 *      A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *      providing on-demand credential management, directory encryption,
 *      webcam OCR authentication, and global auto-fill.
 *
 *    ----------------------------------------------------------------------
 *
 *      Repository:   https://github.com/lextpf/sage
 *      License:      MIT
 */
#include "Cryptography.h"
#include "Utils.h"
#include "Clipboard.h"
#include "Console.h"
#include "FileOperations.h"

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

struct ProgramOptions {
    bool streamMode = false;
    bool encryptMode = false;
    bool decryptMode = false;
    bool uiMode = false;
    bool cliMode = false;
    bool importMode = false;
    std::string importData;
    std::string importOutputPath;
};

static void printHelp()
{
    std::cout << "sage - AES-256-GCM Encryption Utility\n\n";
    std::cout << "Usage:\n";
    std::cout << "  sage [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -e, --encrypt    Stream encryption mode (stdin -> stdout)\n";
    std::cout << "  -d, --decrypt    Stream decryption mode (stdin -> stdout)\n";
    std::cout << "  -u, --ui         Launch graphical user interface\n";
    std::cout << "  --cli            Launch command-line interactive mode\n";
    std::cout << "  --import DATA OUTPUT  Import credentials into a vault file\n";
    std::cout << "  -h, --help       Display this help message\n";
    std::cout << "  (no args)        GUI mode (default)\n\n";
    std::cout << "Import format:\n";
    std::cout << "  DATA is comma-separated entries: plat:user:pass, plat:user:pass, ...\n";
    std::cout << "  DATA can also be a path to a text file containing entries\n";
    std::cout << "  (one per line or comma-separated, spaces around commas are OK)\n";
    std::cout << "  OUTPUT is the vault file path (e.g. myvault.sage)\n\n";
    std::cout << "Examples:\n";
    std::cout << "  sage -e < input.txt > output.sage\n";
    std::cout << "  sage -d < output.sage > decrypted.txt\n";
    std::cout << "  echo \"Hello\" | sage -e | sage -d\n";
    std::cout << "  sage        (Launch GUI mode - default)\n";
    std::cout << "  sage --ui   (Launch GUI mode)\n";
    std::cout << "  sage --cli  (Launch CLI interactive mode)\n";
    std::cout << "  sage --import \"github:alice:pw123, aws:bob:secret\" myvault.sage\n";
    std::cout << "  sage --import entries.txt myvault.sage\n";
}

// Returns: -1 = parsed OK (continue), 0 = help shown (exit 0), 1 = error (exit 1)
static int parseArguments(int argc, char* argv[], ProgramOptions& opts)
{
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "-e" || arg == "--encrypt") {
            opts.streamMode = true;
            opts.encryptMode = true;
        }
        else if (arg == "-d" || arg == "--decrypt") {
            opts.streamMode = true;
            opts.decryptMode = true;
        }
        else if (arg == "-u" || arg == "--ui") {
            opts.uiMode = true;
        }
        else if (arg == "--cli") {
            opts.cliMode = true;
        }
        else if (arg == "--import") {
            opts.importMode = true;
            if (i + 2 < argc) {
                opts.importData = argv[++i];
                opts.importOutputPath = argv[++i];
            } else {
                std::cerr << "Error: --import requires two arguments\n";
                std::cerr << "Usage: sage --import \"plat:user:pass,...\" output.sage\n";
                return 1;
            }
        }
        else if (arg == "-h" || arg == "--help") {
            printHelp();
            return 0;
        }
        else {
            std::cerr << "Unknown option: " << arg << "\n";
            std::cerr << "Use -h or --help for usage information.\n";
            return 1;
        }
    }

    if (opts.uiMode && opts.cliMode) {
        std::cerr << "Error: Cannot specify both --ui and --cli\n";
        return 1;
    }
    return -1;
}

static int initializeSecurity(bool allowDynamicCode)
{
    sage::Cryptography::detectDebugger();

    if (!sage::Cryptography::setSecureProcessMitigations(allowDynamicCode)) return -1;
    if (sage::Cryptography::isRemoteSession()) return -1;

    sage::Cryptography::hardenHeap();
    sage::Cryptography::hardenProcessAccess();
    sage::Cryptography::disableCrashDumps();
    if (!sage::Cryptography::tryEnableLockPrivilege()) {
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
static sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>
utf8ToSecureWide(const std::string& utf8)
{
    sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>> result;
    if (utf8.empty()) return result;
    int need = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), nullptr, 0);
    if (need > 0) {
        result.s.resize(need);
        MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), (int)utf8.size(), result.s.data(), need);
    }
    return result;
}

static std::string importTrim(const std::string& s)
{
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

static void loadImportDataFromFile(std::string& importData)
{
    std::ifstream testFile(importData);
    if (!testFile.good()) return;

    std::string fileContent((std::istreambuf_iterator<char>(testFile)),
                             std::istreambuf_iterator<char>());
    testFile.close();
    // Replace newlines with commas so entries can be one-per-line or comma-separated
    std::replace_if(fileContent.begin(), fileContent.end(),
        [](char c) { return c == '\n' || c == '\r'; }, ',');
    importData = fileContent;
    std::cout << "Reading entries from file...\n";
}

static int parseImportEntries(const std::string& importData,
                              std::vector<std::tuple<std::string, std::string, std::string>>& entries)
{
    std::string remaining = importData;
    while (!remaining.empty())
    {
        size_t commaPos = remaining.find(',');
        std::string token = (commaPos != std::string::npos)
            ? remaining.substr(0, commaPos) : remaining;
        remaining = (commaPos != std::string::npos)
            ? remaining.substr(commaPos + 1) : "";

        token = importTrim(token);
        if (token.empty()) continue;

        size_t firstColon = token.find(':');
        if (firstColon == std::string::npos) {
            std::cerr << "Error: Invalid entry (missing colon): " << token << "\n";
            std::cerr << "Expected format: platform:username:password\n";
            return 1;
        }
        size_t secondColon = token.find(':', firstColon + 1);
        if (secondColon == std::string::npos) {
            std::cerr << "Error: Invalid entry (missing second colon): " << token << "\n";
            std::cerr << "Expected format: platform:username:password\n";
            return 1;
        }

        std::string platform = importTrim(token.substr(0, firstColon));
        std::string user     = importTrim(token.substr(firstColon + 1, secondColon - firstColon - 1));
        std::string pass     = token.substr(secondColon + 1);

        if (platform.empty() || user.empty() || pass.empty()) {
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
    if (rc != 0) return rc;

    if (entries.empty()) {
        std::cerr << "Error: No valid entries found in import data\n";
        return 1;
    }

    std::cout << "Importing " << entries.size() << " credential(s)...\n";

    sage::basic_secure_string<wchar_t> masterPassword;
    try {
        masterPassword = sage::readPasswordSecureDesktop();
    } catch (...) {
        std::cerr << "Error: Failed to read master password\n";
        return 1;
    }
    sage::DPAPIGuard<sage::basic_secure_string<wchar_t>> importDpapi(&masterPassword);

    importDpapi.unprotect();
    std::vector<sage::VaultRecord> records;
    records.reserve(entries.size());
    for (const auto& [platform, user, pass] : entries) {
        auto secUser = utf8ToSecureWide(user);
        auto secPass = utf8ToSecureWide(pass);
        records.push_back(sage::encryptCredential(platform, secUser, secPass, masterPassword));
        sage::Cryptography::cleanseString(secUser, secPass);
    }

    QString outputPath = QString::fromUtf8(importOutputPath.c_str());
    if (!outputPath.endsWith(".sage", Qt::CaseInsensitive))
        outputPath += ".sage";

    if (sage::saveVaultV2(outputPath, records, masterPassword)) {
        std::cout << "Successfully saved " << records.size()
                  << " credential(s) to " << outputPath.toStdString() << "\n";
        sage::Cryptography::cleanseString(masterPassword);
        return 0;
    }
    std::cerr << "Error: Failed to save vault file\n";
    sage::Cryptography::cleanseString(masterPassword);
    return 1;
}
#endif // USE_QT_UI

static int handleStreamMode(bool encryptMode, bool decryptMode,
                             sage::basic_secure_string<wchar_t>& password,
                             sage::DPAPIGuard<sage::basic_secure_string<wchar_t>>& dpapi)
{
    dpapi.unprotect();
    bool success = false;
    if (encryptMode)
        success = sage::FileOperations::streamEncrypt(password);
    else if (decryptMode)
        success = sage::FileOperations::streamDecrypt(password);
    sage::Cryptography::cleanseString(password);
    return success ? 0 : 1;
}

static void processSageFileBatch(sage::DPAPIGuard<sage::basic_secure_string<wchar_t>>& dpapi,
                                 sage::basic_secure_string<wchar_t>& password)
{
    std::ifstream fin("sage");
    if (!fin) return;

    auto fileBatch = sage::readBulkLinesDualFrom(fin);
    const auto& flines = fileBatch.first;
    if (flines.empty()) return;

    dpapi.unprotect();
    sage::FileOperations::processBatch(flines, fileBatch.second, password);
    dpapi.reprotect();
    std::cout << "\n";
}

static bool handleEscSageFile(sage::DPAPIGuard<sage::basic_secure_string<wchar_t>>& dpapi,
                               sage::basic_secure_string<wchar_t>& password)
{
    std::ifstream fin("sage");
    if (!fin) return false;

    auto fileBatch = sage::readBulkLinesDualFrom(fin);
    const auto& flines = fileBatch.first;
    if (flines.empty()) return false;

    bool hasFiles = false;
    for (const auto& line : flines)
    {
        if (_stricmp(line.c_str(), ".") == 0 ||
            sage::utils::isDirectoryA(line.c_str()) ||
            sage::utils::fileExistsA(line.c_str()))
        {
            hasFiles = true;
            break;
        }
    }
    if (hasFiles)
    {
        dpapi.unprotect();
        sage::FileOperations::processBatch(flines, fileBatch.second, password);
        dpapi.reprotect();
    }
    return true;
}

static int handleCliMode(bool streamMode, bool encryptMode, bool decryptMode)
{
    if (encryptMode && decryptMode) {
        std::cerr << "Error: Cannot specify both -e and -d\n";
        return 1;
    }

    try {
        sage::basic_secure_string<wchar_t> password = sage::readPasswordSecureDesktop();
        sage::DPAPIGuard<sage::basic_secure_string<wchar_t>> dpapi(&password);

        if (streamMode)
            return handleStreamMode(encryptMode, decryptMode, password, dpapi);

        processSageFileBatch(dpapi, password);

        std::cout << "+----------------------------------------- sage - Interactive Mode -----------------------------------------+\n";
        std::cout << "|              Paste/type and finish with '?' (MASKED) or '!' (UNCENSORED) Press Esc to exit.               |\n";
        std::cout << "|    Commands '.'= current dir | ':clip'= copy sage | ':open'= edit sage | ':none'= clear clipboard         |\n";
        std::cout << "+-----------------------------------------------------------------------------------------------------------+\n";

        for (;;) {
            std::pair<std::vector<std::string>, bool> batch;
            if (!sage::readBulkLinesDualOrEsc(batch)) {
                (void)handleEscSageFile(dpapi, password);
                return 0;
            }
            if (batch.first.empty()) break;

            dpapi.unprotect();
            sage::FileOperations::processBatch(batch.first, batch.second, password);
            dpapi.reprotect();
        }
        sage::Cryptography::cleanseString(password);
        sage::wipeConsoleBuffer();
    }
    catch (const std::exception& e) {
        if (streamMode) {
            std::cerr << "Error: " << e.what() << "\n";
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Program entry point for sage.
 *
 * @details
 * Main execution flow:
 *
 * **Command-line Arguments:**
 * - `-e` or `--encrypt`: Stream encryption mode (stdin -> stdout)
 * - `-d` or `--decrypt`: Stream decryption mode (stdin -> stdout)
 * - `-u` or `--ui`: Launch graphical user interface (default if no mode specified)
 * - `--cli`: Launch command-line interactive mode
 * - `-h` or `--help`: Display usage information
 * - No arguments: GUI mode (default)
 *
 * @see FileOperations::processBatch
 * @see FileOperations::streamEncrypt
 * @see FileOperations::streamDecrypt
 * @see readPasswordSecureDesktop
 * @see Cryptography::setSecureProcessMitigations
 * @see Cryptography::tryEnableLockPrivilege
 */
int main(int argc, char* argv[]) {
    ProgramOptions opts;
    int rc = parseArguments(argc, argv, opts);
    if (rc >= 0) return rc;

    const bool useUIMode = opts.uiMode || (!opts.cliMode && !opts.streamMode);
    const bool allowDynamicCode = useUIMode && !opts.importMode;

    rc = initializeSecurity(allowDynamicCode);
    if (rc != 0) return rc;

    if (opts.importMode) {
#ifdef USE_QT_UI
        return handleImportMode(opts.importData, opts.importOutputPath);
#else
        std::cerr << "Error: --import requires Qt UI support (USE_QT_UI).\n";
        std::cerr << "Please rebuild with USE_QT_UI enabled.\n";
        return 1;
#endif
    }

    if (useUIMode) {
#ifdef USE_QT_UI
        return RunQMLMode(argc, argv);
#else
        std::cerr << "Error: GUI mode requested but Qt UI support is not compiled in.\n";
        std::cerr << "Please rebuild with USE_QT_UI enabled or use --cli for CLI mode.\n";
        return 1;
#endif
    }

    return handleCliMode(opts.streamMode, opts.encryptMode, opts.decryptMode);
}
