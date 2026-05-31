#include "CliModes.hpp"

#include "Clipboard.hpp"
#include "Console.hpp"
#include "ConsoleStyle.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "PasswordGen.hpp"
#include "ScopedDpapiUnprotect.hpp"
#include "Utils.hpp"

#include <windows.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

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

        // verifyPacket streams 64 KB chunks; peak memory ~n (blob) instead
        // of ~2n (blob + plaintext).
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

        // Encrypt to destination (default: input + ".seal"); source is
        // deleted only after the destination is fully written.
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

        // Decrypt to destination (default: strip ".seal"); source is
        // deleted only after the destination is fully written.
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

// Text <-> hex/base64. Reads inline arg or stdin; prompt is on stderr so
// piping works.
int HandleStringMode(bool encryptMode, const std::string& inlineData)
{
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);
        ScopedUnprotect<decltype(dpapi)> dpapiScope(dpapi);

        std::string input = inlineData;
        if (input.empty())
        {
            input.assign(std::istreambuf_iterator<char>(std::cin),
                         std::istreambuf_iterator<char>());
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
            // Auto-detect: hex first (stricter -- even length + xdigit only),
            // then Base64. Hex chars are a Base64 subset, so this order
            // makes the more specific test win.
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

// ---------------------------------------------------------------------------
// Browser extension install / uninstall helpers
// ---------------------------------------------------------------------------

namespace
{

constexpr std::wstring_view kHostName = L"com.seal.fill";
constexpr std::string_view kHostNameAscii = "com.seal.fill";

// Deterministic Chrome extension ID derived from the RSA "key" field in
// extensions/seal-browser/manifest.json: first 16 bytes of SHA-256(SPKI
// DER), each nibble 0..15 -> a..p. Hardcoded so the install handler can
// pre-fill allowed_origins without manual JSON editing. **MUST** be
// updated if the manifest's "key" is ever regenerated.
constexpr std::string_view kSealExtensionIdAscii = "dfjclelhkideboildnjihgildihjjmdo";

// Browser registry roots under HKCU.
struct BrowserTarget
{
    std::wstring_view m_DisplayName;
    std::wstring_view m_SubKey;
    std::wstring_view m_AppPathsExe;    ///< Executable name registered under App Paths.
    std::wstring_view m_ExtensionsUrl;  ///< URL to open after install for sideloading.
};

// Chrome + Brave. Both are Chromium, so they share the same extension (same
// RSA "key" -> same extension ID -> same chrome-extension:// origin) and the
// same Chromium manifest (com.seal.fill.json); only the per-browser registry
// root differs. Edge/Opera/Vivaldi would slot in the same way. Firefox is a
// different engine (separate manifest schema + Mozilla registry root) and is
// intentionally not included here.
constexpr std::array<BrowserTarget, 2> kBrowserTargets{{
    {L"Chrome",
     L"Software\\Google\\Chrome\\NativeMessagingHosts\\com.seal.fill",
     L"chrome.exe",
     L"chrome://extensions/"},
    {L"Brave",
     L"Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\com.seal.fill",
     L"brave.exe",
     L"brave://extensions/"},
}};

// Resolve a browser via App Paths (HKCU then HKLM); empty if uninstalled.
std::wstring resolveAppPath(std::wstring_view exeName)
{
    const std::wstring keyPath =
        std::wstring(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\") +
        std::wstring(exeName);

    for (HKEY hive : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE})
    {
        std::array<wchar_t, MAX_PATH> buf{};
        DWORD bufBytes = static_cast<DWORD>(buf.size() * sizeof(wchar_t));
        const LONG status = RegGetValueW(
            hive, keyPath.c_str(), nullptr, RRF_RT_REG_SZ, nullptr, buf.data(), &bufBytes);
        if (status == ERROR_SUCCESS && buf[0] != L'\0')
        {
            return std::wstring(buf.data());
        }
    }
    return {};
}

// Launch a browser at a URL via CreateProcessW + `--new-window`.
//
// Why not `chrome.exe URL`: an already-running Chrome forwards bare URL
// args via Mojo IPC; recent Chrome (>=100) filters those as a defence
// against shortcut-hijacking (e.g. chrome://settings/passwords), so the
// arg silently becomes a new-tab-page. `--new-window <URL>` runs through
// a different code path that treats the URL as the initial document of a
// freshly-created window and bypasses that filter.
//
// CreateProcessW (not ShellExecuteW) so command-line quoting is explicit
// -- ShellExecuteW has been inconsistent across Windows versions for
// args containing `://`.
bool launchBrowserAt(const std::wstring& exePath, std::wstring_view url)
{
    std::wstring cmdLine;
    cmdLine.reserve(exePath.size() + url.size() + 32);
    cmdLine.push_back(L'"');
    cmdLine.append(exePath);
    cmdLine.append(L"\" --new-window \"");
    cmdLine.append(url);
    cmdLine.push_back(L'"');

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessW(
        nullptr, cmdLine.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi);
    if (ok == 0)
    {
        return false;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// Best-effort UTF-16 -> clipboard. Silent failure when locked elsewhere.
bool copyTextToClipboard(const std::wstring& text)
{
    if (!OpenClipboard(nullptr))
    {
        return false;
    }
    bool ok = false;
    if (EmptyClipboard() != 0)
    {
        const size_t bytes = (text.size() + 1) * sizeof(wchar_t);
        HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, bytes);
        if (handle != nullptr)
        {
            auto* dest = static_cast<wchar_t*>(GlobalLock(handle));
            if (dest != nullptr)
            {
                std::memcpy(dest, text.c_str(), bytes);
                GlobalUnlock(handle);
                if (SetClipboardData(CF_UNICODETEXT, handle) != nullptr)
                {
                    // Clipboard now owns the handle.
                    ok = true;
                }
                else
                {
                    GlobalFree(handle);
                }
            }
            else
            {
                GlobalFree(handle);
            }
        }
    }
    CloseClipboard();
    return ok;
}

// Absolute dir containing seal.exe (no trailing separator).
std::filesystem::path executableDirectory()
{
    std::wstring buffer(MAX_PATH, L'\0');
    for (;;)
    {
        DWORD got = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (got == 0)
        {
            return {};
        }
        if (got < buffer.size())
        {
            buffer.resize(got);
            break;
        }
        buffer.resize(buffer.size() * 2);
    }
    std::filesystem::path exePath(buffer);
    return exePath.parent_path();
}

// JSON escape: backslash, double-quote, common controls. Manifest paths
// never have other controls, so this covers them.
std::string escapeJson(std::string_view text)
{
    std::string out;
    out.reserve(text.size() + 8);
    for (char c : text)
    {
        switch (c)
        {
            case '\\':
                out += "\\\\";
                break;
            case '"':
                out += "\\\"";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += c;
                break;
        }
    }
    return out;
}

// UTF-16 -> UTF-8 with WideCharToMultiByte. Returns empty on failure.
std::string toUtf8(const std::wstring& wide)
{
    if (wide.empty())
    {
        return {};
    }
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
    {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8,
                        0,
                        wide.data(),
                        static_cast<int>(wide.size()),
                        out.data(),
                        needed,
                        nullptr,
                        nullptr);
    return out;
}

// Write the Chromium-flavoured native-messaging manifest. Returns true on success.
bool writeChromeManifest(const std::filesystem::path& manifestPath,
                         const std::filesystem::path& hostExePath)
{
    const std::string hostPathUtf8 = toUtf8(hostExePath.wstring());
    if (hostPathUtf8.empty())
    {
        return false;
    }

    std::ostringstream json;
    json << "{\n";
    json << "  \"name\": \"" << kHostNameAscii << "\",\n";
    json << "  \"description\": \"seal credential manager bridge\",\n";
    json << "  \"path\": \"" << escapeJson(hostPathUtf8) << "\",\n";
    json << "  \"type\": \"stdio\",\n";
    // Pre-fill allowed_origins with the deterministic sideload ID, so no
    // post-install JSON editing is needed.
    json << "  \"allowed_origins\": [\n";
    json << "    \"chrome-extension://" << kSealExtensionIdAscii << "/\"\n";
    json << "  ]\n";
    json << "}\n";

    std::ofstream out(manifestPath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        return false;
    }
    const std::string text = json.str();
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
    return static_cast<bool>(out);
}

// Firefox manifest writer removed with scope reduction; restore from git
// history when multi-browser support returns.

// Write the (default) value of HKCU\<subKey> to point at the manifest file.
bool writeRegistryString(std::wstring_view subKey, const std::wstring& valueData)
{
    const std::wstring subKeyOwned(subKey);
    const DWORD valueByteSize = static_cast<DWORD>((valueData.size() + 1) * sizeof(wchar_t));
    const LSTATUS status = RegSetKeyValueW(HKEY_CURRENT_USER,
                                           subKeyOwned.c_str(),
                                           nullptr,  // default value
                                           REG_SZ,
                                           valueData.c_str(),
                                           valueByteSize);
    return status == ERROR_SUCCESS;
}

// Delete HKCU\<subKey>'s default value. true if removed or absent.
bool deleteRegistryValue(std::wstring_view subKey)
{
    const std::wstring subKeyOwned(subKey);
    const LSTATUS status = RegDeleteKeyValueW(HKEY_CURRENT_USER,
                                              subKeyOwned.c_str(),
                                              nullptr  // default value
    );
    if (status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND)
    {
        return true;
    }
    return false;
}

}  // namespace

int installBrowserExtensionInternal(std::string* outMessage)
{
    const std::filesystem::path exeDir = executableDirectory();
    if (exeDir.empty())
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.install-extension.finish",
                      "result=fail",
                      "reason=module_path_unavailable"});
        if (outMessage != nullptr)
        {
            *outMessage = "Failed to determine seal.exe location.";
        }
        return 1;
    }

    const std::filesystem::path hostExe = exeDir / "seal-browser.exe";
    if (!std::filesystem::exists(hostExe))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.install-extension.finish",
                      "result=fail",
                      "reason=host_exe_missing",
                      seal::diag::pathSummary(hostExe.string(), "host")});
        if (outMessage != nullptr)
        {
            *outMessage = "seal-browser.exe not found beside seal.exe.";
        }
        return 1;
    }

    // Manifest next to seal.exe -- install layout is self-contained;
    // registry entries use absolute paths.
    const std::filesystem::path chromeManifest = exeDir / "com.seal.fill.json";

    if (!writeChromeManifest(chromeManifest, hostExe))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.install-extension.finish",
                      "result=fail",
                      "reason=manifest_write_failed",
                      seal::diag::pathSummary(chromeManifest.string(), "manifest")});
        if (outMessage != nullptr)
        {
            *outMessage = "Failed to write Chromium manifest file.";
        }
        return 1;
    }

    int installedCount = 0;
    std::vector<std::wstring> skipped;
    for (const auto& target : kBrowserTargets)
    {
        const std::wstring manifestPath = chromeManifest.wstring();

        if (writeRegistryString(target.m_SubKey, manifestPath))
        {
            ++installedCount;
        }
        else
        {
            skipped.emplace_back(target.m_DisplayName);
        }
    }

    // Extension folder for sideloading. Prefer sibling extensions/ (CMake
    // install layout); fall back to the repo layout (two levels up from
    // build/bin/Release) when running from a dev tree.
    std::filesystem::path extensionsDir = exeDir / "extensions" / "seal-browser";
    if (!std::filesystem::exists(extensionsDir))
    {
        // Walk up from exeDir to find extensions/ at the repo root (dev
        // tree puts seal.exe under build/bin/Release/).
        std::filesystem::path probe = exeDir;
        for (int depth = 0; depth < 6 && probe.has_parent_path(); ++depth)
        {
            const std::filesystem::path candidate = probe / "extensions" / "seal-browser";
            if (std::filesystem::exists(candidate))
            {
                extensionsDir = candidate;
                break;
            }
            probe = probe.parent_path();
        }
    }

    std::cout << "Native-messaging host registered for " << installedCount << " browser(s).\n";
    std::cout << "Manifest: " << chromeManifest.string() << "\n";

    // Sideload UX: launch each installed browser at its extensions page
    // and copy the extension folder path to the clipboard for paste into
    // "Load unpacked". Failures are non-fatal -- user can use the printed
    // paths manually.
    std::vector<std::wstring> launched;
    if (std::filesystem::exists(extensionsDir))
    {
        for (const auto& target : kBrowserTargets)
        {
            const std::wstring exePath = resolveAppPath(target.m_AppPathsExe);
            if (exePath.empty())
            {
                continue;
            }
            if (launchBrowserAt(exePath, target.m_ExtensionsUrl))
            {
                launched.emplace_back(std::wstring(target.m_DisplayName));
            }
        }
    }

    const bool clipboardOk =
        std::filesystem::exists(extensionsDir) && copyTextToClipboard(extensionsDir.wstring());

    if (std::filesystem::exists(extensionsDir))
    {
        std::cout << "\nExtension folder:\n  " << extensionsDir.string() << "\n";
        if (clipboardOk)
        {
            std::cout << "  (copied to clipboard -- paste with Ctrl+V in the file picker)\n";
        }
        if (!launched.empty())
        {
            std::cout << "\nLaunched browser extensions pages:\n";
            for (const auto& name : launched)
            {
                std::cout << "  - " << toUtf8(name) << "\n";
            }
        }
        std::cout << "\nFinish the sideload (Chrome or Brave):\n"
                     "  1) Toggle 'Developer mode' (top-right of chrome://extensions/\n"
                     "     or brave://extensions/).\n"
                     "  2) Click 'Load unpacked' and paste the path above.\n"
                     "\nThe extension ID is pre-registered in the manifest, so no further\n"
                     "configuration is required after the unpacked load.\n";
    }
    else
    {
        std::cout << "\nExtension folder not found. Place the extension under:\n  "
                  << (exeDir / "extensions" / "seal-browser").string() << "\n";
    }

    writeCliDiag(seal::console::Tone::Success,
                 {"event=cli.install-extension.finish",
                  "result=ok",
                  seal::diag::kv("browsers", installedCount)});

    if (outMessage != nullptr)
    {
        std::ostringstream msg;
        msg << "Registered native-messaging host for " << installedCount << " browser(s).";
        *outMessage = msg.str();
    }
    return 0;
}

int uninstallBrowserExtensionInternal(std::string* outMessage)
{
    int removed = 0;
    int missed = 0;
    for (const auto& target : kBrowserTargets)
    {
        if (deleteRegistryValue(target.m_SubKey))
        {
            ++removed;
        }
        else
        {
            ++missed;
        }
    }

    // Leave manifest JSONs in place so a follow-up --install only needs
    // to re-write the registry entries.
    writeCliDiag(seal::console::Tone::Success,
                 {"event=cli.uninstall-extension.finish",
                  "result=ok",
                  seal::diag::kv("removed", removed),
                  seal::diag::kv("missed", missed)});

    std::cout << "Native-messaging host registry entries cleared (" << removed << " removed).\n";
    if (outMessage != nullptr)
    {
        std::ostringstream msg;
        msg << "Cleared " << removed << " native-messaging host entries.";
        *outMessage = msg.str();
    }
    return 0;
}

int HandleInstallBrowserExtensionMode()
{
    return installBrowserExtensionInternal(nullptr);
}

int HandleUninstallBrowserExtensionMode()
{
    return uninstallBrowserExtensionInternal(nullptr);
}

}  // namespace seal
