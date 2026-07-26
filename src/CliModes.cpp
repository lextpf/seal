#include "CliModes.hpp"

#include "Clipboard.hpp"
#include "Console.hpp"
#include "ConsoleStyle.hpp"
#include "CryptoConfig.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "PasswordGen.hpp"
#include "ScopedDpapiUnprotect.hpp"
#include "SignerUtils.hpp"
#include "Utils.hpp"
#include "Vault.hpp"

#include <windows.h>

#include <algorithm>
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

// Resolve an explicit-or-default vault path; empty result means not found.
std::filesystem::path resolveVaultPath(const std::string& vaultPathArg)
{
    if (!vaultPathArg.empty())
    {
        std::string p = vaultPathArg;
        if (!seal::utils::endsWithCi(p, ".seal"))
        {
            p += ".seal";
        }
        return std::filesystem::path{p};
    }
    return seal::findDefaultVault();
}

// Shared body for HandleFileEncrypt/HandleFileDecrypt: existence check, password
// prompt, begin/finish diagnostics, the crypto op, source deletion on success,
// and cleanse on every non-throw path. `op` is encryptFileTo/decryptFileTo;
// `computeDest` derives the output path; `eventBase` is e.g. "cli.file_encrypt";
// `opScope` seeds nextOpId; `failReason` is the op-failure reason token.
int handleFileCrypt(const std::string& inputPath,
                    const std::string& outputPath,
                    const char* opScope,
                    const char* eventBase,
                    const char* failReason,
                    bool (*op)(const std::string&,
                               const std::string&,
                               const seal::basic_secure_string<wchar_t>&),
                    std::string (*computeDest)(const std::string&, const std::string&))
{
    const std::string finishEvent = std::string("event=") + eventBase + ".finish";
    if (!seal::utils::fileExistsA(inputPath))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {finishEvent,
                      "result=fail",
                      "reason=file_not_found",
                      seal::diag::pathSummary(inputPath)});
        return 1;
    }

    const std::string opId = seal::diag::nextOpId(opScope);
    const auto started = std::chrono::steady_clock::now();
    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> dpapi(&password);
        ScopedUnprotect<decltype(dpapi)> dpapiScope(dpapi);

        const std::string dest = computeDest(inputPath, outputPath);

        writeCliDiag(seal::console::Tone::Step,
                     {std::string("event=") + eventBase + ".begin",
                      "result=start",
                      seal::diag::kv("op", opId),
                      seal::diag::pathSummary(inputPath)});

        bool ok = op(inputPath, dest, password);
        if (!ok)
        {
            writeCliDiag(seal::console::Tone::Error,
                         {finishEvent,
                          "result=fail",
                          seal::diag::kv("op", opId),
                          failReason,
                          seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                          seal::diag::pathSummary(inputPath)});
            seal::Cryptography::cleanseString(password);
            return 1;
        }

        DeleteFileA(inputPath.c_str());
        writeCliDiag(seal::console::Tone::Success,
                     {finishEvent,
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
                     {finishEvent,
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::errorFields(e.what()),
                      seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                      seal::diag::pathSummary(inputPath)});
        return 1;
    }
}

// Load a vault index, unprotecting `guard` only for the load (re-protected on
// return). Shared by the CLI read commands; the caller owns password + guard so
// the password can be reused after the index is loaded.
std::vector<seal::VaultRecord> loadIndexUnprotected(
    seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>& guard,
    const seal::basic_secure_string<wchar_t>& password,
    const std::filesystem::path& vaultPath)
{
    ScopedUnprotect dpapiScope(guard);
    return seal::loadVaultIndex(vaultPath, password);
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
                      seal::diag::errorFields(e.what()),
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
    return handleFileCrypt(
        inputPath,
        outputPath,
        "cli_file_encrypt",
        "cli.file_encrypt",
        "reason=encrypt_failed",
        &seal::FileOperations::encryptFileTo<seal::basic_secure_string<wchar_t>>,
        [](const std::string& in, const std::string& out) -> std::string
        { return out.empty() ? seal::utils::add_ext(in, std::string_view{".seal"}) : out; });
}

int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath)
{
    return handleFileCrypt(inputPath,
                           outputPath,
                           "cli_file_decrypt",
                           "cli.file_decrypt",
                           "reason=decrypt_failed",
                           &seal::FileOperations::decryptFileTo<seal::basic_secure_string<wchar_t>>,
                           [](const std::string& in, const std::string& out) -> std::string
                           {
                               // Default: strip ".seal"; else append ".decrypted".
                               std::string dest = out;
                               if (dest.empty())
                               {
                                   if (seal::utils::endsWithCi(in, ".seal"))
                                       dest =
                                           seal::utils::strip_ext_ci(in, std::string_view{".seal"});
                                   else
                                       dest = in + ".decrypted";
                               }
                               return dest;
                           });
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
            // Auto-detect: hex first (stricter even length + xdigit only),
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
                     {"event=cli.text.finish", "result=fail", seal::diag::errorFields(e.what())});
        return 1;
    }
}

namespace
{

constexpr std::string_view kHostNameAscii = "com.seal.fill";

// Deterministic Chrome extension ID from the RSA "key" in
// extensions/browser/manifest.json: first 16 bytes of SHA-256(SPKI DER),
// each nibble 0..15 -> a..p. Hardcoded so allowed_origins needs no manual JSON
// edit. Regenerating the manifest "key" invalidates this constant: update it
// here and in the host's argv[1] origin gate together.
constexpr std::string_view kSealExtensionIdAscii = "dfjclelhkideboildnjihgildihjjmdo";

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

std::filesystem::path environmentDirectory(const wchar_t* variable)
{
    const DWORD needed = GetEnvironmentVariableW(variable, nullptr, 0);
    if (needed == 0)
    {
        return {};
    }
    std::wstring value(needed, L'\0');
    const DWORD written = GetEnvironmentVariableW(variable, value.data(), needed);
    if (written == 0 || written >= needed)
    {
        return {};
    }
    value.resize(written);
    return std::filesystem::path(value);
}

bool registryKeyExists(HKEY root, const std::wstring& subKey)
{
    for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY})
    {
        HKEY key = nullptr;
        const LSTATUS status = RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ | view, &key);
        if (status == ERROR_SUCCESS)
        {
            RegCloseKey(key);
            return true;
        }
    }
    return false;
}

bool appPathExists(std::wstring_view imageName)
{
    const std::wstring subKey =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + std::wstring(imageName);
    return registryKeyExists(HKEY_CURRENT_USER, subKey) ||
           registryKeyExists(HKEY_LOCAL_MACHINE, subKey);
}

bool pathExists(const std::filesystem::path& path)
{
    std::error_code error;
    return !path.empty() && std::filesystem::exists(path, error) && !error;
}

std::vector<std::filesystem::path> standardBrowserPaths(seal::signer::BrowserKind kind)
{
    const std::filesystem::path local = environmentDirectory(L"LOCALAPPDATA");
    const std::filesystem::path programFiles = environmentDirectory(L"ProgramFiles");
    const std::filesystem::path programFilesX86 = environmentDirectory(L"ProgramFiles(x86)");
    std::vector<std::filesystem::path> paths;

    const auto add =
        [&paths](const std::filesystem::path& base, const std::filesystem::path& relative)
    {
        if (!base.empty())
        {
            paths.push_back(base / relative);
        }
    };

    using seal::signer::BrowserKind;
    switch (kind)
    {
        case BrowserKind::Chrome:
            add(local, L"Google\\Chrome\\Application\\chrome.exe");
            add(programFiles, L"Google\\Chrome\\Application\\chrome.exe");
            add(programFilesX86, L"Google\\Chrome\\Application\\chrome.exe");
            break;
        case BrowserKind::Edge:
            add(local, L"Microsoft\\Edge\\Application\\msedge.exe");
            add(programFiles, L"Microsoft\\Edge\\Application\\msedge.exe");
            add(programFilesX86, L"Microsoft\\Edge\\Application\\msedge.exe");
            break;
        case BrowserKind::Brave:
            add(local, L"BraveSoftware\\Brave-Browser\\Application\\brave.exe");
            add(programFiles, L"BraveSoftware\\Brave-Browser\\Application\\brave.exe");
            add(programFilesX86, L"BraveSoftware\\Brave-Browser\\Application\\brave.exe");
            break;
        case BrowserKind::Opera:
            add(local, L"Programs\\Opera\\opera.exe");
            add(local, L"Programs\\Opera GX\\opera.exe");
            add(programFiles, L"Opera\\opera.exe");
            add(programFilesX86, L"Opera\\opera.exe");
            break;
        case BrowserKind::Vivaldi:
            add(local, L"Vivaldi\\Application\\vivaldi.exe");
            add(programFiles, L"Vivaldi\\Application\\vivaldi.exe");
            add(programFilesX86, L"Vivaldi\\Application\\vivaldi.exe");
            break;
        case BrowserKind::Thorium:
            add(local, L"Thorium\\Application\\thorium.exe");
            add(programFiles, L"Thorium\\Application\\thorium.exe");
            add(programFilesX86, L"Thorium\\Application\\thorium.exe");
            break;
        case BrowserKind::Chromium:
            add(local, L"Chromium\\Application\\chromium.exe");
            add(local, L"Chromium\\Application\\chrome.exe");
            add(programFiles, L"Chromium\\Application\\chromium.exe");
            add(programFiles, L"Chromium\\Application\\chrome.exe");
            add(programFilesX86, L"Chromium\\Application\\chromium.exe");
            add(programFilesX86, L"Chromium\\Application\\chrome.exe");
            break;
        case BrowserKind::Unknown:
        case BrowserKind::Firefox:
        case BrowserKind::LibreWolf:
        case BrowserKind::Waterfox:
        case BrowserKind::Floorp:
        case BrowserKind::Zen:
        case BrowserKind::Count:
        default:
            break;
    }
    return paths;
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

// No Gecko manifest is written: Gecko needs a different `allowed_extensions`
// shape, and seal ships no Firefox extension.

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

enum class RegistryDeleteOutcome
{
    Removed,
    Absent,
    Failed,
};

// Delete HKCU\<subKey>'s default value while preserving absent vs failure.
RegistryDeleteOutcome deleteRegistryValue(std::wstring_view subKey)
{
    const std::wstring subKeyOwned(subKey);
    const LSTATUS status = RegDeleteKeyValueW(HKEY_CURRENT_USER,
                                              subKeyOwned.c_str(),
                                              nullptr  // default value
    );
    if (status == ERROR_SUCCESS)
    {
        return RegistryDeleteOutcome::Removed;
    }
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND)
    {
        return RegistryDeleteOutcome::Absent;
    }
    return RegistryDeleteOutcome::Failed;
}

}  // namespace

std::filesystem::path findBrowserExtensionDirectory(const std::filesystem::path& executableDir)
{
    const std::filesystem::path installed = executableDir / "extensions" / "browser";
    if (pathExists(installed))
    {
        return installed;
    }

    std::filesystem::path probe = executableDir;
    for (int depth = 0; depth < 6 && probe.has_parent_path(); ++depth)
    {
        const std::filesystem::path candidate = probe / "extensions" / "browser";
        if (pathExists(candidate))
        {
            return candidate;
        }
        probe = probe.parent_path();
    }
    return installed;
}

bool isBrowserInstalled(seal::signer::BrowserKind kind)
{
    const auto* browser = seal::signer::browserMetadata(kind);
    if (browser == nullptr ||
        browser->m_EngineFamily != seal::signer::BrowserEngineFamily::Chromium)
    {
        return false;
    }

    if (appPathExists(browser->m_ImageName))
    {
        return true;
    }
    if (kind == seal::signer::BrowserKind::Opera && appPathExists(L"launcher.exe"))
    {
        return true;
    }
    for (const auto& path : standardBrowserPaths(kind))
    {
        if (pathExists(path))
        {
            return true;
        }
    }
    return false;
}

std::string formatBrowserExtensionInstallReport(const BrowserExtensionInstallReport& report)
{
    if (!report.m_Success)
    {
        return report.m_ErrorMessage.empty() ? "Browser companion setup failed."
                                             : report.m_ErrorMessage;
    }

    std::size_t registered = 0;
    for (const auto& result : report.m_Browsers)
    {
        if (result.m_Outcome == BrowserRegistrationOutcome::Registered)
        {
            ++registered;
        }
    }

    std::ostringstream message;
    message << "Native-messaging setup completed for " << registered << " browser(s).\n";
    message << "Manifest: " << report.m_ManifestPath.string() << "\n\n";
    message << "Browser registration:\n";
    for (const auto& result : report.m_Browsers)
    {
        const auto* browser = seal::signer::browserMetadata(result.m_Kind);
        const std::string_view name =
            browser == nullptr ? std::string_view("Unknown") : browser->m_DisplayName;
        message << "  - " << name << ": ";
        switch (result.m_Outcome)
        {
            case BrowserRegistrationOutcome::Registered:
                message << "registered";
                break;
            case BrowserRegistrationOutcome::SkippedNotInstalled:
                message << "not installed (skipped)";
                break;
            case BrowserRegistrationOutcome::RegistrationFailed:
                message << "registry write failed";
                break;
            default:
                message << "not processed";
                break;
        }
        message << "\n";
    }

    message << "\nExtension folder:\n  " << report.m_ExtensionDirectory.string() << "\n";
    if (!report.m_ExtensionDirectoryFound)
    {
        message << "\nExtension folder not found. Reinstall seal so extensions/browser is "
                   "present beside the application, then run Setup again.";
        return message.str();
    }

    if (report.m_ExtensionDirectoryCopied)
    {
        message << "  (copied to the clipboard)\n";
    }

    message << "\nOne manual step remains for each browser:\n";
    message << "  1) Open its extensions page";
    bool firstPage = true;
    for (const auto& result : report.m_Browsers)
    {
        if (result.m_Outcome != BrowserRegistrationOutcome::Registered)
        {
            continue;
        }
        const auto* browser = seal::signer::browserMetadata(result.m_Kind);
        if (browser == nullptr)
        {
            continue;
        }
        message << (firstPage ? " (" : ", ") << browser->m_ExtensionsPage;
        firstPage = false;
    }
    if (!firstPage)
    {
        message << ")";
    }
    message << ".\n";
    message << "  2) Turn on Developer mode.\n";
    message << "  3) Click Load unpacked and paste/select the extension folder above.\n";
    message << "seal does not launch a browser or install an unpacked extension "
               "programmatically.";
    return message.str();
}

std::string formatBrowserExtensionUninstallReport(const BrowserExtensionUninstallReport& report)
{
    std::ostringstream message;
    message << (report.m_Success ? "Native-messaging host unregistered."
                                 : "Native-messaging host removal was incomplete.");
    message << "\n\nBrowser registration:\n";
    for (const auto& result : report.m_Browsers)
    {
        const auto* browser = seal::signer::browserMetadata(result.m_Kind);
        const std::string_view name =
            browser == nullptr ? std::string_view("Unknown") : browser->m_DisplayName;
        message << "  - " << name << ": ";
        switch (result.m_Outcome)
        {
            case BrowserRegistrationOutcome::Removed:
                message << "removed";
                break;
            case BrowserRegistrationOutcome::AlreadyAbsent:
                message << "already absent";
                break;
            case BrowserRegistrationOutcome::RemovalFailed:
                message << "registry removal failed";
                break;
            default:
                message << "not processed";
                break;
        }
        message << "\n";
    }
    message << "\nThis unregisters only the native-messaging host. seal cannot remove an "
               "unpacked extension for you. Open each browser's extensions page, find "
               "'seal companion', and click Remove.";
    return message.str();
}

int installBrowserExtensionInternal(std::string* outMessage,
                                    BrowserExtensionInstallReport* outReport)
{
    BrowserExtensionInstallReport report;
    const auto finishFailure = [&report, outMessage, outReport](std::string message)
    {
        report.m_ErrorMessage = std::move(message);
        if (outMessage != nullptr)
        {
            *outMessage = formatBrowserExtensionInstallReport(report);
        }
        if (outReport != nullptr)
        {
            *outReport = report;
        }
        return 1;
    };

    const std::filesystem::path exeDir = executableDirectory();
    if (exeDir.empty())
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.install-extension.finish",
                      "result=fail",
                      "reason=module_path_unavailable"});
        return finishFailure("Failed to determine seal.exe location.");
    }

    const std::filesystem::path hostExe = exeDir / "seal-browser.exe";
    if (!pathExists(hostExe))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.install-extension.finish",
                      "result=fail",
                      "reason=host_exe_missing",
                      seal::diag::pathSummary(hostExe.string(), "host")});
        return finishFailure("seal-browser.exe not found beside seal.exe.");
    }

    report.m_ManifestPath = exeDir / "com.seal.fill.json";
    if (!writeChromeManifest(report.m_ManifestPath, hostExe))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.install-extension.finish",
                      "result=fail",
                      "reason=manifest_write_failed",
                      seal::diag::pathSummary(report.m_ManifestPath.string(), "manifest")});
        return finishFailure("Failed to write Chromium manifest file.");
    }

    int installedCount = 0;
    for (const auto& browser : seal::signer::kBrowserMetadata)
    {
        if (browser.m_EngineFamily != seal::signer::BrowserEngineFamily::Chromium)
        {
            continue;
        }

        BrowserRegistrationResult result;
        result.m_Kind = browser.m_Kind;
        if (!isBrowserInstalled(browser.m_Kind))
        {
            result.m_Outcome = BrowserRegistrationOutcome::SkippedNotInstalled;
            report.m_Browsers.push_back(result);
            continue;
        }

        bool succeeded = true;
        for (const std::wstring_view subKey : browser.m_NativeMessagingSubKeys)
        {
            if (subKey.empty())
            {
                continue;
            }
            if (writeRegistryString(subKey, report.m_ManifestPath.wstring()))
            {
                ++result.m_RegistryValueCount;
            }
            else
            {
                succeeded = false;
            }
        }
        result.m_Outcome = succeeded && result.m_RegistryValueCount > 0
                               ? BrowserRegistrationOutcome::Registered
                               : BrowserRegistrationOutcome::RegistrationFailed;
        if (result.m_Outcome == BrowserRegistrationOutcome::Registered)
        {
            ++installedCount;
        }
        report.m_Browsers.push_back(result);
    }

    report.m_ExtensionDirectory = findBrowserExtensionDirectory(exeDir);
    report.m_ExtensionDirectoryFound = pathExists(report.m_ExtensionDirectory);
    report.m_ExtensionDirectoryCopied = report.m_ExtensionDirectoryFound &&
                                        copyTextToClipboard(report.m_ExtensionDirectory.wstring());
    report.m_Success = true;

    // Progress goes to stdout even for the GUI caller: these lines are the
    // CLI's stdout contract. The GUI reads the structured report and the
    // detailed formatter instead.
    std::cout << "Native-messaging host registered for " << installedCount << " browser(s).\n";
    std::cout << "Manifest: " << report.m_ManifestPath.string() << "\n";
    if (report.m_ExtensionDirectoryFound)
    {
        std::cout << "\nExtension folder:\n  " << report.m_ExtensionDirectory.string() << "\n";
        if (report.m_ExtensionDirectoryCopied)
        {
            std::cout << "  (copied to clipboard - paste with Ctrl+V in the file picker)\n";
        }
        std::cout << "\nOne manual step remains (Chrome/Brave restriction on unpacked "
                     "extensions):\n"
                     "  1) Open chrome://extensions/ (or brave://extensions/).\n"
                     "  2) Turn on 'Developer mode' (top-right).\n"
                     "  3) Click 'Load unpacked' and paste the path above.\n"
                     "The extension ID is pinned in the manifest, so nothing else is needed.\n";
    }
    else
    {
        std::cout << "\nExtension folder not found. Place the extension under:\n  "
                  << (exeDir / "extensions" / "browser").string() << "\n";
    }

    writeCliDiag(seal::console::Tone::Success,
                 {"event=cli.install-extension.finish",
                  "result=ok",
                  seal::diag::kv("browsers", installedCount)});

    if (outMessage != nullptr)
    {
        *outMessage = formatBrowserExtensionInstallReport(report);
    }
    if (outReport != nullptr)
    {
        *outReport = report;
    }
    return 0;
}

int uninstallBrowserExtensionInternal(std::string* outMessage,
                                      BrowserExtensionUninstallReport* outReport)
{
    struct CachedDelete
    {
        std::wstring m_SubKey;
        RegistryDeleteOutcome m_Outcome;
    };
    std::vector<CachedDelete> cache;
    const auto deleteOnce = [&cache](std::wstring_view subKey)
    {
        for (const auto& cached : cache)
        {
            if (cached.m_SubKey == subKey)
            {
                return cached.m_Outcome;
            }
        }
        const RegistryDeleteOutcome outcome = deleteRegistryValue(subKey);
        cache.push_back({std::wstring(subKey), outcome});
        return outcome;
    };

    BrowserExtensionUninstallReport report;
    int removed = 0;
    int missed = 0;
    for (const auto& browser : seal::signer::kBrowserMetadata)
    {
        if (browser.m_EngineFamily != seal::signer::BrowserEngineFamily::Chromium)
        {
            continue;
        }

        BrowserRegistrationResult result;
        result.m_Kind = browser.m_Kind;
        bool anyRemoved = false;
        bool anyFailed = false;
        for (const std::wstring_view subKey : browser.m_NativeMessagingSubKeys)
        {
            if (subKey.empty())
            {
                continue;
            }
            switch (deleteOnce(subKey))
            {
                case RegistryDeleteOutcome::Removed:
                    anyRemoved = true;
                    ++result.m_RegistryValueCount;
                    break;
                case RegistryDeleteOutcome::Failed:
                    anyFailed = true;
                    break;
                case RegistryDeleteOutcome::Absent:
                    break;
            }
        }

        if (anyFailed)
        {
            result.m_Outcome = BrowserRegistrationOutcome::RemovalFailed;
            ++missed;
        }
        else
        {
            result.m_Outcome = anyRemoved ? BrowserRegistrationOutcome::Removed
                                          : BrowserRegistrationOutcome::AlreadyAbsent;
            ++removed;
        }
        report.m_Browsers.push_back(result);
    }
    report.m_Success = missed == 0;

    // Leave the generated manifest in place so a follow-up install only needs
    // to restore registry entries.
    writeCliDiag(report.m_Success ? seal::console::Tone::Success : seal::console::Tone::Error,
                 {"event=cli.uninstall-extension.finish",
                  report.m_Success ? "result=ok" : "result=fail",
                  seal::diag::kv("removed", removed),
                  seal::diag::kv("missed", missed)});

    std::cout << "Native-messaging host registry entries cleared (" << removed << " removed).\n";
    std::cout << "\nThis unregisters the native-messaging host only. The 'seal companion'\n"
                 "extension is still loaded in your browser - seal cannot remove an\n"
                 "unpacked extension for you (only the browser can). To finish removing it:\n"
                 "  1) Open chrome://extensions/ (or brave://extensions/).\n"
                 "  2) Find 'seal companion' and click Remove.\n";

    if (outMessage != nullptr)
    {
        *outMessage = formatBrowserExtensionUninstallReport(report);
    }
    if (outReport != nullptr)
    {
        *outReport = report;
    }
    return report.m_Success ? 0 : 1;
}

int HandleInstallBrowserExtensionMode()
{
    return installBrowserExtensionInternal(nullptr);
}

int HandleUninstallBrowserExtensionMode()
{
    return uninstallBrowserExtensionInternal(nullptr);
}

bool GetOptionsValid(const std::string& field, bool toStdout)
{
    if (field == "both")
    {
        return toStdout;
    }
    return field == "pass" || field == "user";
}

int ClampGetTtlSeconds(int requested)
{
    return std::clamp(requested, 1, 600);
}

int HandleListMode(const std::string& vaultPathArg)
{
    const std::filesystem::path vaultPath = resolveVaultPath(vaultPathArg);
    const std::string opId = seal::diag::nextOpId("cli_list");
    if (vaultPath.empty())
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.list.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=no_vault_found"});
        return 1;
    }

    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> guard(&password);
        std::vector<seal::VaultRecord> records = loadIndexUnprotected(guard, password, vaultPath);
        for (const auto& rec : records)
        {
            if (!rec.deleted)
            {
                std::cout << rec.platform << "\n";
            }
        }
        writeCliDiag(seal::console::Tone::Success,
                     {"event=cli.list.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("record_count", records.size())});
        seal::Cryptography::cleanseString(password);
        return 0;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.list.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what()))});
        return 1;
    }
}

int HandleGetMode(const std::string& platformQuery,
                  const std::string& vaultPathArg,
                  const std::string& field,
                  bool toStdout,
                  int ttlSeconds)
{
    const std::string opId = seal::diag::nextOpId("cli_get");
    if (!GetOptionsValid(field, toStdout))
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.get.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=invalid_options",
                      "hint=both_requires_stdout"});
        return 1;
    }
    const std::filesystem::path vaultPath = resolveVaultPath(vaultPathArg);
    if (vaultPath.empty())
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.get.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      "reason=no_vault_found"});
        return 1;
    }

    try
    {
        seal::basic_secure_string<wchar_t> password = seal::readPasswordConsole();
        seal::DPAPIGuard<seal::basic_secure_string<wchar_t>> guard(&password);

        std::vector<seal::VaultRecord> records = loadIndexUnprotected(guard, password, vaultPath);

        // Blank (not remove) deleted entries so indices stay aligned.
        std::vector<std::string> names;
        names.reserve(records.size());
        for (const auto& rec : records)
        {
            names.push_back(rec.deleted ? std::string{} : rec.platform);
        }

        const seal::PlatformMatch match = seal::matchPlatform(names, platformQuery);
        if (match.outcome == seal::MatchOutcome::NotFound)
        {
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.get.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=not_found"});
            seal::Cryptography::cleanseString(password);
            return 2;
        }
        if (match.outcome == seal::MatchOutcome::Ambiguous)
        {
            std::cerr << "Ambiguous platform; candidates:\n";
            for (const auto& cand : match.candidates)
            {
                std::cerr << "  " << cand << "\n";
            }
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.get.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=ambiguous",
                          seal::diag::kv("candidates", match.candidates.size())});
            seal::Cryptography::cleanseString(password);
            return 2;
        }

        seal::DecryptedCredential cred;
        {
            ScopedUnprotect dpapiScope(guard);
            cred = seal::decryptCredentialOnDemand(records[(size_t)match.index], password);
        }

        std::string userUtf8 = seal::utils::secureWideToUtf8(cred.username);
        std::string passUtf8 = seal::utils::secureWideToUtf8(cred.password);
        cred.cleanse();

        int rc = 0;
        if (toStdout)
        {
            // Raw value(s) + newline only: pipe-clean by contract.
            if (field == "user")
            {
                std::cout << userUtf8 << "\n";
            }
            else if (field == "pass")
            {
                std::cout << passUtf8 << "\n";
            }
            else
            {
                std::cout << userUtf8 << "\t" << passUtf8 << "\n";
            }
            std::cout.flush();
        }
        else
        {
            const std::string& value = (field == "user") ? userUtf8 : passUtf8;
            const DWORD ttlMs = static_cast<DWORD>(ClampGetTtlSeconds(ttlSeconds)) * 1000u;
            if (!seal::Clipboard::copyWithTTL(value.data(), value.size(), ttlMs))
            {
                writeCliDiag(seal::console::Tone::Error,
                             {"event=cli.get.finish",
                              "result=fail",
                              seal::diag::kv("op", opId),
                              "reason=clipboard_failed"});
                rc = 1;
            }
            else
            {
                std::cerr << ((field == "user") ? "Username" : "Password")
                          << " copied to clipboard (scrubbed in " << ClampGetTtlSeconds(ttlSeconds)
                          << "s).\n";
            }
        }

        seal::Cryptography::cleanseString(userUtf8, passUtf8, password);
        if (rc == 0)
        {
            writeCliDiag(seal::console::Tone::Success,
                         {"event=cli.get.finish",
                          "result=ok",
                          seal::diag::kv("op", opId),
                          std::string("sink=") + (toStdout ? "stdout" : "clipboard")});
        }
        return rc;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.get.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what()))});
        return 1;
    }
}

int HandleRekeyMode(const std::string& path)
{
    std::string vaultPathStr = path;
    if (!seal::utils::endsWithCi(vaultPathStr, ".seal"))
    {
        vaultPathStr += ".seal";
    }
    const std::filesystem::path vaultPath{vaultPathStr};

    const std::string opId = seal::diag::nextOpId("cli_rekey");
    writeCliDiag(seal::console::Tone::Step,
                 {"event=cli.rekey.begin",
                  "result=start",
                  seal::diag::kv("op", opId),
                  seal::diag::pathSummary(vaultPathStr)});

    try
    {
        seal::basic_secure_string<wchar_t> currentPw =
            seal::readPasswordConsole("Current password: ");
        seal::basic_secure_string<wchar_t> newPw = seal::readPasswordConsole("New password: ");
        seal::basic_secure_string<wchar_t> confirmPw =
            seal::readPasswordConsole("Confirm new password: ");

        if (newPw.size() == 0)
        {
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.rekey.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=empty_new_password"});
            seal::Cryptography::cleanseString(currentPw, newPw, confirmPw);
            return 1;
        }

        // Constant-time confirmation compare over the raw wide bytes
        // (ctEqual's byte_like concept excludes wchar_t containers).
        bool pwMatch = newPw.size() == confirmPw.size();
        if (pwMatch)
        {
            seal::RWGuard<wchar_t> newGuard(newPw.data());
            seal::RWGuard<wchar_t> confirmGuard(confirmPw.data());
            pwMatch = seal::Cryptography::ctEqualRaw(
                reinterpret_cast<const unsigned char*>(newPw.data()),
                reinterpret_cast<const unsigned char*>(confirmPw.data()),
                newPw.size() * sizeof(wchar_t));
        }
        if (!pwMatch)
        {
            writeCliDiag(seal::console::Tone::Error,
                         {"event=cli.rekey.finish",
                          "result=fail",
                          seal::diag::kv("op", opId),
                          "reason=confirmation_mismatch"});
            seal::Cryptography::cleanseString(currentPw, newPw, confirmPw);
            return 1;
        }

        const size_t count = seal::rekeyVault(vaultPath, currentPw, newPw);
        seal::Cryptography::cleanseString(currentPw, newPw, confirmPw);

        writeCliDiag(seal::console::Tone::Success,
                     {"event=cli.rekey.finish",
                      "result=ok",
                      seal::diag::kv("op", opId),
                      seal::diag::kv("record_count", count)});
        return 0;
    }
    catch (const std::exception& e)
    {
        writeCliDiag(seal::console::Tone::Error,
                     {"event=cli.rekey.finish",
                      "result=fail",
                      seal::diag::kv("op", opId),
                      seal::diag::errorFields(e.what())});
        return 1;
    }
}

}  // namespace seal
