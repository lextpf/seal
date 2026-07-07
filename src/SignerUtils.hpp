#pragma once

/**
 * @brief Shared signer-verification and process-introspection helpers.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Header-only utilities used by both the in-process BrowserBridge and the
 * standalone seal-browser stdio shim. Both sides verify each other's
 * Authenticode signer identity so a same-user attacker cannot impersonate
 * either the pipe server (seal.exe) or the pipe client (seal-browser.exe).
 *
 * Signer identity is represented as a SHA-256 thumbprint of the certificate's
 * SubjectPublicKeyInfo (the same form used for HPKP / cert-pinning). This
 * binds to the publisher's public key rather than to a CN string (two CAs
 * can issue certs with the same CN; collisions on the SPKI hash require
 * actual key compromise). Returned thumbprints are 64 lowercase hex chars.
 *
 * Revocation checking is configured to consult the whole chain but only
 * the OS cache (WTD_CACHE_ONLY_URL_RETRIEVAL); a published revocation
 * therefore takes effect once Windows has refreshed the CRL/OCSP cache
 * (typically within hours of the OS background update cycle).
 *
 * Functions return empty strings or zero on any failure; callers treat
 * those as "cannot verify" (which in dev/unsigned builds degrades to
 * "tolerated" by the surrounding policy).
 *
 * ## :material-shield: Threat Model
 *
 * The helpers exist to defeat three impersonation classes on a single
 * Windows account:
 *
 * - **Pipe-name impersonation** - a same-user process pre-creates a
 *   `\\.\pipe\seal-fill-<bogus-hex>` and accepts the connection from
 *   `seal-browser.exe`. Mitigation: the host queries the pipe
 *   server's PID via `GetNamedPipeServerProcessId` and demands that
 *   the server's binary share seal.exe's SPKI thumbprint. The
 *   attacker can't produce a signed seal.exe.
 * - **Signed-host puppeting** - malware runs the real signed
 *   `seal-browser.exe` as a subprocess with attacker-owned
 *   stdin/stdout, forwarding crafted JSON to the bridge. Mitigation:
 *   the bridge resolves the host's parent process via the chain
 *   walker and demands the immediate (or shell-traversal) ancestor be
 *   a known signed browser image. Malware's not a signed browser, so
 *   the bridge disconnects before any payload is parsed.
 * - **Re-parented puppet** - malware uses
 *   `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)`
 *   to make the host's parent appear to be chrome.exe even though
 *   malware created the stdio pipes. Mitigation: the host queries the
 *   NT object name of its stdin and uses `NtQuerySystemInformation`
 *   to enumerate the claimed parent's handle table. If the parent
 *   doesn't actually hold a handle to that pipe object, the host
 *   exits before opening the bridge pipe (fail closed in production,
 *   warn-and-continue in dev/unsigned builds).
 *
 * @note Returns of empty / zero from any function in this header are
 *       intentionally ambiguous (could be "no signature" or "API
 *       failed"). Production callers MUST fail closed on empty
 *       results; dev callers tolerate the ambiguity so local unsigned
 *       builds keep working.
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <bcrypt.h>
#include <knownfolders.h>
#include <shlobj_core.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <wintrust.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Microsoft headers split SoftPub.h / wincrypt.h between SDK versions; declare
// the GUID locally if the SDK didn't already.
#ifndef WINTRUST_ACTION_GENERIC_VERIFY_V2
// clang-format off
#define WINTRUST_ACTION_GENERIC_VERIFY_V2                            \
    { 0xaac56b, 0xcd44, 0x11d0,                                      \
      { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } }
// clang-format on
#endif

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Shell32.lib")

namespace seal::signer
{

namespace detail
{

/**
 * @brief RAII wrapper around the two output handles of `CryptQueryObject`.
 *
 * `CryptQueryObject` populates both an `HCERTSTORE` and an `HCRYPTMSG`
 * on success; if any subsequent step in the signature query fails, the
 * caller would normally have to remember to release both before
 * returning. This guard centralises that cleanup so the public helpers
 * can early-return on any failure without leaking handles.
 */
struct CryptQueryGuard
{
    HCERTSTORE m_Store = nullptr;  ///< Owning handle to the cert store; closed in dtor.
    HCRYPTMSG m_Msg = nullptr;     ///< Owning handle to the crypt message; closed in dtor.

    CryptQueryGuard() = default;
    CryptQueryGuard(const CryptQueryGuard&) = delete;
    CryptQueryGuard& operator=(const CryptQueryGuard&) = delete;
    ~CryptQueryGuard()
    {
        if (m_Msg != nullptr)
        {
            CryptMsgClose(m_Msg);
        }
        if (m_Store != nullptr)
        {
            CertCloseStore(m_Store, 0);
        }
    }
};

/// @brief ASCII-range tolower for `wchar_t`. Leaves non-ASCII chars unchanged.
inline wchar_t asciiLower(wchar_t c) noexcept
{
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

/// @brief Lowercased (ASCII) basename of an image path, or empty when the path
/// is empty. Shared by the browser/shell image classifiers below.
inline std::wstring lowerBasename(const std::wstring& imagePath)
{
    if (imagePath.empty())
    {
        return {};
    }
    const auto sep = imagePath.find_last_of(L"\\/");
    std::wstring basename = (sep == std::wstring::npos) ? imagePath : imagePath.substr(sep + 1);
    for (auto& c : basename)
    {
        c = asciiLower(c);
    }
    return basename;
}

/// @brief Whether `basename` exactly equals any entry in `names`.
template <std::size_t N>
inline bool matchesAny(std::wstring_view basename,
                       const std::array<std::wstring_view, N>& names) noexcept
{
    for (const auto& name : names)
    {
        if (basename == name)
        {
            return true;
        }
    }
    return false;
}

}  // namespace detail

/**
 * @brief Verify a file's Authenticode signature including cached revocation.
 *
 * Revocation is checked against the WHOLE CERTIFICATE CHAIN but using only
 * the local OS CRL/OCSP cache (@c WTD_CACHE_ONLY_URL_RETRIEVAL). This means:
 *   - A revoked publisher cert is rejected as soon as Windows has refreshed
 *     its cache (typically within hours via the OS background cycle, or
 *     immediately after the user opens a properties dialog that forces a
 *     refresh).
 *   - We never stall the accept loop on a network round trip; on a machine
 *     that has never seen the relevant CRL, the result is "trust" rather
 *     than "stall" - matching how SmartScreen/AppLocker behave for the
 *     same reason.
 *
 * Returns true only when the signature chain validates against an OS-trusted
 * root and the chain is not revoked according to the cache.
 */
inline bool winVerifyTrustOk(const std::wstring& path)
{
    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &fileInfo;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    data.dwUIContext = WTD_UICONTEXT_EXECUTE;

    LONG status = WinVerifyTrust(nullptr, &actionId, &data);

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &actionId, &data);

    return status == ERROR_SUCCESS;
}

namespace detail
{

/// @brief Lowercase-hex character for the low nibble of `v`.
inline char hexNibble(unsigned char v) noexcept
{
    static constexpr char kHex[] = "0123456789abcdef";
    return kHex[v & 0x0F];
}

/**
 * @brief Lowercase-hex-encode a byte buffer.
 *
 * The encoder is allocation-light (single contiguous string) and ASCII-
 * safe by construction, suitable for embedding the resulting digest in
 * a pipe name or a log line.
 *
 * @param data Pointer to the input bytes.
 * @param len  Length of the input in bytes.
 * @return `2 * len` lowercase hex chars.
 */
inline std::string hexEncode(const unsigned char* data, std::size_t len)
{
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i)
    {
        out[2 * i] = hexNibble(static_cast<unsigned char>(data[i] >> 4));
        out[2 * i + 1] = hexNibble(data[i]);
    }
    return out;
}

inline bool asciiIEquals(std::wstring_view a, std::wstring_view b) noexcept
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        if (asciiLower(a[i]) != asciiLower(b[i]))
        {
            return false;
        }
    }
    return true;
}

template <std::size_t N>
inline bool matchesAnyAsciiI(std::wstring_view value,
                             const std::array<std::wstring_view, N>& expected) noexcept
{
    if (value.empty())
    {
        return false;
    }
    for (const auto& item : expected)
    {
        if (asciiIEquals(value, item))
        {
            return true;
        }
    }
    return false;
}

inline std::wstring normalisedPathForCompare(std::wstring path)
{
    if (path.rfind(LR"(\\?\)", 0) == 0 || path.rfind(LR"(\??\)", 0) == 0)
    {
        path.erase(0, 4);
    }

    for (auto& c : path)
    {
        if (c == L'/')
        {
            c = L'\\';
        }
        c = asciiLower(c);
    }

    while (!path.empty() && path.back() == L'\\')
    {
        path.pop_back();
    }
    return path;
}

inline std::wstring appendNormalisedPath(std::wstring base, std::wstring_view tail)
{
    if (!base.empty() && base.back() != L'\\')
    {
        base.push_back(L'\\');
    }
    base.append(tail);
    return normalisedPathForCompare(std::move(base));
}

inline bool pathEqualsOrIsUnder(std::wstring_view path, std::wstring_view root) noexcept
{
    if (root.empty() || path.size() < root.size() || path.substr(0, root.size()) != root)
    {
        return false;
    }
    return path.size() == root.size() || path[root.size()] == L'\\';
}

inline std::wstring windowsDirectory()
{
    wchar_t buf[MAX_PATH * 2]{};
    const UINT chars = GetWindowsDirectoryW(buf, static_cast<UINT>(std::size(buf)));
    if (chars == 0 || chars >= std::size(buf))
    {
        return {};
    }
    return std::wstring(buf, chars);
}

inline std::wstring knownFolderPath(REFKNOWNFOLDERID folderId)
{
    PWSTR raw = nullptr;
    if (FAILED(SHGetKnownFolderPath(folderId, KF_FLAG_DEFAULT, nullptr, &raw)) || raw == nullptr)
    {
        return {};
    }
    std::wstring path(raw);
    CoTaskMemFree(raw);
    return path;
}

inline PCCERT_CONTEXT findSignerCertificate(const std::wstring& path, CryptQueryGuard& query)
{
    DWORD encoding = 0;
    DWORD contentType = 0;
    DWORD formatType = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                          path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0,
                          &encoding,
                          &contentType,
                          &formatType,
                          &query.m_Store,
                          &query.m_Msg,
                          nullptr))
    {
        return nullptr;
    }

    DWORD signerInfoBytes = 0;
    if (!CryptMsgGetParam(query.m_Msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoBytes))
    {
        return nullptr;
    }
    std::vector<BYTE> signerInfoBuf(signerInfoBytes);
    if (!CryptMsgGetParam(
            query.m_Msg, CMSG_SIGNER_INFO_PARAM, 0, signerInfoBuf.data(), &signerInfoBytes))
    {
        return nullptr;
    }
    const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerInfoBuf.data());

    CERT_INFO certInfo{};
    certInfo.Issuer = signerInfo->Issuer;
    certInfo.SerialNumber = signerInfo->SerialNumber;
    return CertFindCertificateInStore(query.m_Store,
                                      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                      0,
                                      CERT_FIND_SUBJECT_CERT,
                                      &certInfo,
                                      nullptr);
}

}  // namespace detail

/**
 * @brief Extract a SHA-256 SubjectPublicKeyInfo thumbprint of the publisher
 *        cert from a signed PE on disk.
 *
 * The returned thumbprint is 64 lowercase hex chars binding to the
 * publisher's public key (not the CN, not the cert serial). This is the
 * appropriate granularity for "two binaries signed by the same publisher":
 * cert renewals with the same key still match; reissues with a different
 * key (e.g., after a key compromise) do NOT match.
 *
 * Returns an empty string on any failure. Callers treat "no identity" as
 * "dev/unsigned mode" - the surrounding policy decides whether to fail
 * open or closed.
 */
inline std::string extractSignerIdentityFromFile(const std::wstring& path)
{
    detail::CryptQueryGuard query;
    PCCERT_CONTEXT certContext = detail::findSignerCertificate(path, query);
    if (certContext == nullptr)
    {
        return {};
    }

    // DER-encode the SubjectPublicKeyInfo blob, then SHA-256 it. Two certs
    // sharing the same key (the typical renewal case) produce the same
    // thumbprint; certs reissued with a fresh key do not.
    DWORD encodedSize = 0;
    if (!CryptEncodeObject(X509_ASN_ENCODING,
                           X509_PUBLIC_KEY_INFO,
                           &certContext->pCertInfo->SubjectPublicKeyInfo,
                           nullptr,
                           &encodedSize) ||
        encodedSize == 0)
    {
        CertFreeCertificateContext(certContext);
        return {};
    }
    std::vector<BYTE> encoded(encodedSize);
    if (!CryptEncodeObject(X509_ASN_ENCODING,
                           X509_PUBLIC_KEY_INFO,
                           &certContext->pCertInfo->SubjectPublicKeyInfo,
                           encoded.data(),
                           &encodedSize))
    {
        CertFreeCertificateContext(certContext);
        return {};
    }
    CertFreeCertificateContext(certContext);

    std::array<unsigned char, 32> hash{};
    const NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE,
                                       nullptr,
                                       0,
                                       encoded.data(),
                                       encodedSize,
                                       hash.data(),
                                       static_cast<ULONG>(hash.size()));
    if (!BCRYPT_SUCCESS(status))
    {
        return {};
    }
    return detail::hexEncode(hash.data(), hash.size());
}

/**
 * @brief Extract the Authenticode signer display name from a signed PE.
 *
 * This is used only for browser-vendor pinning. It is deliberately combined
 * with @ref winVerifyTrustOk by callers; the display name alone is not a trust
 * decision.
 */
inline std::wstring extractSignerPublisherFromFile(const std::wstring& path)
{
    detail::CryptQueryGuard query;
    PCCERT_CONTEXT certContext = detail::findSignerCertificate(path, query);
    if (certContext == nullptr)
    {
        return {};
    }

    const DWORD chars =
        CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (chars <= 1)
    {
        CertFreeCertificateContext(certContext);
        return {};
    }
    std::vector<wchar_t> buf(chars, L'\0');
    const DWORD written = CertGetNameStringW(
        certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf.data(), chars);
    CertFreeCertificateContext(certContext);
    if (written <= 1)
    {
        return {};
    }
    return std::wstring(buf.data(), written - 1);
}

/**
 * @brief Build the SPKI thumbprint for the calling module (this exe).
 *
 * Returns empty when the exe is unsigned, untrusted, or revoked - callers
 * degrade gracefully (dev-mode tolerance) instead of refusing to function.
 */
inline std::string readOwnSignerIdentity()
{
    wchar_t buf[MAX_PATH * 2]{};
    const DWORD chars = GetModuleFileNameW(nullptr, buf, sizeof(buf) / sizeof(buf[0]));
    if (chars == 0 || chars >= sizeof(buf) / sizeof(buf[0]))
    {
        return {};
    }
    const std::wstring path(buf, chars);
    if (!winVerifyTrustOk(path))
    {
        return {};
    }
    return extractSignerIdentityFromFile(path);
}

/**
 * @brief Resolve a PID to its on-disk image path.
 *
 * PROCESS_QUERY_LIMITED_INFORMATION is the minimum right that
 * QueryFullProcessImageNameW honours and works across integrity-level
 * boundaries within the same user.
 */
inline std::wstring resolveProcessPath(DWORD pid)
{
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr || process == INVALID_HANDLE_VALUE)
    {
        return {};
    }
    wchar_t buf[MAX_PATH * 2]{};
    DWORD bufChars = sizeof(buf) / sizeof(buf[0]);
    const BOOL ok = QueryFullProcessImageNameW(process, 0, buf, &bufChars);
    CloseHandle(process);
    if (!ok)
    {
        return {};
    }
    return std::wstring(buf, bufChars);
}

/**
 * @brief Look up the parent process PID via Toolhelp32.
 *
 * Returns 0 when the child PID is no longer alive or the snapshot fails.
 * Note: Windows recycles PIDs, so callers must treat the result as a hint
 * valid only at the instant of the snapshot (typically within the same
 * synchronous control flow that opened the child handle).
 */
inline DWORD resolveParentPid(DWORD childPid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD parent = 0;
    if (Process32FirstW(snap, &entry))
    {
        do
        {
            if (entry.th32ProcessID == childPid)
            {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return parent;
}

/**
 * @brief Whether an image-path basename matches a known browser launcher.
 *
 * Case-insensitive ASCII comparison. The list covers the chromium family
 * and the gecko family; uncommon forks must be added explicitly. Combined
 * with winVerifyTrustOk() this gives "known browser, signed by its
 * publisher" - which is the assurance we want for the bridge's accept
 * loop.
 */
inline bool isKnownBrowserImage(const std::wstring& imagePath)
{
    static constexpr std::array<std::wstring_view, 12> kBrowsers = {{
        L"chrome.exe",
        L"msedge.exe",
        L"brave.exe",
        L"firefox.exe",
        L"opera.exe",
        L"vivaldi.exe",
        L"librewolf.exe",
        L"thorium.exe",
        L"chromium.exe",
        L"waterfox.exe",
        L"floorp.exe",
        L"zen.exe",
    }};
    return detail::matchesAny(detail::lowerBasename(imagePath), kBrowsers);
}

/**
 * @brief A specific browser recognised by isKnownBrowserImage().
 * @ingroup Utilities
 *
 * Each value names one launcher in the allow-list. The bridge attributes an
 * accepted connection to a kind so the UI can show a per-browser status dot.
 * `Unknown` is index 0 and `Count` is the sentinel size (used to dimension a
 * per-kind array). Keep the set in sync with identifyBrowser() and
 * isKnownBrowserImage().
 *
 * @par Kind / image / logfmt token
 * The enum, @ref identifyBrowser, @ref isKnownBrowserImage, and
 * @ref browserKindToken carry the same 12 launchers and must move in lockstep;
 * `Unknown` and `Count` both map to token `"unknown"`.
 * | BrowserKind | Image basename  | logfmt token |
 * |-------------|-----------------|--------------|
 * | Chrome      | `chrome.exe`    | `chrome`     |
 * | Edge        | `msedge.exe`    | `edge`       |
 * | Brave       | `brave.exe`     | `brave`      |
 * | Opera       | `opera.exe`     | `opera`      |
 * | Vivaldi     | `vivaldi.exe`   | `vivaldi`    |
 * | Thorium     | `thorium.exe`   | `thorium`    |
 * | Chromium    | `chromium.exe`  | `chromium`   |
 * | Firefox     | `firefox.exe`   | `firefox`    |
 * | LibreWolf   | `librewolf.exe` | `librewolf`  |
 * | Waterfox    | `waterfox.exe`  | `waterfox`   |
 * | Floorp      | `floorp.exe`    | `floorp`     |
 * | Zen         | `zen.exe`       | `zen`        |
 */
enum class BrowserKind
{
    Unknown = 0,  ///< Not a recognised browser image.
    Chrome,       ///< chrome.exe
    Edge,         ///< msedge.exe
    Brave,        ///< brave.exe
    Opera,        ///< opera.exe
    Vivaldi,      ///< vivaldi.exe
    Thorium,      ///< thorium.exe
    Chromium,     ///< chromium.exe
    Firefox,      ///< firefox.exe
    LibreWolf,    ///< librewolf.exe
    Waterfox,     ///< waterfox.exe
    Floorp,       ///< floorp.exe
    Zen,          ///< zen.exe
    Count         ///< Sentinel: number of kinds (including Unknown).
};

/**
 * @brief Classify an image path as a specific @ref BrowserKind.
 *
 * Case-insensitive basename match against the same allow-list as
 * isKnownBrowserImage(); anything unrecognised maps to @ref
 * BrowserKind::Unknown.
 *
 * @param imagePath Full path or basename of the process image.
 * @return The matching @ref BrowserKind, or Unknown.
 */
inline BrowserKind identifyBrowser(const std::wstring& imagePath)
{
    const std::wstring basename = detail::lowerBasename(imagePath);

    struct KindEntry
    {
        std::wstring_view m_Image;
        BrowserKind m_Kind;
    };
    static constexpr std::array<KindEntry, 12> kKinds = {{
        {L"chrome.exe", BrowserKind::Chrome},
        {L"msedge.exe", BrowserKind::Edge},
        {L"brave.exe", BrowserKind::Brave},
        {L"opera.exe", BrowserKind::Opera},
        {L"vivaldi.exe", BrowserKind::Vivaldi},
        {L"thorium.exe", BrowserKind::Thorium},
        {L"chromium.exe", BrowserKind::Chromium},
        {L"firefox.exe", BrowserKind::Firefox},
        {L"librewolf.exe", BrowserKind::LibreWolf},
        {L"waterfox.exe", BrowserKind::Waterfox},
        {L"floorp.exe", BrowserKind::Floorp},
        {L"zen.exe", BrowserKind::Zen},
    }};
    for (const auto& entry : kKinds)
    {
        if (basename == entry.m_Image)
        {
            return entry.m_Kind;
        }
    }
    return BrowserKind::Unknown;
}

/**
 * @brief Short logfmt token for a @ref BrowserKind ("chrome", "brave", ...).
 *
 * @param kind The browser kind.
 * @return A stable lowercase token; "unknown" for Unknown/Count.
 */
inline std::string_view browserKindToken(BrowserKind kind) noexcept
{
    switch (kind)
    {
        case BrowserKind::Chrome:
            return "chrome";
        case BrowserKind::Edge:
            return "edge";
        case BrowserKind::Brave:
            return "brave";
        case BrowserKind::Opera:
            return "opera";
        case BrowserKind::Vivaldi:
            return "vivaldi";
        case BrowserKind::Thorium:
            return "thorium";
        case BrowserKind::Chromium:
            return "chromium";
        case BrowserKind::Firefox:
            return "firefox";
        case BrowserKind::LibreWolf:
            return "librewolf";
        case BrowserKind::Waterfox:
            return "waterfox";
        case BrowserKind::Floorp:
            return "floorp";
        case BrowserKind::Zen:
            return "zen";
        case BrowserKind::Unknown:
        case BrowserKind::Count:
        default:
            return "unknown";
    }
}

/**
 * @brief Verify that a signer display name belongs to the expected browser vendor.
 *
 * The input is the Authenticode signer simple display name returned by
 * @ref extractSignerPublisherFromFile. This is a second gate after
 * @ref winVerifyTrustOk and defeats the "trusted executable renamed to
 * chrome.exe" class: the filename must identify a browser family and the
 * signer must be that family/vendor.
 */
inline bool browserPublisherMatches(BrowserKind kind, std::wstring_view publisher) noexcept
{
    switch (kind)
    {
        case BrowserKind::Chrome:
            return detail::matchesAnyAsciiI(publisher,
                                            std::array<std::wstring_view, 1>{L"Google LLC"});
        case BrowserKind::Edge:
            return detail::matchesAnyAsciiI(
                publisher, std::array<std::wstring_view, 1>{L"Microsoft Corporation"});
        case BrowserKind::Brave:
            return detail::matchesAnyAsciiI(
                publisher, std::array<std::wstring_view, 1>{L"Brave Software, Inc."});
        case BrowserKind::Opera:
            return detail::matchesAnyAsciiI(publisher,
                                            std::array<std::wstring_view, 1>{L"Opera Norway AS"});
        case BrowserKind::Vivaldi:
            return detail::matchesAnyAsciiI(
                publisher, std::array<std::wstring_view, 1>{L"Vivaldi Technologies AS"});
        case BrowserKind::Chromium:
            return detail::matchesAnyAsciiI(
                publisher,
                std::array<std::wstring_view, 2>{L"Google LLC", L"The Chromium Authors"});
        case BrowserKind::Firefox:
            return detail::matchesAnyAsciiI(
                publisher, std::array<std::wstring_view, 1>{L"Mozilla Corporation"});
        case BrowserKind::LibreWolf:
            return detail::matchesAnyAsciiI(publisher,
                                            std::array<std::wstring_view, 1>{L"LibreWolf"});
        case BrowserKind::Waterfox:
            return detail::matchesAnyAsciiI(
                publisher,
                std::array<std::wstring_view, 2>{L"Waterfox Limited", L"BrowserWorks Ltd"});
        case BrowserKind::Floorp:
            return detail::matchesAnyAsciiI(
                publisher, std::array<std::wstring_view, 2>{L"Ablaze", L"Ablaze, Inc."});
        case BrowserKind::Zen:
            return detail::matchesAnyAsciiI(publisher,
                                            std::array<std::wstring_view, 1>{L"Zen Browser"});
        case BrowserKind::Thorium:
            return detail::matchesAnyAsciiI(
                publisher, std::array<std::wstring_view, 2>{L"Alex313031", L"The Thorium Authors"});
        case BrowserKind::Unknown:
        case BrowserKind::Count:
        default:
            return false;
    }
}

/**
 * @brief Full browser image trust check for the native-messaging boundary.
 */
inline bool isTrustedBrowserImage(const std::wstring& imagePath)
{
    const BrowserKind kind = identifyBrowser(imagePath);
    if (kind == BrowserKind::Unknown)
    {
        return false;
    }
    if (!winVerifyTrustOk(imagePath))
    {
        return false;
    }
    return browserPublisherMatches(kind, extractSignerPublisherFromFile(imagePath));
}

/**
 * @brief A specific Windows shell executable tolerated as a browser-launch hop.
 */
enum class ShellKind
{
    Unknown = 0,
    Cmd,
    WindowsPowerShell,
    PowerShell,
    ConsoleHost
};

/**
 * @brief Classify a process image as a shell hop candidate by basename.
 */
inline ShellKind identifyShell(const std::wstring& imagePath)
{
    const std::wstring basename = detail::lowerBasename(imagePath);
    if (basename == L"cmd.exe")
    {
        return ShellKind::Cmd;
    }
    if (basename == L"powershell.exe")
    {
        return ShellKind::WindowsPowerShell;
    }
    if (basename == L"pwsh.exe")
    {
        return ShellKind::PowerShell;
    }
    if (basename == L"conhost.exe")
    {
        return ShellKind::ConsoleHost;
    }
    return ShellKind::Unknown;
}

/**
 * @brief Verify that a signer display name belongs to Microsoft.
 *
 * Windows inbox binaries commonly report "Microsoft Windows", while
 * PowerShell 7 packages commonly report "Microsoft Corporation".
 */
inline bool shellPublisherMatches(ShellKind kind, std::wstring_view publisher) noexcept
{
    if (kind == ShellKind::Unknown)
    {
        return false;
    }
    return detail::matchesAnyAsciiI(
        publisher,
        std::array<std::wstring_view, 2>{L"Microsoft Windows", L"Microsoft Corporation"});
}

/**
 * @brief Path allow-list for shell hop candidates.
 *
 * This is deliberately narrower than @ref identifyShell: basename alone is not
 * enough for a trust decision. Inbox shells must be under the real Windows
 * directory; PowerShell 7 must be under a machine-wide Program Files
 * PowerShell install.
 */
inline bool isShellPathAllowed(ShellKind kind, const std::wstring& imagePath)
{
    const std::wstring image = detail::normalisedPathForCompare(imagePath);
    if (image.empty())
    {
        return false;
    }

    const std::wstring windows = detail::normalisedPathForCompare(detail::windowsDirectory());
    if (kind == ShellKind::Cmd)
    {
        return image == detail::appendNormalisedPath(windows, LR"(system32\cmd.exe)") ||
               image == detail::appendNormalisedPath(windows, LR"(syswow64\cmd.exe)");
    }
    if (kind == ShellKind::WindowsPowerShell)
    {
        return image == detail::appendNormalisedPath(
                            windows, LR"(system32\windowspowershell\v1.0\powershell.exe)") ||
               image == detail::appendNormalisedPath(
                            windows, LR"(syswow64\windowspowershell\v1.0\powershell.exe)");
    }
    if (kind == ShellKind::ConsoleHost)
    {
        return image == detail::appendNormalisedPath(windows, LR"(system32\conhost.exe)") ||
               image == detail::appendNormalisedPath(windows, LR"(syswow64\conhost.exe)");
    }
    if (kind == ShellKind::PowerShell)
    {
        const std::wstring programFiles = detail::appendNormalisedPath(
            detail::knownFolderPath(FOLDERID_ProgramFiles), L"PowerShell");
        const std::wstring programFilesX86 = detail::appendNormalisedPath(
            detail::knownFolderPath(FOLDERID_ProgramFilesX86), L"PowerShell");
        return detail::pathEqualsOrIsUnder(image, programFiles) ||
               detail::pathEqualsOrIsUnder(image, programFilesX86);
    }
    return false;
}

/**
 * @brief Whether an image path is an allowed shell-hop location.
 *
 * This helper intentionally rejects basename-only and user-writable lookalike
 * paths. It is only the path allow-list; use @ref isTrustedShellImage for a
 * bridge trust decision.
 */
inline bool isShellImage(const std::wstring& imagePath)
{
    const ShellKind kind = identifyShell(imagePath);
    return kind != ShellKind::Unknown && isShellPathAllowed(kind, imagePath);
}

/**
 * @brief Full shell-hop image trust check for the native-messaging boundary.
 *
 * Chromium on Windows occasionally wraps native-messaging host launches
 * in cmd.exe (depends on Chrome version, manifest layout, and
 * intermediate path quoting - the bridge sees the host's parent as
 * cmd.exe and the real browser as the grandparent). The accept loop
 * walks the chain through trusted shell hops looking for a signed-browser
 * ancestor.
 */
inline bool isTrustedShellImage(const std::wstring& imagePath)
{
    const ShellKind kind = identifyShell(imagePath);
    if (kind == ShellKind::Unknown || !isShellPathAllowed(kind, imagePath))
    {
        return false;
    }
    if (!winVerifyTrustOk(imagePath))
    {
        return false;
    }
    return shellPublisherMatches(kind, extractSignerPublisherFromFile(imagePath));
}

}  // namespace seal::signer
