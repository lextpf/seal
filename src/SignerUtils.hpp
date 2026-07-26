#pragma once

/**
 * @brief Shared signer-verification and process-introspection helpers.
 * @author Fable 5 (https://github.com/claude)
 * @ingroup Utilities
 *
 * Header-only, shared by the in-process BrowserBridge and the standalone
 * seal-browser stdio shim. Both sides check the other's Authenticode signer
 * identity, so a same-user attacker cannot impersonate the pipe server
 * (seal.exe) or the pipe client (seal-browser.exe).
 *
 * @par Signer identity
 * A SHA-256 thumbprint of the certificate's SubjectPublicKeyInfo, returned as
 * 64 lowercase hex chars (the form used for HPKP and cert pinning). It binds to
 * the publisher's public key rather than to a CN string: two CAs can issue
 * certs with the same CN, while a collision on the SPKI hash needs the key.
 *
 * @par Revocation
 * Checked across the whole chain, but against the OS cache only
 * (WTD_CACHE_ONLY_URL_RETRIEVAL). A published revocation takes effect once
 * Windows has refreshed its CRL/OCSP cache, typically within hours.
 *
 * @par Failure convention
 * Every function returns an empty string or zero on failure, which callers read
 * as "cannot verify". The surrounding policy decides what that means: a signed
 * release fails closed, an unsigned dev build tolerates it.
 *
 * ## :material-shield: Threat Model
 *
 * The helpers exist to defeat three impersonation classes on a single
 * Windows account:
 *
 * - **Pipe-name impersonation** - a same-user process pre-creates a
 *   `\\.\pipe\seal-fill-<bogus-hex>` and accepts the connection from
 *   `seal-browser.exe`. Mitigation: the host queries the pipe server's PID via
 *   `GetNamedPipeServerProcessId` and requires the server binary to share
 *   seal.exe's SPKI thumbprint, which the attacker cannot produce.
 * - **Signed-host puppeting** - malware runs the real signed
 *   `seal-browser.exe` as a subprocess with attacker-owned stdin and stdout,
 *   forwarding crafted JSON to the bridge. Mitigation: the bridge walks the
 *   host's process chain and requires the ancestor it reaches, directly or
 *   through allowed shell hops, to be a known signed browser image. Malware is
 *   not one, so the bridge disconnects before any payload is parsed.
 * - **Re-parented puppet** - malware uses
 *   `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)` to make
 *   the host's parent appear to be chrome.exe even though malware created the
 *   stdio pipes. Mitigation: the host queries the NT object name of its stdin
 *   and enumerates the claimed parent's handle table with
 *   `NtQuerySystemInformation`. If that parent holds no handle to the pipe
 *   object, the host exits before opening the bridge pipe - fail closed in
 *   production, warn and continue in an unsigned dev build.
 *
 * @note An empty or zero return is deliberately ambiguous: it can mean "no
 *       signature" or "the API call failed". Production callers fail closed on
 *       it; dev callers tolerate it so local unsigned builds keep working.
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

// Kept in its own block so clang-format cannot sort it above wincrypt.h:
// mscat.h uses CRYPT_HASH_BLOB but does not include the header declaring it,
// and WIN32_LEAN_AND_MEAN above stops windows.h from pulling wincrypt.h in.
#include <mscat.h>

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

// Catalog subsystem GUID. It acquires the HCATADMIN that resolves an inbox
// binary to its signing catalog. Same split-header caveat as above; the value
// is the CatRoot subdirectory name every system catalog lives under.
#ifndef DRIVER_ACTION_VERIFY
// clang-format off
#define DRIVER_ACTION_VERIFY                                         \
    { 0xf750e6c3, 0x38ee, 0x11d1,                                    \
      { 0x85, 0xe5, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } }
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
 * @struct CryptQueryGuard
 * @brief RAII wrapper around the two output handles of `CryptQueryObject`.
 *
 * `CryptQueryObject` populates both an `HCERTSTORE` and an `HCRYPTMSG` on
 * success. This guard closes both, so the public helpers can return early from
 * any later failure in the signature query without leaking a handle.
 *
 * Non-copyable and non-movable. The `PCCERT_CONTEXT` that
 * @ref findSignerCertificate returns belongs to the caller: release it with
 * `CertFreeCertificateContext` while this guard is still in scope.
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
/// Case-sensitive; callers pass an already-lowercased basename.
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
 * Revocation is checked across the whole certificate chain, but against the
 * local OS CRL/OCSP cache only (@c WTD_CACHE_ONLY_URL_RETRIEVAL):
 *   - A revoked publisher cert is rejected once Windows has refreshed its
 *     cache, typically within hours of the background cycle, or immediately
 *     after a properties dialog forces a refresh.
 *   - The accept loop never stalls on a network round trip. On a machine that
 *     has never seen the relevant CRL the result is "trust" rather than
 *     "stall", matching SmartScreen and AppLocker.
 *
 * Only an embedded Authenticode signature is consulted. A catalog-signed image,
 * which is every Windows inbox binary, reports "no signature" here; use
 * @ref detail::catalogTrustOk for those.
 *
 * The verify state is closed again even on failure, so no provider state leaks.
 *
 * @param path Full path to the image to verify.
 * @return true only when the signature chain validates against an OS-trusted
 *         root and the cache reports no revocation.
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
 * One contiguous allocation, ASCII-safe by construction, so the digest can go
 * straight into a pipe name or a log line.
 *
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

/// @brief Case-insensitive ASCII comparison. Bytes >= 0x80 compare exactly, so
/// two strings that differ only in non-ASCII case are reported unequal.
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

/// @brief Whether `value` equals any entry of `expected`, ignoring ASCII case.
/// An empty `value` never matches, so a failed signer lookup cannot satisfy a
/// publisher gate that happens to list an empty string.
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

/// @brief Canonical form for path equality: strips a leading `\\?\` or `\??\`
/// prefix, turns `/` into `\`, lowercases ASCII, and drops trailing separators.
/// It resolves no symlink, junction, 8.3 short name or `..`, so it is a textual
/// comparison aid only, never a security boundary on its own.
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

/// @brief Join `tail` onto `base` with one separator, then normalise the whole
/// result with @ref normalisedPathForCompare.
inline std::wstring appendNormalisedPath(std::wstring base, std::wstring_view tail)
{
    if (!base.empty() && base.back() != L'\\')
    {
        base.push_back(L'\\');
    }
    base.append(tail);
    return normalisedPathForCompare(std::move(base));
}

/// @brief Whether `path` is `root` itself or sits below it. Both arguments must
/// already be normalised. The next character after the prefix must be `\`, so
/// "c:\program files (x86)" is not accepted as being under "c:\program files".
/// An empty `root` never matches.
inline bool pathEqualsOrIsUnder(std::wstring_view path, std::wstring_view root) noexcept
{
    if (root.empty() || path.size() < root.size() || path.substr(0, root.size()) != root)
    {
        return false;
    }
    return path.size() == root.size() || path[root.size()] == L'\\';
}

/// @brief The Windows directory, or empty when the query fails or the path does
/// not fit the buffer. Not normalised; callers pass it through
/// @ref normalisedPathForCompare.
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

/// @brief Path of a known folder, or empty on failure. The shell-allocated
/// buffer is freed here, so the returned string owns its own storage.
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

/**
 * @brief Locate the signing certificate inside a PE's embedded PKCS#7 blob.
 *
 * Opens the file's embedded signature, reads the first signer info, and finds
 * the matching certificate by issuer plus serial number in the store the query
 * produced. Only the first signer is inspected, so a dual-signed binary is
 * judged by its primary signature alone.
 *
 * This evaluates no trust: it builds no chain and consults no revocation data.
 * Pair every call with @ref winVerifyTrustOk.
 *
 * @param path  Full path to the image.
 * @param query Receives the store and message handles and closes them on
 *              destruction. It must outlive every use of the returned context.
 * @return A certificate context the caller must release with
 *         `CertFreeCertificateContext`, or null when the file carries no
 *         embedded signature or any query step fails.
 */
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

/// @brief Simple display name of a certificate, or empty when unavailable.
inline std::wstring certSimpleDisplayName(PCCERT_CONTEXT certContext)
{
    if (certContext == nullptr)
    {
        return {};
    }
    const DWORD chars =
        CertGetNameStringW(certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (chars <= 1)
    {
        return {};
    }
    std::vector<wchar_t> buf(chars, L'\0');
    const DWORD written = CertGetNameStringW(
        certContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, buf.data(), chars);
    if (written <= 1)
    {
        return {};
    }
    return std::wstring(buf.data(), written - 1);
}

/**
 * @struct CatAdminGuard
 * @brief RAII owner for a catalog administrator context.
 *
 * Non-copyable and non-movable. Every catalog context obtained through
 * @ref m_Admin must be released before this guard is destroyed.
 */
struct CatAdminGuard
{
    HCATADMIN m_Admin = nullptr;  ///< Owning context handle; released in dtor.

    CatAdminGuard() = default;
    CatAdminGuard(const CatAdminGuard&) = delete;
    CatAdminGuard& operator=(const CatAdminGuard&) = delete;
    ~CatAdminGuard()
    {
        if (m_Admin != nullptr)
        {
            CryptCATAdminReleaseContext(m_Admin, 0);
        }
    }
};

/**
 * @struct FileHandleGuard
 * @brief RAII owner for a `CreateFileW` handle.
 *
 * Non-copyable and non-movable. The destructor closes @ref m_Handle unless it
 * is `INVALID_HANDLE_VALUE` or null, so an unchecked `CreateFileW` result is
 * safe to hand straight to the constructor.
 */
struct FileHandleGuard
{
    HANDLE m_Handle = INVALID_HANDLE_VALUE;  ///< Owning file handle; closed in dtor.

    FileHandleGuard() = default;
    explicit FileHandleGuard(HANDLE handle) noexcept
        : m_Handle(handle)
    {
    }
    FileHandleGuard(const FileHandleGuard&) = delete;
    FileHandleGuard& operator=(const FileHandleGuard&) = delete;
    ~FileHandleGuard()
    {
        if (m_Handle != INVALID_HANDLE_VALUE && m_Handle != nullptr)
        {
            CloseHandle(m_Handle);
        }
    }
};

/**
 * @brief Uppercase-hex-encode a byte buffer as a wide string.
 *
 * Separate from @ref hexEncode (lowercase, narrow) because a catalog member
 * tag is conventionally the uppercase hex of the member's file hash.
 */
inline std::wstring hexEncodeWideUpper(const BYTE* data, DWORD len)
{
    static constexpr wchar_t kHex[] = L"0123456789ABCDEF";
    const std::size_t count = static_cast<std::size_t>(len);
    std::wstring out;
    out.resize(count * 2);
    for (std::size_t i = 0; i < count; ++i)
    {
        out[2 * i] = kHex[data[i] >> 4];
        out[2 * i + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

/**
 * @brief Verify a catalog-signed image and recover its signer display name.
 *
 * Windows inbox binaries (cmd.exe, conhost.exe, powershell.exe) carry no
 * embedded Authenticode signature: their PE certificate table is empty and the
 * signature lives in a system catalog under `%SystemRoot%\System32\CatRoot`.
 * `WinVerifyTrust` with @c WTD_CHOICE_FILE and `CryptQueryObject` with
 * @c CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED both report "no signature" for
 * such an image, so a gate built from those two alone can never pass for an
 * inbox shell.
 *
 * This resolves the containing catalog by file hash and verifies through
 * @c WTD_CHOICE_CATALOG instead, then reads the signer out of the trust
 * provider's state data. The provider has already built and validated the
 * chain, so the catalog's PKCS#7 blob needs no second parse.
 *
 * @par Deliberate narrowing
 * Only SHA-256 catalogs are consulted. Windows still offers the SHA-1 catalog
 * context, but honouring it would let a SHA-1 collision satisfy a gate whose
 * whole purpose is publisher pinning.
 *
 * @par One catalog only
 * Only the first catalog reported for the image hash is verified; the
 * enumeration does not continue. Servicing can leave a stale catalog first, and
 * that fails the whole check even when a later catalog would validate.
 *
 * @param path         Full path to the image to verify.
 * @param publisherOut Receives the signer's simple display name on success.
 *                     Left untouched on failure.
 * @return true iff the first catalog holding the image's hash validates
 *         against an OS-trusted root and a signer name was recovered. Fails
 *         closed on every error.
 */
inline bool catalogTrustOk(const std::wstring& path, std::wstring& publisherOut)
{
    CatAdminGuard admin;
    GUID subsystem = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext2(
            &admin.m_Admin, &subsystem, BCRYPT_SHA256_ALGORITHM, nullptr, 0) ||
        admin.m_Admin == nullptr)
    {
        return false;
    }

    const FileHandleGuard file(CreateFileW(path.c_str(),
                                           GENERIC_READ,
                                           FILE_SHARE_READ | FILE_SHARE_DELETE,
                                           nullptr,
                                           OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL,
                                           nullptr));
    if (file.m_Handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    // First call sizes the digest; it reports failure by design, so only the
    // returned length is meaningful here.
    DWORD hashBytes = 0;
    CryptCATAdminCalcHashFromFileHandle2(admin.m_Admin, file.m_Handle, &hashBytes, nullptr, 0);
    if (hashBytes == 0)
    {
        return false;
    }
    std::vector<BYTE> hash(hashBytes);
    if (!CryptCATAdminCalcHashFromFileHandle2(
            admin.m_Admin, file.m_Handle, &hashBytes, hash.data(), 0))
    {
        return false;
    }

    // An image can appear in several catalogs, because servicing leaves stale
    // ones behind. Only the first catalog holding the hash is verified: the
    // enumeration does not continue, so a first hit whose own signature fails
    // makes this check fail rather than moving on to the next catalog.
    HCATINFO catalog =
        CryptCATAdminEnumCatalogFromHash(admin.m_Admin, hash.data(), hashBytes, 0, nullptr);
    if (catalog == nullptr)
    {
        return false;
    }
    CATALOG_INFO catalogInfo{};
    catalogInfo.cbStruct = sizeof(catalogInfo);
    const bool haveCatalogInfo = CryptCATCatalogInfoFromContext(catalog, &catalogInfo, 0) != FALSE;
    CryptCATAdminReleaseCatalogContext(admin.m_Admin, catalog, 0);
    if (!haveCatalogInfo)
    {
        return false;
    }

    const std::wstring memberTag = hexEncodeWideUpper(hash.data(), hashBytes);

    WINTRUST_CATALOG_INFO catalogChoice{};
    catalogChoice.cbStruct = sizeof(catalogChoice);
    catalogChoice.pcwszCatalogFilePath = catalogInfo.wszCatalogFile;
    catalogChoice.pcwszMemberFilePath = path.c_str();
    catalogChoice.pcwszMemberTag = memberTag.c_str();
    catalogChoice.hMemberFile = file.m_Handle;
    catalogChoice.pbCalculatedFileHash = hash.data();
    catalogChoice.cbCalculatedFileHash = hashBytes;
    // Measured: leaving hCatAdmin null makes the SHA-256 provider path report
    // TRUST_E_NOSIGNATURE even for a catalog that demonstrably holds the hash.
    catalogChoice.hCatAdmin = admin.m_Admin;

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // Revocation and provider flags mirror winVerifyTrustOk so the catalog
    // path is not a softer check than the embedded one.
    WINTRUST_DATA data{};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &catalogChoice;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
    data.dwUIContext = WTD_UICONTEXT_EXECUTE;

    const LONG status = WinVerifyTrust(nullptr, &actionId, &data);

    std::wstring publisher;
    if (status == ERROR_SUCCESS)
    {
        CRYPT_PROVIDER_DATA* provider = WTHelperProvDataFromStateData(data.hWVTStateData);
        if (provider != nullptr)
        {
            CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(provider, 0, FALSE, 0);
            if (signer != nullptr && signer->csCertChain > 0)
            {
                const CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(signer, 0);
                if (cert != nullptr)
                {
                    publisher = certSimpleDisplayName(cert->pCert);
                }
            }
        }
    }

    // Must run before the state data (and the chain read above) is released.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &actionId, &data);

    if (status != ERROR_SUCCESS || publisher.empty())
    {
        return false;
    }
    publisherOut = std::move(publisher);
    return true;
}

}  // namespace detail

/**
 * @brief Extract a SHA-256 SubjectPublicKeyInfo thumbprint of the publisher
 *        cert from a signed PE on disk.
 *
 * The returned thumbprint is 64 lowercase hex chars bound to the publisher's
 * public key, not to the CN and not to the cert serial. That is the right
 * granularity for "two binaries signed by the same publisher": a renewal that
 * keeps the key still matches, while a reissue with a fresh key does not.
 *
 * @warning This reads the certificate only. It builds no chain and consults no
 *          revocation data, so a thumbprint alone proves nothing about trust -
 *          an attacker can self-sign a binary and still get one. Every caller
 *          runs @ref winVerifyTrustOk first.
 *
 * @param path Full path to the signed image.
 * @return 64 lowercase hex chars, or an empty string when the file carries no
 *         embedded signature or any crypto step fails. Callers treat "no
 *         identity" as "dev/unsigned mode" - the surrounding policy decides
 *         whether to fail open or closed.
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
 * Used only for browser-vendor and shell-vendor pinning, and always alongside
 * @ref winVerifyTrustOk: the display name alone is not a trust decision,
 * because any self-signed certificate can carry an arbitrary subject name.
 *
 * Reads the embedded signature only. A catalog-signed image yields an empty
 * name here; @ref detail::catalogTrustOk recovers it for those.
 *
 * @param path Full path to the signed image.
 * @return The signer's simple display name, or empty on any failure.
 */
inline std::wstring extractSignerPublisherFromFile(const std::wstring& path)
{
    detail::CryptQueryGuard query;
    PCCERT_CONTEXT certContext = detail::findSignerCertificate(path, query);
    if (certContext == nullptr)
    {
        return {};
    }

    std::wstring publisher = detail::certSimpleDisplayName(certContext);
    CertFreeCertificateContext(certContext);
    return publisher;
}

/**
 * @brief Build the SPKI thumbprint for the calling module (this exe).
 *
 * This validates first, unlike @ref extractSignerIdentityFromFile: the
 * thumbprint comes back only after @ref winVerifyTrustOk accepts the running
 * image.
 *
 * @return 64 lowercase hex chars, or empty when the exe is unsigned, untrusted
 *         or revoked. Callers then degrade to dev-mode tolerance rather than
 *         refuse to function; a build compiled with
 *         @c SEAL_REQUIRE_SIGNED_PEER refuses to start the bridge instead.
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
 * PROCESS_QUERY_LIMITED_INFORMATION is the minimum right
 * QueryFullProcessImageNameW honours, and it works across integrity-level
 * boundaries within the same user.
 *
 * @warning The handle is opened and closed inside the call, so the PID may
 *          already be recycled by the time the caller uses the result. A call
 *          site that needs a stable identity opens the process once and keeps
 *          it pinned instead (@c seal::signer::PinnedProcess in ProcessPin.hpp).
 *
 * @return Full Win32 image path, or empty when the process is gone or the
 *         handle cannot be opened.
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
 * Windows recycles PIDs and never invalidates the stored parent field, so the
 * result is a hint valid only at the instant of the snapshot. The bridge's
 * chain walk therefore also compares creation times: a "parent" created later
 * than its own child is a recycled link and is rejected.
 *
 * @par Cost
 * One full process-table snapshot per call, so a chain walk of depth N takes N
 * snapshots.
 *
 * @return The parent PID recorded for @p childPid, or 0 when that process is
 *         not in the snapshot or the snapshot itself failed.
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
 * @enum BrowserKind
 * @brief A specific browser recognised by @ref isKnownBrowserImage.
 * @ingroup Utilities
 *
 * Each value names one launcher in the allow-list. The bridge attributes an
 * accepted connection to a kind so the UI can show a per-browser status dot.
 * `Unknown` is index 0 and `Count` is the sentinel size that dimensions the
 * bridge's per-kind connection-count array, so `Count` must stay last and no
 * value may carry an explicit number.
 *
 * @par Single source of truth
 * @ref kBrowserMetadata is the table, and @ref identifyBrowser,
 * @ref isKnownBrowserImage, @ref browserKindToken, @ref browserMetadata and
 * @ref isChromiumBrowser all scan it, so they cannot drift. Adding a browser
 * takes four edits: an enumerator here, a row in the table (whose fixed length
 * must be bumped), a vendor case in @ref browserPublisherMatches, which keeps
 * its own switch, and a `case` in `standardBrowserPaths()` (src/CliModes.cpp).
 * That last switch ends in `default:`, so an omission still compiles: the
 * browser is then detected only through its `App Paths` registry key, and an
 * installer that registers none is reported as not installed. `Unknown` and
 * `Count` have no row and both map to the token `"unknown"`.
 *
 * @par Kind / image / logfmt token
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
 * @enum BrowserEngineFamily
 * @brief Browser engine family, which selects the native-messaging manifest
 *        and registry format.
 * @ingroup Utilities
 *
 * Every @ref BrowserMetadata row carries one family. Only the Chromium family
 * is installable today; the Gecko rows exist for attribution only.
 */
enum class BrowserEngineFamily
{
    Chromium,  ///< Uses `allowed_origins` and Chromium-family registry roots.
    Gecko      ///< Uses `allowed_extensions`; deliberately not installed yet.
};

/**
 * @struct BrowserMetadata
 * @brief Canonical metadata shared by peer attribution, installation, and QML.
 * @ingroup Utilities
 *
 * One row per @ref BrowserKind that has an image name. Gecko kinds stay in the
 * trust and attribution table, but carry no registry subkey because seal does
 * not currently ship a working Gecko native-host manifest. An empty registry
 * entry is an explicit "unsupported" marker, never a guessed key.
 *
 * Every field is a non-owning view into a static string literal, so a
 * @ref BrowserMetadata copy is safe to hold for the process lifetime.
 */
struct BrowserMetadata
{
    BrowserKind m_Kind;                  ///< The enumerator this row describes.
    std::wstring_view m_ImageName;       ///< Lowercase launcher basename, e.g. `chrome.exe`.
    std::string_view m_DisplayName;      ///< Human-readable name shown in the UI.
    std::string_view m_Token;            ///< Stable lowercase logfmt token.
    std::string_view m_BrandIconToken;   ///< Key into the brand-icon resolver.
    BrowserEngineFamily m_EngineFamily;  ///< Selects the manifest / registry format.
    /// `HKCU` subkeys for the `com.seal.fill` native-messaging host. The second
    /// slot is used only by browsers with two roots (Opera Stable and GX); an
    /// empty view means "no further key". Both empty means unsupported.
    std::array<std::wstring_view, 2> m_NativeMessagingSubKeys;
    std::string_view m_ExtensionsPage;  ///< In-browser URL of the extensions page.
};

/**
 * @brief Canonical browser table; the single source of truth for browser
 *        identity, attribution, and native-host registration.
 *
 * Opera has distinct Stable and GX roots, so it is the only row that fills the
 * second registry slot. Thorium uses Chromium's Windows native-messaging
 * registry root, matching its Chromium host-discovery base. The five Gecko rows
 * carry no registry subkey - see @ref BrowserMetadata.
 */
inline constexpr std::array<BrowserMetadata, 12> kBrowserMetadata = {{
    {BrowserKind::Chrome,
     L"chrome.exe",
     "Chrome",
     "chrome",
     "chrome",
     BrowserEngineFamily::Chromium,
     {L"Software\\Google\\Chrome\\NativeMessagingHosts\\com.seal.fill", L""},
     "chrome://extensions/"},
    {BrowserKind::Edge,
     L"msedge.exe",
     "Edge",
     "edge",
     "edge",
     BrowserEngineFamily::Chromium,
     {L"Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.seal.fill", L""},
     "edge://extensions/"},
    {BrowserKind::Brave,
     L"brave.exe",
     "Brave",
     "brave",
     "brave",
     BrowserEngineFamily::Chromium,
     {L"Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\com.seal.fill", L""},
     "brave://extensions/"},
    {BrowserKind::Opera,
     L"opera.exe",
     "Opera",
     "opera",
     "opera",
     BrowserEngineFamily::Chromium,
     {L"Software\\Opera Software\\Opera Stable\\NativeMessagingHosts\\com.seal.fill",
      L"Software\\Opera Software\\Opera GX Stable\\NativeMessagingHosts\\com.seal.fill"},
     "opera://extensions/"},
    {BrowserKind::Vivaldi,
     L"vivaldi.exe",
     "Vivaldi",
     "vivaldi",
     "vivaldi",
     BrowserEngineFamily::Chromium,
     {L"Software\\Vivaldi\\NativeMessagingHosts\\com.seal.fill", L""},
     "vivaldi://extensions/"},
    {BrowserKind::Thorium,
     L"thorium.exe",
     "Thorium",
     "thorium",
     "thorium",
     BrowserEngineFamily::Chromium,
     {L"Software\\Chromium\\NativeMessagingHosts\\com.seal.fill", L""},
     "chrome://extensions/"},
    {BrowserKind::Chromium,
     L"chromium.exe",
     "Chromium",
     "chromium",
     "chromium",
     BrowserEngineFamily::Chromium,
     {L"Software\\Chromium\\NativeMessagingHosts\\com.seal.fill", L""},
     "chrome://extensions/"},
    {BrowserKind::Firefox,
     L"firefox.exe",
     "Firefox",
     "firefox",
     "firefox-browser",
     BrowserEngineFamily::Gecko,
     {L"", L""},
     "about:addons"},
    {BrowserKind::LibreWolf,
     L"librewolf.exe",
     "LibreWolf",
     "librewolf",
     "librewolf",
     BrowserEngineFamily::Gecko,
     {L"", L""},
     "about:addons"},
    {BrowserKind::Waterfox,
     L"waterfox.exe",
     "Waterfox",
     "waterfox",
     "waterfox",
     BrowserEngineFamily::Gecko,
     {L"", L""},
     "about:addons"},
    {BrowserKind::Floorp,
     L"floorp.exe",
     "Floorp",
     "floorp",
     "floorp",
     BrowserEngineFamily::Gecko,
     {L"", L""},
     "about:addons"},
    {BrowserKind::Zen,
     L"zen.exe",
     "Zen",
     "zen",
     "zen",
     BrowserEngineFamily::Gecko,
     {L"", L""},
     "about:addons"},
}};

/// @brief Canonical metadata row for @p kind, or null for Unknown and Count.
/// The returned pointer targets static storage and never dangles.
inline const BrowserMetadata* browserMetadata(BrowserKind kind) noexcept
{
    for (const auto& browser : kBrowserMetadata)
    {
        if (browser.m_Kind == kind)
        {
            return &browser;
        }
    }
    return nullptr;
}

/// @brief Whether @p kind uses the Chromium native-messaging format.
/// Unknown and Count have no row, so both report false.
inline bool isChromiumBrowser(BrowserKind kind) noexcept
{
    const BrowserMetadata* browser = browserMetadata(kind);
    return browser != nullptr && browser->m_EngineFamily == BrowserEngineFamily::Chromium;
}

/**
 * @brief Whether an image-path basename matches a known browser launcher.
 *
 * Case-insensitive ASCII comparison of the basename against
 * @ref kBrowserMetadata. Name only - no signature, no path constraint.
 *
 * @param imagePath Full path or basename of the process image.
 * @return true iff the basename equals a table row's image name.
 */
inline bool isKnownBrowserImage(const std::wstring& imagePath)
{
    const std::wstring basename = detail::lowerBasename(imagePath);
    for (const auto& browser : kBrowserMetadata)
    {
        if (basename == browser.m_ImageName)
        {
            return true;
        }
    }
    return false;
}

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
    for (const auto& browser : kBrowserMetadata)
    {
        if (basename == browser.m_ImageName)
        {
            return browser.m_Kind;
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
    const BrowserMetadata* browser = browserMetadata(kind);
    return browser == nullptr ? std::string_view("unknown") : browser->m_Token;
}

/**
 * @brief Verify that a signer display name belongs to the expected browser vendor.
 *
 * The input is the Authenticode signer simple display name returned by
 * @ref extractSignerPublisherFromFile. This is a second gate after
 * @ref winVerifyTrustOk and defeats the "trusted executable renamed to
 * chrome.exe" class: the filename must identify a browser family and the
 * signer must be that family's vendor.
 *
 * The accepted vendor names are a hand-maintained switch, not part of
 * @ref kBrowserMetadata, so a new browser needs a case added here too. Some
 * kinds accept two names because the vendor renamed (Waterfox, Floorp) or the
 * build can come from either publisher (Chromium, Thorium).
 *
 * @param kind      Browser classification from @ref identifyBrowser. Unknown
 *                  and Count always fail.
 * @param publisher Signer display name. An empty name always fails.
 * @return true iff @p publisher is an accepted vendor name for @p kind,
 *         compared ignoring ASCII case.
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
 *
 * Three gates, all of which must pass: the basename identifies a known
 * browser, @ref winVerifyTrustOk accepts the file, and the Authenticode signer
 * display name is that browser's vendor. The name gate alone would accept any
 * signed binary renamed to `chrome.exe`; the trust gate alone would accept any
 * signed binary at all.
 *
 * Embedded signatures only - browsers ship one, so there is no catalog
 * fallback here (unlike @ref isTrustedShellImage). Path is not constrained: a
 * browser may legitimately live in a per-user install directory.
 *
 * @param imagePath Full path to the candidate browser image.
 * @return true iff all three gates pass.
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
 * @enum ShellKind
 * @brief A specific Windows shell executable tolerated as a browser-launch hop.
 * @ingroup Utilities
 *
 * Chromium sometimes wraps a native-messaging host launch in a shell, so the
 * bridge's ancestor walk passes through these images while it looks for the
 * browser. Each kind has its own path allow-list in @ref isShellPathAllowed;
 * a shell is never itself an acceptable endpoint of the walk.
 *
 * @par Gate ladder
 * Four helpers share the "shell" name and layer, each adding one check. Only
 * the last is a trust decision, and it is the one the ancestor walk calls.
 * @verbatim
 *   identifyShell(path)          basename only          -> ShellKind
 *     |
 *   isShellPathAllowed(k, path)  per-kind allow-list    -> bool
 *                                (exact path for the inbox
 *                                shells, subtree for pwsh)
 *     |
 *   isShellImage(path)           both of the above      -> bool
 *     |
 *   isTrustedShellImage(path)    both, plus a signature -> bool
 *                                carrier (embedded, else
 *                                catalog) whose publisher
 *                                passes shellPublisherMatches
 * @endverbatim
 */
enum class ShellKind
{
    Unknown = 0,        ///< Not a recognised shell image.
    Cmd,                ///< cmd.exe
    WindowsPowerShell,  ///< powershell.exe (inbox, v1.0)
    PowerShell,         ///< pwsh.exe (PowerShell 7)
    ConsoleHost         ///< conhost.exe
};

/**
 * @brief Classify a process image as a shell hop candidate by basename.
 *
 * Basename only, so this is not a trust decision: any file named `cmd.exe`
 * classifies as @ref ShellKind::Cmd. Pair it with @ref isShellPathAllowed, or
 * use @ref isTrustedShellImage, which does both plus the signature check.
 *
 * @param imagePath Full path or basename of the process image.
 * @return The matching @ref ShellKind, or Unknown.
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
 * PowerShell 7 packages commonly report "Microsoft Corporation". Both names
 * are accepted for every kind, so the check is "signed by Microsoft", not
 * "signed by the vendor of this exact shell".
 *
 * @param kind      Shell classification from @ref identifyShell. Unknown always
 *                  fails.
 * @param publisher Signer display name. An empty name always fails.
 * @return true iff @p kind is known and @p publisher is one of the two
 *         accepted Microsoft names, compared ignoring ASCII case.
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
 * enough for a trust decision. Inbox shells must sit at their exact System32
 * or SysWOW64 path under the real Windows directory; PowerShell 7 must be
 * anywhere under a machine-wide `Program Files\PowerShell` (or the x86 root),
 * because its version number is part of the path. Both roots are queried at
 * call time, so a relocated Windows or Program Files install still works.
 *
 * The comparison is textual (see @ref detail::normalisedPathForCompare) and
 * does not resolve symlinks or junctions.
 *
 * @param kind      Shell classification from @ref identifyShell.
 * @param imagePath Full path to the candidate shell image.
 * @return true iff @p imagePath is an allowed location for @p kind. Unknown,
 *         an empty path, and a bare basename all return false.
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
 * Rejects basename-only paths and user-writable lookalike paths. It is the path
 * allow-list only; use @ref isTrustedShellImage for a bridge trust decision.
 *
 * @param imagePath Full path to the candidate shell image.
 * @return true iff the basename classifies as a shell and the path is allowed
 *         for that kind. No signature is checked.
 */
inline bool isShellImage(const std::wstring& imagePath)
{
    const ShellKind kind = identifyShell(imagePath);
    return kind != ShellKind::Unknown && isShellPathAllowed(kind, imagePath);
}

/**
 * @brief Full shell-hop image trust check for the native-messaging boundary.
 *
 * Chromium on Windows sometimes wraps a native-messaging host launch in
 * cmd.exe, depending on the Chrome version, the manifest layout and
 * intermediate path quoting. The bridge then sees the host's parent as cmd.exe
 * and the real browser as the grandparent, so the accept loop walks the chain
 * through trusted shell hops looking for a signed-browser ancestor.
 *
 * @par Two signature carriers
 * Both must be honoured, because the allowed shells are split across them:
 *
 * - **Embedded** - PowerShell 7 under Program Files ships an ordinary
 *   embedded Authenticode signature.
 * - **Catalog** - every inbox shell (cmd.exe, conhost.exe, the v1.0
 *   powershell.exe) has an empty PE certificate table and is signed only by a
 *   system catalog. Checking embedded signatures alone makes this function
 *   unsatisfiable for them, which silently kills the whole shell traversal
 *   above; see @ref detail::catalogTrustOk.
 *
 * Neither carrier is the weaker check: both require a chain that validates to
 * an OS-trusted root, and both feed @ref shellPublisherMatches, so the
 * publisher must be Microsoft either way. The embedded carrier runs first and
 * the catalog carrier only on its failure, so a PowerShell 7 hop costs one
 * verify and an inbox hop costs two.
 *
 * @param imagePath Full path to the candidate shell image.
 * @return true iff the basename classifies as a shell, the path is allowed for
 *         that kind, and one of the two signature carriers yields a Microsoft
 *         publisher. Fails closed on every error.
 */
inline bool isTrustedShellImage(const std::wstring& imagePath)
{
    const ShellKind kind = identifyShell(imagePath);
    if (kind == ShellKind::Unknown || !isShellPathAllowed(kind, imagePath))
    {
        return false;
    }
    if (winVerifyTrustOk(imagePath) &&
        shellPublisherMatches(kind, extractSignerPublisherFromFile(imagePath)))
    {
        return true;
    }
    std::wstring catalogPublisher;
    if (!detail::catalogTrustOk(imagePath, catalogPublisher))
    {
        return false;
    }
    return shellPublisherMatches(kind, catalogPublisher);
}

}  // namespace seal::signer
