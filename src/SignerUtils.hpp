#pragma once

/**
 * @brief Signer verification shared by the bridge and native host.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * SPKI identity is SHA-256 of SubjectPublicKeyInfo, encoded as 64 lowercase hex
 * characters. Certificate renewal preserves identity only if the public key stays
 * the same. Trust checks use whole-chain revocation from the OS cache; these
 * helpers do not refresh CRL/OCSP data.
 *
 * The host verifies the pipe server signer. The bridge verifies the relay signer
 * and browser ancestry. The host also checks that the claimed browser owns the
 * stdio pipe, which rejects a forged parent process.
 *
 * Empty or zero results mean verification failed or identity is unavailable.
 * Signed releases fail closed; unsigned development builds may tolerate them.
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

// mscat.h needs wincrypt.h first; keep separate include groups to preserve that order.
#include <mscat.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// declare the GUID if this SDK does not provide it.
#ifndef WINTRUST_ACTION_GENERIC_VERIFY_V2
// clang-format off
#define WINTRUST_ACTION_GENERIC_VERIFY_V2                            \
    { 0xaac56b, 0xcd44, 0x11d0,                                      \
      { 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee } }
// clang-format on
#endif

// catalog subsystem GUID; SDK header placement varies.
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
 * @brief Owns the store and message handles returned by CryptQueryObject.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Release certificate contexts before this guard is destroyed.
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

/**
 * @fn wchar_t asciiLower(wchar_t c) noexcept
 * @brief ASCII-range tolower for wchar_t.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Leaves non-ASCII chars unchanged.
 */
inline wchar_t asciiLower(wchar_t c) noexcept
{
    return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
}

/**
 * @fn std::wstring lowerBasename(const std::wstring& imagePath)
 * @brief Lowercased (ASCII) basename of an image path, or empty when the path is empty.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Shared by the browser/shell image classifiers below.
 */
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

/**
 * @fn bool matchesAny(std::wstring_view basename,
 *     const std::array<std::wstring_view, N>& names) noexcept
 * @brief Whether basename exactly equals any entry in names.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Case-sensitive; callers pass an already-lowercased basename.
 */
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
 * @fn bool winVerifyTrustOk(const std::wstring& path)
 * @brief Validate an embedded Authenticode signature using cached revocation.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Checks the whole chain against OS-trusted roots without network retrieval.
 * Use `detail::catalogTrustOk` for catalog signatures.
 *
 * @return `true` only when chain validation and cached revocation checks pass.
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

/**
 * @fn char hexNibble(unsigned char v) noexcept
 * @brief Lowercase-hex character for the low nibble of v.
 * @author Alex (<https://github.com/lextpf>)
 */
inline char hexNibble(unsigned char v) noexcept
{
    static constexpr char kHex[] = "0123456789abcdef";
    return kHex[v & 0x0F];
}

/**
 * @fn std::string hexEncode(const unsigned char* data, std::size_t len)
 * @brief Encode bytes as lowercase hexadecimal.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return `2 * len` ASCII characters.
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

/**
 * @fn bool asciiIEquals(std::wstring_view a, std::wstring_view b) noexcept
 * @brief Case-insensitive ASCII comparison.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Bytes >= 0x80 compare exactly, so two strings that differ only in non-ASCII case are reported
 * unequal.
 */
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

/**
 * @fn bool matchesAnyAsciiI(std::wstring_view value,
 *     const std::array<std::wstring_view, N>& expected) noexcept
 * @brief Whether value equals any entry of expected, ignoring ASCII case.
 * @author Alex (<https://github.com/lextpf>)
 *
 * An empty `value` never matches, so a failed signer lookup cannot satisfy a publisher gate that
 * happens to list an empty string.
 */
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

/**
 * @fn std::wstring normalisedPathForCompare(std::wstring path)
 * @brief Normalize a path for textual equality checks.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Strips a leading \\?\ or \??\ prefix, turns / into \, lowercases ASCII,
 * and drops trailing separators.
 * It resolves no symlink, junction, 8.3 short name or `..`, so it is a textual comparison aid
 * only, never a security boundary on its own.
 */
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

/**
 * @fn std::wstring appendNormalisedPath(std::wstring base, std::wstring_view tail)
 * @brief Join and normalize a path for textual comparison.
 * @author Alex (<https://github.com/lextpf>)
 */
inline std::wstring appendNormalisedPath(std::wstring base, std::wstring_view tail)
{
    if (!base.empty() && base.back() != L'\\')
    {
        base.push_back(L'\\');
    }
    base.append(tail);
    return normalisedPathForCompare(std::move(base));
}

/**
 * @fn bool pathEqualsOrIsUnder(std::wstring_view path, std::wstring_view root) noexcept
 * @brief Whether path is root itself or sits below it.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Both arguments must already be normalised. The next character after the prefix must be `\`, so
 * "c:\program files (x86)" is not accepted as being under "c:\program files". An empty `root`
 * never matches.
 */
inline bool pathEqualsOrIsUnder(std::wstring_view path, std::wstring_view root) noexcept
{
    if (root.empty() || path.size() < root.size() || path.substr(0, root.size()) != root)
    {
        return false;
    }
    return path.size() == root.size() || path[root.size()] == L'\\';
}

/**
 * @fn std::wstring windowsDirectory()
 * @brief The Windows directory, or empty when the query fails or the path does not fit the buffer.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Not normalised; callers pass it through `normalisedPathForCompare`.
 */
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

/**
 * @fn std::wstring knownFolderPath(REFKNOWNFOLDERID folderId)
 * @brief Path of a known folder, or empty on failure.
 * @author Alex (<https://github.com/lextpf>)
 *
 * The shell-allocated buffer is freed here, so the returned string owns its own storage.
 */
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
 * @fn PCCERT_CONTEXT findSignerCertificate(const std::wstring& path, CryptQueryGuard& query)
 * @brief Read the first signer certificate from an embedded PE signature.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Performs no trust check. Pair with `winVerifyTrustOk`.
 *
 * @param query Owns query handles; must outlive the returned context.
 * @return Caller-owned context; release with `CertFreeCertificateContext`.
 *         null if the signature is absent or any query fails.
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

/**
 * @fn std::wstring certSimpleDisplayName(PCCERT_CONTEXT certContext)
 * @brief Simple display name of a certificate, or empty when unavailable.
 * @author Alex (<https://github.com/lextpf>)
 */
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
 * @brief Owns a catalog administrator context.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Release all catalog contexts before this guard is destroyed.
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
 * @brief Closes a file handle unless it is null or INVALID_HANDLE_VALUE.
 * @author Alex (<https://github.com/lextpf>)
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
 * @fn std::wstring hexEncodeWideUpper(const BYTE* data, DWORD len)
 * @brief Encode a catalog member hash as uppercase wide hexadecimal.
 * @author Alex (<https://github.com/lextpf>)
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
 * @fn bool catalogTrustOk(const std::wstring& path, std::wstring& publisherOut)
 * @brief Validate a catalog signature and recover its publisher name.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Resolves the catalog by SHA-256 file hash. Only the first matching catalog is
 * checked; a stale or invalid first catalog fails the check. Trust and cached
 * revocation requirements match `winVerifyTrustOk`.
 *
 * @param publisherOut Receives the name on success; unchanged on failure.
 * @return `false` if catalog trust or publisher extraction fails.
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

    // only the returned size is meaningful on this sizing call.
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

    // verify only the first matching catalog; a stale first entry fails closed.
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
    // the SHA-256 provider requires hCatAdmin; null can produce TRUST_E_NOSIGNATURE.
    catalogChoice.hCatAdmin = admin.m_Admin;

    GUID actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // use the same trust requirements as embedded signature verification.
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

    // release the catalog before closing provider state.
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
 * @fn std::string extractSignerIdentityFromFile(const std::wstring& path)
 * @brief Read the publisher public-key identity from an embedded PE signature.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return 64 lowercase hex characters, or empty on absent signature or failure.
 * @warning Performs no trust or revocation check. Require `winVerifyTrustOk`
 *          before using this identity for authentication.
 */
inline std::string extractSignerIdentityFromFile(const std::wstring& path)
{
    detail::CryptQueryGuard query;
    PCCERT_CONTEXT certContext = detail::findSignerCertificate(path, query);
    if (certContext == nullptr)
    {
        return {};
    }

    // Hash the DER-encoded public key so renewal with the same key preserves identity.
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
 * @fn std::wstring extractSignerPublisherFromFile(const std::wstring& path)
 * @brief Read the publisher name from an embedded PE signature.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return Empty if the signature is absent or the query fails.
 * @warning A name alone proves no trust. Require `winVerifyTrustOk` first.
 * @see detail::catalogTrustOk
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
 * @fn std::string readOwnSignerIdentity()
 * @brief Validate this executable and return its SPKI identity.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return 64 lowercase hex characters; empty if unsigned, untrusted or revoked.
 *         `SEAL_REQUIRE_SIGNED_PEER` makes an empty identity prevent bridge startup.
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
 * @fn std::wstring resolveProcessPath(DWORD pid)
 * @brief Query an image path using PROCESS_QUERY_LIMITED_INFORMATION.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return Full Win32 image path, or empty on query failure.
 * @warning The process handle closes before return. Use `PinnedProcess` when
 *          later checks must refer to the same process despite PID reuse.
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
 * @fn DWORD resolveParentPid(DWORD childPid)
 * @brief Query the parent PID from one Toolhelp32 process snapshot.
 * @author Alex (<https://github.com/lextpf>)
 *
 * The stored PID may be recycled. Ancestry checks must compare creation times
 * and reject a parent created after its child.
 *
 * @return 0 if the child is absent or the snapshot fails.
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
 * @brief Browser kinds used for attribution and connection counts.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * Keep `Unknown` at zero and `Count` last, without explicit enum values.
 * New kinds also need `kBrowserMetadata`, `browserPublisherMatches`, and
 * `standardBrowserPaths` entries. Omitted standard paths leave registry-only
 * installation detection.
 *
 * | BrowserKind | Image basename  | Logfmt token |
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
 * @brief Selects the native-messaging manifest and registry format.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * Only Chromium supports installation; Gecko kinds support attribution.
 */
enum class BrowserEngineFamily
{
    Chromium,  ///< Uses `allowed_origins` and Chromium-family registry roots.
    Gecko      ///< Uses `allowed_extensions`; deliberately not installed yet.
};

/**
 * @struct BrowserMetadata
 * @brief Browser identity and native-host registration metadata.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * String views refer to static literals. Empty registry entries mean unsupported;
 * Gecko kinds have no native-host registration.
 */
struct BrowserMetadata
{
    BrowserKind m_Kind;                  ///< The enumerator this row describes.
    std::wstring_view m_ImageName;       ///< Lowercase launcher basename, e.g. `chrome.exe`.
    std::string_view m_DisplayName;      ///< Human-readable name shown in the UI.
    std::string_view m_Token;            ///< Stable lowercase logfmt token.
    std::string_view m_BrandIconToken;   ///< Key into the brand-icon resolver.
    BrowserEngineFamily m_EngineFamily;  ///< Selects the manifest / registry format.
    /**
     * `HKCU` subkeys for the `com.seal.fill` native-messaging host. The second
     * slot is used only by browsers with two roots (Opera stable and GX); an
     * empty view means "no further key". Both empty means unsupported.
     */
    std::array<std::wstring_view, 2> m_NativeMessagingSubKeys;
    std::string_view m_ExtensionsPage;  ///< In-browser URL of the extensions page.
};

/**
 * @brief Shared browser identity and native-host registration table.
 *
 * Opera uses both registry slots. Thorium uses the Chromium registry root.
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

/**
 * @fn const BrowserMetadata* browserMetadata(BrowserKind kind) noexcept
 * @brief Canonical metadata row for kind, or null for Unknown and Count.
 * @author Alex (<https://github.com/lextpf>)
 *
 * The returned pointer targets static storage and never dangles.
 */
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

/**
 * @fn bool isChromiumBrowser(BrowserKind kind) noexcept
 * @brief Whether kind uses the Chromium native-messaging format.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Unknown and Count have no row, so both report false.
 */
inline bool isChromiumBrowser(BrowserKind kind) noexcept
{
    const BrowserMetadata* browser = browserMetadata(kind);
    return browser != nullptr && browser->m_EngineFamily == BrowserEngineFamily::Chromium;
}

/**
 * @fn bool isKnownBrowserImage(const std::wstring& imagePath)
 * @brief Match a browser basename using ASCII case folding.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Checks neither path nor signature; this result is not a trust decision.
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
 * @fn BrowserKind identifyBrowser(const std::wstring& imagePath)
 * @brief Classify a browser basename using ASCII case folding.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return `BrowserKind::Unknown` when no table entry matches.
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
 * @fn std::string_view browserKindToken(BrowserKind kind) noexcept
 * @brief Stable lowercase browser token.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return `unknown` for `Unknown` and `Count`.
 */
inline std::string_view browserKindToken(BrowserKind kind) noexcept
{
    const BrowserMetadata* browser = browserMetadata(kind);
    return browser == nullptr ? std::string_view("unknown") : browser->m_Token;
}

/**
 * @fn bool browserPublisherMatches(BrowserKind kind, std::wstring_view publisher) noexcept
 * @brief Match a trusted signer name to the browser vendor.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Require `winVerifyTrustOk` first. This additional gate rejects trusted binaries
 * renamed to a browser basename. New browser kinds need a publisher case here.
 *
 * @return `false` for an empty name, `Unknown`, or `Count`; comparison ignores ASCII case.
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
 * @fn bool isTrustedBrowserImage(const std::wstring& imagePath)
 * @brief Require a browser basename, trusted signature, and matching vendor.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Accepts embedded signatures only. Installation paths are unrestricted to allow
 * per-user browser installations.
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
 * @brief Shell kinds allowed as intermediate browser-launch hops.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * A shell cannot terminate the ancestor walk. Only `isTrustedShellImage` applies
 * all path and signature checks.
 *
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
 * @fn ShellKind identifyShell(const std::wstring& imagePath)
 * @brief Classify a shell basename without checking trust.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return `ShellKind::Unknown` when unrecognized.
 * @see isTrustedShellImage
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
 * @fn bool shellPublisherMatches(ShellKind kind, std::wstring_view publisher) noexcept
 * @brief Accept Microsoft Windows or Microsoft Corporation for a known shell.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return `false` for an empty publisher or `Unknown`; comparison ignores ASCII case.
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
 * @fn bool isShellPathAllowed(ShellKind kind, const std::wstring& imagePath)
 * @brief Restrict shell hops to machine installation paths.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Inbox shells require exact System32 or SysWOW64 paths. PowerShell 7 may be
 * anywhere below a machine `Program Files\PowerShell` root. Roots are queried
 * at call time. Textual comparison resolves neither symlinks nor junctions.
 *
 * @return `false` for `Unknown`, empty paths, or bare basenames.
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
 * @fn bool isShellImage(const std::wstring& imagePath)
 * @brief Check shell basename and allowed path without checking signatures.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @see isTrustedShellImage
 */
inline bool isShellImage(const std::wstring& imagePath)
{
    const ShellKind kind = identifyShell(imagePath);
    return kind != ShellKind::Unknown && isShellPathAllowed(kind, imagePath);
}

/**
 * @fn bool isTrustedShellImage(const std::wstring& imagePath)
 * @brief Require an allowed shell path and a trusted Microsoft signature.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Tries the embedded signature first, then a SHA-256 catalog signature. Both
 * require OS trust, cached revocation checks, and `shellPublisherMatches`.
 *
 * @return `false` if no signature carrier passes.
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
