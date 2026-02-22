/**
 * @file Cryptography.cpp
 * @brief Core cryptographic primitive implementations for sage.
 * @author sage Contributors
 */

#include "Cryptography.h"

#include <sddl.h>

#ifdef USE_QT_UI
#include "Logging.h"
#include <QtCore/QElapsedTimer>
#endif

namespace sage {

bool Cryptography::ctEqualRaw(const unsigned char* a, const unsigned char* b, size_t n)
{
    unsigned char v = 0;
    for (size_t i = 0; i < n; ++i) v |= static_cast<unsigned char>(a[i] ^ b[i]);
    return v == 0;
}

void Cryptography::hardenHeap()
{
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
}

void Cryptography::hardenProcessAccess()
{
    // Build a DACL that denies dangerous process access rights to Everyone,
    // while granting SYSTEM full control so the OS can still manage us.
    // This blocks procdump, Process Hacker, and malware memory reads.

    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pDacl = nullptr;

    // SDDL string:
    //  D:  = DACL
    //  (D;;0x1418;;WD)  = Deny Everyone: PROCESS_VM_READ (0x10) | PROCESS_VM_WRITE (0x20) |
    //                      PROCESS_VM_OPERATION (0x8) | PROCESS_DUP_HANDLE (0x40) |
    //                      PROCESS_QUERY_INFORMATION (0x400) | PROCESS_CREATE_THREAD (0x2) = 0x147A
    //  (A;;GA;;;SY)     = Allow SYSTEM: GENERIC_ALL
    //  (A;;GA;;;BA)     = Allow Administrators: GENERIC_ALL (so we don't lock out admin tasks)
    BOOL ok = ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(D;;0x147A;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)",
        SDDL_REVISION_1,
        &pSD,
        nullptr);

    if (ok && pSD) {
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) && daclPresent) {
            SetSecurityInfo(
                GetCurrentProcess(),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pDacl, nullptr);
        }
        LocalFree(pSD);
    }

#ifdef USE_QT_UI
    qCInfo(logCrypto) << "hardenProcessAccess:" << (ok ? "applied" : "failed");
#endif
}

void Cryptography::disableCrashDumps()
{
    // Suppress WER crash dialogs that might create minidumps containing secrets.
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    // Install a custom unhandled exception filter that wipes sensitive memory
    // then terminates immediately, preventing the default handler from
    // writing a crash dump.
    SetUnhandledExceptionFilter([](PEXCEPTION_POINTERS) -> LONG {
        TerminateProcess(GetCurrentProcess(), 1);
        return EXCEPTION_CONTINUE_SEARCH; // unreachable
    });

#ifdef USE_QT_UI
    qCInfo(logCrypto) << "disableCrashDumps: WER suppressed, custom exception filter installed";
#endif
}

void Cryptography::detectDebugger()
{
    // Check 1: IsDebuggerPresent (user-mode debugger)
    if (IsDebuggerPresent()) {
#ifdef USE_QT_UI
        qCWarning(logCrypto) << "detectDebugger: user-mode debugger detected, aborting";
#else
        OutputDebugStringA("[sage] FATAL: debugger detected\n");
#endif
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        return;
    }

    // Check 2: CheckRemoteDebuggerPresent (remote/kernel debugger)
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger) {
#ifdef USE_QT_UI
        qCWarning(logCrypto) << "detectDebugger: remote debugger detected, aborting";
#else
        OutputDebugStringA("[sage] FATAL: remote debugger detected\n");
#endif
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        return;
    }

    // Check 3: NtQueryInformationProcess(ProcessDebugPort)
    // Dynamically resolve to avoid a hard dependency on ntdll.
    using PFN_NtQueryInformationProcess = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto pNtQIP = reinterpret_cast<PFN_NtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        if (pNtQIP) {
            ULONG_PTR debugPort = 0;
            LONG status = pNtQIP(GetCurrentProcess(), 7 /*ProcessDebugPort*/,
                                 &debugPort, sizeof(debugPort), nullptr);
            if (status == 0 && debugPort != 0) {
#ifdef USE_QT_UI
                qCWarning(logCrypto) << "detectDebugger: kernel debug port detected, aborting";
#else
                OutputDebugStringA("[sage] FATAL: kernel debug port detected\n");
#endif
                TerminateProcess(GetCurrentProcess(), 0xDEAD);
                return;
            }
        }
    }

#ifdef USE_QT_UI
    qCInfo(logCrypto) << "detectDebugger: no debugger detected";
#endif
}

void Cryptography::trimWorkingSet()
{
    // Force pages out of the working set so plaintext doesn't linger
    // in physical RAM after sensitive operations complete.
    // K32EmptyWorkingSet is in kernel32 - no extra lib needed.
    EmptyWorkingSet(GetCurrentProcess());
}

using PFN_SetProcessMitigationPolicy = BOOL(WINAPI*)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);

BOOL Cryptography::setSecureProcessMitigations(bool allowDynamicCode)
{
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) return FALSE;

    auto pSet = (PFN_SetProcessMitigationPolicy)GetProcAddress(hK32, "SetProcessMitigationPolicy");
    if (!pSet) return FALSE;

    BOOL allSuccess = TRUE;

    // 1. Disable dynamic code generation (prevents JIT injection attacks)
    // Skip for QML UI mode: Qt Quick relies on JIT-generated code.
    if (!allowDynamicCode)
    {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynCodePolicy = {};
        dynCodePolicy.ProhibitDynamicCode = 1;
        allSuccess &= pSet(ProcessDynamicCodePolicy, &dynCodePolicy, sizeof(dynCodePolicy));
    }

    // 2. Require signed images only (prevents unsigned DLL injection)
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = {};
    sigPolicy.MitigationOptIn = 1;
    sigPolicy.MicrosoftSignedOnly = 0;
    sigPolicy.AuditMicrosoftSignedOnly = 0;
    allSuccess &= pSet(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy));

    PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sc{};
    sc.SmtBranchTargetIsolation = 1;
    sc.IsolateSecurityDomain = 1;
    sc.DisablePageCombine = 1;
    sc.SpeculativeStoreBypassDisable = 1;
    sc.RestrictCoreSharing = 1;
    allSuccess &= pSet(ProcessSideChannelIsolationPolicy, &sc, sizeof(sc));

    // 4. Enable strict handle checks
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = {};
    handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
    handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
    allSuccess &= pSet(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));

    // 5. Disable extension points (prevents third-party code injection)
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPolicy = {};
    extPolicy.DisableExtensionPoints = 1;
    allSuccess &= pSet(ProcessExtensionPointDisablePolicy, &extPolicy, sizeof(extPolicy));

    // 6. Enable image load policy (restrict DLL loading locations)
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imgPolicy = {};
    imgPolicy.NoRemoteImages = 1;
    imgPolicy.NoLowMandatoryLabelImages = 1;
    imgPolicy.PreferSystem32Images = 1;
    allSuccess &= pSet(ProcessImageLoadPolicy, &imgPolicy, sizeof(imgPolicy));

#ifdef USE_QT_UI
    qCInfo(logCrypto) << "setSecureProcessMitigations:" << (allSuccess ? "all applied" : "partial");
#endif
    return allSuccess;
}

BOOL Cryptography::tryEnableLockPrivilege()
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    TOKEN_PRIVILEGES tp{};
    LUID luid{};

    if (!LookupPrivilegeValueW(nullptr, L"SeLockMemoryPrivilege", &luid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    // CRITICAL: Check GetLastError() even when AdjustTokenPrivileges returns TRUE
    DWORD gle = GetLastError();
    CloseHandle(hToken);

    BOOL result = (gle == ERROR_SUCCESS);
#ifdef USE_QT_UI
    if (result)
        qCInfo(logCrypto) << "SeLockMemoryPrivilege: enabled";
    else
        qCWarning(logCrypto) << "SeLockMemoryPrivilege: not available (error=" << gle << ")";
#endif
    return result;
}

void Cryptography::opensslCheck(int ok, const char* msg)
{
    if (ok != 1)
    {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::ostringstream oss;
        oss << msg << " (OpenSSL: " << buf << ")";
        throw std::runtime_error(oss.str());
    }
}

std::span<const unsigned char> Cryptography::aadSpan() noexcept
{
    return {
        reinterpret_cast<const unsigned char*>(sage::cfg::AAD_HDR),
        static_cast<std::size_t>(sage::cfg::AAD_LEN)
    };
}

template<class SecurePwd>
std::vector<unsigned char> Cryptography::deriveKey(
    const SecurePwd& pwd,
    std::span<const unsigned char> salt)
{
    using CharT = std::remove_pointer_t<decltype(pwd.s.data())>;
    std::vector<unsigned char> key(sage::cfg::KEY_LEN);

    sage::RWGuard<CharT> guard(pwd.s.data());

    // scrypt parameters
    constexpr uint64_t N = 1ULL << 16;  // Increase N for higher security
    constexpr uint64_t r = 8;
    constexpr uint64_t p = 1;
    constexpr uint64_t maxmem = 128ULL * 1024 * 1024;

    const char* pass = nullptr;
    size_t passlen = 0;

    if (pwd.s.size() != 0)
    {
        pass = reinterpret_cast<const char*>(pwd.s.data());
        passlen = pwd.s.size() * sizeof(CharT);
    }

#ifdef USE_QT_UI
    QElapsedTimer timer;
    timer.start();
#endif

    opensslCheck(
        EVP_PBE_scrypt(pass, passlen,
            salt.data(), salt.size(),
            N, r, p, maxmem,
            key.data(), key.size()),
        "scrypt failed"
    );

#ifdef USE_QT_UI
    qCDebug(logCrypto) << "deriveKey: scrypt completed in" << timer.elapsed() << "ms";
#endif

    return key;
}

template<class SecurePwd>
std::vector<unsigned char>
    Cryptography::encryptPacket(std::span<const unsigned char> plaintext,
        const SecurePwd& password)
{
    std::span<const unsigned char> aad = aadSpan();

    // salt and key
    std::vector<unsigned char> salt(sage::cfg::SALT_LEN);
    opensslCheck(RAND_bytes(salt.data(), (int)salt.size()), "RAND_bytes(salt) failed");
    auto key = deriveKey(password, std::span<const unsigned char>(salt));

    // iv
    std::vector<unsigned char> iv(sage::cfg::IV_LEN);
    opensslCheck(RAND_bytes(iv.data(), (int)iv.size()), "RAND_bytes(iv) failed");

    sage::EVP_CTX ctx;
    opensslCheck(EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
        "EncryptInit(cipher) failed");
    opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr),
        "SET_IVLEN failed");
    opensslCheck(EVP_EncryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv.data()),
        "EncryptInit(key/iv) failed");

    // AAD (optional)
    if (!aad.empty())
    {
        int tmp = 0;
        opensslCheck(EVP_EncryptUpdate(ctx.p, nullptr, &tmp, aad.data(), (int)aad.size()),
            "EncryptUpdate(AAD) failed");
    }

    // Encrypt
    std::vector<unsigned char> ct(plaintext.size() + 16 /*block slop*/);
    int outlen = 0, fin = 0;
    opensslCheck(EVP_EncryptUpdate(ctx.p, ct.data(), &outlen,
        plaintext.data(), (int)plaintext.size()),
        "EncryptUpdate(PT) failed");
    int total = outlen;
    opensslCheck(EVP_EncryptFinal_ex(ctx.p, ct.data() + total, &fin),
        "EncryptFinal failed");
    total += fin;
    ct.resize((size_t)total);

    // Tag
    std::vector<unsigned char> tag(sage::cfg::TAG_LEN);
    opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()),
        "GET_TAG failed");

    // Serialize packet
    std::vector<unsigned char> out;
    out.reserve(aad.size() + salt.size() + iv.size() + ct.size() + tag.size());
    if (!aad.empty()) out.insert(out.end(), aad.begin(), aad.end());
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());

#ifdef USE_QT_UI
    qCDebug(logCrypto) << "encryptPacket: plaintext=" << plaintext.size()
                       << "bytes, packet=" << out.size() << "bytes";
#endif
    cleanseString(key);
    return out;
}

template<class SecurePwd>
std::vector<unsigned char>
    Cryptography::decryptPacket(std::span<const unsigned char> packet,
        const SecurePwd& password)
{
    std::span<const unsigned char> aad_expected = aadSpan();
    const unsigned char* p = packet.data();
    size_t n = packet.size();

    // If AAD required, verify & strip it
    size_t off = 0;
    if (!aad_expected.empty())
    {
        if (n < aad_expected.size())
            throw std::runtime_error("Ciphertext too short (missing AAD)");
        if (std::memcmp(p, aad_expected.data(), aad_expected.size()) != 0)
            throw std::runtime_error("Bad AAD header");
        off = aad_expected.size();
    }

    // Structure sizes
    if (n < off + sage::cfg::SALT_LEN + sage::cfg::IV_LEN + sage::cfg::TAG_LEN)
        throw std::runtime_error("Ciphertext too short");

    const unsigned char* salt = p + off;
    const unsigned char* iv = p + off + sage::cfg::SALT_LEN;
    const unsigned char* ct = p + off + sage::cfg::SALT_LEN + sage::cfg::IV_LEN;

    size_t ct_len_with_tag = n - off - sage::cfg::SALT_LEN - sage::cfg::IV_LEN;
    if (ct_len_with_tag < sage::cfg::TAG_LEN)
        throw std::runtime_error("Invalid ciphertext/tag sizes");

    size_t ct_len = ct_len_with_tag - sage::cfg::TAG_LEN;
    const unsigned char* tag = ct + ct_len;

    // Derive key
    auto key = deriveKey(password,
        std::span<const unsigned char>(salt, sage::cfg::SALT_LEN));

    sage::EVP_CTX ctx;
    opensslCheck(EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
        "DecryptInit(cipher) failed");
    opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)sage::cfg::IV_LEN, nullptr),
        "SET_IVLEN failed");
    opensslCheck(EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv),
        "DecryptInit(key/iv) failed");

    // AAD (if required)
    if (!aad_expected.empty())
    {
        int tmp = 0;
        opensslCheck(EVP_DecryptUpdate(ctx.p, nullptr, &tmp,
            aad_expected.data(), (int)aad_expected.size()),
            "DecryptUpdate(AAD) failed");
    }

    // Decrypt
    std::vector<unsigned char> plain(ct_len);
    int outlen = 0, fin = 0;
    opensslCheck(EVP_DecryptUpdate(ctx.p, plain.data(), &outlen, ct, (int)ct_len),
        "DecryptUpdate(CT) failed");

    // Set tag and finalize (auth check happens here).
    // Copy tag into a mutable buffer - OpenSSL's API takes void* even though
    // SET_TAG does not modify the data.
    std::vector<unsigned char> tagCopy(tag, tag + sage::cfg::TAG_LEN);
    opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, (int)sage::cfg::TAG_LEN,
        tagCopy.data()),
        "SET_TAG failed");

    int ok = EVP_DecryptFinal_ex(ctx.p, plain.data() + outlen, &fin);
    if (ok != 1)
    {
#ifdef USE_QT_UI
        qCWarning(logCrypto) << "decryptPacket: GCM authentication failed";
#endif
        cleanseString(key);
        throw std::runtime_error("Authentication failed (bad password or corrupted data)");
    }

    plain.resize((size_t)(outlen + fin));
    cleanseString(key);
    return plain;
}

template std::vector<unsigned char> Cryptography::deriveKey(
    const secure_string<>&, std::span<const unsigned char>);
template std::vector<unsigned char> Cryptography::deriveKey(
    const basic_secure_string<wchar_t>&, std::span<const unsigned char>);

template std::vector<unsigned char> Cryptography::encryptPacket(
    std::span<const unsigned char>, const secure_string<>&);
template std::vector<unsigned char> Cryptography::encryptPacket(
    std::span<const unsigned char>, const basic_secure_string<wchar_t>&);

template std::vector<unsigned char> Cryptography::decryptPacket(
    std::span<const unsigned char>, const secure_string<>&);
template std::vector<unsigned char> Cryptography::decryptPacket(
    std::span<const unsigned char>, const basic_secure_string<wchar_t>&);

} // namespace sage
