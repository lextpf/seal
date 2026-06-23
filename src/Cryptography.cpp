#include "Cryptography.hpp"

#include <sddl.h>

#ifdef USE_QT_UI
#include <QtCore/QElapsedTimer>
#include <QtCore/QString>
#include "Diagnostics.hpp"
#include "Logging.hpp"
#endif

namespace seal
{

bool Cryptography::ctEqualRaw(const unsigned char* a, const unsigned char* b, size_t n)
{
    // Constant-time comparison: XOR each byte, OR-accumulate into v.
    // Any difference sets a bit in v; every iteration runs identical work
    // so timing is data-independent.
    unsigned char v = 0;
    for (size_t i = 0; i < n; ++i)
        v |= static_cast<unsigned char>(a[i] ^ b[i]);
    return v == 0;
}

void Cryptography::hardenHeap()
{
    HeapSetInformation(nullptr, HeapEnableTerminationOnCorruption, nullptr, 0);
}

void Cryptography::hardenProcessAccess()
{
    // Build a DACL that denies dangerous process-access rights to Everyone
    // while leaving SYSTEM/Administrators full control. Blocks procdump,
    // Process Hacker, and malware memory reads.

    PSECURITY_DESCRIPTOR pSD = nullptr;
    PACL pDacl = nullptr;

    // SDDL:
    //   D:                = DACL
    //   (D;;0x147A;;;WD)  = Deny Everyone:
    //                       VM_READ|VM_WRITE|VM_OPERATION|DUP_HANDLE|
    //                       QUERY_INFORMATION|CREATE_THREAD
    //   (A;;GA;;;SY)      = Allow SYSTEM: GENERIC_ALL
    //   (A;;GA;;;BA)      = Allow Administrators: GENERIC_ALL
    BOOL ok = ConvertStringSecurityDescriptorToSecurityDescriptorA(
        "D:(D;;0x147A;;;WD)(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &pSD, nullptr);

    if (ok && pSD)
    {
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) && daclPresent)
        {
            SetSecurityInfo(GetCurrentProcess(),
                            SE_KERNEL_OBJECT,
                            DACL_SECURITY_INFORMATION,
                            nullptr,
                            nullptr,
                            pDacl,
                            nullptr);
        }
        LocalFree(pSD);
    }

#ifdef USE_QT_UI
    qCInfo(logCrypto).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=security.process_access.apply", seal::diag::kv("result", ok ? "ok" : "fail")}));
#endif
}

void Cryptography::disableCrashDumps()
{
    // Suppress WER -- minidumps could contain secrets.
    SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

    // Unhandled-exception filter: terminate before the default handler can
    // write a crash dump.
    SetUnhandledExceptionFilter(
        [](PEXCEPTION_POINTERS) -> LONG
        {
            TerminateProcess(GetCurrentProcess(), 1);
            return EXCEPTION_CONTINUE_SEARCH;  // unreachable
        });

#ifdef USE_QT_UI
    qCInfo(logCrypto).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=security.crash_dumps.disable", "result=ok", "wer=suppressed", "filter=installed"}));
#endif
}

void Cryptography::detectDebugger()
{
    // Check 1: user-mode debugger.
    if (IsDebuggerPresent())
    {
#ifdef USE_QT_UI
        qCCritical(logCrypto).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=security.debugger.check",
                                                              "result=fail",
                                                              "reason=user_mode_debugger",
                                                              "action=abort"}));
#else
        OutputDebugStringA("[seal] FATAL: debugger detected\n");
#endif
        // 0xDEAD is the seal "security kill" exit code -- recognizable in
        // logs and crash reports as an anti-debug termination.
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        // __fastfail(7) = FAST_FAIL_FATAL_APP_EXIT: immediate kernel-level
        // termination that cannot be caught.
        __fastfail(7);
        return;
    }

    // Check 2: remote/kernel debugger.
    BOOL remoteDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger) && remoteDebugger)
    {
#ifdef USE_QT_UI
        qCCritical(logCrypto).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=security.debugger.check",
                                                              "result=fail",
                                                              "reason=remote_debugger",
                                                              "action=abort"}));
#else
        OutputDebugStringA("[seal] FATAL: remote debugger detected\n");
#endif
        TerminateProcess(GetCurrentProcess(), 0xDEAD);
        __fastfail(7);
        return;
    }

    // Check 3: NtQueryInformationProcess(ProcessDebugPort).
    // Resolve dynamically to avoid a hard ntdll dependency.
    using PFN_NtQueryInformationProcess = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll)
    {
        auto pNtQIP = reinterpret_cast<PFN_NtQueryInformationProcess>(
            GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        if (pNtQIP)
        {
            ULONG_PTR debugPort = 0;
            LONG status = pNtQIP(GetCurrentProcess(),
                                 7 /*ProcessDebugPort*/,
                                 &debugPort,
                                 sizeof(debugPort),
                                 nullptr);
            if (status == 0 && debugPort != 0)
            {
#ifdef USE_QT_UI
                qCCritical(logCrypto).noquote() << QString::fromStdString(
                    seal::diag::joinFields({"event=security.debugger.check",
                                            "result=fail",
                                            "reason=kernel_debug_port",
                                            "action=abort"}));
#else
                OutputDebugStringA("[seal] FATAL: kernel debug port detected\n");
#endif
                TerminateProcess(GetCurrentProcess(), 0xDEAD);
                __fastfail(7);
                return;
            }
        }
    }

#ifdef USE_QT_UI
    qCInfo(logCrypto).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=security.debugger.check", "result=ok"}));
#endif
}

void Cryptography::trimWorkingSet()
{
    // Force pages out so plaintext doesn't linger in physical RAM
    // after sensitive operations.
    EmptyWorkingSet(GetCurrentProcess());
}

using PFN_SetProcessMitigationPolicy = BOOL(WINAPI*)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);

BOOL Cryptography::setSecureProcessMitigations(bool allowDynamicCode)
{
    // Resolve dynamically (Windows 8+ only).
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32)
        return FALSE;

    auto pSet = (PFN_SetProcessMitigationPolicy)GetProcAddress(hK32, "SetProcessMitigationPolicy");
    if (!pSet)
        return FALSE;

    BOOL allSuccess = TRUE;

    // 1. Block dynamic code generation (JIT-injection mitigation).
    // Skipped in QML UI mode because Qt Quick's V4 needs JIT.
    if (!allowDynamicCode)
    {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynCodePolicy = {};
        dynCodePolicy.ProhibitDynamicCode = 1;
        allSuccess &= pSet(ProcessDynamicCodePolicy, &dynCodePolicy, sizeof(dynCodePolicy));
    }

    // 2. Require signed images (block unsigned DLL injection).
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = {};
    sigPolicy.MitigationOptIn = 1;
    sigPolicy.MicrosoftSignedOnly = 0;
    sigPolicy.AuditMicrosoftSignedOnly = 0;
    allSuccess &= pSet(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy));

    // 3. Side-channel isolation against transient-execution attacks:
    //   - SmtBranchTargetIsolation:   Spectre-BTI cross-thread BTB poisoning.
    //   - IsolateSecurityDomain:      keep foreign work off sibling SMT.
    //   - DisablePageCombine:         no dedup fingerprinting via CoW timing.
    //   - SpeculativeStoreBypassDisable: SSB (CVE-2018-3639).
    //   - RestrictCoreSharing:        no untrusted process on the same core.
    // All best-effort -- the kernel ignores unknown bits on older builds
    // and the call still returns TRUE.
    PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sc{};
    sc.SmtBranchTargetIsolation = 1;
    sc.IsolateSecurityDomain = 1;
    sc.DisablePageCombine = 1;
    sc.SpeculativeStoreBypassDisable = 1;
    sc.RestrictCoreSharing = 1;
    allSuccess &= pSet(ProcessSideChannelIsolationPolicy, &sc, sizeof(sc));

    // 4. Strict handle checks.
    PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = {};
    handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
    handlePolicy.HandleExceptionsPermanentlyEnabled = 1;
    allSuccess &= pSet(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy));

    // 5. Disable extension points (third-party injection mitigation).
    PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extPolicy = {};
    extPolicy.DisableExtensionPoints = 1;
    allSuccess &= pSet(ProcessExtensionPointDisablePolicy, &extPolicy, sizeof(extPolicy));

    // 6. Image-load policy: restrict DLL load locations.
    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imgPolicy = {};
    imgPolicy.NoRemoteImages = 1;
    imgPolicy.NoLowMandatoryLabelImages = 1;
    imgPolicy.PreferSystem32Images = 1;
    allSuccess &= pSet(ProcessImageLoadPolicy, &imgPolicy, sizeof(imgPolicy));

#ifdef USE_QT_UI
    qCInfo(logCrypto).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=security.mitigations.apply",
                                seal::diag::kv("result", allSuccess ? "ok" : "partial"),
                                seal::diag::kv("allow_dynamic_code", allowDynamicCode)}));
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

    // CRITICAL: AdjustTokenPrivileges returns TRUE on partial success (e.g.
    // privilege absent from token). Must check GetLastError() for
    // ERROR_SUCCESS to confirm the privilege was actually enabled.
    DWORD gle = GetLastError();
    CloseHandle(hToken);

    BOOL result = (gle == ERROR_SUCCESS);
#ifdef USE_QT_UI
    if (result)
    {
        qCInfo(logCrypto).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=security.lock_pages.enable", "result=ok"}));
    }
    else
    {
        qCWarning(logCrypto).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=security.lock_pages.enable",
             "result=fail",
             "reason=privilege_unavailable",
             seal::diag::kv("error", static_cast<unsigned long long>(gle))}));
    }
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

Cryptography::PacketHeader Cryptography::makeHeader(const seal::cfg::KdfParams& kdf)
{
    PacketHeader h;
    h.kdf = kdf;
    std::memcpy(h.bytes.data(), seal::cfg::AAD_HDR, seal::cfg::MAGIC_LEN);
    h.bytes[4] = kdf.alg;
    h.bytes[5] = kdf.log2N;
    h.bytes[6] = kdf.r;
    h.bytes[7] = kdf.p;
    h.size = seal::cfg::HDR_LEN;
    return h;
}

Cryptography::PacketHeader Cryptography::parsePacketHeader(std::span<const unsigned char> data)
{
    if (data.size() < seal::cfg::MAGIC_LEN)
    {
        throw std::runtime_error("Ciphertext too short (missing AAD)");
    }
    if (std::memcmp(data.data(), seal::cfg::AAD_HDR, seal::cfg::MAGIC_LEN) == 0)
    {
        if (data.size() < seal::cfg::HDR_LEN)
        {
            throw std::runtime_error("Ciphertext too short (truncated header)");
        }
        PacketHeader h;
        h.kdf = seal::cfg::KdfParams{data[4], data[5], data[6], data[7]};
        if (!seal::cfg::kdfParamsAcceptable(h.kdf))
        {
            throw std::runtime_error("Rejected KDF parameters (out of accepted range)");
        }
        std::memcpy(h.bytes.data(), data.data(), seal::cfg::HDR_LEN);
        h.size = seal::cfg::HDR_LEN;
        return h;
    }
    throw std::runtime_error("Bad AAD header");
}

template <secure_password SecurePwd>
Cryptography::LockedKeyBuffer Cryptography::deriveKey(const SecurePwd& pwd,
                                                      std::span<const unsigned char> salt,
                                                      const seal::cfg::KdfParams& kdf)
{
    using CharT = std::remove_pointer_t<decltype(pwd.data())>;
    // Key material lives in guard-paged, VirtualLock'd memory; never swaps.
    LockedKeyBuffer key(seal::cfg::KEY_LEN);

    // Master password pages are PAGE_NOACCESS most of the time so stray
    // reads trap. scrypt needs raw bytes, so RWGuard flips to
    // PAGE_READWRITE for exactly this span and restores PAGE_NOACCESS on
    // every exit (including throws from opensslCheck below).
    seal::RWGuard<CharT> guard(pwd.data());

    const char* pass = nullptr;
    size_t passlen = 0;

    if (pwd.size() != 0)
    {
        pass = reinterpret_cast<const char*>(pwd.data());
        passlen = pwd.size() * sizeof(CharT);
    }

#ifdef USE_QT_UI
    QElapsedTimer timer;
    timer.start();
#endif

    const uint64_t scryptN = 1ULL << kdf.log2N;
    const uint64_t scryptMaxMem =
        std::max<uint64_t>(seal::cfg::SCRYPT_MAXMEM, 2ULL * 128ULL * kdf.r * scryptN);

    opensslCheck(EVP_PBE_scrypt(pass,
                                passlen,
                                salt.data(),
                                salt.size(),
                                scryptN,
                                kdf.r,
                                kdf.p,
                                scryptMaxMem,
                                key.data(),
                                key.size()),
                 "scrypt failed");

#ifdef USE_QT_UI
    qCDebug(logCrypto).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=crypto.derive_key.finish",
                                "result=ok",
                                "algo=scrypt",
                                seal::diag::kv("duration_ms", timer.elapsed())}));
#endif

    return key;
}

template <secure_password SecurePwd>
std::vector<unsigned char> Cryptography::encryptPacket(std::span<const unsigned char> plaintext,
                                                       const SecurePwd& password,
                                                       const seal::cfg::KdfParams& kdf)
{
    // Packets carry the self-describing KDF header as AAD.
    const PacketHeader header = makeHeader(kdf);
    std::span<const unsigned char> aad(header.bytes.data(), header.size);

    // salt and key
    std::vector<unsigned char> salt(seal::cfg::SALT_LEN);
    opensslCheck(RAND_bytes(salt.data(), (int)salt.size()), "RAND_bytes(salt) failed");
    auto key = deriveKey(password, std::span<const unsigned char>(salt), header.kdf);

    // iv
    std::vector<unsigned char> iv(seal::cfg::IV_LEN);
    opensslCheck(RAND_bytes(iv.data(), (int)iv.size()), "RAND_bytes(iv) failed");

    seal::EvpCipherCtx ctx;
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
    opensslCheck(
        EVP_EncryptUpdate(ctx.p, ct.data(), &outlen, plaintext.data(), (int)plaintext.size()),
        "EncryptUpdate(PT) failed");
    int total = outlen;
    opensslCheck(EVP_EncryptFinal_ex(ctx.p, ct.data() + total, &fin), "EncryptFinal failed");
    total += fin;
    ct.resize((size_t)total);

    // Tag
    std::vector<unsigned char> tag(seal::cfg::TAG_LEN);
    opensslCheck(EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, (int)tag.size(), tag.data()),
                 "GET_TAG failed");

    // Wire format: [ AAD (optional) | salt | IV | ciphertext | GCM tag ].
    // Receiver parses fixed-size fields; ciphertext length = remainder.
    // AAD stays unencrypted so the header can be verified before scrypt.
    std::vector<unsigned char> out;
    out.reserve(aad.size() + salt.size() + iv.size() + ct.size() + tag.size());
    if (!aad.empty())
        out.insert(out.end(), aad.begin(), aad.end());
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ct.begin(), ct.end());
    out.insert(out.end(), tag.begin(), tag.end());

#ifdef USE_QT_UI
    qCDebug(logCrypto).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=crypto.encrypt_packet.finish",
                                "result=ok",
                                seal::diag::kv("plaintext_bytes", plaintext.size()),
                                seal::diag::kv("packet_bytes", out.size())}));
#endif
    cleanseString(key);
    return out;
}

template <secure_password SecurePwd>
std::vector<unsigned char> Cryptography::decryptPacket(std::span<const unsigned char> packet,
                                                       const SecurePwd& password)
{
    // Parse [ header | salt | IV | ciphertext | tag ]. The header doubles
    // as the AAD and carries cap-validated KDF parameters.
    const PacketHeader header = parsePacketHeader(packet);
    std::span<const unsigned char> aad_expected(header.bytes.data(), header.size);
    const unsigned char* p = packet.data();
    size_t n = packet.size();
    size_t off = header.size;

    // Structure sizes
    if (n < off + seal::cfg::SALT_LEN + seal::cfg::IV_LEN + seal::cfg::TAG_LEN)
        throw std::runtime_error("Ciphertext too short");

    // Slice fixed-size fields; ciphertext = bytes between IV and tag.
    const unsigned char* salt = p + off;
    const unsigned char* iv = p + off + seal::cfg::SALT_LEN;
    const unsigned char* ct = p + off + seal::cfg::SALT_LEN + seal::cfg::IV_LEN;

    size_t ct_len_with_tag = n - off - seal::cfg::SALT_LEN - seal::cfg::IV_LEN;
    if (ct_len_with_tag < seal::cfg::TAG_LEN)
        throw std::runtime_error("Invalid ciphertext/tag sizes");

    size_t ct_len = ct_len_with_tag - seal::cfg::TAG_LEN;
    const unsigned char* tag = ct + ct_len;

    // Derive key with the header's effective parameters.
    auto key =
        deriveKey(password, std::span<const unsigned char>(salt, seal::cfg::SALT_LEN), header.kdf);

    seal::EvpCipherCtx ctx;
    opensslCheck(EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                 "DecryptInit(cipher) failed");
    opensslCheck(
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)seal::cfg::IV_LEN, nullptr),
        "SET_IVLEN failed");
    opensslCheck(EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv),
                 "DecryptInit(key/iv) failed");

    // AAD (if required)
    if (!aad_expected.empty())
    {
        int tmp = 0;
        opensslCheck(
            EVP_DecryptUpdate(ctx.p, nullptr, &tmp, aad_expected.data(), (int)aad_expected.size()),
            "DecryptUpdate(AAD) failed");
    }

    // Decrypt
    std::vector<unsigned char> plain(ct_len);
    int outlen = 0, fin = 0;
    opensslCheck(EVP_DecryptUpdate(ctx.p, plain.data(), &outlen, ct, (int)ct_len),
                 "DecryptUpdate(CT) failed");

    // Set tag and finalize -- this is the auth check. SET_TAG takes void*,
    // not const void*, so copy into a mutable buffer.
    std::vector<unsigned char> tagCopy(tag, tag + seal::cfg::TAG_LEN);
    opensslCheck(
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, (int)seal::cfg::TAG_LEN, tagCopy.data()),
        "SET_TAG failed");

    int ok = EVP_DecryptFinal_ex(ctx.p, plain.data() + outlen, &fin);
    if (ok != 1)
    {
#ifdef USE_QT_UI
        qCWarning(logCrypto).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=crypto.decrypt_packet.finish", "result=fail", "reason=gcm_auth_failed"}));
#endif
        cleanseString(key);
        throw std::runtime_error("Authentication failed (bad password or corrupted data)");
    }

    plain.resize((size_t)(outlen + fin));
    cleanseString(key);
    return plain;
}

template <secure_password SecurePwd>
void Cryptography::verifyPacket(std::span<const unsigned char> packet, const SecurePwd& password)
{
    // Parse the wire format (same layout as decryptPacket).
    const PacketHeader header = parsePacketHeader(packet);
    std::span<const unsigned char> aad_expected(header.bytes.data(), header.size);
    const unsigned char* p = packet.data();
    size_t n = packet.size();
    size_t off = header.size;

    if (n < off + seal::cfg::SALT_LEN + seal::cfg::IV_LEN + seal::cfg::TAG_LEN)
        throw std::runtime_error("Ciphertext too short");

    const unsigned char* salt = p + off;
    const unsigned char* iv = p + off + seal::cfg::SALT_LEN;
    const unsigned char* ct = p + off + seal::cfg::SALT_LEN + seal::cfg::IV_LEN;

    size_t ct_len_with_tag = n - off - seal::cfg::SALT_LEN - seal::cfg::IV_LEN;
    if (ct_len_with_tag < seal::cfg::TAG_LEN)
        throw std::runtime_error("Invalid ciphertext/tag sizes");

    size_t ct_len = ct_len_with_tag - seal::cfg::TAG_LEN;
    const unsigned char* tag = ct + ct_len;

    auto key =
        deriveKey(password, std::span<const unsigned char>(salt, seal::cfg::SALT_LEN), header.kdf);

    seal::EvpCipherCtx ctx;
    opensslCheck(EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr),
                 "DecryptInit(cipher) failed");
    opensslCheck(
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, (int)seal::cfg::IV_LEN, nullptr),
        "SET_IVLEN failed");
    opensslCheck(EVP_DecryptInit_ex(ctx.p, nullptr, nullptr, key.data(), iv),
                 "DecryptInit(key/iv) failed");

    if (!aad_expected.empty())
    {
        int tmp = 0;
        opensslCheck(
            EVP_DecryptUpdate(ctx.p, nullptr, &tmp, aad_expected.data(), (int)aad_expected.size()),
            "DecryptUpdate(AAD) failed");
    }

    // Stream ciphertext through GCM and discard plaintext; only the tag
    // matters here. thread_local scratch keeps allocation at O(1) without
    // burning 64 KB of stack per call.
    constexpr size_t VERIFY_CHUNK = 65536;
    thread_local unsigned char scratch[VERIFY_CHUNK];
    int outlen = 0;
    size_t pos = 0;
    while (pos < ct_len)
    {
        size_t remaining = ct_len - pos;
        int chunk = static_cast<int>(remaining < VERIFY_CHUNK ? remaining : VERIFY_CHUNK);
        opensslCheck(EVP_DecryptUpdate(ctx.p, scratch, &outlen, ct + pos, chunk),
                     "DecryptUpdate(CT) failed");
        pos += static_cast<size_t>(chunk);
    }
    SecureZeroMemory(scratch, VERIFY_CHUNK);

    std::vector<unsigned char> tagCopy(tag, tag + seal::cfg::TAG_LEN);
    opensslCheck(
        EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, (int)seal::cfg::TAG_LEN, tagCopy.data()),
        "SET_TAG failed");

    unsigned char finBuf[16]{};
    int fin = 0;
    int ok = EVP_DecryptFinal_ex(ctx.p, finBuf, &fin);
    SecureZeroMemory(finBuf, sizeof(finBuf));
    cleanseString(key);

    if (ok != 1)
    {
#ifdef USE_QT_UI
        qCWarning(logCrypto).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=crypto.verify_packet.finish", "result=fail", "reason=gcm_auth_failed"}));
#endif
        throw std::runtime_error("Authentication failed (bad password or corrupted data)");
    }
}

// Explicit instantiations for narrow (UTF-8) and wide (UTF-16) passwords.
template Cryptography::LockedKeyBuffer Cryptography::deriveKey(const secure_string<>&,
                                                               std::span<const unsigned char>,
                                                               const seal::cfg::KdfParams&);
template Cryptography::LockedKeyBuffer Cryptography::deriveKey(const basic_secure_string<wchar_t>&,
                                                               std::span<const unsigned char>,
                                                               const seal::cfg::KdfParams&);

template std::vector<unsigned char> Cryptography::encryptPacket(std::span<const unsigned char>,
                                                                const secure_string<>&,
                                                                const seal::cfg::KdfParams&);
template std::vector<unsigned char> Cryptography::encryptPacket(std::span<const unsigned char>,
                                                                const basic_secure_string<wchar_t>&,
                                                                const seal::cfg::KdfParams&);

template std::vector<unsigned char> Cryptography::decryptPacket(std::span<const unsigned char>,
                                                                const secure_string<>&);
template std::vector<unsigned char> Cryptography::decryptPacket(
    std::span<const unsigned char>, const basic_secure_string<wchar_t>&);

template void Cryptography::verifyPacket(std::span<const unsigned char>, const secure_string<>&);
template void Cryptography::verifyPacket(std::span<const unsigned char>,
                                         const basic_secure_string<wchar_t>&);

}  // namespace seal
