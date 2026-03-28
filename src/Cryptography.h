#pragma once

#include "CryptoGuards.h"

#include <aclapi.h>
#include <heapapi.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <winnt.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <ranges>
#include <span>
#include <sstream>
#include <stdexcept>

#ifdef _MSC_VER
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Crypt32.lib")
#endif

namespace seal
{

/**
 * @class Cryptography
 * @brief AES-256-GCM encryption, scrypt key derivation, and secure memory.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Static utility class providing the cryptographic core for seal.
 * All methods are stateless and thread-safe.
 *
 * ## :material-lock: Encryption
 *
 * encryptPacket() / decryptPacket() implement framed AES-256-GCM with
 * scrypt key derivation. Each packet carries its own random salt and IV
 * so no external state is needed.
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart LR
 *     subgraph Encrypt
 *         direction LR
 *         S1["RAND salt(16)\nRAND iv(12)"] --> KDF["scrypt\n(N=2^16, r=8, p=1)"]
 *         KDF --> ENC["AES-256-GCM\nencrypt + tag"]
 *         ENC --> PKT["AAD | Salt | IV | CT | Tag"]
 *     end
 *     subgraph Decrypt
 *         direction LR
 *         P["parse\nfixed fields"] --> KDF2["scrypt\n(same params)"]
 *         KDF2 --> DEC["AES-256-GCM\ndecrypt + verify"]
 *         DEC --> PT["plaintext"]
 *     end
 * ```
 *
 * ## :material-shield: Process Hardening
 *
 * A suite of static methods hardens the process against memory
 * disclosure and debugging attacks:
 * - hardenHeap() - enables heap termination on corruption
 * - hardenProcessAccess() - restricts DACL to block external memory reads
 * - disableCrashDumps() - suppresses WER and crash dumps
 * - detectDebugger() - terminates the process if a debugger is detected
 * - setSecureProcessMitigations() - enables DEP, CFG, ASLR, image-load policies
 * - trimWorkingSet() - flushes plaintext from physical RAM
 *
 * @see locked_allocator, secure_string, cfg
 */
class Cryptography
{
public:
    /**
     * @brief Constant-time byte comparison.
     * @param a First buffer.
     * @param b Second buffer.
     * @param n Number of bytes to compare.
     * @return `true` if all @p n bytes are identical.
     */
    static bool ctEqualRaw(const unsigned char* a, const unsigned char* b, size_t n);

    /// @brief Constant-time equality for byte-like ranges.
    template <class A, class B>
        requires requires(const A& aa, const B& bb) {
            { std::ranges::data(aa) };
            { std::ranges::data(bb) };
            { std::ranges::size(aa) } -> std::convertible_to<std::size_t>;
            { std::ranges::size(bb) } -> std::convertible_to<std::size_t>;
            requires seal::byte_like<std::remove_pointer_t<decltype(std::ranges::data(aa))>>;
            requires seal::byte_like<std::remove_pointer_t<decltype(std::ranges::data(bb))>>;
        }
    [[nodiscard]] static constexpr bool ctEqualAny(const A& aa, const B& bb)
    {
        if (std::ranges::size(aa) != std::ranges::size(bb))
            return false;
        return ctEqualRaw(reinterpret_cast<const unsigned char*>(std::ranges::data(aa)),
                          reinterpret_cast<const unsigned char*>(std::ranges::data(bb)),
                          std::ranges::size(aa));
    }

    template <class CharT, class A>
    static bool ctEqual(const basic_secure_string<CharT, A>& a,
                        const basic_secure_string<CharT, A>& b)
    {
        return ctEqualAny(a.s, b.s);
    }

    /// @brief Enable heap termination on corruption via `HeapSetInformation`.
    /// @post The process heap is configured to terminate on detected corruption
    ///       rather than returning an error code.
    static void hardenHeap();

    /// @brief Set a restrictive DACL on the current process to block external memory reads.
    /// @post The process DACL denies PROCESS_VM_READ to all non-SYSTEM principals,
    ///       preventing tools like Process Hacker from dumping secrets.
    static void hardenProcessAccess();

    /// @brief Suppress crash dumps and WER dialogs to prevent memory disclosure.
    /// @post MiniDumpWriteDump, WER, and Dr. Watson are disabled so a crash
    ///       does not write plaintext secrets to disk.
    static void disableCrashDumps();

    /// @brief Detect attached debuggers and terminate the process if found.
    /// @post If `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`, or
    ///       `NtQueryInformationProcess(ProcessDebugPort)` detects a debugger,
    ///       the process calls `TerminateProcess` followed by `__fastfail`.
    static void detectDebugger();

    /// @brief Trim the working set via `EmptyWorkingSet()`.
    /// @post Dirty pages containing decrypted secrets are flushed from
    ///       physical RAM, reducing the window for cold-boot or swap-file recovery.
    static void trimWorkingSet();

    /**
     * @brief Apply process-wide security mitigations (DEP, CFG, image load, etc.).
     * @param allowDynamicCode `true` to permit dynamic code generation
     *        (required for Qt QML's V4 JIT engine); `false` for stricter CLI mode.
     * @return Windows `BOOL` - `TRUE` on success, `FALSE` on failure.
     */
    static BOOL setSecureProcessMitigations(bool allowDynamicCode);

    /**
     * @brief Enable SeLockMemoryPrivilege if available.
     * @return `TRUE` if the privilege was enabled, `FALSE` if not available
     *         (non-admin accounts typically lack this privilege).
     */
    static BOOL tryEnableLockPrivilege();

    /// @brief Base case for the variadic cleanseString fold expression (no-op).
    static void cleanseString() noexcept
    { /* Base case for variadic fold expression - intentionally empty */ }

    /**
     * @brief Securely wipe and release one or more containers.
     *
     * Accepts any mix of `std::string`, `std::vector<byte>`, `secure_string`,
     * `basic_secure_string`, or raw `CharT*` pointers. Each argument is
     * zeroed with `OPENSSL_cleanse` or `SecureZeroMemory` (depending on
     * allocator type) and then released. Locked-page buffers have their
     * protection restored to PAGE_READWRITE before wiping.
     *
     * @tparam Ts Argument types (deduced).
     * @param xs Containers or pointers to wipe.
     */
    template <class... Ts>
    static void cleanseString(Ts&&... xs) noexcept
    {
        (cleanseOne(std::forward<Ts>(xs)), ...);
    }

    /// @brief Detect Remote Desktop session.
    static bool isRemoteSession() { return GetSystemMetrics(SM_REMOTESESSION) != 0; }

    /**
     * @brief Encrypt plaintext into a framed AES-256-GCM packet.
     *
     * Packet format: `AAD(4) | Salt(16) | IV(12) | Ciphertext(n) | Tag(16)`.
     *
     * @tparam SecurePwd Secure password container with `.data()` and `.size()`.
     * @param plaintext Raw bytes to encrypt.
     * @param password  Master password for scrypt key derivation.
     * @return The framed encrypted packet.
     * @throw std::runtime_error on OpenSSL failure.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> encryptPacket(
        std::span<const unsigned char> plaintext, const SecurePwd& password);

    /**
     * @brief Decrypt a framed AES-256-GCM packet.
     *
     * @tparam SecurePwd Secure password container with `.data()` and `.size()`.
     * @param packet   Framed encrypted packet (as produced by encryptPacket()).
     * @param password Master password for scrypt key derivation.
     * @return Decrypted plaintext bytes.
     * @throw std::runtime_error on authentication failure or malformed packet.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> decryptPacket(
        std::span<const unsigned char> packet, const SecurePwd& password);

    /**
     * @brief Verify a framed AES-256-GCM packet without allocating full plaintext.
     *
     * Performs the same key derivation and GCM authentication as decryptPacket()
     * but processes ciphertext in fixed-size chunks, discarding decrypted output.
     * Peak memory is O(1) instead of O(ciphertext_length), making this suitable
     * for verifying large encrypted files where only password correctness matters.
     *
     * @tparam SecurePwd Secure password container with `.data()` and `.size()`.
     * @param packet   Framed encrypted packet (as produced by encryptPacket()).
     * @param password Master password for scrypt key derivation.
     * @throw std::runtime_error on authentication failure or malformed packet.
     */
    template <secure_password SecurePwd>
    static void verifyPacket(std::span<const unsigned char> packet, const SecurePwd& password);

private:
    friend class FileOperations;

    /// @brief Check OpenSSL return code.
    static void opensslCheck(int ok, const char* msg);

    /// @brief Get authenticated AAD span.
    static std::span<const unsigned char> aadSpan() noexcept;

    /// @brief Derived key type backed by guard-paged, locked memory.
    using LockedKeyBuffer = std::vector<unsigned char, locked_allocator<unsigned char>>;

    /// @brief Derive AES-256 key via scrypt into locked memory.
    template <secure_password SecurePwd>
    [[nodiscard]] static LockedKeyBuffer deriveKey(const SecurePwd& pwd,
                                                   std::span<const unsigned char> salt);

    template <class CharT, class Traits, class Alloc>
    static void cleanseOne(std::basic_string<CharT, Traits, Alloc>& s) noexcept
    {
        if (!s.empty())
        {
            OPENSSL_cleanse(static_cast<void*>(s.data()), s.size() * sizeof(CharT));
        }
        s.clear();
        s.shrink_to_fit();
    }

    template <class CharT, class A>
    static void cleanseOne(seal::basic_secure_string<CharT, A>& s) noexcept
    {
        if (!s.s.empty())
        {
            CharT* base = s.s.data();
            if (base)
            {
                auto* hdr = seal::header_from_payload(base);
                DWORD oldProt{}, dummy{};
                (void)VirtualProtect(base, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
                SecureZeroMemory(base, hdr->usable);
                (void)VirtualProtect(base, hdr->payloadSpan, oldProt, &dummy);
            }
        }
        s.s.clear();
        std::vector<CharT, A>().swap(s.s);
    }

    template <seal::byte_like T, class Alloc>
    static void cleanseOne(std::vector<T, Alloc>& v) noexcept
    {
        if (!v.empty())
        {
            OPENSSL_cleanse(static_cast<void*>(v.data()), v.size() * sizeof(T));
        }
        v.clear();
        v.shrink_to_fit();
    }

    template <class CharT>
        requires std::is_trivial_v<CharT>
    static void cleanseOne(CharT* p, size_t len) noexcept
    {
        OPENSSL_cleanse(static_cast<void*>(p), len * sizeof(CharT));
    }

    template <class CharT>
    static void cleanseOne(CharT* p) noexcept
    {
        if (!p)
            return;
        const size_t n = std::char_traits<CharT>::length(p);
        cleanseOne(p, n);
    }
};

}  // namespace seal
