#pragma once

#include "CryptoGuards.hpp"

#include <aclapi.h>
#include <heapapi.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <winnt.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
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
 * The cryptographic core of seal. Every member is static; callers use it without an instance.
 *
 * ## :material-lock: Encryption
 *
 * encryptPacket() and decryptPacket() implement framed AES-256-GCM with scrypt key
 * derivation. Each packet carries its own random salt and IV, so no external state is
 * needed.
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
 *         S1["RAND salt(16)\nRAND iv(12)"] --> KDF["scrypt\n(default N=2^16, r=8, p=1)"]
 *         KDF --> ENC["AES-256-GCM\nencrypt + tag"]
 *         ENC --> PKT["AAD | Salt | IV | CT | Tag"]
 *     end
 *     subgraph Decrypt
 *         direction LR
 *         P["parse + cap-check\nfixed fields"] --> KDF2["scrypt\n(params from header)"]
 *         KDF2 --> DEC["AES-256-GCM\ndecrypt + verify"]
 *         DEC --> PT["plaintext"]
 *     end
 * ```
 *
 * ## :material-shield: Process Hardening
 *
 * These methods change process-wide state and run once during start-up:
 * - hardenHeap() - terminates the process on detected heap corruption
 * - hardenProcessAccess() - restricts the DACL to block external memory reads
 * - disableCrashDumps() - suppresses WER and terminates on unhandled exceptions
 * - detectDebugger() - terminates the process if a debugger is detected
 * - setSecureProcessMitigations() - signature, side-channel, handle, extension-point
 *   and image-load policies (DEP, CFG and ASLR come from the link-time image flags)
 * - tryEnableLockPrivilege() - enables SeLockMemoryPrivilege before the first locked
 *   allocation
 *
 * trimWorkingSet() is not a start-up step. Callers run it at run time after each secret is
 * wiped; see its own warning.
 *
 * @par Threading
 * The class keeps no shared mutable state, so the packet methods may run on several threads
 * at once. verifyPacket() is the only method that keeps memory between calls: a
 * `thread_local` 64 KiB scratch buffer, wiped on every normal exit. A throw from the
 * OpenSSL update call inside the streaming loop skips the wipe.
 *
 * @par Password containers
 * deriveKey(), encryptPacket(), decryptPacket() and verifyPacket() are defined in
 * Cryptography.cpp and instantiated there for `secure_string<>` and
 * `basic_secure_string<wchar_t>` alone, so any other type that satisfies @ref
 * secure_password fails at link time. scrypt hashes the raw code units, so the same text in
 * a narrow and in a wide container derives two different keys.
 *
 * @see locked_allocator, secure_string, cfg
 */
class Cryptography
{
public:
    /**
     * @brief Constant-time byte comparison.
     *
     * The loop has no early exit, so the run time depends on @p n alone, not on where the
     * buffers differ. When @p n is 0 neither pointer is read and the result is `true`.
     *
     * @param a First buffer; at least @p n readable bytes.
     * @param b Second buffer; at least @p n readable bytes.
     * @param n Number of bytes to compare.
     * @return `true` when all @p n bytes are identical.
     */
    static bool ctEqualRaw(const unsigned char* a, const unsigned char* b, size_t n);

    /**
     * @brief Constant-time equality for two byte-like ranges.
     *
     * The per-byte comparison runs in data-independent time, but a size mismatch returns
     * early: the lengths are treated as public, not secret. The constraint accepts
     * contiguous ranges of `char`, `unsigned char` or `std::byte`; wide ranges do not
     * compile, so compare those through ctEqualRaw() after casting.
     *
     * @tparam A First range type; contiguous, with @ref byte_like elements.
     * @tparam B Second range type; contiguous, with @ref byte_like elements.
     * @param aa First range.
     * @param bb Second range.
     * @return `true` when the ranges have equal length and identical bytes.
     * @note Only the size-mismatch path can be constant-evaluated. The equal-size path
     *       calls the out-of-line ctEqualRaw() through `reinterpret_cast`, so it always
     *       runs at run time.
     */
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

    /**
     * @brief Constant-time equality for two secure strings of the same char type.
     *
     * Forwards to ctEqualAny(), so `CharT` must be byte-like: narrow secure strings
     * compare here, wide ones do not compile.
     *
     * @tparam CharT Character type of both strings; must satisfy @ref byte_like.
     * @tparam A     Allocator type shared by both strings.
     * @param a First string.
     * @param b Second string.
     * @return `true` when both strings hold the same number of identical bytes.
     * @pre Both payloads are readable. The comparison reads the buffers directly, so a
     *      payload left at PAGE_NOACCESS must be opened with an @ref RWGuard first, and a
     *      DPAPI-protected buffer must be inside a ScopedDpapiUnprotect window.
     */
    template <class CharT, class A>
    static bool ctEqual(const basic_secure_string<CharT, A>& a,
                        const basic_secure_string<CharT, A>& b)
    {
        return ctEqualAny(a, b);
    }

    /**
     * @brief Enable heap termination on corruption via `HeapSetInformation`.
     *
     * The call passes a null heap handle, so the setting covers every heap in the process
     * and cannot be switched off again while the process runs.
     *
     * @post Detected heap corruption terminates the process instead of returning an error
     *       code to the caller.
     * @note The result of `HeapSetInformation` is ignored; the call is best-effort.
     */
    static void hardenHeap();

    /**
     * @brief Set a restrictive DACL on the current process to block external memory reads.
     *
     * The deny entry names Everyone and comes first, so it covers SYSTEM and Administrators
     * too; the allow entries that follow grant them only what the deny mask leaves over.
     * Denied rights: PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION,
     * PROCESS_DUP_HANDLE, PROCESS_CREATE_THREAD and both query-information rights.
     *
     * @post A normal handle request for a memory read fails, which stops tools such as
     *       procdump or Process Hacker from dumping secrets.
     * @warning A caller that holds SeDebugPrivilege bypasses the DACL, so an elevated
     *          debugger or dumper still reads this process.
     * @note Failures never stop start-up: the return type is void, and neither a rejected
     *       SDDL string nor a failing `SetSecurityInfo` is propagated. The Qt build logs
     *       `event=security.process_access.apply`, whose result reports the SDDL conversion
     *       alone, so a failing apply still logs `result=ok`.
     */
    static void hardenProcessAccess();

    /**
     * @brief Suppress crash dumps and WER dialogs to prevent memory disclosure.
     *
     * Sets SEM_NOGPFAULTERRORBOX and SEM_FAILCRITICALERRORS, then installs an
     * unhandled-exception filter that calls `TerminateProcess` with exit code 1 at once, so
     * the default handler never runs and WER never collects a dump.
     *
     * @post An unhandled exception ends the process without writing a dump file.
     * @note The filter replaces any unhandled-exception filter installed earlier, including
     *       one set by the C runtime or by Qt.
     * @warning Only the process's own dump path is closed. A debugger, a direct
     *          `MiniDumpWriteDump` call from inside the process, or a kernel dump still
     *          captures memory.
     */
    static void disableCrashDumps();

    /**
     * @brief Detect attached debuggers and terminate the process if found.
     *
     * Runs three checks in order: `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()` and
     * `NtQueryInformationProcess(ProcessDebugPort)`. The third check is skipped when ntdll
     * or the export cannot be resolved, so it fails open.
     *
     * @post On a positive check the process calls `TerminateProcess` with exit code 0xDEAD
     *       and then `__fastfail(7)` (FAST_FAIL_FATAL_APP_EXIT); the function does not
     *       return.
     * @note The verdict is a snapshot taken at start-up. A debugger attached after the call
     *       is not detected.
     */
    static void detectDebugger();

    /**
     * @brief Trim the working set via `EmptyWorkingSet()`.
     *
     * Removes pageable pages from the process working set. Pages that locked_allocator
     * pinned with VirtualLock stay resident, so secrets in a secure_string are unaffected.
     *
     * @post The resident set holds fewer plaintext pages.
     * @warning Trimming moves data toward the page file rather than erasing it: a dirty
     *          pageable page that still holds a secret can be written to disk as it is
     *          trimmed. Wipe secrets first and call this afterwards.
     */
    static void trimWorkingSet();

    /**
     * @brief Apply process mitigation policies through `SetProcessMitigationPolicy`.
     *
     * Applies, in this order: dynamic-code prohibition (skipped when @p allowDynamicCode is
     * `true`), binary-signature opt-in, side-channel isolation, strict handle checks,
     * extension-point disable, and image-load restrictions. DEP, CFG and ASLR are not set
     * here; they come from the link-time image flags.
     *
     * Every policy is attempted even after an earlier one fails, and most cannot be undone,
     * so a `FALSE` result still leaves the policies that did apply in force.
     *
     * @param allowDynamicCode `true` to permit dynamic code generation
     *        (required for Qt QML's V4 JIT engine); `false` for stricter CLI mode.
     * @return `TRUE` when every attempted policy succeeded. `FALSE` when kernel32 or the
     *         export cannot be resolved, or when at least one policy call failed, for
     *         example on a Windows build that does not know that policy.
     */
    static BOOL setSecureProcessMitigations(bool allowDynamicCode);

    /**
     * @brief Enable SeLockMemoryPrivilege if available.
     *
     * `AdjustTokenPrivileges` reports success even when the privilege is missing from the
     * token, so the verdict comes from `GetLastError()` instead of its return value.
     *
     * @post The process token keeps the privilege enabled on success. The token handle is
     *       closed on every path.
     * @return `TRUE` when the privilege was enabled. `FALSE` when the process token cannot
     *         be opened, the privilege name cannot be resolved, or the token does not hold
     *         the privilege (non-admin accounts typically do not).
     * @note locked_allocator treats VirtualLock as best-effort, so page locking still works
     *       inside the process working-set quota when this returns `FALSE`.
     */
    static BOOL tryEnableLockPrivilege();

    /// @brief Overload selected when cleanseString() is called with no arguments; it wipes
    /// nothing. A non-template beats the variadic template for an empty pack, so the
    /// zero-argument call stays unambiguous.
    static void cleanseString() noexcept
    { /* Base case for variadic fold expression - intentionally empty */ }

    /**
     * @brief Securely wipe and release one or more containers.
     *
     * Accepts any mix of `std::string`, `std::vector<byte_like>`, `secure_string`,
     * `basic_secure_string` and raw `CharT*` pointers. Each argument is dispatched on its
     * own type, wiped, then released. Container arguments must be lvalues: the wipe
     * overloads take non-const references. A `basic_secure_string` payload is flipped to
     * PAGE_READWRITE for the wipe and set back to its previous protection afterwards. The
     * vector and raw-pointer overloads write in place, so their memory must already be
     * accessible, even when locked_allocator supplied it.
     *
     * @par Per-argument wipe dispatch
     * | Argument type            | Wipe primitive                     | After          |
     * |--------------------------|------------------------------------|----------------|
     * | `std::basic_string`      | `OPENSSL_cleanse`                  | clear + shrink |
     * | `basic_secure_string`    | RW-flip -> `SecureZeroMemory`      | clear          |
     * | `std::vector<byte_like>` | `OPENSSL_cleanse`                  | clear + shrink |
     * | `CharT*` (NUL-term)      | traits length -> `OPENSSL_cleanse` | not freed      |
     * | `CharT*` + length        | `OPENSSL_cleanse(len)`             | not freed      |
     *
     * A raw pointer is wiped up to its terminator and never freed; a null pointer is
     * ignored. The last row is the private primitive the NUL-terminated form delegates to;
     * `cleanseString` cannot select it, because one fold argument cannot carry both a
     * pointer and a length. The secure-string wipe covers the whole `usable` payload from
     * the allocation header, not only the live code units.
     *
     * @tparam Ts Argument types (deduced).
     * @param xs Containers or pointers to wipe.
     */
    template <class... Ts>
    static void cleanseString(Ts&&... xs) noexcept
    {
        (cleanseOne(std::forward<Ts>(xs)), ...);
    }

    /// @brief Report whether the process runs inside a Remote Desktop client session.
    static bool isRemoteSession() { return GetSystemMetrics(SM_REMOTESESSION) != 0; }

    /**
     * @struct PacketHeader
     * @brief Parsed (or freshly built) packet header.
     *
     * `bytes` and `size` hold the exact on-wire header. These bytes are the GCM AAD, so
     * encrypt and decrypt feed them verbatim. A default-constructed header is unusable;
     * makeHeader() and parsePacketHeader() are what fill it in.
     */
    struct PacketHeader
    {
        seal::cfg::KdfParams kdf{};            ///< Effective KDF parameters.
        std::array<unsigned char, 8> bytes{};  ///< Raw header bytes (AAD).
        /// Valid byte count in `bytes`; 0 before the header is filled, `cfg::HDR_LEN`
        /// (8) after makeHeader() or parsePacketHeader() returns.
        size_t size = 0;
    };

    /**
     * @brief Build the on-wire packet header for the given KDF parameters.
     *
     * @param kdf Parameters to serialize; defaults to `cfg::DEFAULT_KDF`.
     * @return Header with `bytes` and `size` filled, ready to write and to use as AAD.
     * @warning @p kdf is copied into the header without a range check. Never build a header
     *          from parameters that came from an untrusted packet; parsePacketHeader() is
     *          the one place that cap-checks.
     */
    [[nodiscard]] static PacketHeader makeHeader(
        const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

    /**
     * @brief Parse and validate a packet header.
     *
     * Parameters are checked against the acceptance caps before any key derivation, so a
     * hostile header cannot trigger an expensive or memory-exhausting scrypt call.
     *
     * The first 8 bytes are copied verbatim into `bytes`, because decryption feeds the
     * received bytes as AAD, not a re-serialized copy. Nothing after byte 7 is inspected;
     * the caller checks the salt, IV, ciphertext and tag sizes.
     *
     * @param data Leading bytes of a packet; at least `cfg::HDR_LEN` (8) bytes.
     * @return Parsed header with effective KDF parameters and `size` = 8.
     * @throw std::runtime_error on short input, unknown magic, or out-of-cap parameters.
     *        The magic is compared before the full-length check, so input that starts with
     *        the packet magic but is shorter than 8 bytes reports a truncated header.
     */
    [[nodiscard]] static PacketHeader parsePacketHeader(std::span<const unsigned char> data);

    /**
     * @brief Encrypt plaintext into a framed AES-256-GCM packet.
     *
     * Packet format: `AAD(8) | Salt(16) | IV(12) | Ciphertext(n) | Tag(16)`.
     *
     * @verbatim
     *  offset  size  field
     *  ------  ----  ------------------------------------------------
     *   0        8   AAD header  (magic "seal" | alg | log2N | r | p)
     *   8       16   Salt        (scrypt, random per packet)
     *  24       12   IV          (AES-GCM nonce, random per packet)
     *  36        n   Ciphertext  (n = |plaintext|)
     *  36+n     16   GCM tag     (authenticates AAD + ciphertext)
     * @endverbatim
     *
     * @tparam SecurePwd See the class-level note on password containers.
     * @param plaintext Raw bytes to encrypt.
     * @param password  Master password for scrypt key derivation.
     * @param kdf       Parameters serialized into the header and used for key derivation;
     *                  defaults to `cfg::DEFAULT_KDF`. Not cap-checked here.
     * @return The framed encrypted packet, 52 bytes longer than @p plaintext.
     * @pre `plaintext.size()` fits in `int`; OpenSSL takes the length as `int`.
     * @throw std::runtime_error when RAND_bytes, scrypt or an OpenSSL cipher call fails.
     * @note Salt and IV are drawn per call, so two packets over the same plaintext and the
     *       same password differ. The derived key is wiped before the return, and its
     *       locked buffer scrubs itself when an exception leaves the function early.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> encryptPacket(
        std::span<const unsigned char> plaintext,
        const SecurePwd& password,
        const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

    /**
     * @brief Decrypt a framed AES-256-GCM packet.
     *
     * The KDF parameters come from the packet's self-describing header and pass through
     * cfg::kdfParamsAcceptable() before any key derivation, so a hostile header cannot
     * force an oversized scrypt call.
     *
     * @tparam SecurePwd See the class-level note on password containers.
     * @param packet   Framed encrypted packet (as produced by encryptPacket()).
     * @param password Master password for scrypt key derivation.
     * @return Decrypted plaintext bytes; empty when the packet carried no ciphertext.
     * @pre The ciphertext length fits in `int`; OpenSSL takes the length as `int`.
     * @throw std::runtime_error on authentication failure or malformed packet. A wrong
     *        password and a corrupted packet raise the same message on purpose.
     * @warning The plaintext is returned in an ordinary `std::vector`, so it sits in
     *          pageable heap memory, not in locked memory. Wipe it with cleanseString() as
     *          soon as the value is consumed. On authentication failure the function
     *          discards the already-decrypted, unauthenticated bytes without a wipe, so they
     *          can stay in freed pageable heap.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> decryptPacket(
        std::span<const unsigned char> packet, const SecurePwd& password);

    /**
     * @brief Verify a framed AES-256-GCM packet without allocating full plaintext.
     *
     * Runs the same key derivation and GCM authentication as decryptPacket(), but decrypts
     * into a fixed 64 KiB scratch buffer and discards the output. Peak extra memory is that
     * buffer instead of the full plaintext length, which suits large encrypted files where
     * only password correctness matters. The packet arrives as a span, so it is already in
     * memory.
     *
     * The scratch buffer is `thread_local`: one per calling thread, never shared. It is
     * wiped on every normal exit, including authentication failure, because the wipe runs
     * before the tag check. A throw from the OpenSSL update call inside the streaming loop
     * skips the wipe and leaves unauthenticated plaintext in the buffer.
     *
     * @tparam SecurePwd See the class-level note on password containers.
     * @param packet   Framed encrypted packet (as produced by encryptPacket()).
     * @param password Master password for scrypt key derivation.
     * @throw std::runtime_error on authentication failure or malformed packet.
     * @note A normal return is the success signal; there is no return value and no
     *       plaintext leaves the function.
     */
    template <secure_password SecurePwd>
    static void verifyPacket(std::span<const unsigned char> packet, const SecurePwd& password);

private:
    // FileOperations builds the same wire format for streamed files, so it calls
    // deriveKey() and opensslCheck() directly.
    friend class FileOperations;

    /**
     * @brief Turn an OpenSSL return code into an exception.
     *
     * @param ok  OpenSSL return code; 1 means success, every other value fails.
     * @param msg Context text placed in front of the OpenSSL error string.
     * @throw std::runtime_error when @p ok is not 1. The message joins @p msg with the
     *        OpenSSL reason as `msg (OpenSSL: reason)`. It pops one entry with
     *        `ERR_get_error()`; older entries stay in the thread error queue.
     */
    static void opensslCheck(int ok, const char* msg);

    /// @brief Derived key type backed by guard-paged, locked memory.
    using LockedKeyBuffer = std::vector<unsigned char, locked_allocator<unsigned char>>;

    /**
     * @brief Derive the AES-256 key with scrypt into locked memory.
     *
     * The password bytes are read inside an @ref RWGuard, so the payload protection is
     * restored on every exit, including a throw from opensslCheck(). scrypt is fed
     * `pwd.size() * sizeof(CharT)` raw code-unit bytes: a narrow and a wide container
     * holding the "same" password derive different keys. An empty password is passed as a
     * null pointer with length 0.
     *
     * The OpenSSL maxmem argument is `max(cfg::SCRYPT_MAXMEM, 2 * 128 * r * N)`, so the
     * cost parameters from an already cap-checked header always fit.
     *
     * @tparam SecurePwd See the class-level note on password containers.
     * @param pwd  Master password; read only for the duration of the call.
     * @param salt Packet salt, `cfg::SALT_LEN` bytes.
     * @param kdf  Effective KDF parameters, normally from a parsed header.
     * @return A `cfg::KEY_LEN`-byte key in locked, guard-paged memory. The buffer wipes
     *         itself when it is destroyed, so an exception on the caller's path still
     *         clears the key.
     * @throw std::runtime_error when `EVP_PBE_scrypt` fails, for example when the working
     *        set cannot be allocated.
     * @warning This function trusts @p kdf. Pass only parameters that were cap-checked.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static LockedKeyBuffer deriveKey(const SecurePwd& pwd,
                                                   std::span<const unsigned char> salt,
                                                   const seal::cfg::KdfParams& kdf);

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
        if (!s.empty())
        {
            CharT* base = s.data();
            if (base)
            {
                auto* hdr = seal::header_from_payload(base);
                DWORD oldProt{}, dummy{};
                (void)VirtualProtect(base, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
                SecureZeroMemory(base, hdr->usable);
                (void)VirtualProtect(base, hdr->payloadSpan, oldProt, &dummy);
            }
        }
        s.clear();
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
