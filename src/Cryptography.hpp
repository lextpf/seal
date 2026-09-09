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
 * @brief AES-256-GCM packets, scrypt derivation and process hardening.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * packet calls are independent and may run concurrently. verifyPacket keeps one thread-local
 * 64 KiB scratch buffer; OpenSSL update exceptions can skip its wipe.
 *
 * crypto templates are instantiated only for secure_string<> and basic_secure_string<wchar_t>.
 * other containers link-fail despite satisfying secure_password. scrypt hashes raw code units:
 * the same text in narrow and wide containers derives different keys.
 *
 * hardening changes process-wide state at startup. trimWorkingSet runs only after secret wiping.
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
 */
class Cryptography
{
public:
    /**
     * @brief compare all bytes without an early exit.
     *
     * @param a readable for n bytes; unused when n is zero.
     * @param b readable for n bytes; unused when n is zero.
     * @param n byte count; determines runtime.
     * @return true for identical buffers, including zero bytes.
     */
    static bool ctEqualRaw(const unsigned char* a, const unsigned char* b, size_t n);

    /**
     * @brief compare equal-sized byte ranges without data-dependent exits.
     *
     * length mismatch returns early; lengths are public. wide ranges require ctEqualRaw with a
     * cast.
     *
     * @note only size mismatch can be constant-evaluated; equal sizes require the runtime raw call.
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
     * @brief apply byte-range equality to secure strings.
     *
     * @tparam CharT must be byte-like; wide strings do not compile.
     * @pre payloads are readable and DPAPI-unprotected; open guards before comparing.
     */
    template <class CharT, class A>
    static bool ctEqual(const basic_secure_string<CharT, A>& a,
                        const basic_secure_string<CharT, A>& b)
    {
        return ctEqualAny(a, b);
    }

    /**
     * @brief attempt irreversible heap-corruption termination for every process heap.
     *
     * HeapSetInformation failure is ignored.
     */
    static void hardenHeap();

    /**
     * @brief deny external memory, handle-duplication, thread-creation and query rights.
     *
     * the Everyone deny ACE precedes allows and includes SYSTEM and administrators.
     *
     * @warning SeDebugPrivilege bypasses the DACL. startup continues on failure; the Qt diagnostic
     *          reports only SDDL conversion, so failed SetSecurityInfo can still log result=ok.
     */
    static void hardenProcessAccess();

    /**
     * @brief suppress WER dialogs and terminate on unhandled exceptions with exit code 1.
     *
     * replaces any existing exception filter.
     *
     * @warning debugger dumps, in-process MiniDumpWriteDump calls and kernel dumps remain possible.
     */
    static void disableCrashDumps();

    /**
     * @brief terminate on a positive startup debugger check.
     *
     * checks IsDebuggerPresent, CheckRemoteDebuggerPresent and ProcessDebugPort in order.
     * unresolved ntdll/export skips the last check.
     *
     * @post detection calls TerminateProcess(0xDEAD), then __fastfail(7); it does not return.
     * @note later debugger attachment is not detected.
     */
    static void detectDebugger();

    /**
     * @brief evict pageable pages from the working set; locked pages stay resident.
     *
     * @warning wipe first. trimming can write dirty pageable secrets to the page file; it does not
     *          erase.
     */
    static void trimWorkingSet();

    /**
     * @brief attempt dynamic-code, signature, side-channel, handle, extension and image policies.
     *
     * DEP, CFG and ASLR come from linker flags. every policy is attempted even after failure;
     * successful policies remain active and most cannot be undone.
     *
     * @param allowDynamicCode true permits the QML V4 JIT; false prohibits dynamic code.
     * @return false if the API cannot resolve or any attempted policy fails.
     */
    static BOOL setSecureProcessMitigations(bool allowDynamicCode);

    /**
     * @brief attempt to enable SeLockMemoryPrivilege on the process token.
     *
     * checks GetLastError because AdjustTokenPrivileges can succeed without assigning the
     * privilege.
     *
     * @return false for token/API failure or missing privilege.
     * @note VirtualLock can still work within the working-set quota without this privilege.
     */
    static BOOL tryEnableLockPrivilege();

    static void cleanseString() noexcept
    { /* base case for variadic fold expression - intentionally empty */ }

    /**
     * @brief wipe mutable containers and pointers, releasing container storage.
     *
     * | argument               | wipe coverage               | after          |
     * |------------------------|-----------------------------|----------------|
     * | std::basic_string      | live bytes                  | clear + shrink |
     * | basic_secure_string    | full allocation usable span | clear          |
     * | std::vector<byte_like> | live bytes                  | clear + shrink |
     * | CharT*                 | code units before first NUL | not freed      |
     *
     * null pointers are ignored. secure strings open payload pages and restore protection;
     * vectors and raw pointers must already be writable. the private pointer-plus-length primitive
     * cannot be selected through this variadic interface.
     */
    template <class... Ts>
    static void cleanseString(Ts&&... xs) noexcept
    {
        (cleanseOne(std::forward<Ts>(xs)), ...);
    }

    /// @brief report whether the process runs inside a remote desktop client session.
    static bool isRemoteSession() { return GetSystemMetrics(SM_REMOTESESSION) != 0; }

    /**
     * @struct PacketHeader
     * @brief exact on-wire header bytes used verbatim as GCM AAD.
     *
     * default construction is unusable; makeHeader() or parsePacketHeader() fills bytes and size.
     */
    struct PacketHeader
    {
        seal::cfg::KdfParams kdf{};            ///< effective KDF parameters.
        std::array<unsigned char, 8> bytes{};  ///< raw header bytes (AAD).
        /// zero until filled; cfg::HDR_LEN (8) after construction or parsing.
        size_t size = 0;
    };

    /**
     * @brief serialize trusted KDF parameters as packet AAD.
     *
     * @warning no range check occurs; never pass parameters from an untrusted packet.
     */
    [[nodiscard]] static PacketHeader makeHeader(
        const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

    /**
     * @brief cap-check KDF fields before derivation and preserve the received AAD bytes.
     *
     * only the first eight bytes are inspected; the caller validates the remaining packet lengths.
     *
     * @throw std::runtime_error on short input, unknown magic or excessive parameters. recognized
     *        magic followed by fewer than eight bytes reports a truncated header.
     */
    [[nodiscard]] static PacketHeader parsePacketHeader(std::span<const unsigned char> data);

    /**
     * @brief frame ciphertext with fresh random salt and IV.
     *
     * the derived key is wiped on success and exceptions.
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
     * @param kdf trusted parameters; not cap-checked.
     * @return packet length is plaintext length plus 52 bytes.
     * @throw std::runtime_error on random-generation, scrypt or cipher failure.
     * @pre plaintext.size() fits in int.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> encryptPacket(
        std::span<const unsigned char> plaintext,
        const SecurePwd& password,
        const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

    /**
     * @brief authenticate packet AAD and ciphertext after cap-checking its KDF fields.
     *
     * @return pageable plaintext vector; empty for authenticated empty ciphertext.
     * @throw std::runtime_error for malformed packets or authentication failure; wrong passwords
     *        and corruption share the same message.
     * @pre ciphertext length fits in int.
     * @warning wipe returned plaintext immediately. authentication failure frees already-decrypted
     *          unauthenticated bytes without wiping them.
     */
    template <secure_password SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> decryptPacket(
        std::span<const unsigned char> packet, const SecurePwd& password);

    /**
     * @brief authenticate an in-memory packet with a 64 KiB thread-local plaintext buffer.
     *
     * normal return means success; no plaintext leaves the function. scratch is wiped before the
     * tag check, including authentication failure.
     *
     * @throw std::runtime_error for malformed packets or authentication failure.
     * @warning an OpenSSL update exception skips the scratch wipe.
     */
    template <secure_password SecurePwd>
    static void verifyPacket(std::span<const unsigned char> packet, const SecurePwd& password);

private:
    // FileOperations builds the same wire format for streamed files, so it calls
    // deriveKey() and opensslCheck() directly.
    friend class FileOperations;

    /**
     * @brief throw on any OpenSSL result other than one.
     *
     * @param msg prefixed to one error popped from the thread queue; remaining errors stay queued.
     * @throw std::runtime_error with format msg (OpenSSL: reason).
     */
    static void opensslCheck(int ok, const char* msg);

    /// @brief derived key type backed by guard-paged, locked memory.
    using LockedKeyBuffer = std::vector<unsigned char, locked_allocator<unsigned char>>;

    /**
     * @brief derive a self-wiping locked key from raw password code units.
     *
     * RWGuard restores password page protection on every exit. scrypt receives
     * pwd.size() * sizeof(CharT) bytes; empty passwords use nullptr and zero length.
     * OpenSSL maxmem is max(SCRYPT_MAXMEM, 2 * 128 * r * N).
     *
     * @param salt readable for cfg::SALT_LEN bytes.
     * @param kdf must already pass acceptance caps.
     * @return cfg::KEY_LEN bytes in guarded memory.
     * @throw std::runtime_error on scrypt failure.
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
