#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32
#error "Platform not supported: This source targets Windows APIs."
#endif

#include <windows.h>
#include <winnt.h>
#include <heapapi.h>
#include <processthreadsapi.h>
#include <wincrypt.h>
#include <psapi.h>
#include <aclapi.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <algorithm>
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <ranges>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Comdlg32.lib")
#pragma comment(lib, "Crypt32.lib")
#endif

namespace sage {
    /**
     * @namespace sage::cfg
     * @brief Cryptographic and framing constants.
     * @author Alex (https://github.com/lextpf)
     */
    namespace cfg {
        static constexpr size_t SALT_LEN = 16;
        static constexpr size_t KEY_LEN = 32;
        static constexpr size_t IV_LEN = 12;
        static constexpr size_t TAG_LEN = 16;
        static constexpr size_t FILE_CHUNK = 1 << 20;
        static constexpr char   AAD_HDR[] = "SAGE$";
        static constexpr size_t AAD_LEN = sizeof(AAD_HDR) - 1;
    }

    /// @brief Concept for byte-addressable element types.
    template<class T>
    concept byte_like = std::same_as<std::remove_cv_t<T>, unsigned char> ||
        std::same_as<std::remove_cv_t<T>, char> ||
#if __cplusplus >= 201703L
        std::same_as<std::remove_cv_t<T>, std::byte>;
#else
        false;
#endif

    /// @brief Round up to the next multiple of an alignment.
    static inline size_t align_up(size_t v, size_t a) { return (v + (a - 1)) & ~(a - 1); }

    static constexpr uint32_t kMagic = 0x53524950u;      //!< Header integrity magic ("PRIS")
    static constexpr uint32_t kVersion = 1u;              //!< Header version number
    static constexpr size_t   kCanaryBytes = 32;          //!< Canary bytes after payload (0xD0)

    /**
     * @brief Per-allocation metadata for guarded regions.
     * @author Alex (https://github.com/lextpf)
     * @ingroup Crypto
     */
    struct locked_header {
        void* base;         //!< Start of reserved region (includes guard pages)
        size_t total;       //!< Total reserved bytes (guard + middle + guard)
        size_t middleSize;  //!< Committed bytes (no guards)
        size_t usable;      //!< Requested payload bytes
        size_t headerSize;  //!< Padded header size used (page-aligned)
        size_t payloadSpan; //!< Committed payload span (usable + canary + slack)
        uint32_t magic;     //!< Integrity check value (must match kMagic)
        uint32_t version;   //!< Header version (must match kVersion)
    };

    /// @brief Reconstruct allocation header from a payload pointer.
    template<class T>
    inline locked_header* header_from_payload(const T* payload) {
        SYSTEM_INFO si{}; GetSystemInfo(&si);
        SIZE_T page = si.dwPageSize ? si.dwPageSize : 4096;
        // The header sits exactly one page-aligned header block before the payload.
        // allocate() placed the payload at (middle + headerSize), so we reverse that.
        SIZE_T headerSize = align_up(sizeof(locked_header), page);
        auto addr = reinterpret_cast<uintptr_t>(payload) - headerSize;
        return reinterpret_cast<locked_header*>(addr);
    }

    /**
     * @brief Secure allocator with guard pages and page locking.
     * @ingroup Crypto
     * @author Alex (https://github.com/lextpf)
     * @tparam T Element type to allocate.
     */
    template <class T>
    struct locked_allocator {
        using value_type = T;

        locked_allocator() noexcept = default;
        template<class U> explicit locked_allocator(const locked_allocator<U>&) noexcept {}

        /// @brief Allocate n objects in a locked, guarded region.
        T* allocate(std::size_t n) {
            if (n == 0) n = 1;
            SIZE_T needBytes = n * sizeof(T);

            SYSTEM_INFO si{}; GetSystemInfo(&si);
            SIZE_T page = si.dwPageSize ? si.dwPageSize : 4096;

            // Layout: [guard page | header | payload + canary + slack | guard page]
            // The header is page-aligned so VirtualProtect can change payload
            // protection without affecting the header.
            SIZE_T headerSize = align_up(sizeof(locked_header), page);
            SIZE_T afterHeader = headerSize + needBytes + kCanaryBytes;
            SIZE_T middleNeed = align_up(afterHeader, page);   // round up to full pages
            SIZE_T total = middleNeed + 2 * page;              // add front + back guard pages

            // Reserve the entire region as PAGE_NOACCESS - the two guard pages at
            // each end stay NOACCESS permanently to trap out-of-bounds access.
            BYTE* base = (BYTE*)VirtualAlloc(nullptr, total, MEM_RESERVE, PAGE_NOACCESS);
            if (!base) throw std::bad_alloc();

            // Commit only the middle (header + payload) as read-write.
            BYTE* middle = (BYTE*)VirtualAlloc(base + page, middleNeed, MEM_COMMIT, PAGE_READWRITE);
            if (!middle) { VirtualFree(base, 0, MEM_RELEASE); throw std::bad_alloc(); }

            // Pin committed pages in physical RAM so they're never swapped to disk.
            // Best-effort: requires SeLockMemoryPrivilege or sufficient working-set quota.
            (void)VirtualLock(middle, middleNeed);

            // Write metadata into the header at the start of the committed region.
            auto* hdr = reinterpret_cast<locked_header*>(middle);
            hdr->base = base;
            hdr->total = total;
            hdr->middleSize = middleNeed;
            hdr->usable = needBytes;
            hdr->headerSize = headerSize;
            hdr->payloadSpan = middleNeed - headerSize; // everything after header (usable + canary + slack)
            hdr->magic = kMagic;
            hdr->version = kVersion;

            BYTE* payload = middle + headerSize;

            // Fill canary bytes (0xD0) immediately after the usable region.
            // deallocate() checks these to detect buffer overruns.
            memset(payload + needBytes, 0xD0, (std::min)(kCanaryBytes, hdr->payloadSpan - hdr->usable));
            return reinterpret_cast<T*>(payload);
        }

        /// @brief Deallocate and securely wipe a prior allocation.
        void deallocate(T* p, std::size_t) noexcept {
            if (!p) return;

            auto* hdr = header_from_payload(p);
            BYTE* bytes = reinterpret_cast<BYTE*>(p);

            // Verify the header wasn't corrupted by a wild write.
            // __fastfail raises a non-continuable exception - better to crash
            // than to free a corrupted region and enable exploitation.
            if (hdr->magic != kMagic || hdr->version != kVersion) {
#ifdef _MSC_VER
                __fastfail(1);
#else
                std::terminate();
#endif
            }

            // Snapshot header fields into locals before we wipe the header,
            // because the header lives in the same committed region we're about to scrub.
            void* base = hdr->base;
            SIZE_T middleSize = hdr->middleSize;
            SIZE_T payloadSpan = hdr->payloadSpan;
            SIZE_T usable = hdr->usable;

            // The payload might be PAGE_NOACCESS (e.g. after protect_noaccess).
            // Temporarily restore RW so we can inspect the canary and wipe.
            DWORD oldProt{}, dummy{};
            (void)VirtualProtect(bytes, payloadSpan, PAGE_READWRITE, &oldProt);

            // Check the 0xD0 canary sentinel placed after the usable region.
            // A corrupted canary means something wrote past the end of the buffer.
            const size_t canary_span = (std::min)(kCanaryBytes, payloadSpan - usable);

            bool canary_ok = true;
            for (size_t i = 0; i < canary_span; ++i) {
                if (bytes[usable + i] != (BYTE)0xD0) { canary_ok = false; break; }
            }

            // If the user already called Cryptography::cleanseString / SecureZeroMemory, the entire
            // region (payload + canary) will be zeroed - that's expected, not a corruption.
            // Only flag a canary failure when the memory wasn't already wiped.
            bool looks_wiped = true;
            for (size_t i = 0; i < usable + canary_span; ++i) {
                if (bytes[i] != 0) { looks_wiped = false; break; }
            }

            // Scrub everything from payload through the end of committed pages.
            // SecureZeroMemory is not elided by the optimizer.
            if (payloadSpan) SecureZeroMemory(bytes, payloadSpan);
            (void)VirtualProtect(bytes, payloadSpan, oldProt, &dummy);

#if defined(_DEBUG)
            // In debug builds, treat a genuine overrun as fatal for early detection.
            if (!canary_ok && !looks_wiped) {
#ifdef _MSC_VER
                __fastfail(2);
#else
                std::terminate();
#endif
            }
#else
            // In release, log a warning but don't crash - the data is already wiped.
            if (!canary_ok && !looks_wiped) {
                OutputDebugStringA("[sage] WARN: canary mismatch on free (not wiped)\n");
            }
#endif

            // Wipe the header so metadata (pointers, sizes) doesn't linger in memory.
            SecureZeroMemory(hdr, sizeof(locked_header));

            // Unlock pinned pages and release the entire reserved region
            // (guard pages + committed pages) back to the OS.
            if (middleSize) (void)VirtualUnlock((LPVOID)((BYTE*)hdr), middleSize);
            if (base)       (void)VirtualFree(base, 0, MEM_RELEASE);
        }

        template<class U> struct rebind { using other = locked_allocator<U>; };
    };

    /// @brief Equality comparison for locked allocators.
    template<class T, class U>
    inline bool operator==(const locked_allocator<T>&, const locked_allocator<U>&) { return true; }
    template<class T, class U>
    inline bool operator!=(const locked_allocator<T>&, const locked_allocator<U>&) { return false; }

    /// @brief Switch the payload protection to PAGE_NOACCESS.
    template<class T>
    inline void protect_noaccess(const T* p) {
        if (!p) return;
        auto* hdr = header_from_payload(p);
        DWORD oldProt;
        (void)VirtualProtect(const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_NOACCESS, &oldProt);
    }

    /// @brief Switch the payload protection to PAGE_READWRITE.
    template<class T>
    inline void protect_readwrite(const T* p) {
        if (!p) return;
        auto* hdr = header_from_payload(p);
        DWORD oldProt;
        (void)VirtualProtect(const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_READWRITE, &oldProt);
    }

    /**
     * @brief Secure string with locked, guarded memory.
     * @author Alex (https://github.com/lextpf)
     * @ingroup Crypto
     */
    template <class A = locked_allocator<char>>
    struct secure_string {
        std::vector<char, A> s;

        secure_string() = default;
        secure_string(const secure_string&) = delete;
        secure_string& operator=(const secure_string&) = delete;
        secure_string(secure_string&& o) noexcept : s(std::move(o.s)) {}
        secure_string& operator=(secure_string&& o) noexcept {
            if (this != &o) { clear(); s = std::move(o.s); }
            return *this;
        }
        ~secure_string() { clear(); }

        void   push_back(char c) { s.push_back(c); }
        void   pop_back() { if (!s.empty()) s.pop_back(); }
        bool   empty() const { return s.empty(); }
        size_t size()  const { return s.size(); }
        char*  data() { return s.data(); }
        const char*      data() const { return s.data(); }
        std::string_view view() const noexcept { return { s.data(), s.size() }; }

        const char* c_str() {
            if (s.empty() || s.back() != '\0') s.push_back('\0');
            return s.data();
        }

        void clear() {
            if (!s.empty()) {
                // The buffer may be PAGE_NOACCESS (e.g. after protect_noaccess).
                // Restore RW so SecureZeroMemory can reach the bytes.
                sage::protect_readwrite(s.data());
                SecureZeroMemory(s.data(), s.size());
                // clear() sets logical size to 0; swap with a temporary releases
                // the allocation back to the locked_allocator (which wipes + frees).
                s.clear();
                std::vector<char, A>().swap(s);
            }
            else {
                // The vector may be empty (size == 0) but still hold a live
                // allocation with capacity > 0.  That buffer is guarded memory
                // that must be freed, not leaked.
                if (s.capacity() > 0 && s.data()) {
                    sage::protect_readwrite(s.data());
                    s.clear();
                    std::vector<char, A>().swap(s);
                }
            }
        }

        std::string str_copy() const { return std::string(s.data(), s.data() + s.size()); }
    };

    /**
     * @brief Wide secure string for arbitrary code unit types.
     * @author Alex (https://github.com/lextpf)
     */
    template <class CharT, class A = locked_allocator<CharT>>
    struct basic_secure_string {
        std::vector<CharT, A> s;

        basic_secure_string() = default;
        basic_secure_string(const basic_secure_string&) = delete;
        basic_secure_string& operator=(const basic_secure_string&) = delete;
        basic_secure_string(basic_secure_string&& o) noexcept : s(std::move(o.s)) {}
        basic_secure_string& operator=(basic_secure_string&& o) noexcept {
            if (this != &o) { clear(); s = std::move(o.s); }
            return *this;
        }
        ~basic_secure_string() { clear(); }

        void   push_back(CharT c) { s.push_back(c); }
        void   pop_back() { if (!s.empty()) s.pop_back(); }
        bool   empty() const { return s.empty(); }
        size_t size()  const { return s.size(); }
        CharT* data() { return s.data(); }
        const CharT*                  data() const { return s.data(); }
        std::basic_string_view<CharT> view() const noexcept { return { s.data(), s.size() }; }

        const CharT* c_str() {
            if (s.empty() || s.back() != CharT{}) s.push_back(CharT{});
            return s.data();
        }

        void clear() {
            if (!s.empty()) {
                // Restore RW in case the buffer was marked PAGE_NOACCESS.
                sage::protect_readwrite(s.data());
                // Wipe in bytes - sizeof(CharT) may be 2 (wchar_t) or 4 (char32_t).
                SecureZeroMemory(s.data(), s.size() * sizeof(CharT));
                // Swap-to-empty releases the guarded allocation back to the OS.
                s.clear();
                std::vector<CharT, A>().swap(s);
            }
            else {
                // Same as secure_string::clear - handle capacity-only allocations.
                if (s.capacity() > 0 && s.data()) {
                    sage::protect_readwrite(s.data());
                    s.clear();
                    std::vector<CharT, A>().swap(s);
                }
            }
        }

        std::basic_string<CharT> str_copy() const { return std::basic_string<CharT>(s.data(), s.data() + s.size()); }
    };

    /// @brief RAII guard to temporarily set a locked payload to RW.
    template<class T>
    struct RWGuard {
        const T* p{};
        DWORD oldProt{};
        bool changed{ false };
        explicit RWGuard(const T* ptr) : p(ptr) {
            if (!p) return;
            // Flip the payload span to PAGE_READWRITE, saving the previous
            // protection so we can restore it when the guard goes out of scope.
            auto* hdr = header_from_payload(p);
            changed = !!VirtualProtect(const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_READWRITE, &oldProt);
        }
        ~RWGuard() {
            if (!p || !changed) return;
            // Restore the original protection (typically PAGE_NOACCESS).
            auto* hdr = header_from_payload(p);
            DWORD tmp;
            (void)VirtualProtect(const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, oldProt, &tmp);
        }
        RWGuard(const RWGuard&) = delete;
        RWGuard& operator=(const RWGuard&) = delete;
        RWGuard(RWGuard&&) = delete;
        RWGuard& operator=(RWGuard&&) = delete;
    };

    /**
     * @brief RAII guard for DPAPI in-memory encryption of secure strings.
     *
     * Wraps CryptProtectMemory / CryptUnprotectMemory with SAME_PROCESS scope.
     * The buffer is encrypted on construction and decrypted only during
     * explicit unprotect/reprotect windows. Destruction unprotects then wipes.
     *
     * CryptProtectMemory requires the buffer size to be a multiple of
     * CRYPTPROTECTMEMORY_BLOCK_SIZE. The guard pads the backing vector
     * to meet this requirement transparently.
     */
    template<class SecStr>
    struct DPAPIGuard {
        using char_type = typename decltype(SecStr::s)::value_type;

        SecStr* m_Str = nullptr;
        bool    m_Protected = false;

        DPAPIGuard() = default;
        explicit DPAPIGuard(SecStr* str) : m_Str(str) { protect(); }

        DPAPIGuard(const DPAPIGuard&) = delete;
        DPAPIGuard& operator=(const DPAPIGuard&) = delete;
        DPAPIGuard(DPAPIGuard&& o) noexcept
            : m_Str(o.m_Str), m_Protected(o.m_Protected)
        {
            o.m_Str = nullptr;
            o.m_Protected = false;
        }
        DPAPIGuard& operator=(DPAPIGuard&& o) noexcept {
            if (this != &o) {
                release();
                m_Str = o.m_Str;
                m_Protected = o.m_Protected;
                o.m_Str = nullptr;
                o.m_Protected = false;
            }
            return *this;
        }

        ~DPAPIGuard() { release(); }

        void protect() {
            if (!m_Str || m_Str->empty() || m_Protected) return;
            padToBlockSize();
            sage::protect_readwrite(m_Str->s.data());
            DWORD cbData = static_cast<DWORD>(m_Str->s.size() * sizeof(char_type));
            if (CryptProtectMemory(m_Str->s.data(), cbData, CRYPTPROTECTMEMORY_SAME_PROCESS))
                m_Protected = true;
        }

        void unprotect() {
            if (!m_Str || m_Str->empty() || !m_Protected) return;
            sage::protect_readwrite(m_Str->s.data());
            DWORD cbData = static_cast<DWORD>(m_Str->s.size() * sizeof(char_type));
            if (CryptUnprotectMemory(m_Str->s.data(), cbData, CRYPTPROTECTMEMORY_SAME_PROCESS))
                m_Protected = false;
        }

        void reprotect() { protect(); }

    private:
        void padToBlockSize() {
            if (!m_Str || m_Str->empty()) return;
            size_t byteSize = m_Str->s.size() * sizeof(char_type);
            size_t rem = byteSize % CRYPTPROTECTMEMORY_BLOCK_SIZE;
            if (rem != 0) {
                size_t padBytes = CRYPTPROTECTMEMORY_BLOCK_SIZE - rem;
                size_t padChars = (padBytes + sizeof(char_type) - 1) / sizeof(char_type);
                m_Str->s.resize(m_Str->s.size() + padChars, char_type{});
            }
        }

        void release() {
            if (m_Str && m_Protected) {
                unprotect();
            }
            m_Str = nullptr;
            m_Protected = false;
        }
    };

    /**
     * @brief RAII console mode guard.
     * @author Alex (https://github.com/lextpf)
     */
    struct scoped_console {
        HANDLE h;
        DWORD  oldMode{};
        bool   changed{ false };
        scoped_console(HANDLE handle, DWORD mode) : h(handle) {
            // Snapshot the current mode so we can restore it in the destructor,
            // then apply the requested mode (e.g. ENABLE_MOUSE_INPUT for
            // MaskedCredentialView hit-testing).
            if (GetConsoleMode(h, &oldMode)) {
                DWORD inNew = mode;
                changed = !!SetConsoleMode(h, inNew);
            }
        }
        ~scoped_console() {
            if (changed) SetConsoleMode(h, oldMode);
        }
        scoped_console(const scoped_console&) = delete;
        scoped_console& operator=(const scoped_console&) = delete;
    };

    /// @brief RAII owner for EVP_CIPHER_CTX.
    struct EVP_CTX {
        EVP_CIPHER_CTX* p{ nullptr };
        EVP_CTX() : p(EVP_CIPHER_CTX_new()) { if (!p) throw std::runtime_error("EVP_CIPHER_CTX_new failed"); }
        ~EVP_CTX() { if (p) EVP_CIPHER_CTX_free(p); }
        EVP_CTX(const EVP_CTX&) = delete;
        EVP_CTX& operator=(const EVP_CTX&) = delete;
    };

    /**
     * @class Cryptography
     * @brief AES-256-GCM encryption, scrypt key derivation, and secure memory.
     * @author Alex (https://github.com/lextpf)
     * @ingroup Crypto
     */
    class Cryptography
    {
    public:
        /// @brief Constant-time byte comparison.
        static bool ctEqualRaw(const unsigned char* a, const unsigned char* b, size_t n);

        /// @brief Constant-time equality for byte-like ranges.
        template<class A, class B>
        requires requires (const A& aa, const B& bb) {
            { std::ranges::data(aa) };
            { std::ranges::data(bb) };
            { std::ranges::size(aa) } -> std::convertible_to<std::size_t>;
            { std::ranges::size(bb) } -> std::convertible_to<std::size_t>;
                requires sage::byte_like<
                    std::remove_pointer_t<decltype(std::ranges::data(aa))>>;
                        requires sage::byte_like<
                            std::remove_pointer_t<decltype(std::ranges::data(bb))>>;
        }
        [[nodiscard]] static constexpr bool ctEqualAny(const A& aa, const B& bb)
        {
            if (std::ranges::size(aa) != std::ranges::size(bb)) return false;
            return ctEqualRaw(
                reinterpret_cast<const unsigned char*>(std::ranges::data(aa)),
                reinterpret_cast<const unsigned char*>(std::ranges::data(bb)),
                std::ranges::size(aa));
        }

        template<class A>
        static bool ctEqual(const secure_string<A>& a, const secure_string<A>& b)
        {
            return ctEqualAny(a.s, b.s);
        }

        template<class CharT, class A>
        static bool ctEqual(const basic_secure_string<CharT, A>& a,
                            const basic_secure_string<CharT, A>& b)
        {
            return ctEqualAny(a.s, b.s);
        }

        /// @brief Enable heap termination on corruption.
        static void hardenHeap();

        /// @brief Set a restrictive DACL on the current process to block memory reads.
        static void hardenProcessAccess();

        /// @brief Suppress crash dumps and WER dialogs to prevent memory disclosure.
        static void disableCrashDumps();

        /// @brief Detect attached debuggers and abort if found.
        static void detectDebugger();

        /// @brief Trim the working set to reduce plaintext residency in physical RAM.
        static void trimWorkingSet();

        /// @brief Apply process-wide security mitigations.
        static BOOL setSecureProcessMitigations(bool allowDynamicCode);

        /// @brief Enable SeLockMemoryPrivilege if available.
        static BOOL tryEnableLockPrivilege();

        /// @brief Securely wipe and release containers.
        static void cleanseString() noexcept { /* Base case for variadic fold expression - intentionally empty */ }

        template <class... Ts>
        static void cleanseString(Ts&&... xs) noexcept
        {
            (cleanseOne(std::forward<Ts>(xs)), ...);
        }

        /// @brief Detect Remote Desktop session.
        static bool isRemoteSession()
        {
            return GetSystemMetrics(SM_REMOTESESSION) != 0;
        }

        /// @brief Encrypt plaintext into a framed AES-256-GCM packet.
        template<class SecurePwd>
        [[nodiscard]] static std::vector<unsigned char>
            encryptPacket(std::span<const unsigned char> plaintext,
                const SecurePwd& password);

        /// @brief Decrypt a framed AES-256-GCM packet.
        template<class SecurePwd>
        [[nodiscard]] static std::vector<unsigned char>
            decryptPacket(std::span<const unsigned char> packet,
                const SecurePwd& password);

    private:
        /// @brief Check OpenSSL return code.
        static void opensslCheck(int ok, const char* msg);

        /// @brief Get authenticated AAD span.
        static std::span<const unsigned char> aadSpan() noexcept;

        /// @brief Derive AES-256 key via scrypt.
        template<class SecurePwd>
        [[nodiscard]] static std::vector<unsigned char> deriveKey(
            const SecurePwd& pwd,
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

        template <class A>
        static void cleanseOne(sage::secure_string<A>& s) noexcept
        {
            if (!s.s.empty())
            {
                char* base = s.s.data();
                if (base)
                {
                    auto* hdr = sage::header_from_payload(base);
                    DWORD oldProt{}, dummy{};
                    (void)VirtualProtect(base, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
                    SecureZeroMemory(base, hdr->usable);
                    (void)VirtualProtect(base, hdr->payloadSpan, oldProt, &dummy);
                }
            }
            s.s.clear();
            std::vector<char, A>().swap(s.s);
        }

        template <class CharT, class A>
        static void cleanseOne(sage::basic_secure_string<CharT, A>& s) noexcept
        {
            if (!s.s.empty())
            {
                CharT* base = s.s.data();
                if (base)
                {
                    auto* hdr = sage::header_from_payload(base);
                    DWORD oldProt{}, dummy{};
                    (void)VirtualProtect(base, hdr->payloadSpan, PAGE_READWRITE, &oldProt);
                    SecureZeroMemory(base, hdr->usable);
                    (void)VirtualProtect(base, hdr->payloadSpan, oldProt, &dummy);
                }
            }
            s.s.clear();
            std::vector<CharT, A>().swap(s.s);
        }

        template <sage::byte_like T, class Alloc>
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
        static void cleanseOne(CharT* p, size_t len) noexcept
        {
            static_assert(std::is_trivial_v<CharT>, "CharT must be trivial");
            OPENSSL_cleanse(static_cast<void*>(p), len * sizeof(CharT));
        }

        template <class CharT>
        static void cleanseOne(CharT* p) noexcept
        {
            if (!p) return;
            const size_t n = std::char_traits<CharT>::length(p);
            cleanseOne(p, n);
        }
    };

    /**
     * @brief RAII holder for three narrow secure strings.
     * @author Alex (https://github.com/lextpf)
     */
    template<class A = sage::locked_allocator<char>>
    struct secure_triplet {
        sage::secure_string<A> service, user, pass;

        secure_triplet(sage::secure_string<A>&& s, sage::secure_string<A>&& u, sage::secure_string<A>&& p) noexcept
            : service(std::move(s)), user(std::move(u)), pass(std::move(p)) {
        }

        secure_triplet(secure_triplet&&) noexcept = default;
        secure_triplet& operator=(secure_triplet&&) noexcept = default;
        secure_triplet(const secure_triplet&) = delete;
        secure_triplet& operator=(const secure_triplet&) = delete;
    };
    using secure_triplet_t = secure_triplet<>;

    /**
     * @brief RAII holder for three wide secure strings.
     * @author Alex (https://github.com/lextpf)
     */
    template<class A = sage::locked_allocator<wchar_t>>
    struct secure_triplet16 {
        using string_type = sage::basic_secure_string<wchar_t, A>;

        // Keep original names
        string_type primary, secondary, tertiary;

        secure_triplet16(string_type&& s, string_type&& u, string_type&& p) noexcept
            : primary(std::move(s)), secondary(std::move(u)), tertiary(std::move(p)) {
        }

        secure_triplet16(secure_triplet16&&) noexcept = default;
        secure_triplet16& operator=(secure_triplet16&&) noexcept = default;
        secure_triplet16(const secure_triplet16&) = delete;
        secure_triplet16& operator=(const secure_triplet16&) = delete;

        // Element count
        static constexpr std::size_t size() noexcept { return 3; }

        // [] Access (unchecked, like std::array::operator[])
        string_type& operator[](std::size_t i) noexcept {
            assert(i < 3);
            switch (i) {
            case 0: return primary;
            case 1: return secondary;
            default: return tertiary;
            }
        }
        const string_type& operator[](std::size_t i) const noexcept {
            assert(i < 3);
            switch (i) {
            case 0: return primary;
            case 1: return secondary;
            default: return tertiary;
            }
        }

        // Bounds-checked access
        string_type& at(std::size_t i) {
            if (i >= 3) throw std::out_of_range("secure_triplet::at");
            return (*this)[i];
        }
        const string_type& at(std::size_t i) const {
            if (i >= 3) throw std::out_of_range("secure_triplet::at");
            return (*this)[i];
        }

        // First/second/third accessors
        string_type& first() noexcept { return primary; }
        string_type& second() noexcept { return secondary; }
        string_type& third() noexcept { return tertiary; }

        const string_type& first()  const noexcept { return primary; }
        const string_type& second() const noexcept { return secondary; }
        const string_type& third()  const noexcept { return tertiary; }

        // Tuple-like member get<I>()
        template<std::size_t I>
        decltype(auto) get() & noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
        template<std::size_t I>
        decltype(auto) get() const& noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
        template<std::size_t I>
        decltype(auto) get() && noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
        template<std::size_t I>
        decltype(auto) get() const&& noexcept {
            static_assert(I < 3, "secure_triplet index out of range");
            if constexpr (I == 0) return (primary);
            else if constexpr (I == 1) return (secondary);
            else return (tertiary);
        }
    };
    using secure_triplet16_t = secure_triplet16<>;

} // namespace sage
