#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32
#error "Platform not supported: This source targets Windows APIs."
#endif

#include <aclapi.h>
#include <heapapi.h>
#include <processthreadsapi.h>
#include <psapi.h>
#include <wincrypt.h>
#include <windows.h>
#include <winnt.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

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

namespace seal
{
/**
 * @namespace seal::cfg
 * @brief Cryptographic and framing constants for AES-256-GCM encryption.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Packet wire format:
 * $[\text{AAD}_{4} \mid \text{Salt}_{16} \mid \text{IV}_{12} \mid \text{CT}_{n} \mid
 * \text{Tag}_{16}]$ where $n = |\text{plaintext}|$.
 *
 * scrypt memory usage: $M = 128 \cdot r \cdot N = 128 \cdot 8 \cdot 2^{16} = 64\text{ MiB}$.
 */
namespace cfg
{
static constexpr size_t SALT_LEN = 16;         ///< scrypt salt length in bytes.
static constexpr size_t KEY_LEN = 32;          ///< AES-256 key length in bytes.
static constexpr size_t IV_LEN = 12;           ///< AES-GCM initialisation vector length in bytes.
static constexpr size_t TAG_LEN = 16;          ///< GCM authentication tag length in bytes.
static constexpr size_t FILE_CHUNK = 1 << 20;  ///< Read-buffer chunk size (1 MiB).
static constexpr char AAD_HDR[] = "seal";      ///< Additional authenticated data header
static constexpr size_t AAD_LEN =
    sizeof(AAD_HDR) - 1;  ///< AAD header length excluding null terminator.
static constexpr uint64_t SCRYPT_N =
    1ULL << 16;                          ///< scrypt CPU/memory cost parameter ($2^{16} = 65536$).
static constexpr uint64_t SCRYPT_R = 8;  ///< scrypt block size parameter.
static constexpr uint64_t SCRYPT_P = 1;  ///< scrypt parallelisation parameter.
static constexpr uint64_t SCRYPT_MAXMEM =
    128ULL * 1024 * 1024;  ///< scrypt maximum memory allowance (128 MiB, ~2x working set).
}  // namespace cfg

/// @brief Concept for byte-addressable element types.
template <class T>
concept byte_like =
    std::same_as<std::remove_cv_t<T>, unsigned char> || std::same_as<std::remove_cv_t<T>, char> ||
#if __cplusplus >= 201703L
    std::same_as<std::remove_cv_t<T>, std::byte>;
#else
    false;
#endif

/// @brief Round up to the next multiple of an alignment.
static inline size_t align_up(size_t v, size_t a)
{
    return (v + (a - 1)) & ~(a - 1);
}

static constexpr uint32_t kMagic = 0x6C616573u;  //!< Header integrity magic ("seal")
static constexpr uint32_t kVersion = 1u;         //!< Header version number
static constexpr size_t kCanaryBytes = 32;       //!< Canary bytes after payload (0xD0)

/**
 * @struct locked_header
 * @brief Per-allocation metadata for guarded regions.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Stored at the start of the committed region, immediately after the
 * front guard page. The header is page-aligned so that payload
 * protection changes (via VirtualProtect) never affect the header.
 *
 * @see locked_allocator, header_from_payload
 */
struct locked_header
{
    void* base;          //!< Start of reserved region (includes guard pages)
    size_t total;        //!< Total reserved bytes (guard + middle + guard)
    size_t middleSize;   //!< Committed bytes (no guards)
    size_t usable;       //!< Requested payload bytes
    size_t headerSize;   //!< Padded header size used (page-aligned)
    size_t payloadSpan;  //!< Committed payload span (usable + canary + slack)
    uint32_t magic;      //!< Integrity check value (must match kMagic)
    uint32_t version;    //!< Header version (must match kVersion)
};

/// @brief Cached system page size (thread-safe, computed once).
inline SIZE_T cachedPageSize()
{
    static const SIZE_T ps = []
    {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        return si.dwPageSize ? si.dwPageSize : 4096;
    }();
    return ps;
}

/// @brief Reconstruct allocation header from a payload pointer.
/// @pre @p payload was returned by locked_allocator::allocate().
template <class T>
inline locked_header* header_from_payload(const T* payload)
{
    SIZE_T page = cachedPageSize();
    // The header sits exactly one page-aligned header block before the payload.
    // allocate() placed the payload at (middle + headerSize), so we reverse that.
    SIZE_T headerSize = align_up(sizeof(locked_header), page);
    auto addr = reinterpret_cast<uintptr_t>(payload) - headerSize;
    return reinterpret_cast<locked_header*>(addr);
}

/**
 * @brief Secure allocator with guard pages, canary sentinels, and page locking.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 * @tparam T Element type to allocate.
 *
 * Memory layout per allocation:
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 * ---
 * flowchart LR
 *     classDef guard fill:#7f1d1d,stroke:#ef4444,color:#fca5a5
 *     classDef hdr fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
 *     classDef pay fill:#1e4a3a,stroke:#22c55e,color:#e2e8f0
 *
 *     G1["Guard Page<br/>NOACCESS"]:::guard
 *     H["Header<br/>(locked_header)"]:::hdr
 *     P["Payload + Canary<br/>READWRITE"]:::pay
 *     G2["Guard Page<br/>NOACCESS"]:::guard
 *
 *     G1 --> H --> P --> G2
 * ```
 *
 * - Guard pages trap out-of-bounds reads/writes.
 * - Committed pages are pinned in RAM via VirtualLock (best-effort).
 * - Canary bytes (0xD0) after the payload detect buffer overruns.
 * - deallocate() verifies the canary and calls `__fastfail` on corruption.
 *
 * @see locked_header, protect_noaccess, protect_readwrite
 */
template <class T>
struct locked_allocator
{
    using value_type = T;

    locked_allocator() noexcept = default;
    template <class U>
    explicit locked_allocator(const locked_allocator<U>&) noexcept
    {
    }

    /**
     * @brief Allocate @p n objects in a locked, guarded region.
     * @param n Number of objects to allocate (clamped to 1 if zero).
     * @return Pointer to the payload region within the guarded allocation.
     * @throw std::bad_alloc on overflow or if VirtualAlloc fails.
     */
    T* allocate(std::size_t n)
    {
        if (n == 0)
            n = 1;
        if (n > SIZE_MAX / sizeof(T))
            throw std::bad_alloc();
        SIZE_T needBytes = n * sizeof(T);

        SIZE_T page = cachedPageSize();

        // Layout: [guard page | header | payload + canary + slack | guard page]
        // The header is page-aligned so VirtualProtect can change payload
        // protection without affecting the header.
        SIZE_T headerSize = align_up(sizeof(locked_header), page);
        SIZE_T afterHeader = headerSize + needBytes + kCanaryBytes;
        SIZE_T middleNeed = align_up(afterHeader, page);  // round up to full pages
        SIZE_T total = middleNeed + 2 * page;             // add front + back guard pages

        // Reserve the entire region as PAGE_NOACCESS - the two guard pages at
        // each end stay NOACCESS permanently to trap out-of-bounds access.
        BYTE* base = (BYTE*)VirtualAlloc(nullptr, total, MEM_RESERVE, PAGE_NOACCESS);
        if (!base)
            throw std::bad_alloc();

        // Commit only the middle (header + payload) as read-write.
        BYTE* middle = (BYTE*)VirtualAlloc(base + page, middleNeed, MEM_COMMIT, PAGE_READWRITE);
        if (!middle)
        {
            VirtualFree(base, 0, MEM_RELEASE);
            throw std::bad_alloc();
        }

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
        hdr->payloadSpan =
            middleNeed - headerSize;  // everything after header (usable + canary + slack)
        hdr->magic = kMagic;
        hdr->version = kVersion;

        BYTE* payload = middle + headerSize;

        // Fill canary bytes (0xD0) immediately after the usable region.
        // deallocate() checks these to detect buffer overruns.
        memset(payload + needBytes, 0xD0, (std::min)(kCanaryBytes, hdr->payloadSpan - hdr->usable));
        return reinterpret_cast<T*>(payload);
    }

    /**
     * @brief Deallocate and securely wipe a prior allocation.
     * @param p Payload pointer returned by allocate() (null is a no-op).
     *
     * Verifies the header magic and canary bytes. On corruption, calls
     * `__fastfail` (MSVC) or `std::terminate` to prevent exploitation.
     */
    void deallocate(T* p, std::size_t) noexcept
    {
        if (!p)
            return;

        auto* hdr = header_from_payload(p);
        BYTE* bytes = reinterpret_cast<BYTE*>(p);

        // Verify the header wasn't corrupted by a wild write.
        // __fastfail raises a non-continuable exception - better to crash
        // than to free a corrupted region and enable exploitation.
        if (hdr->magic != kMagic || hdr->version != kVersion)
        {
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
        for (size_t i = 0; i < canary_span; ++i)
        {
            if (bytes[usable + i] != (BYTE)0xD0)
            {
                canary_ok = false;
                break;
            }
        }

        // If the user already called Cryptography::cleanseString / SecureZeroMemory, the entire
        // region (payload + canary) will be zeroed - that's expected, not a corruption.
        // Only flag a canary failure when the memory wasn't already wiped.
        bool looks_wiped = true;
        for (size_t i = 0; i < usable + canary_span; ++i)
        {
            if (bytes[i] != 0)
            {
                looks_wiped = false;
                break;
            }
        }

        // Scrub everything from payload through the end of committed pages.
        // SecureZeroMemory is not elided by the optimizer.
        if (payloadSpan)
            SecureZeroMemory(bytes, payloadSpan);
        (void)VirtualProtect(bytes, payloadSpan, oldProt, &dummy);

        // A genuine canary mismatch (not caused by pre-wiping) means a buffer
        // overrun occurred. This is a security-critical condition - crash
        // immediately to prevent exploitation.
        if (!canary_ok && !looks_wiped)
        {
#ifdef _MSC_VER
            __fastfail(2);
#else
            std::terminate();
#endif
        }

        // Wipe the header so metadata (pointers, sizes) doesn't linger in memory.
        SecureZeroMemory(hdr, sizeof(locked_header));

        // Unlock pinned pages and release the entire reserved region
        // (guard pages + committed pages) back to the OS.
        if (middleSize)
            (void)VirtualUnlock((LPVOID)((BYTE*)hdr), middleSize);
        if (base)
            (void)VirtualFree(base, 0, MEM_RELEASE);
    }

    template <class U>
    struct rebind
    {
        using other = locked_allocator<U>;
    };
};

/// @brief Equality comparison for locked allocators.
template <class T, class U>
inline bool operator==(const locked_allocator<T>&, const locked_allocator<U>&)
{
    return true;
}
template <class T, class U>
inline bool operator!=(const locked_allocator<T>&, const locked_allocator<U>&)
{
    return false;
}

/// @brief Switch the payload protection to PAGE_NOACCESS.
/// @pre @p p was returned by locked_allocator::allocate() (or is null).
template <class T>
inline void protect_noaccess(const T* p)
{
    if (!p)
        return;
    auto* hdr = header_from_payload(p);
    DWORD oldProt;
    (void)VirtualProtect(
        const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_NOACCESS, &oldProt);
}

/// @brief Switch the payload protection to PAGE_READWRITE.
/// @pre @p p was returned by locked_allocator::allocate() (or is null).
template <class T>
inline void protect_readwrite(const T* p)
{
    if (!p)
        return;
    auto* hdr = header_from_payload(p);
    DWORD oldProt;
    (void)VirtualProtect(
        const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_READWRITE, &oldProt);
}

/**
 * @brief Move-only secure string backed by locked, guard-paged memory.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * All character data lives in VirtualAlloc'd pages that are pinned in
 * physical RAM and bordered by PAGE_NOACCESS guard pages. Copy is
 * deleted; only move semantics are supported.
 *
 * @tparam A Allocator type (default: locked_allocator\<char\>).
 *
 * @see locked_allocator, protect_noaccess, protect_readwrite
 */
template <class A = locked_allocator<char>>
struct secure_string
{
    std::vector<char, A> s;

    secure_string() = default;
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    secure_string(secure_string&& o) noexcept
        : s(std::move(o.s))
    {
    }
    secure_string& operator=(secure_string&& o) noexcept
    {
        if (this != &o)
        {
            clear();
            s = std::move(o.s);
        }
        return *this;
    }
    ~secure_string() { clear(); }

    /// @brief Append a character to the string.
    void push_back(char c) { s.push_back(c); }

    /// @brief Remove the last character (no-op if empty).
    void pop_back()
    {
        if (!s.empty())
            s.pop_back();
    }

    /// @brief Check whether the string is empty.
    bool empty() const { return s.empty(); }

    /// @brief Return the number of characters stored.
    size_t size() const { return s.size(); }

    /// @brief Return a mutable pointer to the underlying buffer.
    char* data() { return s.data(); }

    /// @brief Return a const pointer to the underlying buffer.
    const char* data() const { return s.data(); }

    /// @brief Return a non-owning string_view over the contents.
    std::string_view view() const noexcept { return {s.data(), s.size()}; }

    /**
     * @brief Return a null-terminated C string.
     *
     * Appends a null terminator if one is not already present.
     * This may reallocate the underlying buffer.
     *
     * @return Pointer to the null-terminated data.
     */
    const char* c_str()
    {
        if (s.empty() || s.back() != '\0')
        {
            if (s.size() == s.capacity())
                s.reserve(s.size() + 1);
            s.push_back('\0');
        }
        return s.data();
    }

    /**
     * @brief Securely wipe and release all memory.
     *
     * Restores PAGE_READWRITE if needed, zeroes the buffer with
     * `SecureZeroMemory`, then releases the guarded allocation.
     */
    void clear()
    {
        if (!s.empty())
        {
            // The buffer may be PAGE_NOACCESS (e.g. after protect_noaccess).
            // Restore RW so SecureZeroMemory can reach the bytes.
            seal::protect_readwrite(s.data());
            SecureZeroMemory(s.data(), s.size());
            // clear() sets logical size to 0; swap with a temporary releases
            // the allocation back to the locked_allocator (which wipes + frees).
            s.clear();
            std::vector<char, A>().swap(s);
        }
        else
        {
            // The vector may be empty (size == 0) but still hold a live
            // allocation with capacity > 0.  That buffer is guarded memory
            // that must be freed, not leaked.
            if (s.capacity() > 0 && s.data())
            {
                seal::protect_readwrite(s.data());
                s.clear();
                std::vector<char, A>().swap(s);
            }
        }
    }

    /**
     * @brief Copy contents into a regular std::string.
     * @return A heap-allocated copy in pageable memory.
     * @warning The returned string is **not** in locked memory and may be
     *          swapped to disk. Use only when an insecure copy is acceptable.
     */
    std::string str_copy() const { return std::string(s.data(), s.data() + s.size()); }
};

/**
 * @brief Move-only secure string for arbitrary wide code unit types.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Generalisation of secure_string for `wchar_t`, `char16_t`, etc.
 * All data lives in locked, guard-paged memory. Copy is deleted;
 * only move semantics are supported.
 *
 * @tparam CharT Character type (e.g. `wchar_t`, `char16_t`).
 * @tparam A     Allocator type (default: locked_allocator\<CharT\>).
 *
 * @see secure_string, locked_allocator
 */
template <class CharT, class A = locked_allocator<CharT>>
struct basic_secure_string
{
    std::vector<CharT, A> s;

    basic_secure_string() = default;
    basic_secure_string(const basic_secure_string&) = delete;
    basic_secure_string& operator=(const basic_secure_string&) = delete;
    basic_secure_string(basic_secure_string&& o) noexcept
        : s(std::move(o.s))
    {
    }
    basic_secure_string& operator=(basic_secure_string&& o) noexcept
    {
        if (this != &o)
        {
            clear();
            s = std::move(o.s);
        }
        return *this;
    }
    ~basic_secure_string() { clear(); }

    /// @brief Append a code unit to the string.
    void push_back(CharT c) { s.push_back(c); }

    /// @brief Remove the last code unit (no-op if empty).
    void pop_back()
    {
        if (!s.empty())
            s.pop_back();
    }

    /// @brief Check whether the string is empty.
    bool empty() const { return s.empty(); }

    /// @brief Return the number of code units stored.
    size_t size() const { return s.size(); }

    /// @brief Return a mutable pointer to the underlying buffer.
    CharT* data() { return s.data(); }

    /// @brief Return a const pointer to the underlying buffer.
    const CharT* data() const { return s.data(); }

    /// @brief Return a non-owning string_view over the contents.
    std::basic_string_view<CharT> view() const noexcept { return {s.data(), s.size()}; }

    /**
     * @brief Return a null-terminated wide C string.
     *
     * Appends a zero code unit if one is not already present.
     *
     * @return Pointer to the null-terminated data.
     */
    const CharT* c_str()
    {
        if (s.empty() || s.back() != CharT{})
        {
            if (s.size() == s.capacity())
                s.reserve(s.size() + 1);
            s.push_back(CharT{});
        }
        return s.data();
    }

    /**
     * @brief Securely wipe and release all memory.
     *
     * Restores PAGE_READWRITE if needed, zeroes the buffer with
     * `SecureZeroMemory` (accounting for `sizeof(CharT)`), then
     * releases the guarded allocation.
     */
    void clear()
    {
        if (!s.empty())
        {
            // Restore RW in case the buffer was marked PAGE_NOACCESS.
            seal::protect_readwrite(s.data());
            // Wipe in bytes - sizeof(CharT) may be 2 (wchar_t) or 4 (char32_t).
            SecureZeroMemory(s.data(), s.size() * sizeof(CharT));
            // Swap-to-empty releases the guarded allocation back to the OS.
            s.clear();
            std::vector<CharT, A>().swap(s);
        }
        else
        {
            // Same as secure_string::clear - handle capacity-only allocations.
            if (s.capacity() > 0 && s.data())
            {
                seal::protect_readwrite(s.data());
                s.clear();
                std::vector<CharT, A>().swap(s);
            }
        }
    }

    /**
     * @brief Copy contents into a regular std::basic_string.
     * @return A heap-allocated copy in pageable memory.
     * @warning The returned string is **not** in locked memory and may be
     *          swapped to disk. Use only when an insecure copy is acceptable.
     */
    std::basic_string<CharT> str_copy() const
    {
        return std::basic_string<CharT>(s.data(), s.data() + s.size());
    }
};

/**
 * @struct RWGuard
 * @brief RAII guard that temporarily sets a locked payload to PAGE_READWRITE.
 * @ingroup Crypto
 * @tparam T Element type of the guarded allocation.
 *
 * On construction, flips the payload protection to PAGE_READWRITE.
 * On destruction, restores the original protection (typically PAGE_NOACCESS).
 * Non-copyable and non-movable.
 *
 * @pre The pointer must have been returned by locked_allocator::allocate().
 */
template <class T>
struct RWGuard
{
    const T* p{};
    DWORD oldProt{};
    bool changed{false};
    explicit RWGuard(const T* ptr)
        : p(ptr)
    {
        if (!p)
            return;
        // Flip the payload span to PAGE_READWRITE, saving the previous
        // protection so we can restore it when the guard goes out of scope.
        auto* hdr = header_from_payload(p);
        changed = !!VirtualProtect(
            const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_READWRITE, &oldProt);
    }
    ~RWGuard()
    {
        if (!p || !changed)
            return;
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
 * @struct DPAPIGuard
 * @brief RAII guard for DPAPI in-memory encryption of secure strings.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Wraps CryptProtectMemory / CryptUnprotectMemory with SAME_PROCESS scope.
 * The buffer is encrypted on construction and decrypted only during
 * explicit unprotect/reprotect windows. Destruction unprotects and
 * detaches from the buffer but does not wipe it; the caller (or the
 * secure string's own destructor) is responsible for wiping.
 *
 * CryptProtectMemory requires the buffer size to be a multiple of
 * CRYPTPROTECTMEMORY_BLOCK_SIZE. The guard pads the backing vector
 * to meet this requirement transparently.
 */
template <class SecStr>
struct DPAPIGuard
{
    using char_type = typename decltype(SecStr::s)::value_type;

    SecStr* m_Str = nullptr;
    bool m_Protected = false;
    size_t m_OriginalSize = 0;  ///< Pre-pad logical size, restored after unprotect.

    DPAPIGuard() = default;
    explicit DPAPIGuard(SecStr* str)
        : m_Str(str)
    {
        protect();
    }

    DPAPIGuard(const DPAPIGuard&) = delete;
    DPAPIGuard& operator=(const DPAPIGuard&) = delete;
    DPAPIGuard(DPAPIGuard&& o) noexcept
        : m_Str(o.m_Str),
          m_Protected(o.m_Protected),
          m_OriginalSize(o.m_OriginalSize)
    {
        o.m_Str = nullptr;
        o.m_Protected = false;
        o.m_OriginalSize = 0;
    }
    DPAPIGuard& operator=(DPAPIGuard&& o) noexcept
    {
        if (this != &o)
        {
            release();
            m_Str = o.m_Str;
            m_Protected = o.m_Protected;
            m_OriginalSize = o.m_OriginalSize;
            o.m_Str = nullptr;
            o.m_Protected = false;
            o.m_OriginalSize = 0;
        }
        return *this;
    }

    ~DPAPIGuard()
    {
        try
        {
            release();
        }
        catch (...)
        {
        }
    }

    /// @return true if DPAPI encryption succeeded, false on failure or no-op.
    bool protect()
    {
        if (!m_Str || m_Str->empty() || m_Protected)
            return false;
        m_OriginalSize = m_Str->s.size();
        padToBlockSize();
        seal::protect_readwrite(m_Str->s.data());
        DWORD cbData = static_cast<DWORD>(m_Str->s.size() * sizeof(char_type));
        if (CryptProtectMemory(m_Str->s.data(), cbData, CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            m_Protected = true;
            return true;
        }
        return false;
    }

    /// @return true if DPAPI decryption succeeded, false on failure or no-op.
    bool unprotect()
    {
        if (!m_Str || m_Str->empty() || !m_Protected)
            return false;
        seal::protect_readwrite(m_Str->s.data());
        DWORD cbData = static_cast<DWORD>(m_Str->s.size() * sizeof(char_type));
        if (CryptUnprotectMemory(m_Str->s.data(), cbData, CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            m_Protected = false;
            // Restore the original logical size (remove DPAPI block padding).
            if (m_OriginalSize > 0 && m_OriginalSize < m_Str->s.size())
                m_Str->s.resize(m_OriginalSize);
            return true;
        }
        return false;
    }

    /// @brief Re-encrypt the buffer (convenience alias for protect()).
    void reprotect() { protect(); }

private:
    void padToBlockSize()
    {
        if (!m_Str || m_Str->empty())
            return;
        size_t byteSize = m_Str->s.size() * sizeof(char_type);
        size_t rem = byteSize % CRYPTPROTECTMEMORY_BLOCK_SIZE;
        if (rem != 0)
        {
            size_t padBytes = CRYPTPROTECTMEMORY_BLOCK_SIZE - rem;
            size_t padChars = (padBytes + sizeof(char_type) - 1) / sizeof(char_type);
            m_Str->s.resize(m_Str->s.size() + padChars, char_type{});
        }
    }

    void release()
    {
        if (m_Str && m_Protected)
        {
            unprotect();
        }
        m_Str = nullptr;
        m_Protected = false;
    }
};

/**
 * @struct scoped_console
 * @brief RAII console mode guard that saves and restores console input mode.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Snapshots the current console mode on construction and restores it
 * on destruction, ensuring the terminal is never left in an altered
 * state after masked input or mouse-enabled hit-testing.
 */
struct scoped_console
{
    HANDLE h;             ///< Console handle being guarded.
    DWORD oldMode{};      ///< Saved console mode, restored on destruction.
    bool changed{false};  ///< Whether SetConsoleMode succeeded.

    /// @brief Snapshot the current console mode and apply @p mode.
    /// @param handle Console input or output handle.
    /// @param mode   Desired console mode flags (e.g. ENABLE_MOUSE_INPUT).
    scoped_console(HANDLE handle, DWORD mode)
        : h(handle)
    {
        // Snapshot the current mode so we can restore it in the destructor,
        // then apply the requested mode (e.g. ENABLE_MOUSE_INPUT for
        // MaskedCredentialView hit-testing).
        if (GetConsoleMode(h, &oldMode))
        {
            DWORD inNew = mode;
            changed = !!SetConsoleMode(h, inNew);
        }
    }
    ~scoped_console()
    {
        if (changed)
            SetConsoleMode(h, oldMode);
    }
    scoped_console(const scoped_console&) = delete;
    scoped_console& operator=(const scoped_console&) = delete;
};

/**
 * @struct EVP_CTX
 * @brief RAII owner for an OpenSSL EVP_CIPHER_CTX.
 * @ingroup Crypto
 *
 * Allocates a cipher context on construction and frees it on
 * destruction. Non-copyable.
 *
 * @throw std::runtime_error if EVP_CIPHER_CTX_new() fails.
 */
struct EVP_CTX
{
    EVP_CIPHER_CTX* p{nullptr};
    EVP_CTX()
        : p(EVP_CIPHER_CTX_new())
    {
        if (!p)
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }
    ~EVP_CTX()
    {
        if (p)
            EVP_CIPHER_CTX_free(p);
    }
    EVP_CTX(const EVP_CTX&) = delete;
    EVP_CTX& operator=(const EVP_CTX&) = delete;
};

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
 * ## :material-shield: Process Hardening
 *
 * A suite of static methods hardens the process against memory
 * disclosure and debugging attacks:
 * - hardenHeap() - enables heap termination on corruption
 * - hardenProcessAccess() - restricts DACL to block external memory reads
 * - disableCrashDumps() - suppresses WER and crash dumps
 * - detectDebugger() - aborts if a debugger is attached
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

    template <class A>
    static bool ctEqual(const secure_string<A>& a, const secure_string<A>& b)
    {
        return ctEqualAny(a.s, b.s);
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

    /// @brief Detect attached debuggers and abort if found.
    /// @post If `IsDebuggerPresent()` or `NtQueryInformationProcess` detects
    ///       a debugger, the process calls `__fastfail` immediately.
    static void detectDebugger();

    /// @brief Trim the working set via `SetProcessWorkingSetSize(-1, -1)`.
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
    template <class SecurePwd>
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
    template <class SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> decryptPacket(
        std::span<const unsigned char> packet, const SecurePwd& password);

private:
    /// @brief Check OpenSSL return code.
    static void opensslCheck(int ok, const char* msg);

    /// @brief Get authenticated AAD span.
    static std::span<const unsigned char> aadSpan() noexcept;

    /// @brief Derive AES-256 key via scrypt.
    template <class SecurePwd>
    [[nodiscard]] static std::vector<unsigned char> deriveKey(const SecurePwd& pwd,
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
    static void cleanseOne(seal::secure_string<A>& s) noexcept
    {
        if (!s.s.empty())
        {
            char* base = s.s.data();
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
        std::vector<char, A>().swap(s.s);
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
    static void cleanseOne(CharT* p, size_t len) noexcept
    {
        static_assert(std::is_trivial_v<CharT>, "CharT must be trivial");
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

/**
 * @brief Move-only holder for three narrow secure strings (service, username, password).
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 * @tparam A Locked allocator type (default: locked_allocator\<char\>).
 */
template <class A = seal::locked_allocator<char>>
struct secure_triplet
{
    seal::secure_string<A> service;  ///< Service / platform name.
    seal::secure_string<A> user;     ///< Username or email.
    seal::secure_string<A> pass;     ///< Password.

    secure_triplet(seal::secure_string<A>&& s,
                   seal::secure_string<A>&& u,
                   seal::secure_string<A>&& p) noexcept
        : service(std::move(s)),
          user(std::move(u)),
          pass(std::move(p))
    {
    }

    secure_triplet(secure_triplet&&) noexcept = default;
    secure_triplet& operator=(secure_triplet&&) noexcept = default;
    secure_triplet(const secure_triplet&) = delete;
    secure_triplet& operator=(const secure_triplet&) = delete;
};
using secure_triplet_t = secure_triplet<>;

/**
 * @brief Move-only holder for three wide secure strings with tuple-like access.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 * @tparam A Locked allocator type (default: locked_allocator\<wchar_t\>).
 *
 * Members: primary (service), secondary (username), tertiary (password).
 * Provides `operator[]`, `at()`, `first()`/`second()`/`third()`, and
 * structured binding support via `get<I>()`.
 */
template <class A = seal::locked_allocator<wchar_t>>
struct secure_triplet16
{
    using string_type = seal::basic_secure_string<wchar_t, A>;

    string_type primary;    ///< Service / platform name.
    string_type secondary;  ///< Username or email.
    string_type tertiary;   ///< Password.

    secure_triplet16(string_type&& s, string_type&& u, string_type&& p) noexcept
        : primary(std::move(s)),
          secondary(std::move(u)),
          tertiary(std::move(p))
    {
    }

    secure_triplet16(secure_triplet16&&) noexcept = default;
    secure_triplet16& operator=(secure_triplet16&&) noexcept = default;
    secure_triplet16(const secure_triplet16&) = delete;
    secure_triplet16& operator=(const secure_triplet16&) = delete;

    /// @brief Return the number of fields (always 3).
    static constexpr std::size_t size() noexcept { return 3; }

    /// @brief Unchecked element access (0=service, 1=username, 2=password).
    string_type& operator[](std::size_t i) noexcept
    {
        assert(i < 3);
        switch (i)
        {
            case 0:
                return primary;
            case 1:
                return secondary;
            default:
                return tertiary;
        }
    }
    const string_type& operator[](std::size_t i) const noexcept
    {
        assert(i < 3);
        switch (i)
        {
            case 0:
                return primary;
            case 1:
                return secondary;
            default:
                return tertiary;
        }
    }

    /**
     * @brief Bounds-checked element access.
     * @param i Index (0-2).
     * @throw std::out_of_range if @p i >= 3.
     */
    string_type& at(std::size_t i)
    {
        if (i >= 3)
            throw std::out_of_range("secure_triplet::at");
        return (*this)[i];
    }
    const string_type& at(std::size_t i) const
    {
        if (i >= 3)
            throw std::out_of_range("secure_triplet::at");
        return (*this)[i];
    }

    /// @brief Named accessors (aliases for primary/secondary/tertiary).
    string_type& first() noexcept { return primary; }
    string_type& second() noexcept { return secondary; }
    string_type& third() noexcept { return tertiary; }

    const string_type& first() const noexcept { return primary; }
    const string_type& second() const noexcept { return secondary; }
    const string_type& third() const noexcept { return tertiary; }

    /// @brief Tuple-like access for structured bindings (`auto& [s, u, p] = triplet`).
    template <std::size_t I>
    decltype(auto) get() & noexcept
    {
        static_assert(I < 3, "secure_triplet index out of range");
        if constexpr (I == 0)
            return (primary);
        else if constexpr (I == 1)
            return (secondary);
        else
            return (tertiary);
    }
    template <std::size_t I>
    decltype(auto) get() const& noexcept
    {
        static_assert(I < 3, "secure_triplet index out of range");
        if constexpr (I == 0)
            return (primary);
        else if constexpr (I == 1)
            return (secondary);
        else
            return (tertiary);
    }
    template <std::size_t I>
    decltype(auto) get() && noexcept
    {
        static_assert(I < 3, "secure_triplet index out of range");
        if constexpr (I == 0)
            return (primary);
        else if constexpr (I == 1)
            return (secondary);
        else
            return (tertiary);
    }
    template <std::size_t I>
    decltype(auto) get() const&& noexcept
    {
        static_assert(I < 3, "secure_triplet index out of range");
        if constexpr (I == 0)
            return (primary);
        else if constexpr (I == 1)
            return (secondary);
        else
            return (tertiary);
    }
};
using secure_triplet16_t = secure_triplet16<>;

}  // namespace seal
