#pragma once

#include "CryptoConfig.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <new>

namespace seal
{

/**
 * @struct locked_header
 * @brief Per-allocation metadata for guarded regions.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * Stored at the start of the committed region, immediately after the
 * front guard page. The header is page-aligned so that payload
 * protection changes (via VirtualProtect) never affect the header.
 *
 * @see locked_allocator, header_from_payload
 */
struct locked_header
{
    void* base;          ///< Start of reserved region (includes guard pages).
    size_t total;        ///< Total reserved bytes (guard + middle + guard).
    size_t middleSize;   ///< Committed bytes (no guards).
    size_t usable;       ///< Requested payload bytes.
    size_t headerSize;   ///< Padded header size used (page-aligned).
    size_t payloadSpan;  ///< Committed payload span (usable + canary + slack).
    uint32_t magic;      ///< Integrity check value (must match kMagic).
    uint32_t version;    ///< Header version (must match kVersion).
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

/**
 * @brief Reconstruct allocation header from a payload pointer.
 * @pre @p payload was returned by locked_allocator::allocate().
 */
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
 * @ingroup Memory
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
 * Byte-offset map (addresses increase left to right):
 *
 *   base = start of the reserved region; committed middle begins at base + page
 *   total (reserved) = middleSize + 2 * page
 *
 * @verbatim
 *    +--------------+------------------------------------+--------------+
 *    | FRONT GUARD  |  committed middle (middleSize)     |  BACK GUARD  |
 *    | 1 page       | header+payload+canary+slack        |  1 page      |
 *    | NOACCESS     | PAGE_READWRITE (VirtualLock'd)      | NOACCESS     |
 *    | reserve only |                                    | reserve only |
 *    +--------------+------------------------------------+--------------+
 *
 *   committed middle, expanded:
 *    +----------------+-------------+---------------+---------+
 *    | header         | payload     | canary 0xD0   | slack   |
 *    | headerSize     | usable      | <= 32 bytes   | pad to  |
 *    | (page-aligned) | n*sizeof(T) | kCanaryBytes  | page    |
 *    +----------------+-------------+---------------+---------+
 *                     |<----------- payloadSpan ------------->|
 *                     ^ the span toggled by protect_noaccess /
 *                       protect_readwrite / RWGuard
 * @endverbatim
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

        // Guard against overflow in the intermediate sums. Each addition
        // could wrap when needBytes is near SIZE_MAX.
        if (needBytes > SIZE_MAX - headerSize - kCanaryBytes)
        {
            throw std::bad_alloc();
        }
        SIZE_T afterHeader = headerSize + needBytes + kCanaryBytes;
        SIZE_T middleNeed = align_up(afterHeader, page);  // round up to full pages
        if (middleNeed < afterHeader || middleNeed > SIZE_MAX - 2 * page)
        {
            throw std::bad_alloc();
        }
        SIZE_T total = middleNeed + 2 * page;  // add front + back guard pages

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

/**
 * @brief Switch the payload protection to PAGE_NOACCESS.
 * @pre @p p was returned by locked_allocator::allocate() (or is null).
 */
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

/**
 * @brief Switch the payload protection to PAGE_READWRITE.
 * @pre @p p was returned by locked_allocator::allocate() (or is null).
 */
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

}  // namespace seal
