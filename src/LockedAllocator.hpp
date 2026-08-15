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
 * Sits at the start of the committed region, right after the front guard page.
 * It occupies whole pages, so a payload protection change never touches it.
 *
 * deallocate() checks magic and version before it trusts any other field, and
 * zeroes the whole header before it releases the region, so the metadata does
 * not linger in memory.
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

/**
 * @brief Return the system page size, queried once and cached.
 *
 * The value comes from GetSystemInfo(), with a fallback to 4096 when the OS
 * reports zero. A function-local static caches it, so the first call is
 * thread-safe and every later call is a plain read.
 *
 * @return Page size in bytes; never zero.
 */
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
 * @brief Reconstruct the allocation header from a payload pointer.
 *
 * allocate() places the payload at (start of the committed middle + headerSize),
 * so the header starts headerSize bytes before the payload. headerSize is
 * sizeof(locked_header) rounded up to a whole page, which keeps the returned
 * pointer page-aligned and keeps the header out of every payload
 * VirtualProtect call.
 *
 * @tparam T       Element type of the payload.
 * @return Pointer to the header of that allocation.
 * @pre @p payload was returned by locked_allocator::allocate() and the
 *      allocation is still live. There is no null check: a null argument yields
 *      a wild pointer, so a caller that accepts null tests it first.
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
 * @struct locked_allocator
 * @brief Secure allocator with guard pages, canary sentinels, and page locking.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
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
 *    | NOACCESS     | PAGE_READWRITE (VirtualLock'd)     | NOACCESS     |
 *    | reserve only |                                    | reserve only |
 *    +--------------+------------------------------------+--------------+
 *
 *   committed middle, expanded:
 *    +----------------+-------------+---------------+---------+
 *    | header         | payload     | canary 0xD0   | slack   |
 *    | headerSize     | usable      | 32 bytes      | pad to  |
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
 * @par Allocator model
 * The allocator is stateless, so any two instances compare equal and any
 * instance of the same element type can release another's block. It supplies
 * only value_type, the converting constructor, allocate(), deallocate() and
 * rebind; std::allocator_traits fills in the rest.
 *
 * @par Cost
 * Every allocation costs two VirtualAlloc calls, one VirtualLock and at least
 * four pages of address space: two guard pages, one header page and one payload
 * page. Use it for few, long-lived secrets, not for churn.
 *
 * @par Thread safety
 * The allocator holds no shared state, so concurrent allocate() and
 * deallocate() calls on different blocks are safe. A protection change belongs
 * to the pages, not to the calling thread: every thread of the process sees a
 * protect_noaccess() or @ref RWGuard flip at once.
 *
 * @tparam T Element type to allocate.
 *
 * @see locked_header, protect_noaccess, protect_readwrite, RWGuard
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
     *
     * Reserves the middle plus two guard pages, commits only the middle as
     * PAGE_READWRITE and calls VirtualLock on it. The guard pages stay reserved
     * and PAGE_NOACCESS, so an access one page past either end raises an access
     * violation. The returned pointer is page-aligned, because the header in
     * front of it is padded to a whole page. Committed pages arrive zero-filled
     * from the OS; no object is constructed here.
     *
     * VirtualLock is best-effort: it needs working-set quota and its result is
     * ignored. A failure leaves the pages pageable but usable.
     *
     * The middle is rounded up to whole pages after header, payload and canary
     * are counted, so the space behind the payload always holds a full canary:
     *
     * @f[ \text{payloadSpan} - \text{usable} \;=\;
     *     \text{align\_up}(H + ns + C,\ P) - H - ns \;\ge\; C @f]
     *
     * with @f$H@f$ = headerSize, @f$ns@f$ = usable bytes, @f$C@f$ =
     * kCanaryBytes and @f$P@f$ = page size. The canary is therefore always
     * exactly kCanaryBytes long.
     *
     * @param n Number of objects to allocate (clamped to 1 if zero).
     * @return Pointer to the payload region within the guarded allocation.
     * @throw std::bad_alloc if the size computation would overflow, or if
     *        either VirtualAlloc call fails.
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

        // Reserve the whole region as PAGE_NOACCESS. The guard page at each end
        // keeps that protection for good, so it traps out-of-bounds access.
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

        // Pin the committed pages in physical RAM so they are not swapped to disk.
        // Best-effort: needs SeLockMemoryPrivilege or enough working-set quota.
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

        // Fill canary bytes (0xD0) right after the usable region.
        // deallocate() checks them to detect a buffer overrun.
        memset(payload + needBytes, 0xD0, (std::min)(kCanaryBytes, hdr->payloadSpan - hdr->usable));
        return reinterpret_cast<T*>(payload);
    }

    /**
     * @brief Deallocate and securely wipe a prior allocation.
     *
     * Every size comes from the header; the element-count parameter is ignored.
     *
     * @par Order
     * - Check magic and version before trusting any other header field.
     * - Copy the sizes into locals: the header lives in the region this call
     *   scrubs.
     * - Restore PAGE_READWRITE over the payload span, which protect_noaccess()
     *   may have sealed.
     * - Compare the canary, scrub the whole payload span with SecureZeroMemory,
     *   then put the saved protection back.
     * - Scrub the header, unlock the committed pages, release the region.
     *
     * The scrub covers unused capacity too, not only the bytes the container
     * counted as live.
     *
     * @par Canary
     * An all-zero payload and canary counts as a match: a caller that already
     * wiped the buffer, for example through Cryptography::cleanseString(),
     * erases the canary with it.
     *
     * @param p Payload pointer returned by allocate() (null is a no-op).
     *
     * @warning Corruption is fatal and is never reported to the caller. The
     *          function calls `__fastfail` (MSVC) or std::terminate: code 1 for
     *          a header magic or version mismatch, code 2 for a canary that no
     *          longer reads 0xD0, unless the payload and the canary are
     *          entirely zero. The canary crash runs after the scrub, so the
     *          secret is already zeroed by then.
     */
    void deallocate(T* p, std::size_t) noexcept
    {
        if (!p)
            return;

        auto* hdr = header_from_payload(p);
        BYTE* bytes = reinterpret_cast<BYTE*>(p);

        // Reject a header corrupted by a wild write. __fastfail raises a
        // non-continuable exception: crashing beats releasing a corrupted
        // region and handing an attacker a primitive.
        if (hdr->magic != kMagic || hdr->version != kVersion)
        {
#ifdef _MSC_VER
            __fastfail(1);
#else
            std::terminate();
#endif
        }

        // Snapshot the header fields into locals: the header lives in the same
        // committed region this call is about to scrub.
        void* base = hdr->base;
        SIZE_T middleSize = hdr->middleSize;
        SIZE_T payloadSpan = hdr->payloadSpan;
        SIZE_T usable = hdr->usable;

        // The payload may rest at PAGE_NOACCESS after protect_noaccess().
        // Restore read-write access for the canary check and the wipe.
        DWORD oldProt{}, dummy{};
        (void)VirtualProtect(bytes, payloadSpan, PAGE_READWRITE, &oldProt);

        // Check the 0xD0 canary after the usable region. A changed canary means
        // something wrote past the end of the buffer.
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

        // A caller that already ran Cryptography::cleanseString or SecureZeroMemory
        // leaves payload and canary all zero. That is expected, not corruption, so
        // only an unwiped region raises a canary failure.
        bool looks_wiped = true;
        for (size_t i = 0; i < usable + canary_span; ++i)
        {
            if (bytes[i] != 0)
            {
                looks_wiped = false;
                break;
            }
        }

        // Scrub from the payload to the end of the committed pages.
        // The optimizer cannot elide SecureZeroMemory, unlike memset.
        if (payloadSpan)
            SecureZeroMemory(bytes, payloadSpan);
        (void)VirtualProtect(bytes, payloadSpan, oldProt, &dummy);

        // A canary mismatch that pre-wiping does not explain means a buffer
        // overrun. Crash at once rather than continue on corrupted memory.
        if (!canary_ok && !looks_wiped)
        {
#ifdef _MSC_VER
            __fastfail(2);
#else
            std::terminate();
#endif
        }

        // Wipe the header so its pointers and sizes do not linger in memory.
        SecureZeroMemory(hdr, sizeof(locked_header));

        // Unlock the pinned pages and release the whole reserved region,
        // guard pages included, back to the OS.
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

/**
 * @brief Compare two locked allocators.
 *
 * The allocator carries no state, so all instances are interchangeable. A
 * container relies on that to move a buffer by pointer instead of copying the
 * secret.
 *
 * @return Always true.
 */
template <class T, class U>
inline bool operator==(const locked_allocator<T>&, const locked_allocator<U>&)
{
    return true;
}

/**
 * @brief Switch the payload protection to PAGE_NOACCESS.
 *
 * The change covers the whole payload span from the header, so payload, canary
 * and page slack change together. The header page keeps its read-write
 * protection, which is what keeps header_from_payload() usable afterwards. The
 * call is best-effort: the VirtualProtect result is discarded and a failure
 * leaves the previous protection in place.
 *
 * @note No call site in this tree calls this function today, so a locked
 *       payload stays PAGE_READWRITE from allocate() to deallocate(). This
 *       function and @ref RWGuard exist so that a later sealed-at-rest mode
 *       does not have to change every reader.
 *
 * @tparam T Element type of the payload.
 * @param  p Payload pointer; a null pointer is a no-op.
 * @pre @p p was returned by locked_allocator::allocate() (or is null).
 * @warning Every read or write through @p p raises an access violation until
 *          protect_readwrite() or an @ref RWGuard restores access.
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
 *
 * The change covers the whole payload span, like protect_noaccess(). The call
 * is best-effort: the VirtualProtect result is discarded. It is safe on a span
 * that is already read-write.
 *
 * @tparam T Element type of the payload.
 * @param  p Payload pointer; a null pointer is a no-op.
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
