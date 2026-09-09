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
 * @brief page-isolated metadata preceding a guarded payload.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * deallocate() checks magic/version before trusting sizes and wipes the header before release.
 */
struct locked_header
{
    void* base;          ///< start of reserved region (includes guard pages).
    size_t total;        ///< total reserved bytes (guard + middle + guard).
    size_t middleSize;   ///< committed bytes (no guards).
    size_t usable;       ///< requested payload bytes.
    size_t headerSize;   ///< padded header size used (page-aligned).
    size_t payloadSpan;  ///< committed payload span (usable + canary + slack).
    uint32_t magic;      ///< integrity check value (must match kMagic).
    uint32_t version;    ///< header version (must match kVersion).
};

/// cache the system page size in bytes; use 4096 if the OS reports zero.
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
 * @brief recover the header one page-rounded header size before the payload.
 *
 * @pre payload is non-null and comes from a live locked_allocator allocation.
 */
template <class T>
inline locked_header* header_from_payload(const T* payload)
{
    SIZE_T page = cachedPageSize();
    // the header sits exactly one page-aligned header block before the payload.
    // allocate() placed the payload at (middle + headerSize), so we reverse that.
    SIZE_T headerSize = align_up(sizeof(locked_header), page);
    auto addr = reinterpret_cast<uintptr_t>(payload) - headerSize;
    return reinterpret_cast<locked_header*>(addr);
}

/**
 * @struct locked_allocator
 * @brief guard allocations with inaccessible pages and a 32-byte canary.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * VirtualLock is best-effort. corruption triggers __fastfail during deallocation.
 * all instances compare equal and can free same-type allocations.
 *
 * each allocation costs two VirtualAlloc calls, one VirtualLock and at least four pages.
 * calls on separate blocks may run concurrently; page-protection changes affect every thread.
 *
 * base is the reserved-region start; the committed middle begins at base + page.
 * total reserved bytes = middleSize + 2 * page.
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
     * @brief allocate n objects in a locked, guarded region.
     *
     * reserves the middle plus two guard pages, commits only the middle as
     * PAGE_READWRITE and calls VirtualLock on it. the guard pages stay reserved
     * and PAGE_NOACCESS, so an access one page past either end raises an access
     * violation. the returned pointer is page-aligned, because the header in
     * front of it is padded to a whole page. committed pages arrive zero-filled
     * from the OS; no object is constructed here.
     *
     * VirtualLock is best-effort: it needs working-set quota and its result is
     * ignored. a failure leaves the pages pageable but usable.
     *
     * the middle is rounded up to whole pages after header, payload and canary
     * are counted, so the space behind the payload always holds a full canary:
     *
     * $$ \text{payloadSpan} - \text{usable} \;=\;
     *     \text{align\_up}(H + ns + C,\ P) - H - ns \;\ge\; C $$
     *
     * with $H$ = headerSize, $ns$ = usable bytes, $C$ =
     * kCanaryBytes and $P$ = page size. the canary is therefore always
     * exactly kCanaryBytes long.
     *
     * @param n number of objects to allocate (clamped to 1 if zero).
     * @return pointer to the payload region within the guarded allocation.
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

        // layout: [guard page | header | payload + canary + slack | guard page]
        // the header is page-aligned so VirtualProtect can change payload
        // protection without affecting the header.
        SIZE_T headerSize = align_up(sizeof(locked_header), page);

        // guard against overflow in the intermediate sums. each addition
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

        // reserve the whole region as PAGE_NOACCESS. the guard page at each end
        // keeps that protection for good, so it traps out-of-bounds access.
        BYTE* base = (BYTE*)VirtualAlloc(nullptr, total, MEM_RESERVE, PAGE_NOACCESS);
        if (!base)
            throw std::bad_alloc();

        // commit only the middle (header + payload) as read-write.
        BYTE* middle = (BYTE*)VirtualAlloc(base + page, middleNeed, MEM_COMMIT, PAGE_READWRITE);
        if (!middle)
        {
            VirtualFree(base, 0, MEM_RELEASE);
            throw std::bad_alloc();
        }

        // pin the committed pages in physical RAM so they are not swapped to disk.
        // best-effort: needs SeLockMemoryPrivilege or enough working-set quota.
        (void)VirtualLock(middle, middleNeed);

        // write metadata into the header at the start of the committed region.
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

        // fill canary bytes (0xD0) right after the usable region.
        // deallocate() checks them to detect a buffer overrun.
        memset(payload + needBytes, 0xD0, (std::min)(kCanaryBytes, hdr->payloadSpan - hdr->usable));
        return reinterpret_cast<T*>(payload);
    }

    /**
     * @brief deallocate and securely wipe a prior allocation.
     *
     * every size comes from the header; the element-count parameter is ignored.
     *
     * ### :material-note-text-outline: order
     *
     * - check magic and version before trusting any other header field.
     * - copy the sizes into locals: the header lives in the region this call
     *   scrubs.
     * - restore PAGE_READWRITE over the payload span, which protect_noaccess()
     *   may have sealed.
     * - compare the canary, scrub the whole payload span with SecureZeroMemory,
     *   then put the saved protection back.
     * - scrub the header, unlock the committed pages, release the region.
     *
     * the scrub covers unused capacity too, not only the bytes the container
     * counted as live.
     *
     * ### :material-note-text-outline: canary
     *
     * an all-zero payload and canary counts as a match: a caller that already
     * wiped the buffer, for example through Cryptography::cleanseString(),
     * erases the canary with it.
     *
     * @param p payload pointer returned by allocate() (null is a no-op).
     * @warning corruption is fatal and is never reported to the caller. the
     *          function calls `__fastfail` (MSVC) or std::terminate: code 1 for
     *          a header magic or version mismatch, code 2 for a canary that no
     *          longer reads 0xD0, unless the payload and the canary are
     *          entirely zero. the canary crash runs after the scrub, so the
     *          secret is already zeroed by then.
     */
    void deallocate(T* p, std::size_t) noexcept
    {
        if (!p)
            return;

        auto* hdr = header_from_payload(p);
        BYTE* bytes = reinterpret_cast<BYTE*>(p);

        // reject a header corrupted by a wild write. __fastfail raises a
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

        // snapshot the header fields into locals: the header lives in the same
        // committed region this call is about to scrub.
        void* base = hdr->base;
        SIZE_T middleSize = hdr->middleSize;
        SIZE_T payloadSpan = hdr->payloadSpan;
        SIZE_T usable = hdr->usable;

        // the payload may rest at PAGE_NOACCESS after protect_noaccess().
        // restore read-write access for the canary check and the wipe.
        DWORD oldProt{}, dummy{};
        (void)VirtualProtect(bytes, payloadSpan, PAGE_READWRITE, &oldProt);

        // check the 0xD0 canary after the usable region. a changed canary means
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

        // a caller that already ran Cryptography::cleanseString or SecureZeroMemory
        // leaves payload and canary all zero. that is expected, not corruption, so
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

        // scrub from the payload to the end of the committed pages.
        // the optimizer cannot elide SecureZeroMemory, unlike memset.
        if (payloadSpan)
            SecureZeroMemory(bytes, payloadSpan);
        (void)VirtualProtect(bytes, payloadSpan, oldProt, &dummy);

        // a canary mismatch that pre-wiping does not explain means a buffer
        // overrun. crash at once rather than continue on corrupted memory.
        if (!canary_ok && !looks_wiped)
        {
#ifdef _MSC_VER
            __fastfail(2);
#else
            std::terminate();
#endif
        }

        // wipe the header so its pointers and sizes do not linger in memory.
        SecureZeroMemory(hdr, sizeof(locked_header));

        // unlock the pinned pages and release the whole reserved region,
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
 * @brief compare two locked allocators.
 *
 * the allocator carries no state, so all instances are interchangeable. a
 * container relies on that to move a buffer by pointer instead of copying the
 * secret.
 *
 * @return always true.
 */
template <class T, class U>
inline bool operator==(const locked_allocator<T>&, const locked_allocator<U>&)
{
    return true;
}

/**
 * @brief switch the payload protection to PAGE_NOACCESS.
 *
 * the change covers the whole payload span from the header, so payload, canary
 * and page slack change together. the header page keeps its read-write
 * protection, which is what keeps header_from_payload() usable afterwards. the
 * call is best-effort: the VirtualProtect result is discarded and a failure
 * leaves the previous protection in place.
 *
 * @tparam T element type of the payload.
 * @param  p payload pointer; a null pointer is a no-op.
 * @pre @p p was returned by locked_allocator::allocate() (or is null).
 * @note no call site in this tree calls this function today, so a locked
 *       payload stays PAGE_READWRITE from allocate() to deallocate(). this
 *       function and @ref RWGuard exist so that a later sealed-at-rest mode
 *       does not have to change every reader.
 * @warning every read or write through @p p raises an access violation until
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
 * @brief switch the payload protection to PAGE_READWRITE.
 *
 * the change covers the whole payload span, like protect_noaccess(). the call
 * is best-effort: the VirtualProtect result is discarded. it is safe on a span
 * that is already read-write.
 *
 * @tparam T element type of the payload.
 * @param  p payload pointer; a null pointer is a no-op.
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
