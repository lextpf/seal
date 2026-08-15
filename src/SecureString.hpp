#pragma once

#include "LockedAllocator.hpp"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace seal
{

/**
 * @struct basic_secure_string
 * @brief Move-only secure string backed by locked, guard-paged memory.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * The code units live in @ref locked_allocator pages: pinned in physical RAM by
 * VirtualLock (best-effort) and bordered by PAGE_NOACCESS guard pages. Copy is
 * deleted, so a secret is never duplicated implicitly.
 *
 * @par Reallocation
 * The storage is a std::vector, so push_back(), reserve(), resize(), assign()
 * and c_str() can reallocate. A reallocation copies the secret into a fresh
 * locked block and locked_allocator::deallocate() scrubs the old one, but it
 * invalidates every pointer from data() or c_str() and every view().
 *
 * @par Wiping model
 * clear() zeroes size() code units and then releases the buffer. It does not
 * zero the bytes between size() and capacity(), so pop_back() and assign() can
 * leave stale code units there. A shrinking resize() is the exception: it
 * zeroes the discarded tail itself. Stale bytes are scrubbed on release in any
 * case: locked_allocator::deallocate() zeroes the whole committed payload span.
 *
 * @par Page protection
 * clear() and a shrinking resize() open the payload themselves. Every other
 * member that touches the code units needs the payload to be PAGE_READWRITE
 * already, as does every access through the pointers and references handed out
 * by data(), c_str(), view(), back() and operator[]. Open a sealed buffer with
 * an @ref RWGuard.
 *
 * @par Thread safety
 * Not thread-safe. Concurrent const access is safe only while no thread calls a
 * mutating member, and c_str() is a mutating member.
 *
 * @tparam CharT Character type (`char`, `wchar_t`, `char16_t`). Sizes count code
 *               units, never bytes.
 * @tparam A     Allocator type. It must produce the locked_allocator layout,
 *               because clear() and resize() call @ref protect_readwrite on
 *               data(), which reads the allocation header in front of the
 *               payload.
 *
 * @see locked_allocator, protect_noaccess, protect_readwrite, RWGuard
 */
template <class CharT, class A = locked_allocator<CharT>>
struct basic_secure_string
{
    /// @brief Construct an empty string. No memory is allocated yet.
    basic_secure_string() = default;
    /// @brief Copy construction is deleted: a secret is never duplicated implicitly.
    basic_secure_string(const basic_secure_string&) = delete;
    /// @brief Copy assignment is deleted: a secret is never duplicated implicitly.
    basic_secure_string& operator=(const basic_secure_string&) = delete;
    /**
     * @brief Take over the buffer of @p o, which is left empty.
     *
     * The buffer moves by pointer, so the secret stays in the same locked pages.
     */
    basic_secure_string(basic_secure_string&& o) noexcept
        : s(std::move(o.s))
    {
    }
    /**
     * @brief Wipe the current contents, then take over the buffer of @p o.
     *
     * Self-assignment is a no-op and keeps the contents. Otherwise clear() runs
     * first, so the previous secret is zeroed and released before the new buffer
     * is adopted. Allocators always compare equal, so the buffer moves by
     * pointer.
     *
     * @param o Source string. It is left valid but unspecified, and empty with
     *          the default allocator.
     */
    basic_secure_string& operator=(basic_secure_string&& o) noexcept
    {
        if (this != &o)
        {
            clear();
            s = std::move(o.s);
        }
        return *this;
    }
    /// @brief Wipe and release the buffer through clear().
    ~basic_secure_string() { clear(); }

    /// @brief Append a code unit.
    void push_back(CharT c) { s.push_back(c); }

    /**
     * @brief Remove the last code unit; a no-op when the string is empty.
     *
     * The removed code unit is not zeroed here. It stays in the unused capacity
     * until the buffer is released.
     */
    void pop_back()
    {
        if (!s.empty())
            s.pop_back();
    }

    /// @brief Check whether the string is empty.
    bool empty() const { return s.empty(); }

    /// @brief Return the number of code units stored.
    size_t size() const { return s.size(); }

    /**
     * @brief Return a pointer to the first code unit.
     *
     * Constness propagates from the object, so a const string yields
     * `const CharT*`. The buffer is not null-terminated; use c_str() when a
     * terminated pointer is needed. While no buffer is allocated the result is
     * unspecified, in practice null.
     *
     * @return Pointer to the buffer, valid until the next reallocation.
     */
    template <class Self>
    auto data(this Self&& self)
    {
        return std::forward<Self>(self).s.data();
    }

    /**
     * @brief Return a non-owning view over the stored code units.
     *
     * The view covers size() code units. A terminator appended by c_str() counts
     * towards size(), so the view ends with that zero code unit.
     *
     * @return View over the buffer, valid until the next reallocation.
     */
    std::basic_string_view<CharT> view() const noexcept { return {s.data(), s.size()}; }

    /**
     * @brief Return a null-terminated C string.
     *
     * Appends a zero code unit when the string is empty, or when the last code
     * unit is not zero. The terminator is a normal element: it raises size() by
     * one and is visible through size(), view(), back() and str_copy(). A second
     * call appends nothing.
     *
     * When the capacity is exhausted the call reserves exactly one more code
     * unit, so the terminator does not trigger the geometric growth of a locked
     * block. That reservation reallocates and invalidates every earlier data(),
     * c_str() and view() result. Call view() before c_str() when the view must
     * exclude the terminator.
     *
     * @verbatim
     *   before:   [ h e l l o ]        size() == 5
     *   c_str():  [ h e l l o 0 ]      size() == 6, the view ends with the zero
     * @endverbatim
     *
     * @return Pointer to the null-terminated data, valid until the next
     *         reallocation.
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
     * Restores PAGE_READWRITE first, because the payload may rest at
     * PAGE_NOACCESS. Then zeroes `size() * sizeof(CharT)` bytes with
     * `SecureZeroMemory` and swaps in an empty vector, which releases the
     * guarded allocation. A string that holds capacity but no elements is
     * released the same way. locked_allocator::deallocate() scrubs the unused
     * capacity during that release.
     *
     * @post size() and capacity() are 0 and no buffer is held.
     */
    void clear()
    {
        if (!s.empty())
        {
            // Restore read-write in case the buffer rests at PAGE_NOACCESS.
            seal::protect_readwrite(s.data());
            // Wipe in bytes - sizeof(CharT) may be 2 (wchar_t) or 4 (char32_t).
            SecureZeroMemory(s.data(), s.size() * sizeof(CharT));
            // Swap-to-empty releases the guarded allocation back to the OS.
            s.clear();
            std::vector<CharT, A>().swap(s);
        }
        else
        {
            // A capacity-only string still owns a guarded block; release it too.
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
     *
     * Copies exactly size() code units, including a terminator that an earlier
     * c_str() call appended.
     *
     * @return A heap-allocated copy in pageable memory.
     * @warning The returned string is not in locked memory and may be swapped to
     *          disk. Use it only when an insecure copy is acceptable.
     */
    std::basic_string<CharT> str_copy() const
    {
        return std::basic_string<CharT>(s.data(), s.data() + s.size());
    }

    /// @brief Const iterator to the first code unit (read source for assign / iteration).
    auto begin() const noexcept { return s.begin(); }
    /// @brief Const iterator past the last code unit.
    auto end() const noexcept { return s.end(); }

    /**
     * @brief Replace contents with the range [first, last) - the sanctioned secret-clone path.
     *
     * The previous contents are overwritten, not wiped: when the new range is
     * shorter, the old tail stays in the unused capacity until the buffer is
     * released.
     */
    template <class InputIt>
    void assign(InputIt first, InputIt last)
    {
        s.assign(first, last);
    }

    /**
     * @brief Resize to @p n code units, zeroing the truncated tail on shrink.
     *
     * A shrink zeroes the discarded code units with `SecureZeroMemory`, so the
     * secret does not linger in freed capacity. A growth zero-initialises the
     * new code units and can reallocate.
     *
     * @param n New size in code units.
     * @pre The payload is PAGE_READWRITE when the call grows the string, because
     *      a reallocation reads the existing code units. The shrink path
     *      restores read-write access itself.
     * @post A shrink leaves the payload PAGE_READWRITE. Call protect_noaccess()
     *       again when the buffer has to rest sealed.
     */
    void resize(std::size_t n)
    {
        if (n < s.size())
        {
            // Wipe the bytes being discarded so the secret does not linger in freed capacity.
            seal::protect_readwrite(s.data());
            SecureZeroMemory(s.data() + n, (s.size() - n) * sizeof(CharT));
        }
        s.resize(n);
    }

    /**
     * @brief Access the last code unit (const + non-const).
     *
     * Constness and value category propagate from the object.
     *
     * @return Reference to the last code unit.
     * @pre The string is not empty; back() on an empty string is undefined
     *      behaviour, as with std::vector::back().
     */
    template <class Self>
    auto&& back(this Self&& self)
    {
        return std::forward<Self>(self).s.back();
    }

    /**
     * @brief Reserve capacity for at least @p n code units (size() is unchanged).
     *
     * A growing reservation reallocates; locked_allocator::deallocate() scrubs
     * the old block.
     *
     * @param n Minimum capacity in code units.
     */
    void reserve(std::size_t n) { s.reserve(n); }

    /**
     * @brief Element access by index (const + non-const).
     *
     * Constness and value category propagate from the object.
     *
     * @param i Index into the buffer (no bounds checking; UB if i >= size()).
     * @return Reference to the code unit at position @p i.
     */
    template <class Self>
    auto&& operator[](this Self&& self, std::size_t i)
    {
        return std::forward<Self>(self).s[i];
    }

private:
    std::vector<CharT, A> s;
};

/// @brief Narrow-character secure string.
/// @tparam A Allocator type; it must produce the locked_allocator layout.
/// @see basic_secure_string
template <class A = locked_allocator<char>>
using secure_string = basic_secure_string<char, A>;

/**
 * @struct RWGuard
 * @brief RAII guard that temporarily sets a locked payload to PAGE_READWRITE.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * Construction flips the payload to PAGE_READWRITE; destruction restores the
 * saved protection. That protection is PAGE_READWRITE today, and PAGE_NOACCESS
 * only if a caller sealed the payload with protect_noaccess() first. The flip
 * covers the whole payload span recorded in the header, so canary and page
 * slack change protection together with the payload. Non-copyable and
 * non-movable.
 *
 * @par Nesting
 * Guards nest safely: an inner guard saves PAGE_READWRITE as the protection to
 * restore, so the outer guard stays the one that seals the payload again.
 *
 * @par Failure mode
 * A VirtualProtect failure is silent: @ref changed stays false, the destructor
 * does nothing, and the payload keeps the protection it already had.
 *
 * @verbatim
 *   payload: entry protection (PAGE_NOACCESS only if a caller sealed it)
 *        |  RWGuard g(p)      save oldProt; VirtualProtect(payloadSpan, RW)
 *        |                    changed = (VirtualProtect succeeded)
 *        v
 *   payload: PAGE_READWRITE   read / write the secret within this scope
 *        |  ~RWGuard()        if changed: VirtualProtect(payloadSpan, oldProt)
 *        v
 *   payload: oldProt          (the entry protection again)
 * @endverbatim
 *
 * @tparam T Element type of the guarded allocation.
 * @pre The pointer is null, or it was returned by locked_allocator::allocate()
 *      and that allocation is still live.
 */
template <class T>
struct RWGuard
{
    const T* p{};         ///< Guarded payload pointer; null makes the guard inert.
    DWORD oldProt{};      ///< Protection saved at construction, restored on destruction.
    bool changed{false};  ///< Whether construction actually flipped protection to RW.

    /**
     * @brief Flip the payload to PAGE_READWRITE and save the old protection.
     * @param ptr Payload pointer, or null for an inert guard.
     */
    explicit RWGuard(const T* ptr)
        : p(ptr)
    {
        if (!p)
            return;
        // Flip the payload span to PAGE_READWRITE and save the previous
        // protection for the destructor to restore.
        auto* hdr = header_from_payload(p);
        changed = !!VirtualProtect(
            const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_READWRITE, &oldProt);
    }
    /// @brief Restore the saved protection when construction changed it.
    ~RWGuard()
    {
        if (!p || !changed)
            return;
        // Restore the saved protection, usually PAGE_NOACCESS.
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
 * @struct secure_triplet16
 * @brief Move-only holder for three wide secure strings with tuple-like access.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * The fields are primary (service), secondary (username) and tertiary
 * (password), reachable through `operator[]`, `at()`, `first()`/`second()`/
 * `third()` and structured bindings via `get<I>()`.
 *
 * There is no default constructor: a triplet is always built from three moved-in
 * strings. Destruction wipes all three fields, because each one is a
 * @ref basic_secure_string that clears itself.
 *
 * @tparam A Locked allocator type used by every field.
 */
template <class A = seal::locked_allocator<wchar_t>>
struct secure_triplet16
{
    /// @brief Type of every field: a wide secure string over the allocator A.
    using string_type = seal::basic_secure_string<wchar_t, A>;

    string_type primary;    ///< Service / platform name.
    string_type secondary;  ///< Username or email.
    string_type tertiary;   ///< Password.

    /**
     * @brief Take ownership of the three field strings.
     * @param s Service / platform name.
     * @param u Username or email.
     * @param p Password.
     */
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

    /**
     * @brief Unchecked element access (0=service, 1=username, 2=password).
     *
     * Constness and value category propagate from the object.
     *
     * @param i Field index.
     * @return Reference to the selected field.
     * @pre `i < 3`. An assert() checks that in a debug build; a release build
     *      returns tertiary for every index above 1. Use at() when the index is
     *      not known to be in range.
     */
    template <class Self>
    auto&& operator[](this Self&& self, std::size_t i) noexcept
    {
        assert(i < 3);
        switch (i)
        {
            case 0:
                return std::forward<Self>(self).primary;
            case 1:
                return std::forward<Self>(self).secondary;
            default:
                return std::forward<Self>(self).tertiary;
        }
    }

    /**
     * @brief Bounds-checked element access.
     *
     * Constness and value category propagate from the object.
     *
     * @param i Index (0-2).
     * @return Reference to the selected field.
     * @throw std::out_of_range if @p i >= 3.
     */
    template <class Self>
    auto&& at(this Self&& self, std::size_t i)
    {
        if (i >= 3)
            throw std::out_of_range("secure_triplet::at");
        return std::forward<Self>(self)[i];
    }

    /// @brief Named accessor for primary (the service name).
    template <class Self>
    auto&& first(this Self&& self) noexcept
    {
        return std::forward<Self>(self).primary;
    }
    /// @brief Named accessor for secondary (the username).
    template <class Self>
    auto&& second(this Self&& self) noexcept
    {
        return std::forward<Self>(self).secondary;
    }
    /// @brief Named accessor for tertiary (the password).
    template <class Self>
    auto&& third(this Self&& self) noexcept
    {
        return std::forward<Self>(self).tertiary;
    }

    /**
     * @brief Tuple-like access for structured bindings (`auto& [s, u, p] = triplet`).
     *
     * A static_assert checks the index, so an out-of-range binding fails the
     * build instead of the run.
     *
     * @tparam I Field index: 0 = primary, 1 = secondary, 2 = tertiary.
     * @return Reference to the selected field.
     */
    template <std::size_t I, class Self>
    auto&& get(this Self&& self) noexcept
    {
        static_assert(I < 3, "secure_triplet index out of range");
        if constexpr (I == 0)
        {
            return std::forward<Self>(self).primary;
        }
        else if constexpr (I == 1)
        {
            return std::forward<Self>(self).secondary;
        }
        else
        {
            return std::forward<Self>(self).tertiary;
        }
    }
};
/// @brief Convenience alias for secure_triplet16 with the default locked allocator.
using secure_triplet16_t = secure_triplet16<>;

}  // namespace seal

/// @brief Structured binding support: a secure_triplet16 always has three fields.
/// @tparam A Locked allocator type of the triplet.
template <class A>
struct std::tuple_size<seal::secure_triplet16<A>> : std::integral_constant<std::size_t, 3>
{
};
/// @brief Field type for structured bindings: every index maps to string_type.
/// @tparam I Field index (0-2).
/// @tparam A Locked allocator type of the triplet.
template <std::size_t I, class A>
struct std::tuple_element<I, seal::secure_triplet16<A>>
{
    using type = typename seal::secure_triplet16<A>::string_type;
};
