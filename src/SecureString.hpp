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
 * @brief Move-only secure string backed by locked, guard-paged memory.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * All character data lives in VirtualAlloc'd pages that are pinned in
 * physical RAM (best-effort, via VirtualLock) and bordered by PAGE_NOACCESS
 * guard pages. Copy is deleted; only move semantics are supported.
 *
 * @tparam CharT Character type (e.g. `char`, `wchar_t`, `char16_t`).
 * @tparam A     Allocator type (default: locked_allocator\<CharT\>).
 *
 * @see locked_allocator, protect_noaccess, protect_readwrite
 */
template <class CharT, class A = locked_allocator<CharT>>
struct basic_secure_string
{
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

    /// @brief Return a pointer to the underlying buffer (const-propagating).
    template <class Self>
    auto data(this Self&& self)
    {
        return std::forward<Self>(self).s.data();
    }

    /// @brief Return a non-owning string_view over the contents.
    std::basic_string_view<CharT> view() const noexcept { return {s.data(), s.size()}; }

    /**
     * @brief Return a null-terminated C string.
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

    /**
     * @brief Const iterator to the first code unit (read-source for assign / iteration).
     * @ingroup Memory
     */
    auto begin() const noexcept { return s.begin(); }
    /**
     * @brief Const iterator past the last code unit.
     * @ingroup Memory
     */
    auto end() const noexcept { return s.end(); }

    /**
     * @brief Replace contents with the range [first, last) - the sanctioned secret-clone path.
     * @param first Iterator to the first source code unit.
     * @param last  Iterator past the last source code unit.
     * @ingroup Memory
     */
    template <class InputIt>
    void assign(InputIt first, InputIt last)
    {
        s.assign(first, last);
    }

    /**
     * @brief Resize to @p n code units, zeroing the truncated tail on shrink.
     * @param n New size in code units.
     * @ingroup Memory
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
     * @return Reference to the last code unit. UB if empty (as std::vector::back()).
     * @ingroup Memory
     */
    template <class Self>
    auto&& back(this Self&& self)
    {
        return std::forward<Self>(self).s.back();
    }

    /**
     * @brief Reserve capacity for at least @p n code units (does not change size()).
     * @param n Minimum capacity in code units.
     * @ingroup Memory
     */
    void reserve(std::size_t n) { s.reserve(n); }

    /**
     * @brief Element access by index (const + non-const).
     * @param i Index into the buffer (no bounds checking; UB if i >= size()).
     * @return Reference to the code unit at position @p i.
     * @ingroup Memory
     */
    template <class Self>
    auto&& operator[](this Self&& self, std::size_t i)
    {
        return std::forward<Self>(self).s[i];
    }

private:
    std::vector<CharT, A> s;
};

/// @brief Narrow-character secure string; alias for basic_secure_string\<char, A\>.
/// @tparam A Allocator type (default: locked_allocator\<char\>).
/// @see basic_secure_string
template <class A = locked_allocator<char>>
using secure_string = basic_secure_string<char, A>;

/**
 * @struct RWGuard
 * @brief RAII guard that temporarily sets a locked payload to PAGE_READWRITE.
 * @ingroup Memory
 * @tparam T Element type of the guarded allocation.
 *
 * On construction, flips the payload protection to PAGE_READWRITE.
 * On destruction, restores the original protection (typically PAGE_NOACCESS).
 * Non-copyable and non-movable.
 *
 * @verbatim
 *   payload: PAGE_NOACCESS
 *        |  RWGuard g(p)      save oldProt; VirtualProtect(payloadSpan, RW)
 *        |                    changed = (VirtualProtect succeeded)
 *        v
 *   payload: PAGE_READWRITE   read / write the secret within this scope
 *        |  ~RWGuard()        if changed: VirtualProtect(payloadSpan, oldProt)
 *        v
 *   payload: oldProt          (typically PAGE_NOACCESS again)
 * @endverbatim
 *
 * @pre The pointer must have been returned by locked_allocator::allocate().
 */
template <class T>
struct RWGuard
{
    const T* p{};         ///< Guarded payload pointer; null makes the guard inert.
    DWORD oldProt{};      ///< Protection saved at construction, restored on destruction.
    bool changed{false};  ///< Whether construction actually flipped protection to RW.
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
 * @brief Move-only holder for three wide secure strings with tuple-like access.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
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
     * @param i Index (0-2).
     * @throw std::out_of_range if @p i >= 3.
     */
    template <class Self>
    auto&& at(this Self&& self, std::size_t i)
    {
        if (i >= 3)
            throw std::out_of_range("secure_triplet::at");
        return std::forward<Self>(self)[i];
    }

    /// @brief Named accessors (aliases for primary/secondary/tertiary).
    template <class Self>
    auto&& first(this Self&& self) noexcept
    {
        return std::forward<Self>(self).primary;
    }
    template <class Self>
    auto&& second(this Self&& self) noexcept
    {
        return std::forward<Self>(self).secondary;
    }
    template <class Self>
    auto&& third(this Self&& self) noexcept
    {
        return std::forward<Self>(self).tertiary;
    }

    /// @brief Tuple-like access for structured bindings (`auto& [s, u, p] = triplet`).
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

/// @brief Structured binding support for secure_triplet16.
template <class A>
struct std::tuple_size<seal::secure_triplet16<A>> : std::integral_constant<std::size_t, 3>
{
};
/// @brief Field type (string_type) for structured bindings over secure_triplet16.
template <std::size_t I, class A>
struct std::tuple_element<I, seal::secure_triplet16<A>>
{
    using type = typename seal::secure_triplet16<A>::string_type;
};
