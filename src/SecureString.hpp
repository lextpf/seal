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
 * @brief own code units in guarded memory with best-effort VirtualLock.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * copy is explicit through assign(). vector growth, including c_str(), invalidates pointers and
 * views and wipes the old allocation on release.
 *
 * clear() wipes live units and releases all capacity; allocator release wipes the full payload.
 * pop_back() and shorter assign() can leave stale capacity until release; shrinking resize()
 * wipes its discarded tail immediately.
 *
 * clear() and shrinking resize() open sealed pages themselves. other code-unit access requires
 * PAGE_READWRITE, including pointers/references from accessors; use RWGuard when sealed.
 * concurrent reads require no mutation; c_str() mutates.
 *
 * @tparam CharT sizes count code units, not bytes.
 * @tparam A must provide locked_allocator layout; protection helpers read its preceding header.
 */
template <class CharT, class A = locked_allocator<CharT>>
struct basic_secure_string
{
    basic_secure_string() = default;
    basic_secure_string(const basic_secure_string&) = delete;
    basic_secure_string& operator=(const basic_secure_string&) = delete;
    /// transfer the allocation without copying plaintext; leave the source empty.
    basic_secure_string(basic_secure_string&& o) noexcept
        : s(std::move(o.s))
    {
    }
    /**
     * @brief wipe the current allocation before taking the source buffer.
     *
     * self-assignment preserves contents. the default allocator leaves the source empty.
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
    /// @brief wipe and release the buffer through clear().
    ~basic_secure_string() { clear(); }

    void push_back(CharT c) { s.push_back(c); }

    /**
     * @brief remove a trailing unit without wiping it; empty input is unchanged.
     *
     * the removed unit remains in spare capacity until allocation release.
     */
    void pop_back()
    {
        if (!s.empty())
            s.pop_back();
    }

    bool empty() const { return s.empty(); }

    size_t size() const { return s.size(); }

    /**
     * @brief borrow unterminated code units until reallocation.
     *
     * @return unspecified when unallocated, normally nullptr.
     */
    template <class Self>
    auto data(this Self&& self)
    {
        return std::forward<Self>(self).s.data();
    }

    /// borrow all size() units, including any terminator appended by c_str().
    std::basic_string_view<CharT> view() const noexcept { return {s.data(), s.size()}; }

    /**
     * @brief append a terminator if needed and include it in size().
     *
     * may reserve one extra unit, invalidating pointers/views. repeated calls append nothing.
     * take view() first when it must exclude the terminator.
     *
     * @verbatim
     *   before:   [ h e l l o ]        size() == 5
     *   c_str():  [ h e l l o 0 ]      size() == 6, the view ends with the zero
     * @endverbatim
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
     * @brief open sealed pages, wipe live units and release all capacity.
     *
     * allocator release scrubs unused capacity. size() and capacity() become zero.
     */
    void clear()
    {
        if (!s.empty())
        {
            // restore read-write in case the buffer rests at PAGE_NOACCESS.
            seal::protect_readwrite(s.data());
            // wipe in bytes - sizeof(CharT) may be 2 (wchar_t) or 4 (char32_t).
            SecureZeroMemory(s.data(), s.size() * sizeof(CharT));
            // swap-to-empty releases the guarded allocation back to the OS.
            s.clear();
            std::vector<CharT, A>().swap(s);
        }
        else
        {
            // a capacity-only string still owns a guarded block; release it too.
            if (s.capacity() > 0 && s.data())
            {
                seal::protect_readwrite(s.data());
                s.clear();
                std::vector<CharT, A>().swap(s);
            }
        }
    }

    /**
     * @brief copy all size() units, including any c_str() terminator.
     *
     * @warning the returned std::basic_string uses pageable memory; cleanse it after use.
     */
    std::basic_string<CharT> str_copy() const
    {
        return std::basic_string<CharT>(s.data(), s.data() + s.size());
    }

    auto begin() const noexcept { return s.begin(); }
    auto end() const noexcept { return s.end(); }

    /**
     * @brief explicitly clone a range into this allocation.
     *
     * shorter assignments leave the old tail in unused capacity until release.
     */
    template <class InputIt>
    void assign(InputIt first, InputIt last)
    {
        s.assign(first, last);
    }

    /**
     * @brief wipe discarded units on shrink; zero-initialize growth.
     *
     * @pre growth requires PAGE_READWRITE and can reallocate.
     * @post shrink leaves pages PAGE_READWRITE; reseal explicitly if needed.
     */
    void resize(std::size_t n)
    {
        if (n < s.size())
        {
            // wipe the bytes being discarded so the secret does not linger in freed capacity.
            seal::protect_readwrite(s.data());
            SecureZeroMemory(s.data() + n, (s.size() - n) * sizeof(CharT));
        }
        s.resize(n);
    }

    /**
     * @brief borrow the final code unit without bounds checking.
     *
     * @pre the string is not empty.
     */
    template <class Self>
    auto&& back(this Self&& self)
    {
        return std::forward<Self>(self).s.back();
    }

    /// reserve code-unit capacity; growth invalidates views and wipes the old allocation.
    void reserve(std::size_t n) { s.reserve(n); }

    /**
     * @brief access a code unit without bounds checking.
     *
     * @pre i < size().
     */
    template <class Self>
    auto&& operator[](this Self&& self, std::size_t i)
    {
        return std::forward<Self>(self).s[i];
    }

private:
    std::vector<CharT, A> s;
};

/**
 * @brief narrow-character secure string.
 *
 * @tparam A allocator type; it must produce the locked_allocator layout.
 * @see basic_secure_string
 */
template <class A = locked_allocator<char>>
using secure_string = basic_secure_string<char, A>;

/**
 * @struct RWGuard
 * @brief open a payload for this scope and restore its prior protection.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * changes cover payload, canary and page slack and affect all threads. nested guards restore
 * PAGE_READWRITE until the outer guard exits. VirtualProtect failure leaves changed false and
 * the original protection intact.
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
 * @pre pointer is nullptr or a live locked_allocator allocation.
 */
template <class T>
struct RWGuard
{
    const T* p{};         ///< guarded payload pointer; null makes the guard inert.
    DWORD oldProt{};      ///< protection saved at construction, restored on destruction.
    bool changed{false};  ///< whether construction actually flipped protection to RW.

    /**
     * @brief attempt a writable scope over the payload.
     *
     * @param ptr nullptr creates an inert guard.
     */
    explicit RWGuard(const T* ptr)
        : p(ptr)
    {
        if (!p)
            return;
        // flip the payload span to PAGE_READWRITE and save the previous
        // protection for the destructor to restore.
        auto* hdr = header_from_payload(p);
        changed = !!VirtualProtect(
            const_cast<std::remove_cv_t<T>*>(p), hdr->payloadSpan, PAGE_READWRITE, &oldProt);
    }
    /// @brief restore the saved protection when construction changed it.
    ~RWGuard()
    {
        if (!p || !changed)
            return;
        // restore the saved protection, usually PAGE_NOACCESS.
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
 * @brief own service, username and password in three self-wiping wide strings.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * primary is service; secondary is username; tertiary is password.
 * index access and structured bindings use that order.
 */
template <class A = seal::locked_allocator<wchar_t>>
struct secure_triplet16
{
    using string_type = seal::basic_secure_string<wchar_t, A>;

    string_type primary;    ///< service / platform name.
    string_type secondary;  ///< username or email.
    string_type tertiary;   ///< password.

    /// adopt service, username and password strings in that order.
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

    static constexpr std::size_t size() noexcept { return 3; }

    /**
     * @brief select service, username or password by index.
     *
     * @pre i < 3; release returns tertiary for every index above 1. use at() for unchecked inputs.
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
     * @brief reject field indices outside 0..2.
     *
     * @throw std::out_of_range when i >= 3.
     */
    template <class Self>
    auto&& at(this Self&& self, std::size_t i)
    {
        if (i >= 3)
            throw std::out_of_range("secure_triplet::at");
        return std::forward<Self>(self)[i];
    }

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

    /**
     * @brief expose fields to structured bindings with compile-time index validation.
     *
     * @tparam I 0 = primary, 1 = secondary, 2 = tertiary.
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
/// @brief convenience alias for secure_triplet16 with the default locked allocator.
using secure_triplet16_t = secure_triplet16<>;

}  // namespace seal

/**
 * @brief structured binding support: a secure_triplet16 always has three fields.
 *
 * @tparam A locked allocator type of the triplet.
 */
template <class A>
struct std::tuple_size<seal::secure_triplet16<A>> : std::integral_constant<std::size_t, 3>
{
};
/**
 * @brief field type for structured bindings: every index maps to string_type.
 *
 * @tparam I field index (0-2).
 * @tparam A locked allocator type of the triplet.
 */
template <std::size_t I, class A>
struct std::tuple_element<I, seal::secure_triplet16<A>>
{
    using type = typename seal::secure_triplet16<A>::string_type;
};
