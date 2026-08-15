#pragma once

#include "SecureString.hpp"

#include <wincrypt.h>

#include <openssl/evp.h>

#include <stdexcept>

namespace seal
{

/**
 * @struct DPAPIGuard
 * @brief RAII guard for DPAPI in-memory encryption of secure strings.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * Wraps CryptProtectMemory and CryptUnprotectMemory with SAME_PROCESS scope, so only this
 * process can decrypt the buffer. The buffer is encrypted on construction and lies in
 * plaintext only inside an explicit unprotect/reprotect window.
 *
 * @par Padding
 * CryptProtectMemory requires the buffer size to be a multiple of
 * CRYPTPROTECTMEMORY_BLOCK_SIZE. protect() pads the backing vector up to that multiple and
 * unprotect() restores the size recorded before the padding, so `size()` reports the padded
 * length while the buffer is protected.
 *
 * ## :material-shield-lock: Lifecycle
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * stateDiagram-v2
 *     [*] --> Detached : default ctor
 *     [*] --> Protected : ctor(ptr), protect() succeeds
 *     [*] --> Unprotected : ctor(ptr), buffer empty or encryption fails
 *     Unprotected --> Protected : protect() / reprotect()
 *     Protected --> Unprotected : unprotect()
 *     Protected --> Detached : ~DPAPIGuard, unprotects first
 *     Unprotected --> Detached : ~DPAPIGuard
 *     Detached --> [*]
 * ```
 *
 * @par Guard operations
 * | Method        | No-op (returns false) when      | On success                  |
 * |---------------|---------------------------------|-----------------------------|
 * | `protect()`   | no buffer / empty / protected   | pad, encrypt; protected=1   |
 * | `unprotect()` | no buffer / empty / unprotected | decrypt, unpad; protected=0 |
 * | `reprotect()` | (alias for `protect()`)         | see `protect()`             |
 *
 * @note Destruction unprotects and detaches, but never wipes. Wiping is up to the caller,
 *       through `Cryptography::cleanseString()` or the secure string's own destructor.
 * @note protect() and unprotect() set the payload to PAGE_READWRITE and leave it there.
 *       Neither one restores PAGE_NOACCESS.
 * @warning Move assignment releases the current guard first, so the buffer that guard held
 *          is decrypted and stays in plaintext.
 *
 * @see ScopedDpapiUnprotect
 */
template <class SecStr>
struct DPAPIGuard
{
    /// @brief Code-unit type of the guarded string, deduced from `SecStr::data()`.
    using char_type = std::remove_pointer_t<decltype(std::declval<SecStr>().data())>;

    SecStr* m_Str = nullptr;    ///< Non-owning pointer to the guarded secure string.
    bool m_Protected = false;   ///< Whether the buffer is currently DPAPI-encrypted.
    size_t m_OriginalSize = 0;  ///< Pre-pad logical size, restored after unprotect.

    /// @brief Create a detached guard. It protects nothing until it is move-assigned.
    DPAPIGuard() = default;
    /**
     * @brief Attach to @p str and protect it at once.
     *
     * @param str Secure string to guard. It must outlive this object. A null pointer
     *            leaves the guard detached, and an empty string leaves it unprotected.
     */
    explicit DPAPIGuard(SecStr* str)
        : m_Str(str)
    {
        protect();
    }

    /// @brief Copy construction is deleted: one guard owns one protection state.
    DPAPIGuard(const DPAPIGuard&) = delete;
    /// @brief Copy assignment is deleted: one guard owns one protection state.
    DPAPIGuard& operator=(const DPAPIGuard&) = delete;
    /// @brief Take over the state of @p o and leave @p o detached.
    DPAPIGuard(DPAPIGuard&& o) noexcept
        : m_Str(o.m_Str),
          m_Protected(o.m_Protected),
          m_OriginalSize(o.m_OriginalSize)
    {
        o.m_Str = nullptr;
        o.m_Protected = false;
        o.m_OriginalSize = 0;
    }
    /// @brief Release the current guard, then take over the state of @p o.
    /// Releasing decrypts the buffer held so far and leaves it in plaintext.
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

    /// @brief Unprotect when protected, then detach. The buffer is not wiped and any
    /// exception is swallowed, so teardown never throws.
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

    /**
     * @brief Encrypt the guarded buffer in place with CryptProtectMemory.
     *
     * Records the logical size, pads the buffer up to the DPAPI block size, sets the
     * payload to PAGE_READWRITE and encrypts. A no-op when there is no buffer, when the
     * buffer is empty, or when it is already protected.
     *
     * @pre The payload is PAGE_READWRITE on entry. The pad grows the string before the
     *      read-write flip, so a buffer left at PAGE_NOACCESS by protect_noaccess() must
     *      be opened with an RWGuard first. unprotect() has no such precondition; it
     *      flips first.
     * @return `true` when DPAPI encryption succeeded; `false` on failure or no-op.
     * @note The padding grows the secure string, so the call can reallocate it and
     *       invalidate every pointer taken from data() beforehand.
     * @warning When CryptProtectMemory fails, the padding stays in place: only unprotect()
     *          removes it, and unprotect() does nothing on an unprotected buffer.
     */
    bool protect()
    {
        if (!m_Str || m_Str->empty() || m_Protected)
            return false;
        m_OriginalSize = m_Str->size();
        padToBlockSize();
        seal::protect_readwrite(m_Str->data());
        DWORD cbData = static_cast<DWORD>(m_Str->size() * sizeof(char_type));
        if (CryptProtectMemory(m_Str->data(), cbData, CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            m_Protected = true;
            return true;
        }
        return false;
    }

    /**
     * @brief Decrypt the guarded buffer in place with CryptUnprotectMemory.
     *
     * Sets the payload to PAGE_READWRITE and decrypts. On success it strips the DPAPI block
     * padding by restoring the logical size captured at protect() time; that shrink zeroes
     * the discarded code units. A no-op when there is no buffer, when the buffer is empty,
     * or when it is not protected.
     *
     * @return `true` when DPAPI decryption succeeded; `false` on failure or no-op.
     * @note The call only shrinks, so it never allocates. ScopedDpapiUnprotect relies on
     *       that: its constructor is `noexcept` and calls this function.
     */
    bool unprotect()
    {
        if (!m_Str || m_Str->empty() || !m_Protected)
            return false;
        seal::protect_readwrite(m_Str->data());
        DWORD cbData = static_cast<DWORD>(m_Str->size() * sizeof(char_type));
        if (CryptUnprotectMemory(m_Str->data(), cbData, CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            m_Protected = false;
            // Restore the original logical size (remove DPAPI block padding).
            if (m_OriginalSize > 0 && m_OriginalSize < m_Str->size())
                m_Str->resize(m_OriginalSize);
            return true;
        }
        return false;
    }

    /// @brief Re-encrypt the buffer (convenience alias for protect()).
    /// The result is discarded, so a failed re-encryption is not observable here and
    /// leaves the buffer in plaintext.
    void reprotect() { protect(); }

private:
    /// @brief Grow the buffer to the next CRYPTPROTECTMEMORY_BLOCK_SIZE multiple.
    void padToBlockSize()
    {
        if (!m_Str || m_Str->empty())
            return;
        size_t byteSize = m_Str->size() * sizeof(char_type);
        size_t rem = byteSize % CRYPTPROTECTMEMORY_BLOCK_SIZE;
        if (rem != 0)
        {
            size_t padBytes = CRYPTPROTECTMEMORY_BLOCK_SIZE - rem;
            size_t padChars = (padBytes + sizeof(char_type) - 1) / sizeof(char_type);
            m_Str->resize(m_Str->size() + padChars);
        }
    }

    /// @brief Unprotect when protected, then detach. The buffer is never wiped here.
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
 * @ingroup CLI
 *
 * Snapshots the current console mode on construction and restores it on destruction, so the
 * terminal is never left altered after masked input or mouse-enabled hit-testing.
 *
 * @par Ownership
 * The handle is borrowed. The guard never closes it, and it must stay valid for the guard's
 * whole lifetime.
 *
 * @warning When GetConsoleMode() fails, for example because the handle is a redirected
 *          pipe, the requested mode is never applied, `changed` stays false and the
 *          destructor does nothing. Nothing reports the failure, so a caller that depends
 *          on the new mode must verify it.
 */
struct scoped_console
{
    HANDLE h;             ///< Console handle being guarded; borrowed, never closed.
    DWORD oldMode{};      ///< Saved console mode, restored on destruction.
    bool changed{false};  ///< Whether the constructor applied the mode and must restore it.

    /**
     * @brief Snapshot the current console mode and apply @p mode.
     *
     * @p mode replaces the whole mode word; it is not OR-ed into the saved value.
     *
     * @param handle Console input or output handle.
     * @param mode   Desired console mode flags (e.g. ENABLE_MOUSE_INPUT).
     */
    scoped_console(HANDLE handle, DWORD mode)
        : h(handle)
    {
        // Snapshot the current mode for the destructor, then apply the requested one
        // (e.g. ENABLE_MOUSE_INPUT for MaskedCredentialView hit-testing).
        if (GetConsoleMode(h, &oldMode))
        {
            DWORD inNew = mode;
            changed = !!SetConsoleMode(h, inNew);
        }
    }
    /// @brief Restore the saved mode, but only when the constructor changed it.
    ~scoped_console()
    {
        if (changed)
            SetConsoleMode(h, oldMode);
    }
    scoped_console(const scoped_console&) = delete;
    scoped_console& operator=(const scoped_console&) = delete;
};

/**
 * @struct EvpCipherCtx
 * @brief RAII owner for an OpenSSL EVP_CIPHER_CTX.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Allocates a cipher context on construction and frees it on destruction. Neither copyable
 * nor movable, so the context has a single owner and cannot outlive its scope. Construction
 * either throws or leaves `p` non-null, so no call site needs a null check.
 *
 * @throw std::runtime_error when EVP_CIPHER_CTX_new() fails.
 */
struct EvpCipherCtx
{
    EVP_CIPHER_CTX* p{nullptr};  ///< Owned cipher context; freed on destruction.
    EvpCipherCtx()
        : p(EVP_CIPHER_CTX_new())
    {
        if (!p)
        {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }
    }
    ~EvpCipherCtx()
    {
        if (p)
        {
            EVP_CIPHER_CTX_free(p);
        }
    }
    EvpCipherCtx(const EvpCipherCtx&) = delete;
    EvpCipherCtx& operator=(const EvpCipherCtx&) = delete;
    EvpCipherCtx(EvpCipherCtx&&) = delete;
    EvpCipherCtx& operator=(EvpCipherCtx&&) = delete;
};

/**
 * @struct EvpMdCtx
 * @brief RAII owner for an OpenSSL EVP_MD_CTX.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Allocates a digest context on construction and frees it on destruction. Neither copyable
 * nor movable, so the context has a single owner and cannot outlive its scope. Construction
 * either throws or leaves `p` non-null, so no call site needs a null check.
 *
 * @throw std::runtime_error when EVP_MD_CTX_new() fails.
 */
struct EvpMdCtx
{
    EVP_MD_CTX* p{nullptr};  ///< Owned digest context; freed on destruction.
    EvpMdCtx()
        : p(EVP_MD_CTX_new())
    {
        if (!p)
        {
            throw std::runtime_error("EVP_MD_CTX_new failed");
        }
    }
    ~EvpMdCtx()
    {
        if (p)
        {
            EVP_MD_CTX_free(p);
        }
    }
    EvpMdCtx(const EvpMdCtx&) = delete;
    EvpMdCtx& operator=(const EvpMdCtx&) = delete;
    EvpMdCtx(EvpMdCtx&&) = delete;
    EvpMdCtx& operator=(EvpMdCtx&&) = delete;
};

}  // namespace seal
