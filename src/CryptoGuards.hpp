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
 * Wraps CryptProtectMemory / CryptUnprotectMemory with SAME_PROCESS scope.
 * The buffer is encrypted on construction and decrypted only during
 * explicit unprotect/reprotect windows. Destruction unprotects and
 * detaches from the buffer but does not wipe it; the caller (or the
 * secure string's own destructor) is responsible for wiping.
 *
 * CryptProtectMemory requires the buffer size to be a multiple of
 * CRYPTPROTECTMEMORY_BLOCK_SIZE. The guard pads the backing vector
 * to meet this requirement transparently.
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
 *     [*] --> Protected : ctor(ptr)
 *     Protected --> Unprotected : unprotect()
 *     Unprotected --> Protected : protect() / reprotect()
 *     Protected --> Detached : ~DPAPIGuard [unprotects first]
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
 * @note Destruction unprotects but does **not** wipe the buffer. The
 *       caller must call `Cryptography::cleanseString()` or let the
 *       secure string's own destructor handle wiping.
 *
 * @see ScopedDpapiUnprotect
 */
template <class SecStr>
struct DPAPIGuard
{
    using char_type = std::remove_pointer_t<decltype(std::declval<SecStr>().data())>;

    SecStr* m_Str = nullptr;    ///< Non-owning pointer to the guarded secure string.
    bool m_Protected = false;   ///< Whether the buffer is currently DPAPI-encrypted.
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

    /**
     * @brief Encrypt the guarded buffer in place with CryptProtectMemory.
     *
     * Pads the buffer up to the DPAPI block size before encrypting; a no-op
     * when there is no buffer, it is empty, or it is already protected.
     * @return true if DPAPI encryption succeeded, false on failure or no-op.
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
     * On success, strips the DPAPI block padding by restoring the original
     * logical size captured at protect() time.
     * @return true if DPAPI decryption succeeded, false on failure or no-op.
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
    void reprotect() { protect(); }

private:
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
 * Snapshots the current console mode on construction and restores it
 * on destruction, ensuring the terminal is never left in an altered
 * state after masked input or mouse-enabled hit-testing.
 */
struct scoped_console
{
    HANDLE h;             ///< Console handle being guarded.
    DWORD oldMode{};      ///< Saved console mode, restored on destruction.
    bool changed{false};  ///< Whether SetConsoleMode succeeded.

    /**
     * @brief Snapshot the current console mode and apply @p mode.
     * @param handle Console input or output handle.
     * @param mode   Desired console mode flags (e.g. ENABLE_MOUSE_INPUT).
     */
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
 * @struct EvpCipherCtx
 * @brief RAII owner for an OpenSSL EVP_CIPHER_CTX.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
 *
 * Allocates a cipher context on construction and frees it on
 * destruction. Non-copyable.
 *
 * @throw std::runtime_error if EVP_CIPHER_CTX_new() fails.
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
 * Allocates a digest context on construction and frees it on
 * destruction. Non-copyable.
 *
 * @throw std::runtime_error if EVP_MD_CTX_new() fails.
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
