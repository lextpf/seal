#pragma once

#include "SecureString.hpp"

#include <wincrypt.h>

#include <openssl/evp.h>

#include <stdexcept>

namespace seal
{

/**
 * @struct DPAPIGuard
 * @brief Apply SAME_PROCESS DPAPI protection to a borrowed secure string.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Memory
 *
 * The buffer must outlive the guard. The protected size includes DPAPI block padding.
 * protect() and unprotect() leave payload pages PAGE_READWRITE.
 *
 * | Method      | No-op state                  | Successful change        |
 * |-------------|------------------------------|--------------------------|
 * | protect()   | Absent, empty or protected   | Pad and encrypt          |
 * | unprotect() | Absent, empty or unprotected | Decrypt and restore size |
 * | reprotect() | Absent, empty or protected   | Same as protect()        |
 *
 * Both boolean methods also return false on DPAPI failure. reprotect() discards this result.
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
 *     Protected --> Detached : ~DPAPIGuard, attempts unprotect
 *     Unprotected --> Detached : ~DPAPIGuard
 *     Detached --> [*]
 * ```
 *
 * @warning Destruction and move assignment attempt to unprotect the released buffer without
 *          wiping it. Failure can leave ciphertext. The owner must wipe either state.
 */
template <class SecStr>
struct DPAPIGuard
{
    using char_type = std::remove_pointer_t<decltype(std::declval<SecStr>().data())>;

    SecStr* m_Str = nullptr;    ///< Non-owning pointer to the guarded secure string.
    bool m_Protected = false;   ///< Whether the buffer is currently DPAPI-encrypted.
    size_t m_OriginalSize = 0;  ///< Pre-pad logical size, restored after unprotect.

    /**
     * @fn DPAPIGuard()
     * @brief Create a detached guard that protects nothing until move assignment.
     * @author Alex (<https://github.com/lextpf>)
     */
    DPAPIGuard() = default;
    /**
     * @fn explicit DPAPIGuard(SecStr* str)
     * @brief Attempt protection on attachment.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param str Must outlive the guard. nullptr leaves it detached; empty leaves it unprotected.
     */
    explicit DPAPIGuard(SecStr* str)
        : m_Str(str)
    {
        protect();
    }

    DPAPIGuard(const DPAPIGuard&) = delete;
    DPAPIGuard& operator=(const DPAPIGuard&) = delete;
    /**
     * @fn DPAPIGuard(DPAPIGuard&& o) noexcept
     * @brief Take over the state of o and leave o detached.
     * @author Alex (<https://github.com/lextpf>)
     */
    DPAPIGuard(DPAPIGuard&& o) noexcept
        : m_Str(o.m_Str),
          m_Protected(o.m_Protected),
          m_OriginalSize(o.m_OriginalSize)
    {
        o.m_Str = nullptr;
        o.m_Protected = false;
        o.m_OriginalSize = 0;
    }
    /**
     * @fn DPAPIGuard& operator=(DPAPIGuard&& o) noexcept
     * @brief Release the old guard without wiping its buffer, then take over the source guard.
     * @author Alex (<https://github.com/lextpf>)
     */
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

    /**
     * @fn ~DPAPIGuard()
     * @brief Attempt to unprotect without wiping; exceptions are swallowed.
     * @author Alex (<https://github.com/lextpf>)
     */
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
     * @fn bool protect()
     * @brief Pad and encrypt in place, with possible reallocation.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return False on failure or no-op; see the type table.
     * @pre Payload pages are PAGE_READWRITE; padding precedes the protection change.
     * @warning Encryption failure leaves padding in place and the buffer unprotected.
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
     * @fn bool unprotect()
     * @brief Decrypt and restore the logical size, wiping discarded padding.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Shrinks without allocation; ScopedDpapiUnprotect relies on this during noexcept construction.
     *
     * @return False on failure or no-op; see the type table.
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

    /**
     * @fn void reprotect()
     * @brief Discard the protection result; encryption failure leaves the buffer plaintext.
     * @author Alex (<https://github.com/lextpf>)
     */
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
 * @brief Restore a borrowed handle's console mode on scope exit.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CLI
 *
 * The handle must outlive the guard and is never closed here. Failed GetConsoleMode or
 * SetConsoleMode leaves `changed` false; callers that require the mode must check it.
 */
struct scoped_console
{
    HANDLE h;             ///< Console handle being guarded; borrowed, never closed.
    DWORD oldMode{};      ///< Saved console mode, restored on destruction.
    bool changed{false};  ///< Whether the constructor applied the mode and must restore it.

    /**
     * @fn scoped_console(HANDLE handle, DWORD mode)
     * @brief Replace the whole console mode word, then restore it on destruction.
     * @author Alex (<https://github.com/lextpf>)
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
    /**
     * @fn ~scoped_console()
     * @brief Restore the saved mode, but only when the constructor changed it.
     * @author Alex (<https://github.com/lextpf>)
     */
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
 * @brief Own a non-null OpenSSL cipher context until scope exit.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Crypto
 *
 * @throw std::runtime_error When EVP_CIPHER_CTX_new() fails.
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
 * @brief Own a non-null OpenSSL digest context until scope exit.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Crypto
 *
 * @throw std::runtime_error When EVP_MD_CTX_new() fails.
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
