#pragma once

#include "CryptoGuards.hpp"
#include "LockedAllocator.hpp"
#include "SecureString.hpp"

namespace seal
{

/**
 * @class CredentialSession
 * @brief Single owner of the master password and its DPAPI in-memory guard.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * Replaces the open-coded `m_Password` / `m_DPAPIGuard` / `m_PasswordSet` trio.
 * The master key is held in locked memory and kept DPAPI-protected while idle;
 * @ref unlock returns an RAII window during which the key is plaintext.
 *
 * @note Not internally synchronised. All calls must occur on the owning
 *       (GUI) thread; background workers must receive an owned SecureWide
 *       copy taken inside an unlock() window, never a CredentialSession&.
 */
class CredentialSession
{
public:
    using SecureWide = basic_secure_string<wchar_t, locked_allocator<wchar_t>>;

    /// @brief Construct an empty (unset) session.
    CredentialSession();

    /// @brief Wipe and release the master key.
    ~CredentialSession();

    CredentialSession(const CredentialSession&) = delete;
    CredentialSession& operator=(const CredentialSession&) = delete;
    CredentialSession(CredentialSession&&) = delete;
    CredentialSession& operator=(CredentialSession&&) = delete;

    /// @brief Whether a master password is currently held.
    bool isSet() const noexcept;

    /// @brief Adopt a new master password (sole acquire path).
    ///
    /// Wipes any previous key, takes ownership of @p password, rebuilds the
    /// DPAPI guard over the new buffer, and leaves it protected (idle).
    ///
    /// @param password Master password to take ownership of.
    void adopt(SecureWide&& password);

    /// @brief Wipe the master key and return to the unset state (sole release).
    void clear();

    /**
     * @class Access
     * @brief RAII plaintext window over the session's master key.
     * @ingroup Memory
     *
     * Unprotects on construction and re-protects on destruction. @ref ok
     * reports whether the buffer is actually readable; callers MUST check it
     * before calling @ref password.
     */
    class [[nodiscard]] Access
    {
    public:
        /// @brief Open a plaintext window over @p session.
        explicit Access(CredentialSession& session) noexcept;

        /// @brief Re-protect the buffer.
        ~Access();

        Access(const Access&) = delete;
        Access& operator=(const Access&) = delete;

        /// @brief Whether the key is plaintext and readable in this window.
        bool ok() const noexcept;

        /// @brief The plaintext master password.
        /// @return Reference to the locked-memory buffer; valid only while ok().
        /// @throw std::logic_error if called when !ok().
        const SecureWide& password() const;

    private:
        CredentialSession& m_Session;
        bool m_Ok = false;
    };

    /// @brief Open a scoped plaintext window over the master key.
    /// @return An Access whose ok() is false when the session is unset or the
    ///         DPAPI unprotect failed.
    [[nodiscard]] Access unlock() noexcept;

private:
    friend class Access;

    SecureWide m_Password;           ///< Master password in locked memory.
    DPAPIGuard<SecureWide> m_Guard;  ///< In-memory DPAPI guard over m_Password.
    bool m_Set = false;              ///< Whether a password is held.
};

}  // namespace seal
