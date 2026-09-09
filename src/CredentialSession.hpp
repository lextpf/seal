#pragma once

#include "CryptoGuards.hpp"
#include "LockedAllocator.hpp"
#include "SecureString.hpp"

namespace seal
{

/**
 * @class CredentialSession
 * @brief Own the long-lived master key and its DPAPI guard.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Memory
 *
 * The key uses the locked allocator, which attempts page locking. After protection succeeds,
 * the idle key is DPAPI-protected. Take temporary clones inside an Access window and cleanse
 * them after use. Keep the session at one address because the guard points into its buffer.
 *
 * @verbatim
 *   States:  unset - no key held
 *            idle  - key held, DPAPI-protected  (the resting state)
 *            open  - Access alive and ok(): key is plaintext-readable
 *
 *   Transitions:
 *     unset  --adopt(pw) [protection succeeds]-> idle
 *     idle   --adopt(pw) [protection succeeds]-> idle
 *     idle   --clear()------------------------>  unset
 *     idle   --unlock() [unprotect succeeds]--> open
 *     open   --~Access [protection succeeds]-> idle
 *     unset  --unlock()----------------------->  unset  (ok() == false)
 * @endverbatim
 *
 * Empty input or a DPAPI failure can leave a held key unprotected. In that state, unlock()
 * fails until a fresh adopt(); isSet() alone does not authorize plaintext access.
 *
 * @note Call only on the owning thread. Background workers receive an owned SecureWide clone.
 * @warning Access windows do not nest; a second unlock() reports `ok() == false`.
 */
class CredentialSession
{
public:
    /// Master-password buffer with guarded allocation and best-effort page locking.
    using SecureWide = basic_secure_string<wchar_t, locked_allocator<wchar_t>>;

    CredentialSession();

    /**
     * @fn ~CredentialSession()
     * @brief Wipe and release the master key by calling clear.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~CredentialSession();

    CredentialSession(const CredentialSession&) = delete;
    CredentialSession& operator=(const CredentialSession&) = delete;
    CredentialSession(CredentialSession&&) = delete;
    CredentialSession& operator=(CredentialSession&&) = delete;

    /**
     * @fn bool isSet() const noexcept
     * @brief Report key ownership, independent of unlock success.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isSet() const noexcept;

    /**
     * @fn void adopt(SecureWide&& password)
     * @brief Replace and wipe the key, then attempt DPAPI protection.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param password Moved into the session; empty on return.
     * @pre No Access window is open.
     * @note Empty input or DPAPI failure leaves the buffer unprotected but isSet() true.
     *       unlock() then fails until a fresh adopt(); the encryption result is not reported.
     */
    void adopt(SecureWide&& password);

    /**
     * @fn void clear()
     * @brief Release the DPAPI guard and wipe the key; repeated calls are safe.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @pre No Access window is open.
     */
    void clear();

    /**
     * @class Access
     * @brief Scoped plaintext access to the session's key.
     * @author Alex (<https://github.com/lextpf>)
     * @ingroup Memory
     *
     * Check ok() before reading and keep the scope short. The session must outlive this window;
     * do not adopt or clear a key while it is open. Borrowed data is plaintext only inside this
     * window. Copy into owned secure storage for use after the window closes.
     *
     * @code{.cpp}
     * auto access = session.unlock();  // Ctor: unprotect() when a key is held
     * if (!access.ok())                // False: unset session or unprotect failed
     * {
     *     // Master key unavailable - do not read
     * }
     * else
     * {
     *     use(access.password());      // Valid only within this scope
     * }
     * // ~access here: reprotect() (best-effort; exceptions swallowed)
     * @endcode
     */
    class [[nodiscard]] Access
    {
    public:
        /**
         * @fn explicit Access(CredentialSession& session) noexcept
         * @brief Attempt scoped access; prefer CredentialSession::unlock().
         * @author Alex (<https://github.com/lextpf>)
         *
         * @param session Must outlive this window; an unset session yields ok() false.
         */
        explicit Access(CredentialSession& session) noexcept;

        /**
         * @fn ~Access()
         * @brief Attempt DPAPI protection without throwing.
         * @author Alex (<https://github.com/lextpf>)
         *
         * Failure leaves the key plaintext and causes later unlock() calls to fail until a fresh
         * adopt().
         */
        ~Access();

        Access(const Access&) = delete;
        Access& operator=(const Access&) = delete;

        /**
         * @fn bool ok() const noexcept
         * @brief Confirm that this window made the key readable.
         * @author Alex (<https://github.com/lextpf>)
         *
         * @return False for an unset or empty key, DPAPI failure or an already-open window.
         */
        bool ok() const noexcept;

        /**
         * @fn const SecureWide& password() const
         * @brief Borrow the session-owned plaintext buffer.
         * @author Alex (<https://github.com/lextpf>)
         *
         * @return Valid only while this window is alive and ok(); not NUL-terminated.
         * @throw std::logic_error When !ok().
         */
        const SecureWide& password() const;

    private:
        CredentialSession& m_Session;  ///< Borrowed session; must outlive this window.
        bool m_Ok = false;             ///< True only when this window unprotected the buffer.
    };

    /**
     * @fn Access unlock() noexcept
     * @brief Keep the key plaintext until the returned window leaves scope.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Bind the result to a named local and check Access::ok() before reading.
     */
    [[nodiscard]] Access unlock() noexcept;

private:
    friend class Access;

    /// Locked ciphertext while idle; size() includes DPAPI padding outside Access.
    SecureWide m_Password;
    DPAPIGuard<SecureWide> m_Guard;  ///< In-memory DPAPI guard pointing at m_Password.
    bool m_Set = false;              ///< Whether a password is held; independent of guard state.
};

}  // namespace seal
