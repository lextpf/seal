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
 * The master key lives in locked memory and stays DPAPI-protected while idle.
 * @ref unlock returns an RAII window during which the key is plaintext. This
 * class is the only long-lived holder of the key in the process; anything else
 * is a short-lived clone taken inside a window, and its holder must cleanse it.
 *
 * @par Master-key lifecycle
 * @verbatim
 *   States:  unset - no key held
 *            idle  - key held, DPAPI-protected  (the resting state)
 *            open  - Access alive and ok(): key is plaintext-readable
 *
 *   Transitions:
 *     unset  --adopt(pw)---------------------->  idle
 *     idle   --adopt(pw)  (clear + re-adopt)-->  idle
 *     idle   --clear()------------------------>  unset
 *     idle   --unlock()  [key held]----------->  open
 *     open   --~Access: reprotect()----------->  idle   (best-effort)
 *     unset  --unlock()----------------------->  unset  (ok() == false)
 * @endverbatim
 *
 * @par Address stability
 * The DPAPI guard stores a raw pointer to the member buffer, so the session
 * must not change address while it holds a key. Copy and move are therefore
 * deleted: own the session in place and pass it by reference.
 *
 * @warning Access windows do not nest. A second @ref unlock inside an open
 *          window finds the buffer already unprotected, so it reports
 *          `ok() == false` and its destructor re-protects nothing. Open one
 *          window per call chain and pass the key down, or copy the key out.
 *
 * @note Not internally synchronised. Call it only on the owning (GUI) thread;
 *       background workers must receive an owned SecureWide copy taken inside
 *       an unlock() window, never a CredentialSession&.
 */
class CredentialSession
{
public:
    /// Master-password buffer type: a wide secure string in locked memory.
    using SecureWide = basic_secure_string<wchar_t, locked_allocator<wchar_t>>;

    /// @brief Construct an empty (unset) session.
    CredentialSession();

    /// @brief Wipe and release the master key by calling @ref clear.
    ~CredentialSession();

    CredentialSession(const CredentialSession&) = delete;
    CredentialSession& operator=(const CredentialSession&) = delete;
    CredentialSession(CredentialSession&&) = delete;
    CredentialSession& operator=(CredentialSession&&) = delete;

    /**
     * @brief Whether a master password is currently held.
     * @return true after @ref adopt and before the next @ref clear. A true
     *         result does not promise that @ref unlock will succeed.
     */
    bool isSet() const noexcept;

    /**
     * @brief Adopt a new master password (sole acquire path).
     *
     * Wipes any previous key, takes ownership of @p password, rebuilds the
     * DPAPI guard over the new buffer, and protects it, which normally leaves
     * the session idle. The locked allocation moves into the session, so
     * @p password is left empty.
     *
     * @param password Master password to take ownership of.
     * @pre No Access window is open on this session.
     * @note The DPAPI encryption result is discarded. Two cases leave the key in
     *       plaintext: a zero-length @p password, which DPAPI cannot protect, and
     *       a CryptProtectMemory failure. Both still set @ref isSet, and every
     *       @ref unlock then reports `ok() == false`. Recovery is a fresh
     *       @ref adopt. Callers reject empty input earlier.
     */
    void adopt(SecureWide&& password);

    /**
     * @brief Wipe the master key and return to the unset state (sole release).
     *
     * Drops the DPAPI guard first, which unprotects the buffer and restores its
     * pre-padding size, then cleanses it. Calling this on an unset session is a
     * harmless no-op.
     *
     * @pre No Access window is open on this session.
     */
    void clear();

    /**
     * @class Access
     * @brief RAII plaintext window over the session's master key.
     * @ingroup Memory
     *
     * Unprotects on construction and re-protects on destruction. @ref ok
     * reports whether the buffer is readable; check it before calling
     * @ref password. The key is plaintext in process memory for the whole
     * lifetime of the window, so keep windows short.
     *
     * An Access must not outlive its session, and the session must not be
     * adopted into or cleared while a window is open. The type is neither
     * copyable nor movable; @ref unlock returns it by guaranteed elision.
     *
     * @par Canonical usage
     * @code{.cpp}
     * auto access = session.unlock();  // ctor: unprotect() when a key is held
     * if (!access.ok())                // false: unset session or unprotect failed
     * {
     *     // master key unavailable - do not read
     * }
     * else
     * {
     *     use(access.password());      // valid only within this scope
     * }
     * // ~access here: reprotect() (best-effort; exceptions swallowed)
     * @endcode
     */
    class [[nodiscard]] Access
    {
    public:
        /**
         * @brief Open a plaintext window over @p session.
         *
         * Prefer @ref CredentialSession::unlock. Unprotects only when the
         * session holds a key, so @ref ok stays false on an unset session.
         *
         * @param session Session to borrow; it must outlive this window.
         */
        explicit Access(CredentialSession& session) noexcept;

        /**
         * @brief Re-protect the buffer.
         *
         * Best-effort and never throws: an exception from the re-protect is
         * swallowed. A failed re-protect leaves the key plaintext and makes
         * every later @ref unlock report `ok() == false`, because the guard no
         * longer considers the buffer protected. Recovery is a fresh @ref adopt.
         */
        ~Access();

        Access(const Access&) = delete;
        Access& operator=(const Access&) = delete;

        /**
         * @brief Whether the key is plaintext and readable in this window.
         * @return false when the session is unset, when the held key is empty,
         *         when the DPAPI unprotect failed, or when another Access
         *         window is already open.
         */
        bool ok() const noexcept;

        /**
         * @brief The plaintext master password.
         * @return Reference to the locked-memory buffer, owned by the session
         *         and valid only while this window is alive and ok(). The
         *         buffer is not NUL-terminated; use size() or the iterators.
         * @throw std::logic_error if called when !ok().
         */
        const SecureWide& password() const;

    private:
        CredentialSession& m_Session;  ///< Borrowed session; must outlive this window.
        bool m_Ok = false;             ///< True only when this window unprotected the buffer.
    };

    /**
     * @brief Open a scoped plaintext window over the master key.
     *
     * Bind the result to a named local: the window closes, and the key is
     * re-protected, when that local goes out of scope.
     *
     * @return An Access whose ok() is false when the session is unset, when the
     *         held key is empty, when the DPAPI unprotect failed, or when a
     *         window is already open.
     */
    [[nodiscard]] Access unlock() noexcept;

private:
    friend class Access;

    /// Master password in locked memory. While protected it holds ciphertext
    /// padded up to the DPAPI block size, so size() is meaningful only inside
    /// an open Access window.
    SecureWide m_Password;
    DPAPIGuard<SecureWide> m_Guard;  ///< In-memory DPAPI guard pointing at m_Password.
    bool m_Set = false;              ///< Whether a password is held; independent of guard state.
};

}  // namespace seal
