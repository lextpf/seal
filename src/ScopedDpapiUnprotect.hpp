#pragma once

#include "Cryptography.hpp"

namespace seal
{

/**
 * @class ScopedDpapiUnprotect
 * @brief RAII guard that calls guard.unprotect() on construction and
 *        guard.reprotect() on destruction.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Memory
 *
 * Brackets code that needs plaintext access to a DPAPI-protected buffer, for any
 * DPAPIGuard specialisation. The secret is plaintext in locked memory for the
 * whole scope, so keep the scope as short as the work allows.
 *
 * Destruction reprotects only when the construction-time `unprotect()` changed
 * state (see @ref ok); a failed or no-op unprotect leaves the buffer untouched.
 * The destructor swallows any exception, so teardown never throws.
 *
 * @verbatim
 *   guarded buffer: DPAPI-protected (ciphertext at rest)
 *        |
 *        |  ScopedDpapiUnprotect g(guard)    m_Changed = guard.unprotect()
 *        v
 *   +-------------------------------------------------------------+
 *   |  g.ok() == true  -> plaintext readable within this scope    |
 *   |  g.ok() == false -> unprotect failed / no-op; do not read   |
 *   +-------------------------------------------------------------+
 *        |
 *        |  ~ScopedDpapiUnprotect()   if m_Changed: guard.reprotect()
 *        v                            (any exception is swallowed)
 *   guarded buffer: re-protected (unchanged if unprotect had failed)
 * @endverbatim
 *
 * @par Lifetime and copying
 * The guard is held by reference, so the DPAPIGuard and the secure string behind
 * it have to outlive this object. The class is neither copyable nor movable: the
 * deleted copy operations suppress the implicit move operations as well.
 *
 * @par Nesting
 * Nesting two scopes over one guard is safe but pointless. The inner scope finds
 * an already-plaintext buffer, so its unprotect() is a no-op, ok() is false and
 * its destructor does nothing.
 *
 * @tparam GuardT A DPAPIGuard specialisation providing `bool unprotect()` and
 *                `reprotect()`. `unprotect()` may not throw: the constructor is
 *                noexcept and calls it in the member initialiser list.
 *                DPAPIGuard::unprotect() only shrinks the buffer to drop the
 *                block padding, so it never allocates.
 * @see DPAPIGuard
 */
template <class GuardT>
class ScopedDpapiUnprotect
{
public:
    /**
     * @brief Unprotect @p guard at once and record whether that changed state.
     * @param guard The DPAPI guard to bracket. It must outlive this object.
     */
    explicit ScopedDpapiUnprotect(GuardT& guard) noexcept
        : m_Guard(guard),
          m_Changed(guard.unprotect())
    {
    }

    /**
     * @brief Reprotect the buffer when construction unprotected it.
     *
     * A failed re-encryption is not observable: DPAPIGuard::reprotect() discards
     * the result of protect(), so a CryptProtectMemory failure leaves the buffer
     * in plaintext and nothing reports it. The owning secure string still wipes
     * that plaintext on destruction.
     */
    ~ScopedDpapiUnprotect()
    {
        try
        {
            if (m_Changed)
            {
                m_Guard.reprotect();
            }
        }
        catch (...)
        {
        }
    }

    /**
     * @brief Whether the construction-time unprotect turned the buffer into
     *        plaintext.
     *
     * The value is false when CryptUnprotectMemory failed, and also when
     * unprotect() was a no-op: the guard holds no buffer, the buffer is empty,
     * or the buffer was already plaintext. The guard cannot tell those cases
     * apart.
     *
     * @return true if unprotect() reported success.
     * @warning When ok() is false the plaintext is not guaranteed. Do not read the
     *          buffer in that case.
     */
    bool ok() const noexcept { return m_Changed; }

    /// @brief Copy construction is deleted: one scope owns one unprotect window.
    ScopedDpapiUnprotect(const ScopedDpapiUnprotect&) = delete;
    /// @brief Copy assignment is deleted: one scope owns one unprotect window.
    ScopedDpapiUnprotect& operator=(const ScopedDpapiUnprotect&) = delete;

private:
    GuardT& m_Guard;         ///< Bracketed guard; not owned, must outlive this object.
    bool m_Changed = false;  ///< Whether the construction-time unprotect() succeeded.
};

}  // namespace seal
