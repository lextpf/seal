#pragma once

#include "Cryptography.hpp"

namespace seal
{

/**
 * @class ScopedDpapiUnprotect
 * @brief Keep a DPAPI buffer plaintext for one scope.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Memory
 *
 * The guard and buffer must outlive this object. Keep scopes short. Nested scopes report
 * ok() false and leave protection to the outer scope.
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
 *   Protection succeeds: ciphertext. Protection fails: plaintext remains.
 *   A failed unprotect leaves the original state unchanged.
 * @endverbatim
 *
 * @tparam GuardT unprotect() must not throw; DPAPIGuard only shrinks without allocating.
 */
template <class GuardT>
class ScopedDpapiUnprotect
{
public:
    /**
     * @fn explicit ScopedDpapiUnprotect(GuardT& guard) noexcept
     * @brief Record whether unprotect() changed state.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param guard Must outlive this object.
     */
    explicit ScopedDpapiUnprotect(GuardT& guard) noexcept
        : m_Guard(guard),
          m_Changed(guard.unprotect())
    {
    }

    /**
     * @fn ~ScopedDpapiUnprotect()
     * @brief Attempt protection only if construction unprotected the buffer.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Exceptions are swallowed. A failed DPAPI call leaves plaintext without reporting failure;
     * the secure-string destructor still wipes it.
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
     * @fn bool ok() const noexcept
     * @brief Confirm that construction made the buffer readable.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return False on DPAPI failure or no-op: no buffer, empty buffer or already plaintext.
     * @warning Do not read the buffer when false.
     */
    bool ok() const noexcept { return m_Changed; }

    ScopedDpapiUnprotect(const ScopedDpapiUnprotect&) = delete;
    ScopedDpapiUnprotect& operator=(const ScopedDpapiUnprotect&) = delete;

private:
    GuardT& m_Guard;         ///< Bracketed guard; not owned, must outlive this object.
    bool m_Changed = false;  ///< Whether the construction-time unprotect() succeeded.
};

}  // namespace seal
