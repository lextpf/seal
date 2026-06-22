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
 * Used to bracket code that needs plaintext access to a DPAPI-protected
 * buffer. The template parameter allows use with any DPAPIGuard
 * specialisation (e.g. narrow or wide secure strings).
 *
 * @tparam GuardT A DPAPIGuard specialisation.
 */
template <class GuardT>
class ScopedDpapiUnprotect
{
public:
    explicit ScopedDpapiUnprotect(GuardT& guard) noexcept
        : m_Guard(guard),
          m_Changed(guard.unprotect())
    {
    }

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

    /// @brief Whether the construction-time unprotect succeeded (the buffer is
    ///        now plaintext). False means CryptUnprotectMemory failed (or the
    ///        buffer was empty/already plaintext) - callers bracketing a
    ///        protected buffer MUST treat false as "do not read plaintext".
    /// @return true if unprotect() reported success.
    bool ok() const noexcept { return m_Changed; }

    ScopedDpapiUnprotect(const ScopedDpapiUnprotect&) = delete;
    ScopedDpapiUnprotect& operator=(const ScopedDpapiUnprotect&) = delete;

private:
    GuardT& m_Guard;
    bool m_Changed = false;
};

}  // namespace seal
