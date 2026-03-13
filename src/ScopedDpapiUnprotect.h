#pragma once

#include "Cryptography.h"

namespace seal
{

/**
 * @class ScopedDpapiUnprotect
 * @brief RAII guard that calls guard.unprotect() on construction and
 *        guard.reprotect() on destruction.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Crypto
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

    ScopedDpapiUnprotect(const ScopedDpapiUnprotect&) = delete;
    ScopedDpapiUnprotect& operator=(const ScopedDpapiUnprotect&) = delete;

private:
    GuardT& m_Guard;
    bool m_Changed = false;
};

}  // namespace seal
