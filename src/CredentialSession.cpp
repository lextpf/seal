#include "CredentialSession.hpp"

#include "Cryptography.hpp"

#include <stdexcept>
#include <utility>

namespace seal
{

CredentialSession::CredentialSession() = default;

CredentialSession::~CredentialSession()
{
    clear();
}

bool CredentialSession::isSet() const noexcept
{
    return m_Set;
}

void CredentialSession::adopt(SecureWide&& password)
{
    // Release any previous key, then take ownership and rebuild the guard over
    // the new buffer so it stays protected while idle. The move steals the
    // locked allocation and leaves the caller's buffer empty. The guard keeps a
    // raw pointer to m_Password - hence the deleted copy/move on this class.
    clear();
    m_Password = std::move(password);
    m_Guard = DPAPIGuard<SecureWide>(&m_Password);
    m_Set = true;
}

void CredentialSession::clear()
{
    m_Guard = DPAPIGuard<SecureWide>{};  // drop the guard before wiping the buffer
    seal::Cryptography::cleanseString(m_Password);
    m_Set = false;
}

CredentialSession::Access::Access(CredentialSession& session) noexcept
    : m_Session(session)
{
    // Unprotect only when a key is held; on an unset session ok() stays false so
    // callers never read a non-existent secret. unprotect() also returns false
    // for an empty buffer (DPAPI cannot protect one) and for an already-open
    // window, so neither case claims plaintext.
    if (m_Session.m_Set)
    {
        m_Ok = m_Session.m_Guard.unprotect();
    }
}

CredentialSession::Access::~Access()
{
    // Best-effort: a destructor must not throw. When the re-protect fails the
    // guard stays unprotected, so every later unlock() reports ok() == false and
    // the caller has to re-adopt the password.
    if (m_Ok)
    {
        try
        {
            m_Session.m_Guard.reprotect();
        }
        catch (...)
        {
        }
    }
}

bool CredentialSession::Access::ok() const noexcept
{
    return m_Ok;
}

const CredentialSession::SecureWide& CredentialSession::Access::password() const
{
    if (!m_Ok)
    {
        throw std::logic_error("CredentialSession::Access::password() called when !ok()");
    }
    return m_Session.m_Password;
}

CredentialSession::Access CredentialSession::unlock() noexcept
{
    return Access(*this);
}

}  // namespace seal
