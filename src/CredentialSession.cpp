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
    // Release any previous key first, then take ownership and (re)build the
    // guard so it points at the new buffer and protects it while idle.
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
    // Only attempt an unprotect when a key is actually held; on an unset
    // session ok() stays false so callers never read a non-existent secret.
    if (m_Session.m_Set)
    {
        m_Ok = m_Session.m_Guard.unprotect();
    }
}

CredentialSession::Access::~Access()
{
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
