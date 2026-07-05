#include "CredentialWorkspace.hpp"

#include "Cryptography.hpp"
#include "Vault.hpp"

#include <algorithm>
#include <stdexcept>

namespace seal
{

// --- session ---

bool CredentialWorkspace::isPasswordSet() const noexcept
{
    return m_Session.isSet();
}

void CredentialWorkspace::adoptPassword(SecureWide&& pw)
{
    m_Session.adopt(std::move(pw));
}

void CredentialWorkspace::clearPassword()
{
    m_Session.clear();
}

CredentialSession& CredentialWorkspace::session() noexcept
{
    return m_Session;
}

// --- records (read) ---

const std::vector<VaultRecord>& CredentialWorkspace::records() const noexcept
{
    return m_Records;
}

const uint64_t& CredentialWorkspace::generation() const noexcept
{
    return m_Generation;
}

bool CredentialWorkspace::empty() const noexcept
{
    return m_Records.empty();
}

size_t CredentialWorkspace::recordCount() const noexcept
{
    size_t count = 0;
    for (const auto& r : m_Records)
    {
        if (!r.deleted)
        {
            ++count;
        }
    }
    return count;
}

// --- vault path ---

const std::filesystem::path& CredentialWorkspace::vaultPath() const noexcept
{
    return m_VaultPath;
}

void CredentialWorkspace::setVaultPath(std::filesystem::path path)
{
    m_VaultPath = std::move(path);
}

// --- domain ops ---

void CredentialWorkspace::addRecord(const std::string& platform,
                                    const SecureWide& username,
                                    const SecureWide& password)
{
    auto access = m_Session.unlock();
    if (!access.ok())
    {
        throw std::runtime_error("master key unavailable");
    }
    VaultRecord rec = seal::encryptCredential(platform, username, password, access.password());
    m_Records.push_back(std::move(rec));
    ++m_Generation;
}

void CredentialWorkspace::editRecord(size_t index,
                                     const std::string& platform,
                                     const SecureWide* username,
                                     const SecureWide* password)
{
    if (index >= m_Records.size())
    {
        throw std::runtime_error("editRecord: index out of range");
    }

    auto access = m_Session.unlock();
    if (!access.ok())
    {
        throw std::runtime_error("master key unavailable");
    }

    DecryptedCredential existing;
    bool reusedExisting = false;

    if (!username || !password)
    {
        existing = seal::decryptCredentialOnDemand(m_Records[index], access.password());
        reusedExisting = true;
    }

    const auto& finalUsername = username ? *username : existing.username;
    const auto& finalPassword = password ? *password : existing.password;

    // Replace the record entirely - fresh salt/IV on re-encrypt.
    m_Records[index] =
        seal::encryptCredential(platform, finalUsername, finalPassword, access.password());
    ++m_Generation;

    if (reusedExisting)
    {
        existing.cleanse();
    }
}

void CredentialWorkspace::markDeleted(size_t index)
{
    if (index >= m_Records.size())
    {
        throw std::runtime_error("markDeleted: index out of range");
    }
    m_Records[index].deleted = true;
    m_Records[index].dirty = true;
    ++m_Generation;
}

void CredentialWorkspace::clearRecords()
{
    m_Records.clear();
    ++m_Generation;
}

void CredentialWorkspace::replaceRecords(std::vector<VaultRecord>&& records)
{
    m_Records = std::move(records);
    ++m_Generation;
}

DecryptedCredential CredentialWorkspace::decrypt(size_t index) const
{
    if (index >= m_Records.size())
    {
        throw std::runtime_error("decrypt: index out of range");
    }
    // m_Session is mutable: the DPAPI unprotect/re-protect cycle mutates the session
    // buffer temporarily, but decrypt() is logically const (it only reads records).
    auto access = m_Session.unlock();
    if (!access.ok())
    {
        throw std::runtime_error("master key unavailable");
    }
    return seal::decryptCredentialOnDemand(m_Records[index], access.password());
}

// --- persistence ---

void CredentialWorkspace::load(const std::filesystem::path& path)
{
    // Clone the password to a local buffer so the Access window can close
    // before we mutate m_Records (replaceRecords bumps the generation and
    // the Access destructor re-protects the session buffer).
    SecureWide pw;
    {
        auto access = m_Session.unlock();
        if (!access.ok())
        {
            throw std::runtime_error("master key unavailable");
        }
        pw.assign(access.password().begin(), access.password().end());
    }

    std::vector<seal::VaultRecord> loaded;
    try
    {
        loaded = seal::loadVaultIndex(path, pw);
    }
    catch (...)
    {
        // Wipe the local copy on the failure path too.
        seal::Cryptography::cleanseString(pw);
        throw;
    }

    // Wipe the local copy before moving data in.
    seal::Cryptography::cleanseString(pw);

    replaceRecords(std::move(loaded));
    m_VaultPath = path;
}

bool CredentialWorkspace::save()
{
    auto access = m_Session.unlock();
    if (!access.ok())
    {
        throw std::runtime_error("master key unavailable");
    }

    if (!seal::saveVault(m_VaultPath, m_Records, access.password()))
    {
        return false;
    }

    for (auto& r : m_Records)
    {
        r.dirty = false;
    }
    std::erase_if(m_Records, [](const VaultRecord& r) { return r.deleted; });

    return true;
}

size_t CredentialWorkspace::rekey(const std::filesystem::path& path,
                                  const SecureWide& current,
                                  const SecureWide& next)
{
    return seal::rekeyVault(path, current, next);
}

}  // namespace seal
