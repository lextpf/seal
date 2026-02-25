#pragma once

#ifdef USE_QT_UI

#include <QtCore/QString>

#include <string>
#include <vector>

#include "Cryptography.h"

namespace sage {

/**
 * @brief One record in the vault index.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Both platform name and credential pair are individually encrypted
 * as separate AES-256-GCM packets.  The cleartext platform is held
 * in memory only (decrypted on load) so the UI can list accounts.
 */
struct VaultRecord
{
    std::string m_Platform;                              ///< Cleartext platform name (in-memory only, UTF-8)
    std::vector<unsigned char> m_EncryptedPlatform;      ///< AES-256-GCM packet of platform name
    std::vector<unsigned char> m_EncryptedBlob;          ///< AES-256-GCM packet of "username\0password"
    bool m_Dirty   = false;                              ///< True if created or modified since last save
    bool m_Deleted = false;                              ///< Soft-deleted; skipped on save and display
};

/**
 * @brief Temporary holder for a decrypted credential pair.
 * @author Alex (https://github.com/lextpf)
 *
 * Both fields live in locked, guarded memory.  Call cleanse() or let the
 * destructor run to wipe them immediately after use.
 */
struct DecryptedCredential
{
    sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>> m_Username;
    sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>> m_Password;

    void cleanse();
};

/**
 * @brief Load the vault index.
 *
 * Decrypts platform names on load so the UI can list accounts.
 * Credentials remain encrypted until explicitly requested.
 * Each line: encrypted_platform_hex | encrypted_credential_hex.
 */
std::vector<VaultRecord> loadVaultIndex(
    const QString& vaultPath,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& password
);

/**
 * @brief Save vault with fully-encrypted records.
 *
 * Each line: encrypted_platform_hex | encrypted_credential_hex.
 * Deleted records are omitted.  Untouched records reuse their existing
 * encrypted blobs (no re-encryption).
 */
bool saveVaultV2(
    const QString& vaultPath,
    const std::vector<VaultRecord>& records,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& password
);

/**
 * @brief Decrypt a single record on demand.
 *
 * Only the requested record's blob is decrypted.  The caller must call
 * cleanse() on the result (or let it destruct) immediately after use.
 */
DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& password
);

/**
 * @brief Encrypt a credential pair into a new VaultRecord.
 *
 * The record is marked dirty so the next save writes it.
 */
VaultRecord encryptCredential(
    const std::string& platform,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& username,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& password,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& masterPassword
);

/// @brief Encrypt a directory recursively (skips .sage and .exe files).
int encryptDirectory(
    const QString& dirPath,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& password
);

/// @brief Decrypt .sage files in a directory recursively.
int decryptDirectory(
    const QString& dirPath,
    const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& password
);

} // namespace sage

#endif // USE_QT_UI
