#pragma once

#ifdef USE_QT_UI

#include <QtCore/QString>

#include <string>
#include <vector>

#include "Cryptography.h"

namespace seal
{

/**
 * @struct VaultRecord
 * @brief One record in the vault index.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Both platform name and credential pair are individually encrypted
 * as separate AES-256-GCM packets.  The cleartext platform is held
 * in memory only (decrypted on load) so the UI can list accounts.
 *
 * Binary format:
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 * ---
 * block-beta
 *   columns 8
 *   magic["magic(4)"]:1
 *   ver["ver(1)"]:1
 *   count["count(4)"]:1
 *   pLen["platLen(4)"]:1
 *   pBlob["platform packet"]:1
 *   cLen["credLen(4)"]:1
 *   cBlob["credential packet"]:1
 *   more["..."]:1
 * ```
 *
 * The binary payload is hex-encoded as a single line when stored on disk;
 * loadVaultIndex() decodes the hex before parsing the binary framing.
 *
 * @see loadVaultIndex, encryptCredential
 */
struct VaultRecord
{
    /// Cleartext platform name (in-memory only, UTF-8; decrypted from encryptedPlatform on load).
    /// Deliberately std::string (not secure_string): platform names are displayed in the vault
    /// list view and used for string operations (.find(), .c_str(), fromUtf8). The locked-memory
    /// discipline is reserved for actual secrets (passwords, usernames, master key).
    std::string platform;
    std::vector<unsigned char> encryptedPlatform;  ///< AES-256-GCM packet of platform name
    std::vector<unsigned char> encryptedBlob;      ///< AES-256-GCM packet of "username\0password"
    bool dirty = false;                            ///< True if created or modified since last save
    bool deleted = false;                          ///< Soft-deleted; skipped on save and display
};

/**
 * @struct DecryptedCredential
 * @brief Temporary holder for a decrypted credential pair.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Both fields live in locked, guarded memory.  Call cleanse() or let the
 * destructor run to wipe them immediately after use.
 *
 * @see decryptCredentialOnDemand
 */
struct DecryptedCredential
{
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> username;
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> password;

    /// @brief Securely wipe both fields.
    void cleanse();
};

/**
 * @brief Load the vault index.
 *
 * Decrypts platform names on load so the UI can list accounts.
 * Credentials remain encrypted until explicitly requested.
 * File format is a single hex blob containing a framed binary payload:
 * `magic(4) + version(1) + record_count(4) + records...`.
 * Each record is `platform_len(4) + platform_packet + cred_len(4) + cred_packet`.
 *
 * Decryption fails fast on the first record: if the master password is
 * wrong the function throws immediately rather than attempting remaining
 * records, preventing a timing side-channel that would reveal the record count.
 *
 * @param vaultPath Absolute path to the `.seal` vault file.
 * @param password  Master password for key derivation.
 * @return Vector of vault records with decrypted platform names.
 * @throw std::runtime_error on wrong password, corrupt file, or I/O error.
 */
std::vector<VaultRecord> loadVaultIndex(
    const QString& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Save vault with fully-encrypted records.
 *
 * Writes a single framed hex blob (same format as loadVaultIndex()).
 * Deleted records are omitted. Untouched records reuse their existing
 * encrypted platform packet (no re-encryption).
 *
 * @param vaultPath Absolute path to the `.seal` vault file.
 * @param records   Records to save (deleted records are skipped).
 * @param password  Master password for key derivation.
 * @return `true` on success, `false` on I/O error.
 */
bool saveVaultV2(
    const QString& vaultPath,
    const std::vector<VaultRecord>& records,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Decrypt a single record on demand.
 *
 * Only the requested record's blob is decrypted.  The caller must call
 * cleanse() on the result (or let it destruct) immediately after use.
 *
 * @param record   The vault record whose credential to decrypt.
 * @param password Master password for key derivation.
 * @return Decrypted credential pair in locked memory.
 * @throw std::runtime_error on authentication failure or malformed data.
 */
DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Encrypt a credential pair into a new VaultRecord.
 *
 * The record is marked dirty so the next save writes it.
 *
 * @param platform       Cleartext platform/service name (UTF-8).
 * @param username       Username in secure wide string.
 * @param password       Password in secure wide string.
 * @param masterPassword Master password for key derivation.
 * @return Newly constructed VaultRecord with encrypted blobs.
 * @throw std::runtime_error on OpenSSL encryption failure.
 */
VaultRecord encryptCredential(
    const std::string& platform,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword);

/**
 * @brief Encrypt a directory recursively (skips .seal, .exe, .dll, and .pdb files).
 *
 * Symlinks and junction points are skipped to prevent escape from the
 * intended directory tree.
 *
 * @param dirPath  Root directory path.
 * @param password Master password for key derivation.
 * @return Number of files successfully encrypted.
 *
 * @post Each successfully encrypted source file is **deleted** from disk.
 *       Only the `.seal` output remains.
 */
int encryptDirectory(
    const QString& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Decrypt `.seal` files in a directory recursively.
 *
 * Symlinks and junction points are skipped to prevent escape from the
 * intended directory tree.
 *
 * @param dirPath  Root directory path.
 * @param password Master password for key derivation.
 * @return Number of files successfully decrypted.
 *
 * @post Each successfully decrypted `.seal` file is **deleted** from disk.
 *       Only the plaintext output remains.
 */
int decryptDirectory(
    const QString& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

}  // namespace seal

#endif  // USE_QT_UI
