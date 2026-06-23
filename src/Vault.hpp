#pragma once

#include "Cryptography.hpp"
#include "VaultRecord.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace seal
{

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
 * @param vaultPath Path to the `.seal` vault file.
 * @param password  Master password for key derivation.
 * @return Vector of vault records with decrypted platform names.
 * @throw std::runtime_error on wrong password, corrupt file, or I/O error.
 */
std::vector<VaultRecord> loadVaultIndex(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Save vault with fully-encrypted records.
 *
 * Writes a single framed hex blob (same format as loadVaultIndex()).
 * Deleted records are omitted. Untouched records reuse their existing
 * encrypted platform packet (no re-encryption).
 *
 * @param vaultPath Path to the `.seal` vault file.
 * @param records   Records to save (deleted records are skipped).
 * @param password  Master password for key derivation.
 * @param kdf       KDF parameters for newly-encrypted (dirty) records.
 *                  Defaults to DEFAULT_KDF; existing callers are unaffected.
 * @return `true` on success, `false` on I/O error.
 */
bool saveVault(const std::filesystem::path& vaultPath,
               const std::vector<VaultRecord>& records,
               const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
               const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

/**
 * @brief Re-encrypt every record with a new master password, atomically.
 *
 * Loads the vault with @p currentPassword (fail-fast on wrong password),
 * decrypts and re-encrypts every record with @p newPassword (writing
 * current-format packets), writes the result to `<vault>.rekey.tmp`,
 * verifies the temp file by reloading it with the new password, then
 * atomically replaces the original. On any failure the original file is
 * untouched and the temp file is removed.
 *
 * @param vaultPath       Path to the `.seal` vault file.
 * @param currentPassword Current master password.
 * @param newPassword     Replacement master password.
 * @return Number of records re-encrypted.
 * @throw std::runtime_error on wrong password, I/O failure, or
 *        verification mismatch.
 */
size_t rekeyVault(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& currentPassword,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& newPassword);

/// @brief Outcome of a platform-name lookup.
enum class MatchOutcome
{
    Found,      ///< Exactly one record matched.
    NotFound,   ///< Nothing matched.
    Ambiguous,  ///< Multiple prefix candidates; see candidates.
};

/**
 * @brief Result of matchPlatform: index into the input list on success.
 */
struct PlatformMatch
{
    MatchOutcome outcome = MatchOutcome::NotFound;  ///< Lookup outcome.
    int index = -1;                                 ///< Matched index (Found only).
    std::vector<std::string> candidates;            ///< Prefix candidates (Ambiguous only).
};

/**
 * @brief Resolve a platform query against a list of platform names.
 *
 * Case-insensitive exact match wins; otherwise a unique case-insensitive
 * prefix matches; multiple prefix hits are Ambiguous with candidates.
 *
 * @param names Platform names in record order.
 * @param query User-supplied platform query.
 * @return Match outcome with index or candidate list.
 */
PlatformMatch matchPlatform(const std::vector<std::string>& names, std::string_view query);

/**
 * @brief Locate the default vault file.
 *
 * Priority: `SEAL_VAULT` environment variable (used verbatim when the file
 * exists) -> first `*.seal` in the executable's directory -> current working
 * directory -> user home (`USERPROFILE`).
 *
 * @return Path to the vault, or an empty path when none is found.
 */
std::filesystem::path findDefaultVault();

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
 * @param kdf            KDF parameters for both encrypted packets.
 *                       Defaults to DEFAULT_KDF; existing callers are unaffected.
 * @return Newly constructed VaultRecord with encrypted blobs.
 * @throw std::runtime_error on OpenSSL encryption failure.
 */
VaultRecord encryptCredential(
    const std::string& platform,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword,
    const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

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
    const std::filesystem::path& dirPath,
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
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

}  // namespace seal
