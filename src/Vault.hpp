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
 * An empty or whitespace-only file is treated as an empty vault and yields an
 * empty vector rather than throwing.
 *
 * @par Decode pipeline
 * @code
 * on-disk text  --strip ws-->  compact hex  --hex-decode-->  binary frame
 * binary frame  --parse-->     magic "SVH2" | version 1 | record count (BE u32)
 * per record    --decrypt-->   platform name only; credential blob stays sealed
 * first bad decrypt         ->  throw "Wrong password"  (no record-count leak)
 * all bytes consumed?       ->  else "Corrupted vault file"
 * @endcode
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
 * Writes a single framed hex blob (same format as loadVaultIndex()) via an
 * atomic temp+flush+rename. Deleted records are omitted. A record's
 * platform-name packet is reused verbatim unless the record is dirty or has
 * no existing packet, in which case the name is re-encrypted under @p kdf.
 *
 * @warning Credential packets (`encryptedBlob`) are **always copied verbatim**;
 * this function never re-encrypts them. New or edited credentials must already
 * be encrypted via encryptCredential() before saving, and changing the master
 * password requires rekeyVault(), not saveVault().
 *
 * @param vaultPath Path to the `.seal` vault file.
 * @param records   Records to save (deleted records are skipped).
 * @param password  Master password used to (re)encrypt dirty platform names.
 * @param kdf       KDF parameters for platform-name packets that must be
 *                  (re)encrypted. Defaults to DEFAULT_KDF; credential packets
 *                  are unaffected.
 * @return `true` on success; `false` on I/O error, or when a field length or a
 *         record count exceeds the 32-bit on-disk limits.
 * @see rekeyVault, encryptCredential
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
 * Soft-deleted records are dropped from the rekeyed vault and excluded from
 * the returned count.
 *
 * @par Rekey flow
 * @code
 * load(current key)  ->  fail-fast "Wrong password" on a bad current key
 *   for each non-deleted record:
 *     decrypt (current key)  ->  re-encrypt (new key)  ->  cleanse plaintext
 *   write <vault>.rekey.tmp
 *   reload+verify (new key): record count and platform names must match
 *   flush temp  ->  atomic swap (ReplaceFileW; MoveFileExW cross-volume fallback)
 *   any failure: remove temp, original untouched, rethrow
 * @endcode
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
 * prefix matches; multiple prefix hits are Ambiguous with candidates. An
 * empty @p query yields NotFound.
 *
 * @par Resolution order
 * @code
 * empty query              ->  NotFound
 * case-insensitive exact   ->  Found (index)
 * exactly one CI prefix    ->  Found (index)
 * two or more CI prefixes  ->  Ambiguous (candidates)
 * otherwise                ->  NotFound
 * @endcode
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
 * exists) -> alphabetically first `*.seal` in the executable's directory ->
 * current working directory -> user home (`USERPROFILE`).
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
 * The credential packet's plaintext is `username\0password` (a single NUL
 * separator); a blob with no separator is rejected as malformed.
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
 * The record is marked dirty so the next save writes it. The username and
 * password are joined as `username\0password` and encrypted as one packet,
 * mirroring the layout decryptCredentialOnDemand() splits on.
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
