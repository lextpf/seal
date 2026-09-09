#pragma once

#include "Cryptography.hpp"
#include "ProtectedFolderPolicy.hpp"
#include "VaultRecord.hpp"

#include <cstddef>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace seal
{

/**
 * @fn std::vector<VaultRecord> loadVaultIndex(const std::filesystem::path& vaultPath, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
 * @brief Load the vault index.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Decrypts every platform name so the account list can render, and leaves the
 * credential packets sealed until decryptCredentialOnDemand() opens one.
 *
 * The file is one hex blob wrapping a binary frame:
 * `magic(4) + version(1) + record_count(4)`, then that many
 * `platform_len(4) + platform packet + cred_len(4) + cred packet` records.
 * Every length field is big-endian.
 *
 * ### :material-note-text-outline: Cost
 *
 * Each packet carries its own salt and its own KDF parameters, and no derived
 * key is cached, so an N-record vault runs N scrypt derivations at the
 * parameters stored in each packet header. Packets this build writes use
 * cfg::DEFAULT_KDF and cost 64 MiB each; a packet written with other parameters
 * costs what its own header asks for, up to the 512 MiB ceiling
 * cfg::kdfParamsAcceptable() enforces before derivation starts. The call blocks
 * for that whole time; run it off the UI thread.
 *
 * ### :material-note-text-outline: Hardening
 *
 * The first platform decryption failure stops the load. This avoids deriving keys for the
 * remaining records with a rejected password; it does not make the operation constant-time.
 * A record count that cannot fit in the remaining payload is rejected before reservation.
 * Each record needs at least two 4-byte length fields.
 *
 * Only platform packets are authenticated here. Credential packets remain unchecked until
 * opened, and an empty vault has no packet with which to verify the password.
 *
 * ### :material-note-text-outline: Decode pipeline
 *
 * @code{.text}
 * on-disk text  --strip ws-->  compact hex  --hex-decode-->  binary frame
 * binary frame  --parse-->     magic "SVH2" | version 1 | record count (BE u32)
 * per record    --decrypt-->   platform name only; credential blob stays sealed
 *
 * cannot open the file               ->  "Cannot open vault file"
 * non-hex input, or magic != "SVH2"  ->  "Invalid vault format"
 * version above 1                    ->  "Vault was written by a newer version ..."
 * version below 1                    ->  "Unsupported (older) vault format version."
 * short header, impossible count,
 *   truncated record, trailing bytes ->  "Corrupted vault file"
 * first platform decryption failure  ->  "Wrong password"
 * @endcode
 *
 * @param vaultPath `.seal` vault file. An empty or whitespace-only file is a
 *                  valid empty vault and yields an empty vector.
 * @param password  Master password for key derivation.
 * @return Records in file order, each with the decrypted UTF-8 platform name,
 *         both packets exactly as read, and `dirty` and `deleted` cleared.
 * @throw std::runtime_error On wrong password, corrupt file, unsupported
 *        format version, or I/O error.
 */
std::vector<VaultRecord> loadVaultIndex(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @fn bool saveVault(const std::filesystem::path& vaultPath, const std::vector<VaultRecord>&
 *     records, const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
 *     const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF)
 * @brief Write non-deleted records as one framed hex blob.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Reuse platform packets unless dirty or absent; replacements use fresh salt/IV and the supplied
 * password/KDF. Empty record sets produce a 9-byte frame (18 hex characters).
 *
 * Stages at `<vaultPath>.tmp`, truncating any existing file there. Flush is best-effort; rename
 * is atomic on one NTFS volume, with non-atomic copy/delete fallback across volumes.
 *
 * @return False for I/O failure or 32-bit field/count overflow; reported failures remove staging.
 * @throw std::runtime_error For platform encryption failure; the staging file can remain.
 * @warning Credential packets are copied verbatim. Use encryptCredential for edits and rekeyVault
 *          for master-key changes.
 */
bool saveVault(const std::filesystem::path& vaultPath,
               const std::vector<VaultRecord>& records,
               const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
               const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

/**
 * @fn size_t rekeyVault(const std::filesystem::path& vaultPath, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& currentPassword, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& newPassword)
 * @brief Rekey both packets per record and verify the index before replacing the vault.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Uses DEFAULT_KDF with fresh salt/IV and cleanses each credential before the next. Verification
 * compares record count and platform names; it does not reopen the new credential packets.
 * About six scrypt derivations per record make this more expensive than loading.
 *
 * @code{.text}
 * load(current key)  ->  fail-fast "Wrong password" on a bad current key
 *   for each non-deleted record:
 *     decrypt (current key)  ->  re-encrypt (new key)  ->  cleanse plaintext
 *   write <vault>.rekey.tmp
 *   reload+verify (new key): record count and platform names must match
 *   flush temp  ->  replace (ReplaceFileW; MoveFileExW copy/delete fallback)
 *   any failure: remove <vault>.rekey.tmp, original untouched, rethrow
 * @endcode
 *
 * @return On-disk record count.
 * @throw std::runtime_error On authentication, I/O or verification failure; original is unchanged.
 * @note Failure removes `<vault>.rekey.tmp`; saveVault exceptions can leave its nested
 *       `<vault>.rekey.tmp.tmp` staging file.
 * @warning No file lock is taken. Reload held records with the new key before saving.
 */
size_t rekeyVault(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& currentPassword,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& newPassword);

/**
 * @enum MatchOutcome
 * @brief Outcome of a platform-name lookup.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 */
enum class MatchOutcome
{
    Found,      ///< Exactly one record matched.
    NotFound,   ///< Nothing matched.
    Ambiguous,  ///< Multiple prefix candidates; see PlatformMatch::candidates.
};

/**
 * @struct PlatformMatch
 * @brief Lookup result with an index or ambiguous candidates.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Index is set only for Found; candidates only for Ambiguous.
 */
struct PlatformMatch
{
    MatchOutcome outcome = MatchOutcome::NotFound;  ///< Lookup outcome.
    int index = -1;                                 ///< Matched index (Found only).
    std::vector<std::string> candidates;            ///< Prefix candidates (Ambiguous only).
};

/**
 * @fn PlatformMatch matchPlatform(const std::vector<std::string>& names, std::string_view query)
 * @brief Prefer the first ASCII-insensitive exact match, then a unique prefix.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Non-ASCII bytes compare unchanged, unlike the Qt list filter's Unicode substring matching.
 * Prefix candidates retain original spelling and record order.
 *
 * @code{.text}
 * empty query              ->  NotFound
 * case-insensitive exact   ->  Found (index)
 * exactly one CI prefix    ->  Found (index)
 * two or more CI prefixes  ->  Ambiguous (candidates)
 * otherwise                ->  NotFound
 * @endcode
 *
 * @param names Result indices refer to this list.
 * @param query Empty yields NotFound.
 */
PlatformMatch matchPlatform(const std::vector<std::string>& names, std::string_view query);

/**
 * @fn bool looksLikeVault(const std::filesystem::path& path) noexcept
 * @brief Sniff SVH2 magic from an 18-character decoded frame header.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Skips whitespace within a 4096-byte read cap. Version and count are decoded but not validated;
 * loadVaultIndex validates the frame.
 *
 * @return False on open, read or decode failure, truncation or wrong magic; never throws.
 */
[[nodiscard]] bool looksLikeVault(const std::filesystem::path& path) noexcept;

/**
 * @fn bool isVaultCandidateName(const std::filesystem::path& path) noexcept
 * @brief Accept filenames or extensions equal to .seal, ignoring ordinal case.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Performs no I/O; includes the hidden name .seal. Use looksLikeVault to verify contents.
 *
 * @return False on internal failure; never throws.
 */
[[nodiscard]] bool isVaultCandidateName(const std::filesystem::path& path) noexcept;

/**
 * @struct VaultCandidate
 * @brief A pre-sniffed file considered by vault auto-selection.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 */
struct VaultCandidate
{
    std::filesystem::path path;  ///< Candidate file, as the caller enumerated it.
    bool vault = false;          ///< What looksLikeVault() already told the caller.
};

/**
 * @fn std::filesystem::path selectVaultCandidate(std::span<const VaultCandidate> candidates)
 * @brief Preserve caller order when selecting the first vault-flagged candidate.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Trusts the supplied flag without I/O.
 *
 * @return Empty path if none is flagged.
 */
[[nodiscard]] std::filesystem::path selectVaultCandidate(
    std::span<const VaultCandidate> candidates);

/**
 * @fn std::filesystem::path findDefaultVault()
 * @brief Search default vault locations without checking contents.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Priority is existing SEAL_VAULT path, executable directory, current directory, then USERPROFILE.
 * Directory searches are non-recursive and choose the smallest filename in ordinal wide-string
 * order. Extension matching excludes the hidden dotfile .seal.
 *
 * @return Empty path if none exists; use looksLikeVault to verify contents.
 */
std::filesystem::path findDefaultVault();

/**
 * @fn DecryptedCredential decryptCredentialOnDemand(const VaultRecord& record, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
 * @brief Open the credential packet using its authenticated KDF parameters.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Splits UTF-8 at the first NUL. Temporary pageable UTF-8 strings are wiped on successful
 * return; their ordinary destructors do not wipe them if conversion or allocation throws.
 *
 * @return Pair in locked memory; cleanse or destroy immediately after use.
 * @throw std::runtime_error For no NUL separator or crypto failure.
 */
DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @fn seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> decryptUsernameOnDemand(
 *     const VaultRecord& record, const seal::basic_secure_string<wchar_t,
 *     seal::locked_allocator<wchar_t>>& password)
 * @brief Copy only the username into locked memory.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * The whole credential packet becomes plaintext transiently. The secure packet buffer is wiped
 * after copying the username. A temporary pageable username string is wiped on successful
 * return; an exception during conversion bypasses that wipe. A leading NUL yields an empty name.
 *
 * @throw std::runtime_error For no NUL separator or crypto failure.
 */
seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> decryptUsernameOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @fn VaultRecord encryptCredential(const std::string& platform, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword, const
 *     seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF)
 * @brief Create separate platform and credential packets with fresh salt and IV.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Joins username and password with one NUL. The username must not contain NUL: decryption uses
 * the first NUL as the separator. Temporary pageable strings are wiped on the success path;
 * allocation, conversion or encryption exceptions can bypass those wipes.
 * The record starts dirty and not deleted; saveVault persists it and re-encrypts its dirty
 * platform packet.
 *
 * @param platform UTF-8 cleartext in memory.
 * @param kdf Applies to both packets.
 * @throw std::runtime_error On OpenSSL encryption failure.
 */
VaultRecord encryptCredential(
    const std::string& platform,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPassword,
    const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

/**
 * @struct ProtectedFolderScan
 * @brief Result of inventorying a directory for a protected-folder plan.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 */
struct ProtectedFolderScan
{
    /**
     * Snapshot sorted by relative path in ordinal wide-string order.
     * Reparse directories appear once; plain directories are omitted.
     */
    std::vector<protected_folder::Entry> entries;
    /**
     * Unreadable entries, invalid paths, size failures and iterator errors.
     * Only size failures retain an entry with zero size. Iterator errors stop the walk;
     * invalid roots or failed iterator construction yield no entries and one failure.
     */
    std::size_t failures = 0;
};

/**
 * @struct DirectoryProcessResult
 * @brief Count entries whose transform and source removal both succeeded.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * A source recognized as a credential vault only during execution counts in neither field.
 * Partial failure keeps the exit-protection plaintext marker.
 */
struct DirectoryProcessResult
{
    std::size_t succeeded = 0;  ///< Sources transformed and then removed.
    std::size_t failed = 0;     ///< Sources refused, or failed to transform or remove.
};

/**
 * @fn ProtectedFolderScan scanProtectedFolder(const std::filesystem::path& root)
 * @brief Snapshot relative paths, sizes and vault identity for folder planning.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Opens regular files to sniff vault headers. Reparse points are listed once with the symlink
 * flag, size zero and no vault flag; recursion never crosses them.
 * Unreadable entries and invalid relative paths are omitted. Failed size queries retain an
 * entry with size zero. Iterator failure stops the walk, so inventory can be truncated.
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart LR
 *     S["scanProtectedFolder\n(I/O: inventory)"] --> P["planEncrypt /\nplanDecrypt (pure)"]
 *     P --> X["processFolderPlan\n(I/O: revalidate)"]
 *     X --> F["FileOperations\nencryptFileTo / decryptFileTo"]
 *     X --> R["remove source"]
 * ```
 *
 * @return Entries and failure count; invalid root or iterator construction yields one failure.
 */
[[nodiscard]] ProtectedFolderScan scanProtectedFolder(const std::filesystem::path& root);

/**
 * @fn DirectoryProcessResult processFolderPlan(const std::filesystem::path& root, const
 *     protected_folder::FolderPlan& plan, const seal::basic_secure_string<wchar_t,
 *     seal::locked_allocator<wchar_t>>& password, bool encrypt)
 * @brief Revalidate each planned source before transforming it.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * | Refusal gate      | Condition                                              |
 * |-------------------|--------------------------------------------------------|
 * | Unsafe path       | Empty, absolute or contains ..                         |
 * | Wrong source      | Missing, reparse point or non-regular file             |
 * | Staging collision | Name reserved for another planned entry                |
 * | Occupied output   | Destination or its .tmp exists, or the probe fails     |
 * | Credential vault  | Live header now has vault magic; skipped without count |
 *
 * Destination probes do not follow links; dangling links fail closed. Encryption adds .seal;
 * decryption removes the final extension. Source removal follows successful commit; removal
 * failure counts as failure even with output present. Each std::exception is counted per entry and
 * processing continues; other exception types escape. Skip/refusal logs exist only in Qt builds.
 *
 * @param encrypt Must match the planner used.
 * @return Plan-only counts, excluding scan failures and protected/skipped entries.
 */
[[nodiscard]] DirectoryProcessResult processFolderPlan(
    const std::filesystem::path& root,
    const protected_folder::FolderPlan& plan,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool encrypt);

/**
 * @fn int encryptDirectory(const std::filesystem::path& dirPath, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
 * @brief Scan, plan and encrypt eligible files with the default protected-folder policy.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Never crosses reparse points. Policy protects runtime files, profile/marker/staging files,
 * deployment directories, manifests, credential vaults, .seal files and .zombielock files.
 *
 * @return Successful transform-and-removal count; scan omissions are absent from summary logs.
 * @post Successful sources are deleted; only .seal output remains.
 */
int encryptDirectory(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @fn int decryptDirectory(const std::filesystem::path& dirPath, const
 *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password)
 * @brief Apply the protected-folder policy to eligible .seal files.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Plaintext and protected files remain untouched; recursion never crosses reparse points.
 *
 * @return Successful transform-and-removal count; scan omissions are absent from summary logs.
 * @post Successful encrypted sources are deleted; only plaintext output remains.
 */
int decryptDirectory(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

}  // namespace seal
