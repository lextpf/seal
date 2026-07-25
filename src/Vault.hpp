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
 * @brief Load the vault index.
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
 * @par Cost
 * Each packet carries its own salt and its own KDF parameters, and no derived
 * key is cached, so an N-record vault runs N scrypt derivations at the
 * parameters stored in each packet header. Packets this build writes use
 * cfg::DEFAULT_KDF and cost 64 MiB each; a packet written with other parameters
 * costs what its own header asks for, up to the 512 MiB ceiling
 * cfg::kdfParamsAcceptable() enforces before derivation starts. The call blocks
 * for that whole time; run it off the UI thread.
 *
 * @par Hardening
 * The first record that fails to decrypt throws at once: a best-effort loop
 * would leak the record count by timing. A record count that cannot fit in the
 * remaining payload is rejected as well, since each record needs at least its
 * two 4-byte length fields, so a hostile count cannot force a large
 * reservation.
 *
 * @par Decode pipeline
 * @code
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
 * first record fails to decrypt      ->  "Wrong password" (no record-count leak)
 * @endcode
 *
 * @param vaultPath `.seal` vault file. An empty or whitespace-only file is a
 *                  valid empty vault and yields an empty vector.
 * @param password  Master password for key derivation.
 * @return Records in file order, each with the decrypted UTF-8 platform name,
 *         both packets exactly as read, and `dirty` and `deleted` cleared.
 * @throw std::runtime_error on wrong password, corrupt file, unsupported
 *        format version, or I/O error.
 */
std::vector<VaultRecord> loadVaultIndex(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Save vault with fully-encrypted records.
 * @ingroup Vault
 *
 * Writes one framed hex blob in the layout loadVaultIndex() parses, through
 * `<vaultPath>.tmp`, a durable flush, and a rename. Deleted records are
 * omitted. A platform-name packet is reused verbatim unless the record is
 * dirty or has none yet; then the name is re-encrypted under @p password and
 * @p kdf with a fresh salt and IV. An empty or fully deleted record list still
 * writes a valid 9-byte frame with a record count of zero (18 hex characters),
 * never an empty file.
 *
 * @warning Credential packets (`encryptedBlob`) are always copied verbatim;
 *          this function never re-encrypts them. Encrypt a new or edited
 *          credential with encryptCredential() first, and change the master
 *          password with rekeyVault(), not with saveVault().
 *
 * @par Commit
 * The rename is atomic on one NTFS volume; across volumes it falls back to
 * copy-then-delete, which is not. The staging path is truncated without a
 * probe, so an unrelated file at `<vaultPath>.tmp` is destroyed. The durable
 * flush result is not checked: a failed flush still commits the rename.
 *
 * @note Re-encrypting a dirty platform name can throw `std::runtime_error`
 *       from the crypto core. That exception propagates instead of becoming a
 *       `false` return, and it is the one failure path that leaves the temp
 *       file behind; every reported failure removes it.
 *
 * @param vaultPath Path to the `.seal` vault file.
 * @param records   Records to save; deleted records are skipped.
 * @param password  Master password used to re-encrypt dirty platform names.
 * @param kdf       Parameters for platform-name packets that need
 *                  re-encryption. Credential packets are unaffected.
 * @return `true` on success; `false` when the temp file cannot be opened or
 *         written, when the rename fails, or when a field length or the record
 *         count exceeds the 32-bit on-disk limits.
 * @see rekeyVault, encryptCredential
 */
bool saveVault(const std::filesystem::path& vaultPath,
               const std::vector<VaultRecord>& records,
               const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
               const seal::cfg::KdfParams& kdf = seal::cfg::DEFAULT_KDF);

/**
 * @brief Re-encrypt every record with a new master password, atomically.
 * @ingroup Vault
 *
 * Loads the vault with @p currentPassword, rebuilds both packets of every
 * record under @p newPassword, writes `<vault>.rekey.tmp`, verifies it by
 * reloading with the new password, then atomically replaces the original. On
 * any failure the original is untouched and `<vault>.rekey.tmp` is removed.
 * Cleanup covers that file alone: when saveVault() throws while it re-encrypts
 * a platform name, its own staging file `<vault>.rekey.tmp.tmp` stays on disk.
 *
 * Every packet is rebuilt with cfg::DEFAULT_KDF and a fresh salt and IV, so a
 * rekey also normalises records written with other KDF parameters. Peak
 * plaintext exposure is one credential: each record is decrypted,
 * re-encrypted, and cleansed before the next is read.
 *
 * Verification compares the record count and the platform names, never
 * credential plaintext, which stays sealed throughout.
 *
 * @par Cost
 * About six scrypt derivations per record: the load, the credential decrypt,
 * both re-encrypts, the platform re-encrypt inside saveVault(), and the
 * verification reload. A rekey blocks much longer than a load of the same
 * vault. The temp file goes through saveVault(), so `<vault>.rekey.tmp.tmp` is
 * staged as well.
 *
 * @par Rekey flow
 * @code
 * load(current key)  ->  fail-fast "Wrong password" on a bad current key
 *   for each non-deleted record:
 *     decrypt (current key)  ->  re-encrypt (new key)  ->  cleanse plaintext
 *   write <vault>.rekey.tmp
 *   reload+verify (new key): record count and platform names must match
 *   flush temp  ->  atomic swap (ReplaceFileW; MoveFileExW cross-volume fallback)
 *   any failure: remove <vault>.rekey.tmp, original untouched, rethrow
 * @endcode
 *
 * @warning No lock is taken on @p vaultPath. VaultRecord copies the caller
 *          still holds are stale once this returns, because their packets are
 *          keyed to the old password. Reload with loadVaultIndex() under the
 *          new password before saving anything.
 *
 * @param vaultPath       Path to the `.seal` vault file.
 * @param currentPassword Current master password; a wrong one throws before
 *                        any file is written.
 * @param newPassword     Replacement master password.
 * @return Number of records re-encrypted. loadVaultIndex() never marks a
 *         record deleted, so this equals the on-disk record count.
 * @throw std::runtime_error on wrong password, I/O failure, or verification
 *        mismatch.
 */
size_t rekeyVault(
    const std::filesystem::path& vaultPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& currentPassword,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& newPassword);

/**
 * @enum MatchOutcome
 * @brief Outcome of a platform-name lookup.
 * @author Alex (https://github.com/lextpf)
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
 * @brief Result of matchPlatform: index into the input list on success.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * @ref index is set only for MatchOutcome::Found, and @ref candidates is
 * filled only for MatchOutcome::Ambiguous. Both keep their defaults otherwise.
 */
struct PlatformMatch
{
    MatchOutcome outcome = MatchOutcome::NotFound;  ///< Lookup outcome.
    int index = -1;                                 ///< Matched index (Found only).
    std::vector<std::string> candidates;            ///< Prefix candidates (Ambiguous only).
};

/**
 * @brief Resolve a platform query against a list of platform names.
 * @ingroup Vault
 *
 * A case-insensitive exact match wins wherever it sits in @p names: it
 * returns at once, and prefix hits are consulted only after the loop ends.
 * Otherwise a unique case-insensitive prefix matches, and two or more prefix
 * hits are Ambiguous with candidates. A prefix hit must be strictly longer
 * than the query, so an equal-length name can match only exactly. When two
 * names fold to the query text, the lower index wins.
 *
 * @par Case folding
 * Folding is ASCII-only: bytes outside `A`-`Z` compare unchanged, so a
 * non-ASCII UTF-8 name matches only byte for byte. The account-list filter
 * instead uses Qt case-insensitive substring containment, which folds
 * non-ASCII letters too, so the two selections can disagree on one query.
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
 * @param names Platform names in record order; the result indexes into it.
 * @param query Platform query; an empty query yields NotFound.
 * @return Match outcome with index or candidate list. Candidates carry the
 *         original names, not the folded copies, in record order.
 */
PlatformMatch matchPlatform(const std::vector<std::string>& names, std::string_view query);

/**
 * @brief Cheaply identify a credential vault by its decoded frame header.
 * @ingroup Vault
 *
 * Reads only the leading non-whitespace hex of the fixed vault header (18
 * characters, decoding to magic(4), version(1) and record_count(4)) and checks
 * that the magic is `SVH2`. The version and the count are decoded but not
 * validated; only loadVaultIndex() parses the whole frame. Empty, truncated,
 * non-hex, and unrelated `.seal` files return false.
 *
 * Whitespace is skipped, but the read stops after 4096 bytes, so a file that
 * buries its header behind more leading whitespace returns false rather than
 * making an inventory walk read it to the end.
 *
 * @param path File to sniff.
 * @return `true` when the leading header decodes and carries the vault magic.
 *         An open, read, or decode failure returns `false`; nothing throws.
 */
[[nodiscard]] bool looksLikeVault(const std::filesystem::path& path) noexcept;

/**
 * @brief Whether auto-load can discover a credential-vault filename.
 * @ingroup Vault
 *
 * Name-only test that performs no I/O: the filename or the extension must
 * equal `.seal` under an ordinal case-insensitive comparison. That accepts
 * `vault.seal` and the repository's hidden-dotfile name `.seal`. Pair it with
 * looksLikeVault() when the content must also be a vault.
 *
 * @param path Path whose filename is tested.
 * @return `true` for a vault-shaped name, `false` otherwise and on any
 *         internal failure; nothing throws.
 */
[[nodiscard]] bool isVaultCandidateName(const std::filesystem::path& path) noexcept;

/**
 * @struct VaultCandidate
 * @brief A pre-sniffed file considered by vault auto-selection.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct VaultCandidate
{
    std::filesystem::path path;  ///< Candidate file, as the caller enumerated it.
    bool vault = false;          ///< What looksLikeVault() already told the caller.
};

/**
 * @brief Select the first candidate known to carry credential-vault magic.
 * @ingroup Vault
 *
 * Pure helper: callers do the I/O while building candidates, then use this
 * function to preserve their search-root and sort order. The `vault` flag is
 * trusted as supplied and is never re-checked here.
 *
 * @param candidates Candidates in the caller's preferred order.
 * @return Path of the first candidate whose `vault` flag is set, or an empty
 *         path when no candidate has it.
 */
[[nodiscard]] std::filesystem::path selectVaultCandidate(
    std::span<const VaultCandidate> candidates);

/**
 * @brief Locate the default vault file.
 * @ingroup Vault
 *
 * Priority: `SEAL_VAULT` environment variable (used verbatim when the file
 * exists) -> first `*.seal` in the executable's directory -> current working
 * directory -> user home (`USERPROFILE`). Each directory is scanned one level
 * deep for regular files; the winner is the smallest filename in ordinal
 * wide-string order, which is case-sensitive rather than a locale collation.
 *
 * The match is on the `.seal` extension, so the hidden dotfile `.seal` that
 * isVaultCandidateName() accepts is not found here. There is no content check
 * either: call looksLikeVault() when the result must really be a vault.
 *
 * @return Path to the vault, or an empty path when none is found.
 */
std::filesystem::path findDefaultVault();

/**
 * @brief Decrypt a single record on demand.
 * @ingroup Vault
 *
 * Decrypts only the record's `encryptedBlob`. `encryptedPlatform` is never
 * touched, and `platform` contributes only its length to the Qt debug log. The
 * KDF parameters come from the packet header, so a record written with other
 * parameters still opens.
 *
 * The plaintext is `username\0password`. The first NUL is the separator, and a
 * blob without one is malformed. The transient UTF-8 buffers are wiped before
 * this function returns.
 *
 * @note Call cleanse() on the result, or let it destruct, immediately after
 *       use; both wipe the locked pages.
 *
 * @param record   The vault record whose credential to decrypt.
 * @param password Master password for key derivation.
 * @return Decrypted credential pair in locked memory; move-only.
 * @throw std::runtime_error `Malformed credential blob` when the plaintext
 *        carries no NUL separator, or the crypto core's message when the
 *        packet is truncated, tampered with, or keyed to another password.
 */
DecryptedCredential decryptCredentialOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Decrypt only the username portion of a credential record.
 * @ingroup Vault
 *
 * One packet holds `username\0password`, so the whole plaintext still exists
 * transiently. This helper copies only the username into locked memory and
 * wipes the combined buffer at once, which avoids a second locked password
 * field for username injection. A separator at offset zero yields an empty
 * result.
 *
 * @param record   The vault record whose username to decrypt.
 * @param password Master password for key derivation.
 * @return Decrypted username in locked memory; move-only.
 * @throw std::runtime_error `Malformed credential blob` when the plaintext
 *        carries no NUL separator, or the crypto core's message on
 *        authentication failure.
 */
seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> decryptUsernameOnDemand(
    const VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Encrypt a credential pair into a new VaultRecord.
 * @ingroup Vault
 *
 * The username and password are joined as `username\0password` and encrypted
 * as one packet, the layout decryptCredentialOnDemand() splits on. The
 * platform name becomes a second, independent packet. Each packet gets its own
 * random salt and IV, and the transient UTF-8 buffers are wiped before this
 * function returns.
 *
 * The record exists in memory only, with `dirty` set and `deleted` cleared;
 * call saveVault() to persist it. `dirty` does not decide whether the record
 * is written, because saveVault() writes every non-deleted record; it forces
 * saveVault() to re-encrypt the platform name instead of reusing the packet
 * built here.
 *
 * @param platform       Cleartext platform/service name (UTF-8).
 * @param username       Stored before the NUL separator.
 * @param password       Stored after the NUL separator.
 * @param masterPassword Master password for key derivation.
 * @param kdf            KDF parameters for both encrypted packets.
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
 * @struct ProtectedFolderScan
 * @brief Result of inventorying a directory for a protected-folder plan.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct ProtectedFolderScan
{
    /// Regular files and reparse points below the root, sorted by relative path
    /// in ordinal wide-string order. A plain directory is not listed; a
    /// directory that is a reparse point is listed once and not descended into.
    /// The vector is a snapshot: the filesystem can change before the plan runs.
    std::vector<protected_folder::Entry> entries;
    /// Problems the scan hit: an unreadable entry, an unusable relative path,
    /// or a failed size query. Only the failed size query still yields an
    /// entry; the other two leave nothing in @ref entries, so neither a plan
    /// nor a log line mentions them. A directory-iterator error also raises the
    /// count and stops the walk, so a non-zero count can mean the inventory is
    /// truncated rather than short by the entries above. An empty or
    /// non-directory root, or an iterator that cannot be constructed, yields no
    /// entries and a count of one.
    std::size_t failures = 0;
};

/**
 * @struct DirectoryProcessResult
 * @brief Per-plan execution counts.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * A source counts as successful only when its transformed destination is
 * committed and the source is then removed. That distinction lets exit
 * protection keep its plaintext marker after a partial failure.
 *
 * The counters need not add up to the plan size: a source that reveals itself
 * as a credential vault only at execution time is skipped and counted in
 * neither.
 */
struct DirectoryProcessResult
{
    std::size_t succeeded = 0;  ///< Sources transformed and then removed.
    std::size_t failed = 0;     ///< Sources refused, or failed to transform or remove.
};

/**
 * @brief Inventory regular files and symlinks beneath @p root.
 * @ingroup Vault
 *
 * The I/O boundary for `ProtectedFolderPolicy.hpp`. Result paths are relative
 * to @p root, sizes are captured for the arming preview, and credential-vault
 * identity comes from looksLikeVault(), so every regular file is opened once
 * for the header sniff.
 *
 * @par Reparse points
 * Recursion never crosses one. A symlink or junction is recorded with the
 * symlink flag set and is not descended into, so the policy can explain it
 * with the stable `symlink` token. Such an entry always reports a size of zero
 * and a cleared vault flag, because neither is probed through the link.
 *
 * @par Failures
 * Every unreadable entry, unusable relative path, failed size query, and
 * directory-iterator error raises the failure count; an entry whose size could
 * not be read is still listed, with a size of zero. The walk stops at the first
 * iterator error rather than continuing past a subtree it may have silently
 * skipped, so a non-zero count can also mean a truncated inventory.
 *
 * @par Folder pipeline
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
 * @param root Directory to inventory.
 * @return Entries plus the failure count. An empty or non-directory @p root
 *         yields no entries and a failure count of one.
 */
[[nodiscard]] ProtectedFolderScan scanProtectedFolder(const std::filesystem::path& root);

/**
 * @brief Execute an already-decided folder plan.
 * @ingroup Vault
 *
 * The plan was built from an earlier snapshot, so every entry in `plan.act` is
 * revalidated against live filesystem state before it is touched. Encryption
 * writes `<source>.seal`; decryption strips the last extension.
 *
 * @par Refusal gates
 * - **Unsafe path** - empty, absolute, or containing `..`.
 * - **Wrong source** - gone, a reparse point, or not a regular file.
 * - **Staging collision** - the path is a staging name reserved for another
 *   entry of the same plan.
 * - **Occupied destination** - FileOperations commits through a deterministic
 *   `<destination>.tmp`, so that path and the destination must both be absent.
 *   A probe that reports either present, or that fails outright, refuses the
 *   entry instead of replacing a user-owned file. The probe does not follow
 *   links, so a dangling link fails closed.
 * - **Credential vault** - a source that now carries the vault magic is
 *   skipped and counted in neither field, so an automatic run never consumes a
 *   vault that appeared after planning.
 *
 * @par Failure handling
 * The source is removed only after a successful transform; a failed removal
 * counts the entry as failed even though the destination now exists. Work
 * continues after a failed entry. A `std::exception` from one entry is caught
 * and counted; any other exception type escapes. Skips and refusals are logged
 * in Qt builds only; the log sink compiles out elsewhere.
 *
 * @param root     Directory the plan's relative paths resolve against.
 * @param plan     Entries to act on plus the entries the policy protected;
 *                 each protected entry yields one skip log line and no count.
 * @param password Master password for key derivation.
 * @param encrypt  `true` to encrypt `plan.act`, `false` to decrypt it; must
 *                 match the planner that produced @p plan.
 * @return Counts for this plan only; the scan's own failure count is not
 *         included.
 */
[[nodiscard]] DirectoryProcessResult processFolderPlan(
    const std::filesystem::path& root,
    const protected_folder::FolderPlan& plan,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool encrypt);

/**
 * @brief Encrypt a directory recursively using the protected-folder policy.
 * @ingroup Vault
 *
 * Inventories @p dirPath with scanProtectedFolder(), plans with
 * protected_folder::planEncrypt() and a default PolicyContext, then runs
 * processFolderPlan().
 *
 * Skipped: application and runtime files (`.exe`, `.dll`, `.pdb`, `qt.conf`,
 * the folder marker, and the profile with its `.tmp` sibling), Qt deployment
 * directories, native-messaging manifests, credential vaults, existing `.seal`
 * files, `*.zombielock` lock files, symlinks, and junction points.
 *
 * @param dirPath  Root of the inventory; the walk never crosses a reparse
 *                 point.
 * @param password Master password for key derivation.
 * @return Number of files encrypted. Failed entries appear only in the summary
 *         log line; entries the scan could not inventory reach neither that
 *         count nor the log.
 *
 * @post Each successfully encrypted source file is deleted from disk. Only the
 *       `.seal` output remains.
 */
int encryptDirectory(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

/**
 * @brief Decrypt eligible `.seal` files in a directory recursively.
 * @ingroup Vault
 *
 * Uses protected_folder::planDecrypt(), so only `.seal` files are acted on and
 * plaintext files are left alone. Credential vaults, application and runtime
 * files, Qt deployment directories, native-messaging manifests,
 * `*.zombielock` lock files, symlinks, and junction points stay protected by
 * the same policy encryptDirectory() applies.
 *
 * @param dirPath  Root of the inventory; the walk never crosses a reparse
 *                 point.
 * @param password Master password for key derivation.
 * @return Number of files decrypted. Failed entries appear only in the summary
 *         log line; entries the scan could not inventory reach neither that
 *         count nor the log.
 *
 * @post Each successfully decrypted `.seal` file is deleted from disk. Only
 *       the plaintext output remains.
 */
int decryptDirectory(
    const std::filesystem::path& dirPath,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password);

}  // namespace seal
