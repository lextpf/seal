#pragma once

#include "CredentialSession.hpp"
#include "VaultRecord.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace seal
{

/**
 * @class CredentialWorkspace
 * @brief Owns vault records, the master-key session and the save path.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * The workspace must outlive borrowers and stay at one address: the DPAPI guard points into
 * the session. All calls run on the owning thread; no internal synchronization is provided.
 * Key-using operations throw std::runtime_error on access or crypto failure.
 * Record indices identify current vector positions; they are not persistent record IDs.
 *
 * | Operation      | Opens Access | Bumps generation         |
 * |----------------|--------------|--------------------------|
 * | addRecord      | Yes          | Yes                      |
 * | editRecord     | Yes          | Yes                      |
 * | decrypt        | Yes          | No (logically const)     |
 * | markDeleted    | No           | Yes                      |
 * | clearRecords   | No           | Yes                      |
 * | replaceRecords | No           | Yes                      |
 * | load           | Yes          | Yes (via replaceRecords) |
 * | save           | Yes          | No                       |
 * | rekey          | No           | No                       |
 *
 * ```mermaid
 * flowchart LR
 *     W["CredentialWorkspace"] --> R["records vector"]
 *     W --> S["CredentialSession\n(master key)"]
 *     W --> G["generation counter"]
 *     M["VaultListModel"] -.borrows.-> R
 *     M -.borrows.-> G
 *     F["FillController"] -.borrows.-> R
 *     F -.borrows.-> S
 *     F -.borrows.-> G
 * ```
 *
 * @warning save() erases deleted records without bumping generation. Indices shift; the owner
 *          must rebuild borrowed views after success, as AppViewModel::saveVault does.
 */
class CredentialWorkspace
{
public:
    /// Convenience alias matching CredentialSession's own alias.
    using SecureWide = CredentialSession::SecureWide;

    CredentialWorkspace() = default;

    CredentialWorkspace(const CredentialWorkspace&) = delete;
    CredentialWorkspace& operator=(const CredentialWorkspace&) = delete;

    /**
     * @fn bool isPasswordSet() const noexcept
     * @brief Report whether a password is held, independent of DPAPI access success.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isPasswordSet() const noexcept;

    /**
     * @fn void adoptPassword(SecureWide&& pw)
     * @brief Replace and wipe the held master password.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Loaded packets retain their current key. Adopting a different password requires matching
     * records from load() before decryption.
     *
     * @param pw Moved into the session; empty on return.
     * @pre No Access window is open.
     */
    void adoptPassword(SecureWide&& pw);

    /**
     * @fn void clearPassword()
     * @brief Wipe the key and retain the records.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Key-using operations throw until adoptPassword().
     *
     * @pre No Access window is open.
     */
    void clearPassword();

    /**
     * @fn CredentialSession& session() noexcept
     * @brief Borrow the session for scoped key access.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return Reference valid for this workspace's lifetime.
     * @pre Do not nest Access windows or call key-using domain operations inside one.
     */
    CredentialSession& session() noexcept;

    /**
     * @fn const std::vector<VaultRecord>& records() const noexcept
     * @brief Include soft-deleted records in the borrowed list.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return Vector reference valid for this workspace's lifetime. Mutations can move elements;
     *         retain the vector reference, not element pointers.
     */
    const std::vector<VaultRecord>& records() const noexcept;

    /**
     * @fn const uint64_t& generation() const noexcept
     * @brief Expose the live mutation counter to borrowed views.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @code{.cpp}
     * const uint64_t* gen = &workspace.generation();  // Stable address
     * uint64_t seen = *gen;
     * // ... after any mutator runs on the owning thread ...
     * if (*gen != seen)  // A mutation happened: rebuild the borrowed view
     * {
     *     seen = *gen;
     *     refreshFrom(workspace.records());
     * }
     * @endcode
     *
     * @return Stable reference, initially zero; record mutations advance the counter.
     * @note save() can shift indices without advancing the counter; see the class warning.
     */
    const uint64_t& generation() const noexcept;

    /**
     * @fn bool empty() const noexcept
     * @brief Include soft-deleted records in the emptiness check.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return False when only soft-deleted records remain, even though recordCount() is zero.
     */
    bool empty() const noexcept;

    /**
     * @fn size_t recordCount() const noexcept
     * @brief Count non-deleted records with a linear scan.
     * @author Alex (<https://github.com/lextpf>)
     */
    size_t recordCount() const noexcept;

    /**
     * @fn const std::filesystem::path& vaultPath() const noexcept
     * @brief Expose the save destination, initially empty.
     * @author Alex (<https://github.com/lextpf>)
     *
     * load() adopts its own path on success. rekey() does not use this path.
     */
    const std::filesystem::path& vaultPath() const noexcept;

    /**
     * @fn void setVaultPath(std::filesystem::path path)
     * @brief Choose a save destination without creating a file.
     * @author Alex (<https://github.com/lextpf>)
     */
    void setVaultPath(std::filesystem::path path);

    /**
     * @fn void addRecord(const std::string& platform, const SecureWide& username, const SecureWide&
     *     password)
     * @brief Append a dirty encrypted record for the next save.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Duplicate platform names are allowed. `platform` is UTF-8 plaintext in memory.
     *
     * @throw std::runtime_error On access or encryption failure; records and generation stay
     *        unchanged.
     */
    void addRecord(const std::string& platform,
                   const SecureWide& username,
                   const SecureWide& password);

    /**
     * @fn void editRecord(size_t index, const std::string& platform, const SecureWide* username,
     *     const SecureWide* password)
     * @brief Replace a record with fresh salt and IV and mark it dirty.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Editing a deleted record restores it. Retained fields are decrypted and cleansed after use.
     *
     * @param index Zero-based index into records(), not the filtered UI row.
     * @param platform UTF-8 name; always replaced.
     * @param username A null pointer retains the current value.
     * @param password A null pointer retains the current value.
     * @throw std::runtime_error On invalid index, access failure or crypto failure.
     */
    void editRecord(size_t index,
                    const std::string& platform,
                    const SecureWide* username,
                    const SecureWide* password);

    /**
     * @fn void markDeleted(size_t index)
     * @brief Hide a record and defer erasure until save succeeds.
     * @author Alex (<https://github.com/lextpf>)
     *
     * recordCount() drops immediately; empty() still counts the record.
     *
     * @param index Zero-based index into records(), not the filtered UI row.
     * @throw std::runtime_error For an invalid index.
     */
    void markDeleted(size_t index);

    /**
     * @fn void clearRecords()
     * @brief Discard records and unsaved edits, retaining the password and path.
     * @author Alex (<https://github.com/lextpf>)
     */
    void clearRecords();

    /**
     * @fn void replaceRecords(std::vector<VaultRecord>&& records)
     * @brief Adopt loaded records and invalidate all prior indices.
     * @author Alex (<https://github.com/lextpf>)
     */
    void replaceRecords(std::vector<VaultRecord>&& records);

    /**
     * @fn DecryptedCredential decrypt(size_t index) const
     * @brief Decrypt one record into locked memory.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cleanse the result immediately after use or let its destructor wipe it.
     *
     * @param index Zero-based index into records(); deleted records are allowed.
     * @throw std::runtime_error On invalid index, access failure or GCM authentication failure.
     * @pre No Access window is open; this call drives the session's DPAPI cycle.
     */
    DecryptedCredential decrypt(size_t index) const;

    /**
     * @fn void load(const std::filesystem::path& path)
     * @brief Replace records and path after decrypting the vault index.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Clones the master key in a short Access window, then cleanses the clone on success or
     * failure.
     * Credentials remain sealed until decrypt(); prior indices become invalid on success.
     *
     * @throw std::runtime_error On access, authentication, format or I/O failure; records, path and
     *        generation stay unchanged.
     */
    void load(const std::filesystem::path& path);

    /**
     * @fn bool save()
     * @brief Write non-deleted records through a temporary file and rename.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Success clears dirty flags and erases deleted records without bumping generation; rebuild
     * borrowed views. Failure leaves records unchanged.
     *
     * @return False for an empty path, I/O failure or a 32-bit file-field overflow.
     * @throw std::runtime_error On access failure or dirty-platform encryption failure.
     */
    bool save();

    /**
     * @fn size_t rekey(const std::filesystem::path& path, const SecureWide& current, const
     *     SecureWide& next)
     * @brief Replace the on-disk vault after rekeying and verifying its index.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses both supplied keys without opening the session. Loaded records, session and save path
     * remain unchanged: adopt `next` and reload before decryption. Unsaved edits and deletions do
     * not affect this operation. Verification opens platform packets; it does not reopen the new
     * credential packets.
     *
     * @param path Need not match vaultPath().
     * @return On-disk record count.
     * @throw std::runtime_error On authentication, I/O or verification failure; the file is
     *        unchanged.
     */
    size_t rekey(const std::filesystem::path& path,
                 const SecureWide& current,
                 const SecureWide& next);

private:
    std::vector<VaultRecord> m_Records;  ///< All records, soft-deleted ones included.
    /// Mutable because logically const decryption drives the session DPAPI cycle.
    mutable seal::CredentialSession m_Session;
    uint64_t m_Generation = 0;  ///< Mutation counter; save-time compaction does not advance it.
    /// Save destination; load() adopts its supplied path only on success.
    std::filesystem::path m_VaultPath;
};

}  // namespace seal
