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
 * @brief Qt-free core that owns the vault records, session, and vault path.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Domain operations that need the master key (addRecord, editRecord, decrypt,
 * load, save) open their own short-lived CredentialSession::Access window and
 * throw std::runtime_error on access failure or crypto error. markDeleted,
 * clearRecords and replaceRecords need no key. rekey() takes both the current
 * and the next password as parameters and never opens the session.
 *
 * records() and generation() hand out references that stay valid for the
 * lifetime of the object, so the workspace must outlive every borrower. Copy is
 * deleted and no move is declared: the session's DPAPI guard points into the
 * session, so the object must keep one address.
 *
 * @par Ownership and borrowing
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
 * @par Access window and generation counter per operation
 * | Operation      | Opens Access | Bumps generation         |
 * |----------------|--------------|--------------------------|
 * | addRecord      | yes          | yes                      |
 * | editRecord     | yes          | yes                      |
 * | decrypt        | yes          | no (logically const)     |
 * | markDeleted    | no           | yes                      |
 * | clearRecords   | no           | yes                      |
 * | replaceRecords | no           | yes                      |
 * | load           | yes          | yes (via replaceRecords) |
 * | save           | yes          | no                       |
 * | rekey          | no           | no                       |
 *
 * The mutators bump the monotonic generation counter so borrowed-pointer
 * consumers (VaultListModel, FillController) detect staleness without locks.
 * save() and rekey() deliberately do not: rekey() rewrites the on-disk vault
 * without touching the loaded records, and save() only clears dirty flags and
 * erases records the views already hide.
 *
 * @warning That erase shifts the index of every record behind a removed one
 *          while the generation stays put, so no borrowed view can detect it.
 *          The owner must rebuild its views after each successful save()
 *          (AppViewModel::saveVault calls refreshModel()).
 *
 * @note Not internally synchronised. All calls must occur on the owning thread.
 */
class CredentialWorkspace
{
public:
    /// Convenience alias matching CredentialSession's own alias.
    using SecureWide = CredentialSession::SecureWide;

    /// @brief Construct an empty workspace with no password and no records.
    CredentialWorkspace() = default;

    CredentialWorkspace(const CredentialWorkspace&) = delete;
    CredentialWorkspace& operator=(const CredentialWorkspace&) = delete;

    // --- session ---

    /**
     * @brief Whether a master password is currently held.
     * @return true when the session holds a password. A true result does not
     *         promise that the key can be unprotected; the domain operations
     *         still throw when their Access window fails.
     */
    bool isPasswordSet() const noexcept;

    /**
     * @brief Adopt a new master password.
     *
     * Wipes any previous key. The records already loaded are not re-encrypted
     * and stay bound to the old key, so adopting a different password without a
     * matching load() or rekey() makes every decrypt fail the GCM tag check.
     *
     * @param pw Master password to take ownership of; left empty on return.
     * @pre No CredentialSession::Access window is open on session().
     */
    void adoptPassword(SecureWide&& pw);

    /**
     * @brief Wipe the master key and return to the unset state.
     *
     * The records are kept. Every operation that needs the key throws until the
     * next adoptPassword().
     *
     * @pre No CredentialSession::Access window is open on session().
     */
    void clearPassword();

    /**
     * @brief Reference to the underlying CredentialSession.
     *
     * Escape hatch for collaborators that open their own Access window:
     * FillController borrows the session through arm()/armAuto() and opens a
     * window at its just-in-time decrypt. A caller holding a window open must
     * not call the domain operations from inside it; Access windows do not
     * nest, so the inner window would report `ok() == false`.
     *
     * @return Reference valid for the lifetime of the workspace.
     */
    CredentialSession& session() noexcept;

    // --- records (read) ---

    /**
     * @brief All vault records, soft-deleted ones included.
     *
     * editRecord(), markDeleted() and decrypt() index into this vector.
     *
     * @return Const reference to the internal records vector. The reference
     *         stays valid for the lifetime of the workspace, but the elements
     *         move on any mutation, so hold the vector, never an element
     *         pointer.
     */
    const std::vector<VaultRecord>& records() const noexcept;

    /**
     * @brief Monotonic counter, bumped on each successful mutation.
     *
     * Returns a reference to the live counter so borrowed-pointer holders
     * (VaultListModel, FillController) observe mutations through a stable
     * `const uint64_t*`.
     *
     * @par Staleness check (owning thread)
     * @code{.cpp}
     * const uint64_t* gen = &workspace.generation();  // stable address
     * uint64_t seen = *gen;
     * // ... after any mutator runs on the owning thread ...
     * if (*gen != seen)  // a mutation happened: rebuild the borrowed view
     * {
     *     seen = *gen;
     *     refreshFrom(workspace.records());
     * }
     * @endcode
     *
     * @return Const reference to the current generation number. The address is
     *         stable for the lifetime of the workspace; the value starts at 0,
     *         never decreases, and never moves on a failed operation.
     * @note save() mutates the records without bumping this counter. See the
     *       class warning.
     */
    const uint64_t& generation() const noexcept;

    /**
     * @brief Whether the workspace holds no records.
     * @return true when records() is empty. Soft-deleted records still count,
     *         so this can be false while recordCount() is 0.
     */
    bool empty() const noexcept;

    /**
     * @brief Count of non-deleted records.
     *
     * Linear scan over records(); cost is O(records).
     *
     * @return Number of records where deleted == false.
     */
    size_t recordCount() const noexcept;

    // --- vault path ---

    /**
     * @brief The path to the vault file written by save().
     *
     * load() ignores this path, takes its own, and adopts it on success;
     * rekey() ignores it entirely.
     *
     * @return Current vault path, empty until setVaultPath() or a successful
     *         load().
     */
    const std::filesystem::path& vaultPath() const noexcept;

    /**
     * @brief Set the vault file path used by subsequent save() calls.
     *
     * Records and the session are untouched, and no file is created here.
     *
     * @param path Target vault file; absolute or relative.
     */
    void setVaultPath(std::filesystem::path path);

    // --- domain ops ---

    /**
     * @brief Encrypt and append a new credential record.
     *
     * Opens an Access window, encrypts the credential, appends it, and bumps
     * the generation counter. The new record lands at index
     * `records().size() - 1`, is marked dirty, and reaches disk only on the
     * next save(). Nothing checks for a duplicate platform name.
     *
     * @param platform Platform/service name (UTF-8). Stored in cleartext in
     *                 memory and encrypted as its own packet.
     * @param username Username in locked memory.
     * @param password Password in locked memory.
     * @throw std::runtime_error when the session is unset, the Access window
     *        fails, or OpenSSL encryption fails. On a throw the record list and
     *        the generation are unchanged.
     */
    void addRecord(const std::string& platform,
                   const SecureWide& username,
                   const SecureWide& password);

    /**
     * @brief Re-encrypt an existing record, optionally replacing fields.
     *
     * A nullptr @p username or @p password means "keep the current value": it
     * is decrypted and reused, then cleansed before returning; its destructor
     * wipes it when the re-encrypt throws instead.
     *
     * The record is replaced wholesale with a freshly encrypted packet (new
     * salt and IV), so it becomes dirty, and a soft-deleted record edited this
     * way comes back as not deleted. The generation is bumped.
     *
     * @param index    Zero-based index into records().
     * @param platform New platform name (UTF-8); it is always rewritten, so
     *                 pass the current name to keep it.
     * @param username New username, or nullptr to keep the current value.
     * @param password New password, or nullptr to keep the current value.
     * @throw std::runtime_error when @p index is out of range (checked before
     *        the Access window opens), when the session is unset, when the
     *        Access window fails, or when crypto fails.
     */
    void editRecord(size_t index,
                    const std::string& platform,
                    const SecureWide* username,
                    const SecureWide* password);

    /**
     * @brief Soft-delete a record and mark it dirty.
     *
     * The record keeps its index in records() until the next successful save(),
     * which omits deleted records from the file and then erases them from the
     * vector. recordCount() drops immediately; empty() does not.
     *
     * @param index Zero-based index into records().
     * @throw std::runtime_error when @p index is out of range.
     */
    void markDeleted(size_t index);

    /**
     * @brief Unload all records; the password is retained.
     *
     * Clears the records vector and bumps the generation. Nothing is written to
     * disk, so unsaved edits are lost and vaultPath() still points at the old
     * file.
     */
    void clearRecords();

    /**
     * @brief Replace the record list after an off-thread load completes.
     *
     * Moves @p records into the workspace and bumps the generation. Every index
     * handed out earlier is invalid afterwards.
     *
     * @param records Newly loaded records to adopt; left in a moved-from state.
     */
    void replaceRecords(std::vector<VaultRecord>&& records);

    /**
     * @brief Decrypt a single record on demand.
     *
     * Opens an Access window, delegates to decryptCredentialOnDemand, and
     * returns the result. The caller must call cleanse() right after use, or
     * let the result destruct; both wipe the locked pages. Logically const, but
     * it drives the session's DPAPI unprotect/re-protect cycle, so it must not
     * run inside an Access window the caller already holds.
     *
     * @param index Zero-based index into records(), soft-deleted entries
     *              included.
     * @return Decrypted credential in locked memory.
     * @throw std::runtime_error when @p index is out of range (checked before
     *        the Access window opens), when the session is unset, when Access
     *        fails, or when the ciphertext fails its GCM tag check.
     */
    DecryptedCredential decrypt(size_t index) const;

    // --- persistence ---

    /**
     * @brief Load the vault at @p path and decrypt its platform names.
     *
     * Opens an Access window, clones the password into a local buffer, closes
     * the window, then calls loadVaultIndex and replaceRecords. The clone is
     * cleansed on success and on failure. Each credential stays sealed until
     * decrypt(). The load replaces the whole record list, so every index handed
     * out earlier is invalid. vaultPath() moves to @p path on success only.
     *
     * @param path Path to the vault file.
     * @throw std::runtime_error when the session is unset, when the Access
     *        window fails, and on wrong password, corrupt file, or I/O error.
     *        On a throw the records, the vault path and the generation are
     *        unchanged.
     */
    void load(const std::filesystem::path& path);

    /**
     * @brief Save all non-deleted records to vaultPath().
     *
     * Opens an Access window and calls saveVault, which writes a temp file and
     * renames it over the target. On success it clears the dirty flag on every
     * record and erases the soft-deleted ones. It does not bump the generation,
     * even though that erase renumbers the records behind each removed one; see
     * the class warning. On failure no record is modified.
     *
     * @pre vaultPath() names the target file; save() never prompts for one.
     *      An empty path is not diagnosed here: the write then fails and this
     *      returns false.
     * @return true on success; false when saveVault reports an I/O error or a
     *         field length or record count that overflows the 32-bit on-disk
     *         fields.
     * @throw std::runtime_error when the session is unset, when Access fails,
     *        or when re-encrypting a dirty platform name fails.
     */
    bool save();

    /**
     * @brief Re-encrypt the vault at @p path with a new master password.
     *
     * Delegates entirely to rekeyVault, which re-reads the file, re-encrypts
     * every record under @p next, and swaps the result in atomically. The
     * session, the loaded records and vaultPath() are untouched, and no
     * password needs to be held: both keys arrive as parameters. The loaded
     * records therefore still belong to @p current after a successful rekey, so
     * the caller must adopt @p next and reload before decrypting anything.
     *
     * In-memory state is invisible to this call: rekeyVault works only on the
     * records it reads from disk, and loadVaultIndex never marks a record
     * deleted, so a record that markDeleted() hid but save() has not yet
     * removed is re-encrypted and stays in the file.
     *
     * @param path    Path to the vault file; it need not equal vaultPath().
     * @param current Current master password.
     * @param next    Replacement master password.
     * @return Number of records written to the rekeyed file, which is the
     *         record count the file already held.
     * @throw std::runtime_error on wrong password, I/O failure, or
     *        verification mismatch. The file on disk is then unchanged.
     */
    size_t rekey(const std::filesystem::path& path,
                 const SecureWide& current,
                 const SecureWide& next);

private:
    std::vector<VaultRecord> m_Records;  ///< All records, soft-deleted ones included.
    /// Mutable: the DPAPI unprotect/reprotect cycle mutates the buffer even on
    /// the logically-const decrypt() path.
    mutable seal::CredentialSession m_Session;
    uint64_t m_Generation = 0;  ///< Monotonic mutation counter; never bumped on failure.
    /// Target file for save(); set by setVaultPath() and by a successful
    /// load(). load() itself takes its path as a parameter.
    std::filesystem::path m_VaultPath;
};

}  // namespace seal
