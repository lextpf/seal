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
 * All domain operations (add, edit, delete, load, save, rekey, decrypt) open
 * their own CredentialSession::Access window, throw std::runtime_error on
 * access failure or crypto error, and bump the generation counter on any
 * change so consumers can detect staleness.
 *
 * This class is not internally synchronised.  All calls must occur on the
 * owning thread.
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
     * @return true when the session holds a password.
     */
    bool isPasswordSet() const noexcept;

    /**
     * @brief Adopt a new master password.
     * @param pw Master password to take ownership of.
     */
    void adoptPassword(SecureWide&& pw);

    /**
     * @brief Wipe the master key and return to the unset state.
     */
    void clearPassword();

    /**
     * @brief Return a reference to the underlying CredentialSession.
     *
     * Transitional accessor used by FillController::arm and similar callers
     * that need to open their own Access window (Phase 3 will narrow this).
     *
     * @return Reference to the session.
     */
    CredentialSession& session() noexcept;

    // --- records (read) ---

    /**
     * @brief All vault records including soft-deleted ones.
     * @return Const reference to the internal records vector.
     */
    const std::vector<VaultRecord>& records() const noexcept;

    /**
     * @brief Monotonically increasing counter, bumped on every mutating operation.
     *
     * Returns a reference to the live counter so borrowed-pointer holders
     * (VaultListModel, FillController) can observe mutations through a stable
     * `const uint64_t*`.
     *
     * @return Const reference to the current generation number.
     */
    const uint64_t& generation() const noexcept;

    /**
     * @brief Whether the workspace holds no records.
     * @return true when records() is empty.
     */
    bool empty() const noexcept;

    /**
     * @brief Count of non-deleted records.
     * @return Number of records where deleted == false.
     */
    size_t recordCount() const noexcept;

    // --- vault path ---

    /**
     * @brief The path to the vault file used by save() and load().
     * @return Current vault path (may be empty before setVaultPath is called).
     */
    const std::filesystem::path& vaultPath() const noexcept;

    /**
     * @brief Set the vault file path used by subsequent save() calls.
     * @param path Absolute or relative path to the target vault file.
     */
    void setVaultPath(std::filesystem::path path);

    // --- domain ops ---

    /**
     * @brief Encrypt and append a new credential record.
     *
     * Opens an Access window, encrypts the credential, appends it, and bumps
     * the generation counter.
     *
     * @param platform Platform/service name (UTF-8).
     * @param username Username in secure locked memory.
     * @param password Password in secure locked memory.
     * @throw std::runtime_error when the session is unset, the Access window
     *        fails, or OpenSSL encryption fails.
     */
    void addRecord(const std::string& platform,
                   const SecureWide& username,
                   const SecureWide& password);

    /**
     * @brief Re-encrypt an existing record, optionally replacing fields.
     *
     * When @p username or @p password is nullptr the current value is decrypted
     * and reused.  The record is replaced with a freshly encrypted packet and
     * the generation is bumped.
     *
     * @param index    Zero-based index into records().
     * @param platform New platform name (UTF-8).
     * @param username New username, or nullptr to keep the current value.
     * @param password New password, or nullptr to keep the current value.
     * @throw std::runtime_error when the session is unset, the Access window
     *        fails, the index is out of range, or crypto fails.
     */
    void editRecord(size_t index,
                    const std::string& platform,
                    const SecureWide* username,
                    const SecureWide* password);

    /**
     * @brief Soft-delete a record and mark it dirty.
     *
     * The record remains in records() until the next save(), which omits
     * deleted records and then erases them from the vector.
     *
     * @param index Zero-based index into records().
     * @throw std::runtime_error when @p index is out of range.
     */
    void markDeleted(size_t index);

    /**
     * @brief Unload all records (password is retained).
     *
     * Clears the records vector and bumps the generation.
     */
    void clearRecords();

    /**
     * @brief Replace the record list after an off-thread load completes.
     *
     * Moves @p records into the workspace and bumps the generation.
     *
     * @param records Newly loaded records to adopt.
     */
    void replaceRecords(std::vector<VaultRecord>&& records);

    /**
     * @brief Decrypt a single record on demand.
     *
     * Opens an Access window, delegates to decryptCredentialOnDemand, and
     * returns the result.  The caller must call cleanse() immediately after use.
     *
     * @param index Zero-based index into records().
     * @return Decrypted credential in locked memory.
     * @throw std::runtime_error when the session is unset, Access fails, the
     *        index is out of range, or the ciphertext is corrupt.
     */
    DecryptedCredential decrypt(size_t index) const;

    // --- persistence ---

    /**
     * @brief Load and decrypt the vault index from @p path.
     *
     * Opens an Access window, clones the password to a local buffer, calls
     * loadVaultIndex, then replaceRecords.  The vault path is updated to
     * @p path on success.
     *
     * @param path Path to the vault file.
     * @throw std::runtime_error on wrong password, corrupt file, or I/O error.
     */
    void load(const std::filesystem::path& path);

    /**
     * @brief Save all non-deleted records to vaultPath().
     *
     * Opens an Access window and calls saveVault.  On success, clears the
     * dirty flag on all records and erases soft-deleted records.  Does not
     * bump the generation (contents are unchanged).
     *
     * @return true on success, false on I/O error.
     * @throw std::runtime_error when the session is unset or Access fails.
     */
    bool save();

    /**
     * @brief Re-encrypt the vault at @p path with a new master password.
     *
     * Delegates entirely to rekeyVault.  Password adoption and reload are the
     * caller's responsibility.
     *
     * @param path    Path to the vault file.
     * @param current Current master password.
     * @param next    Replacement master password.
     * @return Number of records re-encrypted.
     * @throw std::runtime_error on wrong password, I/O failure, or
     *        verification mismatch.
     */
    size_t rekey(const std::filesystem::path& path,
                 const SecureWide& current,
                 const SecureWide& next);

private:
    std::vector<VaultRecord> m_Records;
    mutable seal::CredentialSession m_Session;
    uint64_t m_Generation = 0;
    std::filesystem::path m_VaultPath;
};

}  // namespace seal
