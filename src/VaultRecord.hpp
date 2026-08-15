#pragma once

#include "Cryptography.hpp"

#include <string>
#include <vector>

namespace seal
{

/**
 * @struct VaultRecord
 * @brief One record in the vault index.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * The platform name and the credential pair are two separate AES-256-GCM
 * packets. Only the platform name is decrypted on load, so the UI can list
 * accounts.
 *
 * This struct is one record; a vault frame wraps N of them.
 *
 * @verbatim
 * File frame, hex-encoded to a single text line on disk:
 *   +---------+---------+---------+-----------+-----------+-----+
 *   | magic   | version | count   | record[0] | record[1] | ... |
 *   | (4)     | (1)     | (4,BE)  |           |           |     |
 *   +---------+---------+---------+-----------+-----------+-----+
 *
 * One record (what this struct serializes to):
 *   +------------+-----------------+------------+-------------------+
 *   | platLen(4) | platform packet | credLen(4) | credential packet |
 *   | BE         | AES-256-GCM     | BE         | AES-256-GCM       |
 *   +------------+-----------------+------------+-------------------+
 * @endverbatim
 *
 * The frame magic "SVH2" is distinct from the per-packet AAD magic "seal"
 * carried inside each AES-256-GCM packet. loadVaultIndex() strips whitespace
 * and hex-decodes the blob before parsing this framing; saveVault() writes it.
 *
 * @par Two-tier decryption lifecycle
 * @code
 * loadVaultIndex()            -> decrypts platform name; leaves credential sealed
 * decryptCredentialOnDemand() -> decrypts credential   -> DecryptedCredential
 * @endcode
 *
 * @see loadVaultIndex, saveVault, encryptCredential
 */
struct VaultRecord
{
    /// Cleartext platform name (in-memory only, UTF-8; decrypted from encryptedPlatform on load).
    /// Deliberately std::string and not secure_string: the vault list view shows platform names
    /// and plain string operations (.find(), .c_str(), fromUtf8) run on them. Locked memory is
    /// reserved for actual secrets: passwords, usernames, and the master key.
    std::string platform;
    std::vector<unsigned char> encryptedPlatform;  ///< AES-256-GCM packet of platform name
    std::vector<unsigned char> encryptedBlob;      ///< AES-256-GCM packet of "username\0password"
    /// Set by encryptCredential() and by workspace mutations; cleared after a
    /// successful save. It does not decide whether the record is written:
    /// saveVault() writes every non-deleted record. It only forces saveVault()
    /// to re-encrypt the platform name instead of reusing encryptedPlatform.
    bool dirty = false;
    /// Soft-deleted: skipped by saveVault() and by the list model. The record
    /// stays in memory, with both packets intact, until a successful save
    /// drops it from the workspace.
    bool deleted = false;
};

/**
 * @struct DecryptedCredential
 * @brief Temporary holder for a decrypted credential pair.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Both fields live in locked, guarded memory. Call cleanse(), or let the
 * destructor run, immediately after use. The struct is move-only, because
 * basic_secure_string deletes its copy operations.
 *
 * @par Credential packet plaintext (inside the AES-256-GCM blob)
 * @verbatim
 *   +-------------------+------+-------------------+
 *   | username (UTF-8)  | 0x00 | password (UTF-8)  |
 *   +-------------------+------+-------------------+
 *                   one NUL separator
 * @endverbatim
 * A blob with no NUL is rejected as malformed; a NUL at the very end yields
 * an empty password field.
 *
 * @see decryptCredentialOnDemand
 */
struct DecryptedCredential
{
    /// Username, converted from the packet's UTF-8 bytes to UTF-16.
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> username;
    /// Password, converted from the packet's UTF-8 bytes to UTF-16.
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> password;

    /**
     * @brief Wipe both fields and release their locked pages.
     *
     * Each field is flipped to read-write, zeroed, and cleared. The call is
     * idempotent and leaves the object usable but empty, so the destructor
     * repeats no work.
     */
    void cleanse();
};

}  // namespace seal
