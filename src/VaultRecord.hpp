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
 * Both platform name and credential pair are individually encrypted
 * as separate AES-256-GCM packets.  The cleartext platform is held
 * in memory only (decrypted on load) so the UI can list accounts.
 *
 * On-disk framing (this struct is one record; a vault frame wraps N of them):
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
 * @par Credential packet plaintext (inside the AES-256-GCM blob)
 * @verbatim
 *   +-------------------+------+-------------------+
 *   | username (UTF-8)  | 0x00 | password (UTF-8)  |
 *   +-------------------+------+-------------------+
 *                        one NUL separator
 * @endverbatim
 * A blob with no NUL is rejected as malformed; a NUL at the very end yields
 * an empty password field.
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

}  // namespace seal
