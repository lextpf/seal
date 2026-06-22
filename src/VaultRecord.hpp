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

}  // namespace seal
