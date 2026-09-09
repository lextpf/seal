#pragma once

#include "Cryptography.hpp"

#include <string>
#include <vector>

namespace seal
{

/**
 * @struct VaultRecord
 * @brief Indexed platform name with separately sealed credentials.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * The frame magic is SVH2; each AES-256-GCM packet uses seal as its AAD magic.
 * Packets authenticate their own payloads. The outer record count, ordering and association
 * between platform and credential packets have no shared authentication tag.
 * loadVaultIndex() removes whitespace and hex-decodes the frame; saveVault() writes it.
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
 * @code{.text}
 * loadVaultIndex()            -> decrypts platform name; leaves credential sealed
 * decryptCredentialOnDemand() -> decrypts credential   -> DecryptedCredential
 * @endcode
 */
struct VaultRecord
{
    /// UTF-8 display name; pageable storage reserves locked pages for credential secrets.
    std::string platform;
    std::vector<unsigned char> encryptedPlatform;  ///< AES-256-GCM packet of platform name
    std::vector<unsigned char> encryptedBlob;      ///< AES-256-GCM packet of "username\0password"
    /// Forces platform re-encryption on save; credentials are always copied verbatim.
    bool dirty = false;
    /// Hidden until a successful save removes it and its packets from the workspace.
    bool deleted = false;
};

/**
 * @struct DecryptedCredential
 * @brief Hold a credential pair in locked, guarded memory until use completes.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Vault
 *
 * Call cleanse() or let destruction wipe both fields immediately after use. Page locking is
 * best-effort, and these fields are plaintext until wiped; this type adds no DPAPI protection.
 * Packet plaintext requires a NUL separator; a final NUL permits an empty password.
 *
 * @verbatim
 *   +-------------------+------+-------------------+
 *   | username (UTF-8)  | 0x00 | password (UTF-8)  |
 *   +-------------------+------+-------------------+
 *                   one NUL separator
 * @endverbatim
 */
struct DecryptedCredential
{
    /// Username, converted from the packet's UTF-8 bytes to UTF-16.
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> username;
    /// Password, converted from the packet's UTF-8 bytes to UTF-16.
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> password;

    /**
     * @fn void cleanse()
     * @brief Wipe both fields and release locked pages; repeated calls are safe.
     * @author Alex (<https://github.com/lextpf>)
     */
    void cleanse();
};

}  // namespace seal
