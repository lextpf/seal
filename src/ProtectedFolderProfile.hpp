#pragma once

#include "CryptoConfig.hpp"
#include "SecureString.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace seal
{

/// required profile identity; policy also protects its .tmp staging sibling.
inline constexpr std::wstring_view kProtectedFolderProfileFileName = L".seal-folder-profile";

/**
 * @enum ProtectedFolderProfileState
 * @brief structural state after bounded inspection without key derivation.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * frames are 41..4096 bytes and end immediately after the digest. the unkeyed SHA-256 detects
 * corruption; the embedded packet's GCM tag authenticates it.
 *
 * @verbatim
 *   +--------+---------+------------+--------------------+--------------+
 *   | "SFP1" | ver = 1 | len (BE32) | AES-256-GCM packet | SHA-256 (32) |
 *   |  4 B   |   1 B   |    4 B     |      len bytes     |  of packet   |
 *   +--------+---------+------------+--------------------+--------------+
 * @endverbatim
 */
enum class ProtectedFolderProfileState
{
    Missing,  ///< no file at the path.
    Valid,    ///< frame, checksum and packet header all parsed.
    Invalid,  ///< present but unusable; see the paired message.
};

/**
 * @struct ProtectedFolderProfileInspection
 * @brief outcome of a structural profile inspection.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct ProtectedFolderProfileInspection
{
    /// structural verdict.
    ProtectedFolderProfileState state = ProtectedFolderProfileState::Missing;
    /**
     * english explanation for the user. empty when `state` is `Valid`; set on
     * every other verdict, including `Missing`.
     */
    std::string message;
};

/**
 * @enum ProtectedFolderProfileVerification
 * @brief distinguish a password retry from an invalid profile.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * WrongPassword depends on the crypto error prefix "Authentication failed"; keep that contract
 * aligned with Cryptography.cpp.
 */
enum class ProtectedFolderProfileVerification
{
    Verified,       ///< the password decrypted the profile and the verifier matched.
    WrongPassword,  ///< the frame is sound but GCM authentication failed.
    Missing,        ///< no file at the path.
    Invalid,        ///< structurally unusable, or the decrypted verifier did not match.
};

/**
 * @struct ProtectedFolderProfileVerifyResult
 * @brief outcome of a password verification against a profile.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct ProtectedFolderProfileVerifyResult
{
    ProtectedFolderProfileVerification result =
        ProtectedFolderProfileVerification::Invalid;  ///< verification verdict.
    /// english explanation for the user. empty when `result` is `Verified`.
    std::string message;
};

/**
 * locked wide password. scrypt hashes raw wchar_t bytes;
 * a narrow container with the same text derives a different key.
 */
using ProtectedFolderPassword = basic_secure_string<wchar_t, locked_allocator<wchar_t>>;

/**
 * @brief inspect structure, checksum and KDF limits without deriving a key.
 * @ingroup Vault
 *
 * rejects reparse points, non-regular files, sizes outside 41..4096 bytes and malformed frames.
 *
 * @return `Missing` for absent paths, `Valid` with an empty message, otherwise `Invalid` with a
 *         reason.
 * @note all exceptions become `Invalid`.
 */
[[nodiscard]] ProtectedFolderProfileInspection inspectProtectedFolderProfile(
    const std::filesystem::path& profilePath) noexcept;

/**
 * @brief authenticate a profile's fixed verifier after structural inspection.
 * @ingroup Vault
 *
 * profiles contain no password, credentials or folder payload.
 *
 * @return `Missing`/`Invalid` for failed inspection, `WrongPassword` for GCM failure, `Invalid` for
 *         unexpected plaintext, otherwise `Verified` with an empty message.
 * @note all exceptions become `Invalid`.
 * @warning derives one key with the profile's parameters; default cost is 64 MiB. run off the UI
 *          thread. structural rejection returns before derivation.
 */
[[nodiscard]] ProtectedFolderProfileVerifyResult verifyProtectedFolderProfile(
    const std::filesystem::path& profilePath, const ProtectedFolderPassword& password) noexcept;

/**
 * @brief create a durable profile without replacing occupied paths.
 * @ingroup Vault
 *
 * destination and deterministic .tmp staging probes fail closed, including reparse points.
 * CREATE_NEW prevents staging races; write-through rename commits the file. the hidden attribute
 * is presentation only.
 *
 * @param profilePath must use kProtectedFolderProfileFileName under an existing directory.
 * @param password must not be empty.
 * @param errorMessage optional; written only on false, including std::exception text.
 * @param kdf saved in the packet for verification; one derivation runs at this cost.
 * @return true only after durable commit.
 * @post false preserves the destination and removes only staging created by this call.
 * @warning use a worker thread for default KDF parameters.
 */
[[nodiscard]] bool createProtectedFolderProfile(
    const std::filesystem::path& profilePath,
    const ProtectedFolderPassword& password,
    std::string* errorMessage = nullptr,
    const cfg::KdfParams& kdf = cfg::DEFAULT_KDF) noexcept;

/**
 * @brief replace a live profile only after its new frame is durable.
 * @ingroup Vault
 *
 * requires an existing destination; other constraints match createProtectedFolderProfile.
 * uses MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH after staging and flush.
 *
 * @param password non-empty replacement password.
 * @param errorMessage optional; written only on false, including std::exception text.
 * @param kdf recorded in the new packet; one derivation runs at this cost.
 * @return true only after durable commit.
 * @post false preserves the old profile and removes staging created by this call.
 * @warning use a worker thread for default KDF parameters (64 MiB).
 */
[[nodiscard]] bool replaceProtectedFolderProfile(
    const std::filesystem::path& profilePath,
    const ProtectedFolderPassword& password,
    std::string* errorMessage = nullptr,
    const cfg::KdfParams& kdf = cfg::DEFAULT_KDF) noexcept;

}  // namespace seal
