#pragma once

#include "CryptoConfig.hpp"
#include "SecureString.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace seal
{

/// Required file name of a folder profile. The write paths reject any other
/// name, so the profile is always this leading-dot file inside the protected
/// root. Protected-folder policy protects this name and its `.tmp` sibling.
inline constexpr std::wstring_view kProtectedFolderProfileFileName = L".seal-folder-profile";

/**
 * @enum ProtectedFolderProfileState
 * @brief Structural state of a protected-folder password profile.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * Inspection does bounded I/O and validates the frame, the checksum and the
 * embedded packet header without deriving a key, so it is cheap enough for any
 * thread.
 *
 * @par On-disk frame
 * @verbatim
 *   +--------+---------+------------+--------------------+--------------+
 *   | "SFP1" | ver = 1 | len (BE32) | AES-256-GCM packet | SHA-256 (32) |
 *   |  4 B   |   1 B   |    4 B     |      len bytes     |  of packet   |
 *   +--------+---------+------------+--------------------+--------------+
 * @endverbatim
 * The frame must be 41 to 4096 bytes and the file must end right after the
 * digest. The digest is an unkeyed integrity check that catches truncation and
 * corruption early; authentication is the packet's own GCM tag.
 */
enum class ProtectedFolderProfileState
{
    Missing,  ///< No file at the path.
    Valid,    ///< Frame, checksum and packet header all parsed.
    Invalid,  ///< Present but unusable; see the paired message.
};

/**
 * @struct ProtectedFolderProfileInspection
 * @brief Outcome of a structural profile inspection.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct ProtectedFolderProfileInspection
{
    /// Structural verdict.
    ProtectedFolderProfileState state = ProtectedFolderProfileState::Missing;
    /// English explanation for the user. Empty when `state` is `Valid`; set on
    /// every other verdict, including `Missing`.
    std::string message;
};

/**
 * @enum ProtectedFolderProfileVerification
 * @brief Password-verification result for a protected-folder profile.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 *
 * `WrongPassword` is separated from `Invalid` so the caller can re-prompt
 * instead of reporting a damaged folder. The split is derived from the crypto
 * layer's `"Authentication failed"` message prefix, so that prefix is a
 * contract between Cryptography.cpp and this file.
 */
enum class ProtectedFolderProfileVerification
{
    Verified,       ///< The password decrypted the profile and the verifier matched.
    WrongPassword,  ///< The frame is sound but GCM authentication failed.
    Missing,        ///< No file at the path.
    Invalid,        ///< Structurally unusable, or the decrypted verifier did not match.
};

/**
 * @struct ProtectedFolderProfileVerifyResult
 * @brief Outcome of a password verification against a profile.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Vault
 */
struct ProtectedFolderProfileVerifyResult
{
    ProtectedFolderProfileVerification result =
        ProtectedFolderProfileVerification::Invalid;  ///< Verification verdict.
    /// English explanation for the user. Empty when `result` is `Verified`.
    std::string message;
};

/// Folder password held in locked, non-pageable memory. scrypt is fed the raw
/// `wchar_t` code-unit bytes, so a narrow container holding the same characters
/// derives a different key and must never be substituted.
using ProtectedFolderPassword = basic_secure_string<wchar_t, locked_allocator<wchar_t>>;

/**
 * @brief Inspect a profile without attempting password verification.
 * @ingroup Vault
 *
 * Reparse points, non-regular files, files outside the 41 to 4096 byte range,
 * malformed frames, checksum failures, and hostile KDF headers are all
 * rejected. No key is derived, so the call is cheap and never blocks on
 * scrypt.
 *
 * @param profilePath Full path to the profile file. It is read, never written.
 * @return `Missing` with a message when nothing is at the path; `Valid` with
 *         an empty message when every structural check passed; `Invalid` with
 *         the first failing check's message otherwise.
 *
 * @note Every exception is caught and reported as `Invalid`.
 */
[[nodiscard]] ProtectedFolderProfileInspection inspectProtectedFolderProfile(
    const std::filesystem::path& profilePath) noexcept;

/**
 * @brief Verify that @p password opens a structurally valid profile.
 * @ingroup Vault
 *
 * The profile contains only an authenticated fixed verifier; it never stores a
 * password, credential, or folder payload. The structural checks of
 * @ref inspectProtectedFolderProfile run first, so a damaged profile is
 * reported without deriving a key.
 *
 * @param profilePath Full path to the profile file. It is read, never written.
 * @param password    Folder password to test.
 * @return `Missing` or `Invalid` for a profile that fails inspection,
 *         `WrongPassword` when GCM authentication fails, `Invalid` when the
 *         decrypted bytes are not the fixed verifier, and `Verified` with an
 *         empty message otherwise.
 *
 * @warning A profile that passes inspection runs one scrypt derivation at
 *          the profile's own KDF parameters. The default cost needs 64 MiB
 *          and blocks the calling thread for about 100 ms on a current
 *          desktop, longer on slower hardware. Never call this on the UI
 *          thread. A `Missing` or `Invalid` result returns before any
 *          derivation runs.
 * @note Every exception is caught and reported as `Invalid`.
 */
[[nodiscard]] ProtectedFolderProfileVerifyResult verifyProtectedFolderProfile(
    const std::filesystem::path& profilePath, const ProtectedFolderPassword& password) noexcept;

/**
 * @brief Atomically create a new protected-folder profile.
 * @ingroup Vault
 *
 * Fails closed when the destination or the deterministic `<profilePath>.tmp`
 * staging path already exists, is a reparse point, or cannot be probed. The
 * staging file is opened with `CREATE_NEW`, which closes the check-then-open
 * race on that fixed name, then written through and renamed onto the
 * destination. The final file is marked hidden on Windows for presentation
 * only; the leading-dot name is the portable identity.
 *
 * @param profilePath  Destination path. Its file name must equal
 *                     seal::kProtectedFolderProfileFileName and its parent
 *                     must be an existing directory.
 * @param password     Folder password. Must not be empty.
 * @param errorMessage Optional sink for an English failure reason. May be
 *                     `nullptr`; it is written only on `false`.
 * @param kdf          Write-side scrypt parameters. They are recorded in the
 *                     packet header, so verification later reuses them.
 * @return `true` only when the profile is durable on disk.
 *
 * @post A `false` return leaves the destination untouched. Any staging file
 *       this call created is deleted; a staging path that was already occupied
 *       is never touched.
 * @warning One scrypt derivation runs at @p kdf cost. Never call this on the
 *          UI thread with the default parameters.
 * @note Every `std::exception` is caught and reported as `false`. In that
 *       case @p errorMessage receives the exception text instead of one of
 *       this file's curated messages, so do not present it as a fixed string.
 */
[[nodiscard]] bool createProtectedFolderProfile(
    const std::filesystem::path& profilePath,
    const ProtectedFolderPassword& password,
    std::string* errorMessage = nullptr,
    const cfg::KdfParams& kdf = cfg::DEFAULT_KDF) noexcept;

/**
 * @brief Atomically replace an existing profile under a new password.
 * @ingroup Vault
 *
 * Used when a loaded credential vault is rekeyed while folder protection is
 * armed. The old profile remains live until the replacement is durable: the
 * new frame is staged and flushed first, then renamed over the destination
 * with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
 *
 * This is the exact mirror of @ref createProtectedFolderProfile: it fails when
 * the destination is missing, where create fails when it is present. Every
 * other precondition, the staging rules and the scrypt cost are identical.
 *
 * @param profilePath  Existing profile to replace. Same name and parent
 *                     requirements as @ref createProtectedFolderProfile.
 * @param password     New folder password. Must not be empty.
 * @param errorMessage Optional sink for an English failure reason. May be
 *                     `nullptr`; it is written only on `false`.
 * @param kdf          Write-side scrypt parameters for the new profile.
 * @return `true` only when the replacement is durable on disk.
 *
 * @post A `false` return leaves the old profile as the live one, under the old
 *       password. Any staging file this call created is deleted.
 * @warning One scrypt derivation runs at @p kdf cost, so the default
 *          parameters need 64 MiB and about 100 ms. Never call this on the UI
 *          thread with the default parameters.
 * @note Every `std::exception` is caught and reported as `false`. In that
 *       case @p errorMessage receives the exception text instead of one of
 *       this file's curated messages, so do not present it as a fixed string.
 */
[[nodiscard]] bool replaceProtectedFolderProfile(
    const std::filesystem::path& profilePath,
    const ProtectedFolderPassword& password,
    std::string* errorMessage = nullptr,
    const cfg::KdfParams& kdf = cfg::DEFAULT_KDF) noexcept;

}  // namespace seal
