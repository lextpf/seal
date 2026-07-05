#pragma once

#include <filesystem>
#include <string>

namespace seal
{

/**
 * @brief Generate a random password of the given length and copy to clipboard.
 * @ingroup CLI
 * @param length Desired password length (clamped to 8..128).
 * @return 0 on success.
 */
int HandleGenMode(int length);

/**
 * @brief Securely shred (overwrite + delete) a file.
 * @ingroup CLI
 * @param path Filesystem path to the file to shred.
 * @return 0 on success, 1 if the file is not found or shredding fails.
 */
int HandleShredMode(const std::string& path);

/**
 * @brief Compute and print the SHA-256 hash of a file.
 * @ingroup CLI
 * @param path Filesystem path to the file to hash.
 * @return 0 on success, 1 if the file is not found or hashing fails.
 */
int HandleHashMode(const std::string& path);

/**
 * @brief Verify a password against an encrypted file.
 * @ingroup CLI
 * @param path Filesystem path to the encrypted file.
 * @return 0 if the password is correct, 1 on wrong password or error.
 */
int HandleVerifyMode(const std::string& path);

/**
 * @brief Clear the clipboard and console buffer.
 * @ingroup CLI
 * @return 0 on success.
 */
int HandleWipeMode();

/**
 * @brief Change the master password of a vault file in place (atomic).
 * @ingroup CLI
 *
 * Prompts (no echo) for the current password, then for the new password
 * twice. Delegates to seal::rekeyVault: the original file is replaced
 * only after the re-encrypted temp vault verifies with the new password.
 *
 * @param path Filesystem path to the `.seal` vault.
 * @return 0 on success, 1 on wrong password, mismatch, or I/O error.
 */
int HandleRekeyMode(const std::string& path);

/**
 * @brief Validate the seal-get field/output flag combination.
 * @ingroup CLI
 * @param field    One of "pass", "user", "both".
 * @param toStdout True when --stdout was passed.
 * @return `true` for a usable combination ("both" requires --stdout).
 *
 * @par Validity
 * | @p field | @p toStdout | valid |
 * |---|---|---|
 * | `pass` or `user` | any | yes |
 * | `both` | true | yes |
 * | `both` | false | no |
 * | anything else | any | no |
 */
bool GetOptionsValid(const std::string& field, bool toStdout);

/**
 * @brief Clamp the --ttl value to the supported range [1, 600] seconds.
 * @ingroup CLI
 * @param requested Raw user-supplied seconds value.
 * @return The clamped TTL in seconds.
 */
int ClampGetTtlSeconds(int requested);

/**
 * @brief List platform names of a vault, one per line on stdout.
 * @ingroup CLI
 *
 * Decrypts only the vault index (credentials stay encrypted). The
 * password is prompted without echo. Names go to stdout; diagnostics
 * and the record count go to stderr.
 *
 * @param vaultPathArg Vault path, or empty to use findDefaultVault().
 * @return 0 on success, 1 on wrong password / missing vault / I/O error.
 */
int HandleListMode(const std::string& vaultPathArg);

/**
 * @brief Retrieve one credential field from a vault.
 * @ingroup CLI
 *
 * Matches @p platformQuery case-insensitively (exact, then unique
 * prefix). Default delivery copies the secret to the clipboard with a
 * TTL scrub and prints a notice to stderr; `--stdout` prints the raw
 * value (and nothing else) to stdout instead.
 *
 * @param platformQuery Platform name or unique prefix.
 * @param vaultPathArg  Vault path, or empty to use findDefaultVault().
 * @param field         "pass" (default), "user", or "both".
 * @param toStdout      Print to stdout instead of clipboard.
 * @param ttlSeconds    Clipboard scrub delay (clamped to [1, 600]).
 * @return 0 found and delivered; 1 on invalid options, password, vault,
 *         clipboard, or I/O error; 2 not found / ambiguous.
 *
 * @par Return codes
 * | Code | Meaning |
 * |---|---|
 * | 0 | Credential found and delivered (stdout or clipboard) |
 * | 1 | Invalid options, wrong password, missing vault, clipboard or I/O error |
 * | 2 | Platform not found, or an ambiguous prefix match |
 *
 * @par Field delivery
 * | @p field | `--stdout` | default (clipboard) |
 * |---|---|---|
 * | `pass` | password to stdout | password to clipboard (TTL) |
 * | `user` | username to stdout | username to clipboard (TTL) |
 * | `both` | username + TAB + password | rejected (requires `--stdout`) |
 */
int HandleGetMode(const std::string& platformQuery,
                  const std::string& vaultPathArg,
                  const std::string& field,
                  bool toStdout,
                  int ttlSeconds);

/**
 * @brief Encrypt a file to a new destination.
 * @ingroup CLI
 * @param inputPath  Source file to encrypt.
 * @param outputPath Destination path (default: inputPath + ".seal").
 * @return 0 on success, 1 on error.
 * @note On success the original @p inputPath is deleted after the output is written.
 */
int HandleFileEncrypt(const std::string& inputPath, const std::string& outputPath);

/**
 * @brief Decrypt a file to a new destination.
 * @ingroup CLI
 * @param inputPath  Encrypted source file.
 * @param outputPath Destination path (default: strip ".seal" extension).
 * @return 0 on success, 1 on error.
 * @note On success the original @p inputPath is deleted after the output is written.
 */
int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath);

/**
 * @brief Encrypt or decrypt a string with hex/base64 auto-detection.
 * @ingroup CLI
 *
 * In encrypt mode, outputs both hex and base64 representations.
 * In decrypt mode, auto-detects the input format: hex is tried first
 * (even length, at least 4 digits, all hex), then base64.
 *
 * @par Decrypt auto-detection
 * @verbatim
 * input (after stdin read + trailing CR/LF trim)
 *   |
 *   +-- len % 2 == 0  AND  len >= 4  AND  all hex digits
 *   |        -> treat as hex  (decryptLine)
 *   |
 *   +-- else, valid base64
 *   |        -> decode, then decryptPacket
 *   |
 *   +-- else
 *            -> fail: reason=invalid_encoding
 * @endverbatim
 * Hex characters are a base64 subset, so the stricter hex test runs first to
 * keep the more specific format from being misread as base64.
 *
 * @param encryptMode `true` to encrypt plaintext to hex/base64,
 *                    `false` to decrypt hex or base64 to plaintext.
 * @param inlineData  Input string (if empty, reads from stdin).
 * @return 0 on success, 1 on error.
 */
int HandleStringMode(bool encryptMode, const std::string& inlineData);

/**
 * @brief Register the seal-browser native-messaging manifest in HKCU.
 * @ingroup CLI
 *
 * Writes Chrome and Brave NativeMessagingHosts registry entries pointing at
 * a generated com.seal.fill.json alongside seal.exe. Prints the unpacked-
 * extension folder path (also copied to the clipboard) so the user can load
 * it via chrome://extensions or brave://extensions in developer mode.
 *
 * @return 0 on success, 1 on failure (module path unavailable,
 *         seal-browser.exe missing, or manifest write failure).
 */
int HandleInstallBrowserExtensionMode();

/**
 * @brief Remove the seal-browser native-messaging manifest from HKCU.
 * @ingroup CLI
 *
 * Deletes only the named registry values; the parent NativeMessagingHosts
 * keys are left in place because other extensions may share them. The
 * generated manifest JSON files on disk are also left for re-install flows.
 *
 * @return 0 on success.
 */
int HandleUninstallBrowserExtensionMode();

/**
 * @brief Shared implementation of the install flow.
 * @ingroup CLI
 *
 * Used by both the CLI subcommand and the AppViewModel QML invocation so the
 * two surfaces stay in lockstep.
 *
 * @param outMessage Optional human-readable status string for the GUI caller.
 * @return 0 on success, 1 on failure (module path unavailable,
 *         seal-browser.exe missing, or manifest write failure).
 */
int installBrowserExtensionInternal(std::string* outMessage);

/**
 * @brief Shared implementation of the uninstall flow. See installBrowserExtensionInternal.
 * @ingroup CLI
 * @param outMessage Optional human-readable status string for the GUI caller.
 * @return 0 on success.
 */
int uninstallBrowserExtensionInternal(std::string* outMessage);

}  // namespace seal
