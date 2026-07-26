#pragma once

/**
 * @brief argv subcommand handlers for seal.exe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 * Each `Handle*Mode` function implements exactly one argv subcommand and
 * returns the process exit code. The `Mode` switch in main.cpp is the only
 * dispatcher. stdout carries the command payload so the subcommand stays
 * pipeable; prompts and diagnostics go to stderr.
 *
 * The header is Qt-free, and `CliModes.cpp` is the only CLI layer that
 * `seal_tests` compiles.
 *
 * seal has two other command surfaces that share no code with these functions:
 * the `--cli` interactive console (`handleCliMode` in main.cpp) and the
 * embedded GUI terminal panel (`CliDispatch.hpp` and `CliHandler.hpp`, driven
 * by the `Cli` context property). Command names overlap, so read the surface
 * first: `seal gen` here is not the panel's `:gen`.
 */

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace seal::signer
{
enum class BrowserKind;
}

namespace seal
{

/**
 * @enum BrowserRegistrationOutcome
 * @brief Per-browser result of one native-messaging registration change.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 * The install flow produces only the first three values, the uninstall flow
 * only the last three. Every Chromium-family entry of
 * `signer::kBrowserMetadata` yields one row, so a report never omits a browser
 * and its length is stable across runs.
 */
enum class BrowserRegistrationOutcome
{
    Registered,           ///< A registry value was written and none failed.
    SkippedNotInstalled,  ///< Browser not detected; no registry write attempted.
    RegistrationFailed,   ///< A write failed, or no value could be written at all.
    Removed,              ///< A registry value was deleted and none failed.
    AlreadyAbsent,        ///< Nothing to delete; the values were already gone.
    RemovalFailed,        ///< A delete failed for a reason other than "not found".
};

/**
 * @struct BrowserRegistrationResult
 * @brief One browser row in an install or uninstall report.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 */
struct BrowserRegistrationResult
{
    signer::BrowserKind m_Kind{};  ///< Browser this row describes.
    /// Outcome for this browser. The default keeps a row readable when it is
    /// filled in before any registry work runs.
    BrowserRegistrationOutcome m_Outcome = BrowserRegistrationOutcome::SkippedNotInstalled;
    /// Registry values actually written or deleted. Opera has two subkeys
    /// (Stable and GX); every other Chromium browser has one.
    std::size_t m_RegistryValueCount = 0;
};

/**
 * @struct BrowserExtensionInstallReport
 * @brief Structured result of native-host registration and folder discovery.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 * `m_Success` covers only the fatal steps (module path, seal-browser.exe,
 * manifest write). A per-browser registry failure becomes a
 * BrowserRegistrationOutcome::RegistrationFailed row and leaves `m_Success`
 * `true`, so one broken browser cannot hide the browsers that did register.
 */
struct BrowserExtensionInstallReport
{
    bool m_Success = false;  ///< `false` only when a fatal step failed.
    /// Generated `com.seal.fill.json` beside seal.exe. Empty when the module
    /// path or seal-browser.exe could not be resolved.
    std::filesystem::path m_ManifestPath;
    /// Unpacked extension folder the user must load by hand; see
    /// findBrowserExtensionDirectory. Empty after a fatal failure.
    std::filesystem::path m_ExtensionDirectory;
    bool m_ExtensionDirectoryFound = false;   ///< That folder exists on disk.
    bool m_ExtensionDirectoryCopied = false;  ///< That path reached the clipboard.
    /// One row per Chromium-family browser, in `signer::kBrowserMetadata` order.
    std::vector<BrowserRegistrationResult> m_Browsers;
    std::string m_ErrorMessage;  ///< Fatal-step text; empty while m_Success holds.
};

/**
 * @struct BrowserExtensionUninstallReport
 * @brief Structured result of clearing every Chromium-family registration.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 * Values that were already absent count as success, so running the uninstall
 * twice is a no-op that still reports success.
 */
struct BrowserExtensionUninstallReport
{
    bool m_Success = false;  ///< `true` when no registry delete failed.
    /// One row per Chromium-family browser, in `signer::kBrowserMetadata` order.
    std::vector<BrowserRegistrationResult> m_Browsers;
};

/**
 * @brief Generate a random password, print it, and copy it to the clipboard.
 * @ingroup CLI
 *
 * Both deliveries are intentional: the cleartext stdout line makes the command
 * pipeable, the clipboard copy makes it usable interactively.
 *
 * @param length Clamped to [8, 128] by seal::GeneratePassword, so an
 *               out-of-range value never fails the command.
 * @return 0. A clipboard failure is ignored and does not change the result.
 * @note The 6-second clipboard scrub does not run on this path. The process
 *       exits first, and the `Clipboard::shutdown()` guard in main() stops the
 *       pending scrub thread without clearing the clipboard. The password
 *       stays on the clipboard until another application overwrites it or
 *       `seal wipe` runs. The scrub only takes effect in the long-lived GUI
 *       process.
 * @throw std::runtime_error propagated from seal::GeneratePassword when
 *        `RAND_bytes` fails. No handler sits between here and main(), so the
 *        process terminates instead of returning an exit code.
 */
int HandleGenMode(int length);

/**
 * @brief Securely shred (overwrite + delete) a file.
 * @ingroup CLI
 *
 * Delegates to seal::FileOperations::shredFile: three overwrite passes
 * (random, zeros, random), then the delete. There is no password prompt and no
 * confirmation, so the overwrite starts at once. A file of zero length, or one
 * whose size query fails, is deleted without an overwrite pass.
 *
 * @warning The passes use `FILE_FLAG_WRITE_THROUGH`, so each one reaches the
 *          device, but not necessarily the same physical sectors: wear
 *          levelling, copy-on-write filesystems and shadow copies can keep
 *          the old bytes.
 * @return 0 on success, 1 if the file is not found or shredding fails.
 */
int HandleShredMode(const std::string& path);

/**
 * @brief Compute and print the SHA-256 hash of a file.
 * @ingroup CLI
 *
 * Prints `<hex digest>  <path>` to stdout, with two spaces, matching the
 * `sha256sum` layout. The bytes on disk are hashed as they are; an encrypted
 * file is not decrypted first.
 *
 * @return 0 on success, 1 if the file is not found or hashing fails.
 */
int HandleHashMode(const std::string& path);

/**
 * @brief Verify a password against an encrypted file.
 * @ingroup CLI
 *
 * Prompts for the password without echo, then calls
 * seal::Cryptography::verifyPacket, which authenticates the GCM tag in chunks
 * and discards the plaintext. The file is still read into one buffer, so peak
 * memory is the file size and not twice it.
 *
 * @return 0 if the password is correct, 1 on wrong password or error.
 */
int HandleVerifyMode(const std::string& path);

/**
 * @brief Clear the clipboard and console buffer.
 * @ingroup CLI
 *
 * Copies an empty string over the clipboard, then overwrites every cell of
 * the active console screen buffer with spaces. Scrollback retained by the
 * terminal host is outside seal's reach and is not cleared.
 *
 * @return 0. Both steps are best-effort and never fail the command.
 */
int HandleWipeMode();

/**
 * @brief Change the master password of a vault file in place (atomic).
 * @ingroup CLI
 *
 * Appends `.seal` to @p path when the suffix is missing, then prompts (no
 * echo) for the current password and twice for the new one. The two new
 * entries are compared in constant time. An empty new password is rejected
 * before any vault work starts.
 *
 * Delegates to seal::rekeyVault, which replaces the original only after the
 * re-encrypted temp vault verifies with the new password, so a failure at any
 * step leaves the original file untouched.
 *
 * @note seal::rekeyVault skips soft-deleted records, but the soft-delete flag
 *       is GUI session state that is never written to disk. A CLI rekey
 *       therefore re-encrypts every record, and the `record_count` diagnostic
 *       matches the count @ref HandleListMode reports.
 * @return 0 on success, 1 on wrong password, an empty or mismatched new
 *         password, or an I/O error.
 */
int HandleRekeyMode(const std::string& path);

/**
 * @brief Validate the seal-get field/output flag combination.
 * @ingroup CLI
 * @param field    One of "pass", "user", "both". The comparison is exact and
 *                 case-sensitive; "Pass" is not accepted.
 * @param toStdout True when --stdout was passed.
 * @return `true` for a usable combination ("both" requires --stdout).
 *
 * @par Validity
 * |          @p field | @p toStdout | valid |
 * |-------------------|-------------|-------|
 * | `pass` or `user`  | any         | yes   |
 * |            `both` | true        | yes   |
 * |            `both` | false       | no    |
 * |     anything else | any         | no    |
 */
bool GetOptionsValid(const std::string& field, bool toStdout);

/**
 * @brief Clamp the --ttl value to the supported range [1, 600] seconds.
 * @ingroup CLI
 *
 * The result is read only on the clipboard delivery path; `--stdout` ignores it.
 *
 * @param requested Raw user-supplied seconds value.
 * @return The clamped TTL in seconds.
 * @note The clamped value has no observable effect on the one-shot CLI path.
 *       `seal get` exits before the delay elapses, so the scrub never runs and
 *       the value only shapes the stderr notice. See @ref HandleGetMode.
 */
int ClampGetTtlSeconds(int requested);

/**
 * @brief List platform names of a vault, one per line on stdout.
 * @ingroup CLI
 *
 * Decrypts only the vault index; credentials stay encrypted. The password is
 * prompted without echo. Names go to stdout in stored record order (never
 * sorted); diagnostics and the record count go to stderr. `record_count`
 * equals the number of names printed. The deleted-record filter is defensive
 * only: the soft-delete flag is GUI session state, and seal::loadVaultIndex
 * clears it on every record it reads.
 *
 * @param vaultPathArg Vault path; `.seal` is appended when the suffix is
 *                     missing. Empty selects seal::findDefaultVault().
 * @return 0 on success, 1 on wrong password / missing vault / I/O error.
 */
int HandleListMode(const std::string& vaultPathArg);

/**
 * @brief Retrieve one credential field from a vault.
 * @ingroup CLI
 *
 * Matches @p platformQuery case-insensitively through seal::matchPlatform
 * (exact first, then unique prefix). Soft-deleted records keep their slot with
 * a blanked name, so indices stay aligned and a deleted record never matches.
 *
 * Default delivery copies one field to the clipboard and prints a notice to
 * stderr. `--stdout` prints the raw value, and nothing else, to stdout. At
 * most one field ever reaches the clipboard.
 *
 * @warning The stderr notice announces a scrub that this process cannot
 *          perform. The command exits as soon as the copy is made, and the
 *          `Clipboard::shutdown()` guard in main() stops the pending scrub
 *          thread without clearing the clipboard. The value stays on the
 *          clipboard until another application overwrites it or `seal wipe`
 *          runs. The TTL only takes effect in the long-lived GUI process.
 *
 * @param vaultPathArg  Vault path; `.seal` is appended when the suffix is
 *                      missing. Empty selects seal::findDefaultVault().
 * @param field         "pass", "user", or "both"; see @ref GetOptionsValid.
 * @param ttlSeconds    Requested scrub delay (clamped to [1, 600]). It shapes
 *                      only the stderr notice; see the warning above. Unused
 *                      when @p toStdout is `true`.
 * @return 0, 1 or 2; see the return-code table below.
 *
 * @par Return codes
 * | Code | Meaning                                                                |
 * |------|------------------------------------------------------------------------|
 * |    0 | Credential found and delivered (stdout or clipboard)                   |
 * |    1 | Invalid options, wrong password, missing vault, clipboard or I/O error |
 * |    2 | Platform not found, or an ambiguous prefix match                       |
 *
 * @par Field delivery
 * |         @p field | @p toStdout | delivery                                 |
 * |------------------|-------------|------------------------------------------|
 * |           `pass` |       false | password to clipboard (no scrub)         |
 * |           `user` |       false | username to clipboard (no scrub)         |
 * |           `both` |       false | rejected (requires `--stdout`)           |
 * |  `pass`, `user`, |        true | username + TAB + password                |
 */
int HandleGetMode(const std::string& platformQuery,
                  const std::string& vaultPathArg,
                  const std::string& field,
                  bool toStdout,
                  int ttlSeconds);

/**
 * @brief Encrypt a file to a new destination.
 * @ingroup CLI
 *
 * Checks that @p inputPath exists, prompts for the password without echo, then
 * encrypts. The output is written to `<dest>.tmp` and renamed over the
 * destination with `MOVEFILE_REPLACE_EXISTING`, so an existing destination is
 * replaced in one step and a partial file is never left behind.
 *
 * @param outputPath Destination path. Empty selects `inputPath + ".seal"`.
 * @return 0 on success, 1 when the source is missing, the encrypt step
 *         reports failure, or an exception is thrown.
 * @note On success the original @p inputPath is deleted after the output is
 *       written. The delete is best-effort and is not checked, so a locked
 *       source can survive a successful encrypt.
 */
int HandleFileEncrypt(const std::string& inputPath, const std::string& outputPath);

/**
 * @brief Decrypt a file to a new destination.
 * @ingroup CLI
 *
 * Checks that @p inputPath exists, prompts for the password without echo,
 * then decrypts. The output is written to a temporary file and renamed over
 * the destination, exactly as in @ref HandleFileEncrypt.
 *
 * @param outputPath Destination path. Empty strips a trailing `.seal`
 *                   (case-insensitive), or appends `".decrypted"` when the
 *                   source does not end in `.seal`.
 * @return 0 on success, 1 when the source is missing, the password is wrong,
 *         the packet is corrupt, or an exception is thrown. A wrong password
 *         is reported by the decrypt step as a failure, not as an exception,
 *         so the diagnostic carries `reason=decrypt_failed`.
 * @note On success the original @p inputPath is deleted after the output is
 *       written. The delete is best-effort and is not checked.
 */
int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath);

/**
 * @brief Encrypt or decrypt a string with hex/base64 auto-detection.
 * @ingroup CLI
 *
 * The password prompt goes to stderr without echo, so the command stays usable
 * in a pipe. Encrypt mode prints `(hex) ...` and `(b64) ...` lines carrying the
 * same packet in two encodings. Decrypt mode auto-detects the input encoding
 * and prints the plaintext.
 *
 * @par Decrypt auto-detection
 * @verbatim
 * input (inlineData verbatim, or all of stdin with trailing CR/LF trimmed)
 *   |
 *   +-- empty
 *   |        -> fail: reason=no_input
 *   |
 *   +-- len % 2 == 0  AND  len >= 4  AND  all hex digits
 *   |        -> treat as hex  (decryptLine)
 *   |
 *   +-- else, utils::isBase64
 *   |        -> decode, then decryptPacket
 *   |
 *   +-- else
 *           -> fail: reason=invalid_encoding
 * @endverbatim
 * Hex characters are a base64 subset, so the stricter hex test runs first.
 * `utils::isBase64` also rejects pure-hex input, so the two tests can never
 * both claim the same string.
 *
 * @param encryptMode `true` to encrypt plaintext to hex/base64,
 *                    `false` to decrypt hex or base64 to plaintext.
 * @param inlineData  Input string. When empty, all of stdin is read instead
 *                    and its trailing CR/LF characters are trimmed.
 * @return 0 on success, 1 on empty input, an unrecognised encoding, a failed
 *         hex round-trip of the fresh packet, a wrong password, or any thrown
 *         crypto error.
 */
int HandleStringMode(bool encryptMode, const std::string& inlineData);

/**
 * @brief Register the seal-browser native-messaging manifest in HKCU.
 * @ingroup CLI
 *
 * Thin CLI wrapper over @ref installBrowserExtensionInternal with no GUI sinks;
 * that function carries the full contract. It writes NativeMessagingHosts
 * registry values for every detected Chromium-family browser, pointing them at
 * a generated `com.seal.fill.json` beside seal.exe, then prints and copies the
 * unpacked-extension folder path.
 *
 * @return 0 on success, 1 on failure (module path unavailable,
 *         seal-browser.exe missing, or manifest write failure).
 */
int HandleInstallBrowserExtensionMode();

/**
 * @brief Remove the seal-browser native-messaging manifest from HKCU.
 * @ingroup CLI
 *
 * Thin CLI wrapper over @ref uninstallBrowserExtensionInternal with no GUI
 * sinks. It deletes only the default value of each
 * `...\NativeMessagingHosts\com.seal.fill` key. Neither that key nor the
 * shared `NativeMessagingHosts` parent is deleted, because other native hosts
 * live under the same parent.
 *
 * @return 0 when every delete succeeded or the value was already absent,
 *         1 when at least one delete failed.
 */
int HandleUninstallBrowserExtensionMode();

/**
 * @brief Find the unpacked extension directory from an executable directory.
 * @ingroup CLI
 *
 * Checks `<executableDirectory>/extensions/browser` (the installed sibling
 * layout) first, then walks up to five parent directories looking for the
 * repository's `extensions/browser`. The walk stops at the filesystem root.
 * A directory that exists but is empty still counts as a hit.
 *
 * @param executableDirectory Directory that contains seal.exe.
 * @return The first candidate that exists, or the installed sibling path when
 *         none exists, so callers can name an actionable location.
 */
std::filesystem::path findBrowserExtensionDirectory(
    const std::filesystem::path& executableDirectory);

/**
 * @brief Build the GUI install message.
 * @ingroup CLI
 *
 * On a fatal failure returns @p report's `m_ErrorMessage`, or a generic
 * sentence when that is empty. On success it lists every browser row, the
 * extension folder, and the three manual "Load unpacked" steps, naming the
 * extensions page of each browser that was registered.
 *
 * When `m_ExtensionDirectoryFound` is `false` the message stops after the
 * folder line and asks the user to reinstall seal: with no folder to load, the
 * three manual steps make no sense.
 *
 * @return Multi-line message for the GUI dialog; never empty.
 */
std::string formatBrowserExtensionInstallReport(const BrowserExtensionInstallReport& report);

/**
 * @brief Build the GUI uninstall message.
 * @ingroup CLI
 *
 * Always lists every browser row and always closes with the reminder that seal
 * can unregister the native host but cannot remove an unpacked extension from
 * a browser.
 *
 * @return Multi-line message for the GUI dialog; never empty.
 */
std::string formatBrowserExtensionUninstallReport(const BrowserExtensionUninstallReport& report);

/**
 * @brief Best-effort installed-browser detection used by setup and status chips.
 * @ingroup CLI
 *
 * Returns `false` at once for an unknown kind and for every Gecko browser:
 * seal ships no Gecko native-messaging manifest.
 *
 * @par Probe order for a Chromium kind
 * - The `App Paths` key under HKCU, then HKLM, in both the 64-bit and the
 *   32-bit registry view.
 * - Opera only: `launcher.exe`.
 * - The standard install locations under `%LOCALAPPDATA%`, `%ProgramFiles%`
 *   and `%ProgramFiles(x86)%`.
 *
 * @return `true` when any probe hits. A portable copy in a non-standard folder
 *         is not detected.
 */
bool isBrowserInstalled(signer::BrowserKind kind);

/**
 * @brief Shared implementation of the install flow.
 * @ingroup CLI
 *
 * Shared by the CLI subcommand and the AppViewModel QML invocation so the two
 * surfaces stay in lockstep. Progress always goes to stdout, even for the GUI
 * caller, to keep the CLI's stdout contract stable.
 *
 * A browser is registered only when @ref isBrowserInstalled detects it; every
 * other Chromium entry yields a BrowserRegistrationOutcome::SkippedNotInstalled
 * row. Thorium and Chromium share one registry subkey, so on a machine with
 * both, one registry value is written twice and both rows report Registered.
 *
 * @par Failure model
 * @verbatim
 * seal.exe directory resolved?   no -> return 1, m_Success=false
 * seal-browser.exe beside it?    no -> return 1, m_Success=false
 * manifest written?              no -> return 1, m_Success=false
 * per-browser registry write
 *     failed                        -> RegistrationFailed row, return stays 0
 * extension folder / clipboard
 *     failed                        -> Found/Copied false, return stays 0
 * @endverbatim
 *
 * @param outMessage Ignored when null. Otherwise receives the GUI status
 *                   string from @ref formatBrowserExtensionInstallReport.
 * @param outReport  Ignored when null. Otherwise written on both the success
 *                   and the fatal-failure paths.
 * @return 0 on success, 1 on failure (module path unavailable,
 *         seal-browser.exe missing, or manifest write failure).
 */
int installBrowserExtensionInternal(std::string* outMessage,
                                    BrowserExtensionInstallReport* outReport = nullptr);

/**
 * @brief Shared implementation of the uninstall flow.
 * @ingroup CLI
 *
 * Mirrors @ref installBrowserExtensionInternal, including the stdout progress
 * lines. It does not probe for installed browsers: it walks every Chromium
 * entry of `signer::kBrowserMetadata`, so a value left over from an
 * uninstalled browser is still removed.
 *
 * A registry subkey shared by two browsers (Thorium and Chromium) is deleted
 * once and the cached outcome reused, so the second browser reports Removed
 * instead of AlreadyAbsent. The generated manifest JSON on disk is kept, so a
 * re-install only has to rewrite registry values.
 *
 * @param outMessage Ignored when null. Otherwise receives the GUI status
 *                   string from @ref formatBrowserExtensionUninstallReport.
 * @param outReport  Ignored when null. Otherwise receives the structured
 *                   report.
 * @return 0 when every delete succeeded or was already absent, 1 when at
 *         least one delete failed.
 */
int uninstallBrowserExtensionInternal(std::string* outMessage,
                                      BrowserExtensionUninstallReport* outReport = nullptr);

}  // namespace seal
