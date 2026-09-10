#pragma once

/**
 * @brief argv subcommands with process exit codes.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 *
 * main.cpp dispatches these Qt-free handlers. prompts and diagnostics go to stderr.
 * the interactive --cli console and embedded Cli panel have separate dispatchers.
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
 * @brief per-browser native-host registration outcome.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 *
 * install uses the first three values; uninstall uses the last three. reports contain
 * one row for every Chromium entry in signer::kBrowserMetadata.
 */
enum class BrowserRegistrationOutcome
{
    Registered,           ///< a registry value was written and none failed.
    SkippedNotInstalled,  ///< Browser not detected; no registry write attempted.
    RegistrationFailed,   ///< a write failed, or no value could be written at all.
    Removed,              ///< a registry value was deleted and none failed.
    AlreadyAbsent,        ///< Nothing to delete; the values were already gone.
    RemovalFailed,        ///< a delete failed for a reason other than "not found".
};

/**
 * @struct BrowserRegistrationResult
 * @brief one browser row in an install or uninstall report.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 */
struct BrowserRegistrationResult
{
    signer::BrowserKind m_Kind{};  ///< Browser this row describes.
    /**
     * outcome for this browser. the default keeps a row readable when it is
     * filled in before any registry work runs.
     */
    BrowserRegistrationOutcome m_Outcome = BrowserRegistrationOutcome::SkippedNotInstalled;
    /**
     * registry values actually written or deleted. Opera has two subkeys
     * (stable and GX); every other Chromium browser has one.
     */
    std::size_t m_RegistryValueCount = 0;
};

/**
 * @struct BrowserExtensionInstallReport
 * @brief native-host registration and extension discovery results.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 *
 * m_Success covers module lookup, host existence and manifest writing. registry failures
 * remain per-browser outcomes and do not clear m_Success.
 */
struct BrowserExtensionInstallReport
{
    bool m_Success = false;  ///< `false` only when a fatal step failed.
    /**
     * generated `com.seal.fill.json` beside seal.exe. empty when the module
     * path or seal-browser.exe could not be resolved.
     */
    std::filesystem::path m_ManifestPath;
    /**
     * unpacked extension folder the user must load by hand; see
     * findBrowserExtensionDirectory. empty after a fatal failure.
     */
    std::filesystem::path m_ExtensionDirectory;
    bool m_ExtensionDirectoryFound = false;   ///< that folder exists on disk.
    bool m_ExtensionDirectoryCopied = false;  ///< that path reached the clipboard.
    /// one row per Chromium-family browser, in `signer::kBrowserMetadata` order.
    std::vector<BrowserRegistrationResult> m_Browsers;
    std::string m_ErrorMessage;  ///< Fatal-step text; empty while m_Success holds.
};

/**
 * @struct BrowserExtensionUninstallReport
 * @brief results of clearing Chromium native-host registrations.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CLI
 *
 *
 * absent values count as success, so repeated removal is harmless.
 */
struct BrowserExtensionUninstallReport
{
    bool m_Success = false;  ///< `true` when no registry delete failed.
    /// one row per Chromium-family browser, in `signer::kBrowserMetadata` order.
    std::vector<BrowserRegistrationResult> m_Browsers;
};

/**
 * @brief print a generated password and copy it to the clipboard.
 * @ingroup CLI
 *
 * @param length clamped to [8, 128].
 * @return 0; clipboard failure is ignored.
 * @note CLI shutdown stops the scrub thread before its 6 s delay expires. the clipboard
 *       retains the password until overwritten or cleared with `seal wipe`.
 * @throw std::runtime_error on RAND_bytes failure; uncaught by main().
 */
int HandleGenMode(int length);

/**
 * @brief overwrite and delete a file without confirmation.
 * @ingroup CLI
 *
 * use random, zero and random passes. empty files and failed size queries skip overwriting.
 * @return 0 on success, 1 on missing file or failure.
 * @warning write-through cannot erase retained sectors, filesystem snapshots or copies.
 */
int HandleShredMode(const std::string& path);

/**
 * @brief print a file digest in sha256sum format.
 * @ingroup CLI
 *
 * output is `<hex digest>  <path>` with two spaces. encrypted files are hashed as stored.
 * @return 0 on success, 1 on missing file or hash failure.
 */
int HandleHashMode(const std::string& path);

/**
 * @brief authenticate an encrypted file without retaining plaintext.
 * @ingroup CLI
 *
 * prompt without echo. retain the input file buffer; verifyPacket() discards plaintext chunks.
 * @return 0 on valid authentication, 1 on wrong password or error.
 */
int HandleVerifyMode(const std::string& path);

/**
 * @brief clear the clipboard and active console screen buffer.
 * @ingroup CLI
 *
 * terminal-host scrollback is outside this operation's reach.
 * @return 0; both operations are best-effort.
 */
int HandleWipeMode();

/**
 * @brief replace a vault atomically under a new password.
 * @ingroup CLI
 *
 * append `.seal` when absent. prompt for the current password and twice for the new one;
 * reject empty or unequal new entries. replace only after the temporary vault verifies.
 * CLI loading clears session-only soft-delete flags, so every stored record is re-encrypted.
 * @return 0 on success, 1 on password or I/O failure.
 */
int HandleRekeyMode(const std::string& path);

/**
 * @brief validate case-sensitive field and output options.
 * @ingroup CLI
 *
 * | field          | stdout required |
 * |----------------|-----------------|
 * | `pass`, `user` | no              |
 * | `both`         | yes             |
 * | anything else  | invalid         |
 */
bool GetOptionsValid(const std::string& field, bool toStdout);

/**
 * @brief bound the requested clipboard delay.
 * @ingroup CLI
 *
 * @return seconds clamped to [1, 600].
 * @note CLI shutdown prevents the scrub; this value only affects the stderr notice.
 *       stdout delivery ignores it. see HandleGetMode().
 */
int ClampGetTtlSeconds(int requested);

/**
 * @brief print one platform name per line in record order.
 * @ingroup CLI
 *
 * decrypt only the index; credentials stay sealed. password prompts, diagnostics and record
 * count go to stderr. the count equals the number of names printed.
 * @param vaultPathArg append `.seal` when absent; empty selects findDefaultVault().
 * @return 0 on success, 1 on password, lookup or I/O failure.
 */
int HandleListMode(const std::string& vaultPathArg);

/**
 * @brief deliver a credential selected by exact name or unique prefix.
 * @ingroup CLI
 *
 * matching ignores case. blank deleted names preserve record indices without matching.
 * clipboard delivery prints a notice to stderr; stdout values end with a newline.
 *
 * | field  | clipboard | stdout                    |
 * |--------|-----------|---------------------------|
 * | `pass` | password  | password                  |
 * | `user` | username  | username                  |
 * | `both` | invalid   | username + TAB + password |
 *
 * | code | result                                            |
 * |------|---------------------------------------------------|
 * | 0    | delivered                                         |
 * | 1    | invalid options, password, clipboard or I/O error |
 * | 2    | missing platform or ambiguous prefix              |
 *
 * @param vaultPathArg append `.seal` when absent; empty selects findDefaultVault().
 * @param ttlSeconds seconds clamped to [1, 600]; unused for stdout.
 * @warning CLI shutdown cancels the announced clipboard scrub. the value remains until
 *          overwritten or cleared with `seal wipe`.
 */
int HandleGetMode(const std::string& platformQuery,
                  const std::string& vaultPathArg,
                  const std::string& field,
                  bool toStdout,
                  int ttlSeconds);

/**
 * @brief encrypt to a temporary file and replace the destination.
 * @ingroup CLI
 *
 * prompt without echo. rename with MOVEFILE_REPLACE_EXISTING only after a complete write.
 * @param outputPath empty selects `inputPath + ".seal"`.
 * @return 0 on success, 1 on a missing source, encryption failure or exception.
 * @note success triggers an unchecked source deletion; a locked source can remain.
 */
int HandleFileEncrypt(const std::string& inputPath, const std::string& outputPath);

/**
 * @brief decrypt to a temporary file and replace the destination.
 * @ingroup CLI
 *
 * prompt without echo. rename only after a complete write.
 * @param outputPath empty strips a case-insensitive `.seal` suffix, or appends `.decrypted`.
 * @return 0 on success, 1 on source, password, packet or I/O failure.
 *         authentication failure reports `reason=decrypt_failed`.
 * @note success triggers an unchecked source deletion; a locked source can remain.
 */
int HandleFileDecrypt(const std::string& inputPath, const std::string& outputPath);

/**
 * @brief convert text to or from an encrypted packet.
 * @ingroup CLI
 *
 * prompts go to stderr. encryption emits `(hex)` and `(b64)` lines for the same packet;
 * decryption emits plaintext. hex detection precedes base64 because hex is a subset.
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
 *
 * @param inlineData empty reads all stdin and trims trailing CR/LF; otherwise used verbatim.
 * @return 0 on success, 1 on empty input, encoding, round-trip or crypto failure.
 *

 */
int HandleStringMode(bool encryptMode, const std::string& inlineData);

/**
 * @brief register the native host and report the extension folder on the CLI.
 * @ingroup CLI
 *
 * @return the installBrowserExtensionInternal() result.
 * @see installBrowserExtensionInternal
 */
int HandleInstallBrowserExtensionMode();

/**
 * @brief remove native-host registry values on the CLI.
 * @ingroup CLI
 *
 * @return the uninstallBrowserExtensionInternal() result.
 * @see uninstallBrowserExtensionInternal
 */
int HandleUninstallBrowserExtensionMode();

/**
 * @brief locate the unpacked extension from the executable directory.
 * @ingroup CLI
 *
 * try the sibling `extensions/browser`, then up to five parents, stopping at the root.
 * existence is sufficient; the directory may be empty.
 * @return the first existing candidate, or the sibling path if none exists.
 */
std::filesystem::path findBrowserExtensionDirectory(
    const std::filesystem::path& executableDirectory);

/**
 * @brief format installation results and manual setup steps.
 * @ingroup CLI
 *
 * fatal failure uses the report error or a generic message. missing extension files replace
 * setup steps with a reinstall request.
 * @return a non-empty multiline dialog message.
 */
std::string formatBrowserExtensionInstallReport(const BrowserExtensionInstallReport& report);

/**
 * @brief format every browser outcome and the manual extension-removal reminder.
 * @ingroup CLI
 *
 * @return a non-empty multiline dialog message.
 */
std::string formatBrowserExtensionUninstallReport(const BrowserExtensionUninstallReport& report);

/**
 * @brief detect installed Chromium browsers for setup and status.
 * @ingroup CLI
 *
 * probe App Paths in HKCU then HKLM, in both registry views; also probe Opera launcher.exe
 * and standard LOCALAPPDATA/ProgramFiles locations. portable copies elsewhere are missed.
 * @return false for unknown or Gecko kinds; otherwise true on the first matching probe.
 */
bool isBrowserInstalled(signer::BrowserKind kind);

/**
 * @brief register detected Chromium browsers and generate the native-host manifest.
 * @ingroup CLI
 *
 * progress goes to stdout for both CLI and GUI callers. Thorium and Chromium share a
 * registry subkey, so both report Registered after writing the same value.
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
 * @param outMessage optional GUI status output; null is ignored.
 * @param outReport optional structured output, written on success and fatal failure.
 * @return 1 on module-path, host-binary or manifest-write failure; otherwise 0.
 *         registry, extension-folder and clipboard failures remain in the report.
 *

 */
int installBrowserExtensionInternal(std::string* outMessage,
                                    BrowserExtensionInstallReport* outReport = nullptr);

/**
 * @brief remove native-host values while retaining registry keys and the manifest.
 * @ingroup CLI
 *
 * visit every Chromium entry, including uninstalled browsers. shared subkeys are deleted once
 * and reuse the same outcome. progress goes to stdout for both CLI and GUI callers.
 * @param outMessage optional GUI status output; null is ignored.
 * @param outReport optional structured output; null is ignored.
 * @return 0 if all values were removed or absent, 1 on any deletion failure.
 */
int uninstallBrowserExtensionInternal(std::string* outMessage,
                                      BrowserExtensionUninstallReport* outReport = nullptr);

}  // namespace seal
