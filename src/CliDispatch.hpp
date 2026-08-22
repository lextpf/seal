#pragma once

#ifdef USE_QT_UI

#include "Cryptography.hpp"

#include <QtCore/QString>

#include <functional>
#include <string>

namespace seal
{

/**
 * @struct CliDispatchCallbacks
 * @brief Callback interface for the embedded GUI terminal panel's crypto dispatch.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CliHandler
 *
 * Encrypt, decrypt and file dispatch for the embedded GUI terminal panel; its
 * only caller is @ref CliPanelViewModel::executeCliCommand. The argv subcommands
 * (`CliModes.cpp`) and the `--cli` console REPL are separate dispatchers and do
 * not route through here. These callbacks keep the dispatch independent of
 * AppViewModel's signal/slot infrastructure.
 *
 * @par Lifetime
 * @p password is a reference member, so the struct is not assignable and is
 * built by aggregate initialisation; the call site uses designated initialisers.
 * It must not outlive the unlocked master-password buffer it borrows. Any
 * dispatch function may call @p output, so it must be set, but some calls emit
 * nothing: CliDispatchHexTokens() when the input holds no hex token, and
 * CliDispatchBase64() when the input is not base64 ciphertext.
 */
struct CliDispatchCallbacks
{
    std::function<void(const QString&)> output;    ///< Emit a line of panel output.
    const basic_secure_string<wchar_t>& password;  ///< Borrowed ref to master password.
};

/**
 * @brief Dispatch a file path: encrypt or decrypt based on `.seal` extension.
 * @ingroup CliHandler
 *
 * On success the source is deleted: the transformed copy replaces it. The
 * source is removed with `DeleteFileA`, not shredded, so after an encrypt the
 * original plaintext bytes stay recoverable on disk. `FileOperations::shredFile`
 * (the `shred` subcommand) is the overwrite path and is deliberately not used
 * here. Executables and seal itself are never touched. The destination is
 * written to a temporary file and renamed over the target with
 * `MOVEFILE_REPLACE_EXISTING`, so an existing destination is replaced in one
 * step and without a warning.
 *
 * @verbatim
 * target path
 *   |
 *   +-- basename ends ".exe" (ci)  OR  basename == "seal" (ci)
 *   |        -> "(skipped) <target>"          [no crypto, source kept]
 *   |
 *   +-- ends ".seal" (ci)
 *   |        -> decrypt to <target without ".seal">, delete source
 *   |           ok:   "(decrypted) <src> -> <dst>"
 *   |           fail: "(decrypt failed) <target>"
 *   |
 *   +-- otherwise
 *            -> encrypt to <target>.seal, delete source
 *               ok:   "(encrypted) <src> -> <dst>"
 *               fail: "(encrypt failed) <target>"
 * @endverbatim
 *
 * @param stripped Target path, already trimmed and unquoted by the caller.
 */
void CliDispatchFile(const std::string& stripped, const CliDispatchCallbacks& cb);

/**
 * @brief Recursively encrypt or decrypt all files in a directory.
 * @ingroup CliHandler
 *
 * Walks the tree with FindFirstFile/FindNextFile and delegates each plain file
 * to @ref CliDispatchFile. A directory that cannot be listed emits
 * `(dir) cannot list: <dir>` and returns without a summary.
 *
 * Every level emits its own `[dir] <dir>: <n> files processed` line, counting
 * the files dispatched at that level only. Files inside a subdirectory belong
 * to the subdirectory's own summary and are never rolled up into the parent's;
 * skipped entries are never counted.
 *
 * @par Per-entry handling
 * |                    Directory entry | Action                  |
 * |------------------------------------|-------------------------|
 * |                        `.` or `..` | skip                    |
 * | reparse point (symlink / junction) | skip, never traversed   |
 * |                  `*.exe` or `seal` | `(skipped)`, left as-is |
 * |                       subdirectory | recurse                 |
 * |                     any other file | @ref CliDispatchFile    |
 *
 * The name test runs before the directory test, so a directory named `seal` or
 * ending in `.exe` is reported as `(skipped)` and is not descended into.
 *
 * @param dir Directory to walk. Recursion depth is bounded only by the tree.
 */
void CliDispatchDirectory(const std::string& dir, const CliDispatchCallbacks& cb);

/**
 * @brief Dispatch hex tokens: decrypt each and copy to clipboard.
 * @ingroup CliHandler
 *
 * Decrypts every token that `utils::extractHexTokens` finds in @p input. That
 * extractor splits on whitespace and keeps only tokens of even length, made of
 * hex digits, and at least 88 hex digits long (salt + IV + tag). That threshold
 * sits deliberately below the 104-digit true minimum packet, so it never
 * discards a real packet while it still rejects short hex words in a sentence.
 * See @ref utils::extractHexTokens for the framing table.
 *
 * Each success overwrites the clipboard, so after several tokens only the last
 * plaintext remains there, scrubbed after the default 6 seconds. The
 * transcript line is one asterisk per plaintext byte plus `[copied]`; the
 * plaintext itself never reaches QML. A token that fails to decrypt emits
 * `(decrypt failed: <what>)` and the loop moves on to the next token.
 *
 * @param input Raw command text; tokens are extracted from it, not assumed.
 */
void CliDispatchHexTokens(const std::string& input, const CliDispatchCallbacks& cb);

/**
 * @brief Try to dispatch base64 ciphertext: decrypt and copy to clipboard.
 * @ingroup CliHandler
 *
 * Masks the plaintext in the transcript exactly like @ref CliDispatchHexTokens
 * and leaves the value on the clipboard with the default 6-second scrub. The
 * alphabet is not checked here; the caller runs `utils::isBase64` first.
 *
 * @return `true` when a packet was decrypted and copied. `false` when the
 *         input decodes to nothing, or when decryption threw (wrong password,
 *         truncated or corrupt packet). The two cases are not distinguished:
 *         the caller reads both as "not ciphertext" and falls through to
 *         encrypting the input.
 */
bool CliDispatchBase64(const std::string& input, const CliDispatchCallbacks& cb);

/**
 * @brief Dispatch plaintext encryption: emit hex + base64 output.
 * @ingroup CliHandler
 *
 * Emits one `(hex) ...` line and one `(b64) ...` line carrying the same
 * packet in two encodings. Unlike the decrypt paths, the output is not
 * masked: it is ciphertext, not a secret.
 */
void CliDispatchEncrypt(const std::string& input, const CliDispatchCallbacks& cb);

}  // namespace seal

#endif  // USE_QT_UI
