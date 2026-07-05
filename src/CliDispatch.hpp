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
 * @brief Callback interface for CLI crypto dispatch commands.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CliHandler
 *
 * Decouples the CLI encrypt/decrypt/file dispatch logic from AppViewModel's
 * signal/slot infrastructure so the dispatch can be maintained independently.
 */
struct CliDispatchCallbacks
{
    std::function<void(const QString&)> output;    ///< Emit a line of CLI output.
    const basic_secure_string<wchar_t>& password;  ///< Borrowed ref to master password.
};

/**
 * @brief Dispatch a file path: encrypt or decrypt based on `.seal` extension.
 * @ingroup CliHandler
 *
 * On success the source is deleted (the operation replaces it with the
 * transformed copy). Executables and seal itself are never touched.
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
 */
void CliDispatchFile(const std::string& stripped, const CliDispatchCallbacks& cb);

/**
 * @brief Recursively encrypt or decrypt all files in a directory.
 * @ingroup CliHandler
 *
 * Walks the tree with FindFirstFile/FindNextFile, delegating each plain file
 * to @ref CliDispatchFile and finishing with a
 * `[dir] <dir>: <n> files processed` summary (only dispatched files count).
 *
 * @par Per-entry handling
 * | Directory entry | Action |
 * |---|---|
 * | `.` or `..` | skip |
 * | reparse point (symlink / junction) | skip, never traversed |
 * | `*.exe` or `seal` | `(skipped)`, left as-is |
 * | subdirectory | recurse |
 * | any other file | @ref CliDispatchFile |
 */
void CliDispatchDirectory(const std::string& dir, const CliDispatchCallbacks& cb);

/**
 * @brief Dispatch hex tokens: decrypt each and copy to clipboard.
 * @ingroup CliHandler
 */
void CliDispatchHexTokens(const std::string& input, const CliDispatchCallbacks& cb);

/**
 * @brief Try to dispatch base64 ciphertext: decrypt and copy to clipboard.
 * @ingroup CliHandler
 * @return `true` if handled, `false` if not valid base64 ciphertext.
 */
bool CliDispatchBase64(const std::string& input, const CliDispatchCallbacks& cb);

/**
 * @brief Dispatch plaintext encryption: emit hex + base64 output.
 * @ingroup CliHandler
 */
void CliDispatchEncrypt(const std::string& input, const CliDispatchCallbacks& cb);

}  // namespace seal

#endif  // USE_QT_UI
