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
 * @brief Crypto callbacks for the embedded GUI terminal.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * The argv CLI and console REPL use separate dispatchers.
 *
 * @pre `output` is callable; `password` remains unlocked for the dispatch lifetime.
 */
struct CliDispatchCallbacks
{
    std::function<void(const QString&)> output;
    const basic_secure_string<wchar_t>& password;  ///< Borrowed ref to master password.
};

/**
 * @fn void CliDispatchFile(const std::string& stripped, const CliDispatchCallbacks& cb)
 * @brief Replace a source file with its encrypted or decrypted output.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * Existing destinations are replaced atomically without confirmation. Source
 * deletion uses DeleteFileA, so plaintext is not overwritten on disk.
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
 * @param stripped Path already trimmed and unquoted.
 */
void CliDispatchFile(const std::string& stripped, const CliDispatchCallbacks& cb);

/**
 * @fn void CliDispatchDirectory(const std::string& dir, const CliDispatchCallbacks& cb)
 * @brief Recursively dispatch files and report counts per directory.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * Unlistable directories report an error without a summary. Counts exclude
 * skips and subdirectory files; recursion depth is bounded only by the tree.
 *
 * | Entry                       | Action                         |
 * |-----------------------------|--------------------------------|
 * | `.` / `..` or reparse point | Skip                           |
 * | `*.exe` or `seal`, any type | Report skipped; do not descend |
 * | Other directory             | Recurse                        |
 * | Other file                  | CliDispatchFile                |
 */
void CliDispatchDirectory(const std::string& dir, const CliDispatchCallbacks& cb);

/**
 * @fn void CliDispatchHexTokens(const std::string& input, const CliDispatchCallbacks& cb)
 * @brief Decrypt extracted hex tokens into the clipboard and mask transcript output.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * Accepts even-length hex tokens of at least 88 digits; real packets need at
 * least 104. Each success replaces the clipboard with a 6 s scrub and emits one
 * asterisk per plaintext byte. Decryption errors report and continue.
 *
 * @see utils::extractHexTokens
 */
void CliDispatchHexTokens(const std::string& input, const CliDispatchCallbacks& cb);

/**
 * @fn bool CliDispatchBase64(const std::string& input, const CliDispatchCallbacks& cb)
 * @brief Try base64 decryption with the same masking and clipboard lifetime as hex tokens.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * @return False for empty decoding or any decryption error. Callers treat both
 *         as plaintext and fall through to encryption.
 * @pre The caller has checked the alphabet with `utils::isBase64`.
 */
bool CliDispatchBase64(const std::string& input, const CliDispatchCallbacks& cb);

/**
 * @fn void CliDispatchEncrypt(const std::string& input, const CliDispatchCallbacks& cb)
 * @brief Emit one packet as hex and base64 ciphertext without masking.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 */
void CliDispatchEncrypt(const std::string& input, const CliDispatchCallbacks& cb);

}  // namespace seal

#endif  // USE_QT_UI
