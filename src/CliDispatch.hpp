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
 * Decouples the CLI encrypt/decrypt/file dispatch logic from Backend's
 * signal/slot infrastructure so the dispatch can be maintained independently.
 */
struct CliDispatchCallbacks
{
    std::function<void(const QString&)> output;    ///< Emit a line of CLI output.
    const basic_secure_string<wchar_t>& password;  ///< Borrowed ref to master password.
};

/// @brief Dispatch a file path: encrypt or decrypt based on `.seal` extension.
void CliDispatchFile(const std::string& stripped, const CliDispatchCallbacks& cb);

/// @brief Recursively encrypt or decrypt all files in a directory.
void CliDispatchDirectory(const std::string& dir, const CliDispatchCallbacks& cb);

/// @brief Dispatch hex tokens: decrypt each and copy to clipboard.
void CliDispatchHexTokens(const std::string& input, const CliDispatchCallbacks& cb);

/// @brief Try to dispatch base64 ciphertext: decrypt and copy to clipboard.
/// @return `true` if handled, `false` if not valid base64 ciphertext.
bool CliDispatchBase64(const std::string& input, const CliDispatchCallbacks& cb);

/// @brief Dispatch plaintext encryption: emit hex + base64 output.
void CliDispatchEncrypt(const std::string& input, const CliDispatchCallbacks& cb);

}  // namespace seal

#endif  // USE_QT_UI
