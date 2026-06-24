#pragma once

#ifdef USE_QT_UI

#include "Vault.hpp"

#include <QtCore/QString>

#include <functional>
#include <vector>

namespace seal
{

/**
 * @struct CliCallbacks
 * @brief Callback interface for CLI built-in commands.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CliHandler
 *
 * Decouples the command dispatch logic from AppViewModel's signal/slot
 * infrastructure so the handler can be tested and maintained
 * independently.
 */
struct CliCallbacks
{
    std::function<void(const QString&)> output;         ///< Emit a line of CLI output.
    std::function<void()> clearOutput;                  ///< Clear the CLI output panel.
    std::function<void()> requestQrCapture;             ///< Launch webcam QR capture.
    std::function<void(int)> armFill;                   ///< Arm auto-fill for a record index.
    const std::vector<VaultRecord>* records = nullptr;  ///< Borrowed pointer to vault records.
};

/**
 * @brief Dispatch a CLI built-in command that does not require the master password.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CliHandler
 *
 * Handles: `:help`, `:open`, `:copy`, `:clear`, `:cls`, `:gen`, `:qr`,
 * `:fill`, `:hex`, `:unhex`.
 *
 * @param command Trimmed command string.
 * @param cb      Callbacks for output and AppViewModel interaction.
 * @return `true` if the command was handled (caller should return).
 *         `false` if the command requires the master password and should
 *         be handled by AppViewModel's crypto dispatch.
 */
bool HandleCliBuiltin(const QString& command, const CliCallbacks& cb);

/**
 * @brief Build the masked echo line for a CLI command.
 * @author Alex (https://github.com/lextpf)
 * @ingroup CliHandler
 *
 * Colocated with the command definitions so the set of commands that are
 * safe to echo verbatim cannot drift out of sync with the dispatcher.
 * Known non-secret commands echo as typed; `:gen` and `:fill` echo only
 * the command word (their arguments may be sensitive); everything else
 * (potential secrets: plaintext, hex, base64, file paths) echoes as
 * `[input hidden]`.
 *
 * @param command Raw command string as entered by the user.
 * @return The `seal> ...` echo line to append to the CLI transcript.
 */
QString CliEchoLine(const QString& command);

}  // namespace seal

#endif  // USE_QT_UI
