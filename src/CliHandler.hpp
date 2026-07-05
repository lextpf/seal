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
 * @ingroup CliHandler
 *
 * Handles: `:help`, `:open`, `:copy`, `:clear`, `:cls`, `:gen`, `:qr`,
 * `:fill`, `:hex`, `:unhex`.
 *
 * @par Built-in commands
 * | Command (aliases) | Effect |
 * |---|---|
 * | `:help` `:h` | Print the command list |
 * | `:open` `:o` `:edit` | Open the seal input file in Notepad |
 * | `:copy` `:clip` `:copyfile` `:copyinput` | Copy the seal input file to the clipboard |
 * | `:clear` `:none` | Clear the clipboard |
 * | `:cls` `:clear-screen` | Clear the CLI output panel |
 * | `:gen [len]` | Generate a password (default 20, clamped 8..128), then copy |
 * | `:qr` | Launch webcam QR capture |
 * | `:fill <svc>` | Arm auto-fill for a service by name |
 * | `:hex <text>` | Hex-encode text, copy to clipboard |
 * | `:unhex <hex>` | Hex-decode to text, copy to clipboard |
 *
 * Any other input returns `false` (a potential secret, routed to the
 * password-gated crypto dispatch).
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
 * @ingroup CliHandler
 *
 * Colocated with the command definitions so the set of commands that are
 * safe to echo verbatim cannot drift out of sync with the dispatcher.
 * Known non-secret commands echo as typed; `:gen` and `:fill` echo only
 * the command word (their arguments may be sensitive); everything else
 * (potential secrets: plaintext, hex, base64, file paths) echoes as
 * `[input hidden]`.
 *
 * @par Echo masking
 * | Input (trimmed) | Echo line |
 * |---|---|
 * | a fixed non-secret command (help/open/copy/clear/cls/qr and aliases) | `seal> <command>` |
 * | starts with `:gen` | `seal> :gen` |
 * | starts with `:fill` | `seal> :fill` |
 * | anything else (text, hex, base64, paths, `:hex`, `:unhex`) | `seal> [input hidden]` |
 *
 * @param command Raw command string as entered by the user.
 * @return The `seal> ...` echo line to append to the CLI transcript.
 */
QString CliEchoLine(const QString& command);

}  // namespace seal

#endif  // USE_QT_UI
