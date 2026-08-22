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
 * This is the built-in command set of the embedded GUI terminal panel. Its only
 * caller is @ref CliPanelViewModel::executeCliCommand. The argv subcommands
 * (`CliModes.cpp`) and the `--cli` console REPL (`handleCliMode` in main.cpp)
 * are separate dispatchers and do not route through here.
 *
 * The callbacks keep command dispatch independent of AppViewModel's
 * signal/slot infrastructure, so the built-in command set is defined in one
 * place. This translation unit is `USE_QT_UI`-gated and is not compiled into
 * `seal_tests`; its invariants are pinned by the source-scan tests in
 * `tests/test_ui_secret_boundaries.cpp`.
 *
 * @par Which callback each command needs
 * Every handled branch except `:cls` calls @p output, so it must be set. `:cls`
 * calls @p clearOutput alone and is its only user; `:qr` is the only user of
 * @p requestQrCapture, and `:fill` of @p armFill (after a name match). An
 * unhandled command returns `false` without calling any callback. @p records may
 * stay null: `:fill` then answers `(no vault loaded)` instead of dereferencing it.
 */
struct CliCallbacks
{
    std::function<void(const QString&)> output;         ///< Emit a line of CLI output.
    std::function<void()> clearOutput;                  ///< Clear the CLI output panel.
    std::function<void()> requestQrCapture;             ///< Launch webcam QR capture.
    std::function<void(int)> armFill;                   ///< Arm auto-fill for a record index.
    const std::vector<VaultRecord>* records = nullptr;  ///< Borrowed records; may be null.
};

/**
 * @brief Dispatch a CLI built-in command that does not require the master password.
 * @ingroup CliHandler
 *
 * @par Built-in commands
 * |                                  Command | Effect                                                      |
 * |------------------------------------------|-------------------------------------------------------------|
 * |                             `:help` `:h` | Print the command list                                      |
 * |                     `:open` `:o` `:edit` | Open the seal input file in Notepad                         |
 * | `:copy` `:clip` `:copyfile` `:copyinput` | Copy the `seal` file contents to the clipboard              |
 * |                         `:clear` `:none` | Clear the clipboard                                         |
 * |                   `:cls` `:clear-screen` | Clear the CLI output panel                                  |
 * |                             `:gen [len]` | Generate a password (default 20, clamped 8..128), then copy |
 * |                                    `:qr` | Launch webcam QR capture                                    |
 * |                            `:fill <svc>` | Arm auto-fill for a service by name                         |
 * |                            `:hex <text>` | Hex-encode text, copy to clipboard                          |
 * |                           `:unhex <hex>` | Hex-decode to text, copy to clipboard                       |
 *
 * Any other input returns `false` (a potential secret, routed to the
 * password-gated crypto dispatch).
 *
 * @par Matching rules
 * - Fixed commands and their aliases match by exact, case-sensitive
 *   comparison, so `:HELP` is not a command.
 * - `:gen` and `:fill` match by prefix, so any longer word starting with those
 *   letters enters the same branch.
 * - `:hex` and `:unhex` match only with a trailing space. A bare `:hex` falls
 *   through to the crypto dispatch and is treated there as plaintext.
 *
 * @par Argument handling
 * - `:gen` clamps a parsed length to [8, 128]. An unparsable argument leaves
 *   the length at 20.
 * - `:fill` matches platform names case-insensitively, skips soft-deleted records, and
 *   returns `true` for all three misses: `Usage: :fill <service>` with no argument,
 *   `(no vault loaded)` with no records, `(no account found for "<svc>")` with no match.
 * - `:unhex` answers `(invalid hex)` for an argument that is not valid hex.
 *
 * @par Clipboard
 * Every clipboard write goes through `Clipboard::copyWithTTL` with the default
 * 6-second scrub. The generated password, the hex text and the decoded text
 * are copied but never echoed into the transcript.
 *
 * @param command Trimmed command string.
 * @param cb      Callbacks for output and AppViewModel interaction.
 * @return `true` when the command was handled and the caller should return.
 *         `false` when it needs the master password and belongs to the crypto
 *         dispatch.
 */
bool HandleCliBuiltin(const QString& command, const CliCallbacks& cb);

/**
 * @brief Build the masked echo line for a CLI command.
 * @ingroup CliHandler
 *
 * Colocated with the command definitions so the set of commands that are safe
 * to echo verbatim cannot drift out of sync with the dispatcher. A fixed
 * non-secret command echoes as typed, `:gen` and `:fill` echo the command word
 * without their argument, and anything that could be a secret echoes as
 * `[input hidden]`.
 *
 * @par Echo masking
 * |                                Input | Echo line               |
 * |--------------------------------------|-------------------------|
 * |           a fixed non-secret command | `seal> <command>`       |
 * |                   starts with `:gen` | `seal> :gen`            |
 * |                  starts with `:fill` | `seal> :fill`           |
 * | anything else (text, hex, base64...) | `seal> [input hidden]`  |
 *
 * @param command Raw command string as entered, before trimming.
 * @return The `seal> ...` echo line to append to the CLI transcript.
 */
QString CliEchoLine(const QString& command);

}  // namespace seal

#endif  // USE_QT_UI
