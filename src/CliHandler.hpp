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
 * @brief Built-in command callbacks for the embedded GUI terminal.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * The argv CLI and console REPL use separate dispatchers. `output` is required
 * except for `:cls`, which uses `clearOutput`. `:qr` uses `requestQrCapture`;
 * a matched `:fill` uses `armFill`. Null `records` reports no loaded vault.
 * Unhandled commands call nothing.
 */
struct CliCallbacks
{
    std::function<void(const QString&)> output;
    std::function<void()> clearOutput;
    std::function<void()> requestQrCapture;
    std::function<void(int)> armFill;
    const std::vector<VaultRecord>* records = nullptr;  ///< Borrowed records; may be null.
};

/**
 * @fn bool HandleCliBuiltin(const QString& command, const CliCallbacks& cb)
 * @brief Handle built-ins before password-gated crypto dispatch.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * | Command                                  | Effect                           |
 * |------------------------------------------|----------------------------------|
 * | `:help` / `:h`                           | Command list                     |
 * | `:open` / `:o` / `:edit`                 | Open input file in Notepad       |
 * | `:copy`/`:clip`/`:copyfile`/`:copyinput` | Copy input file contents         |
 * | `:clear` / `:none`                       | Clear clipboard                  |
 * | `:cls` / `:clear-screen`                 | Clear transcript                 |
 * | `:gen [len]`                             | Copy password; default 20, 8-128 |
 * | `:qr`                                    | Request webcam capture           |
 * | `:fill <svc>`                            | Arm matching service             |
 * | `:hex <text>`                            | Copy hex encoding                |
 * | `:unhex <hex>`                           | Copy decoded text                |
 *
 * Fixed commands match exact case. `:gen` and `:fill` accept any matching prefix;
 * `:hex` and `:unhex` require a following space. Invalid lengths use 20; parsed
 * lengths clamp to 8-128. Invalid hex reports an error.
 *
 * Fill matching ignores case and soft deletes. Missing arguments, records or
 * matches report a handled error. Clipboard results are masked and scrubbed
 * after 6 s.
 *
 * @param command Trimmed input.
 * @return False for unhandled input, which may contain a secret.
 */
bool HandleCliBuiltin(const QString& command, const CliCallbacks& cb);

/**
 * @fn QString CliEchoLine(const QString& command)
 * @brief Mask command echoes before they reach the QML transcript.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup CliHandler
 *
 * | Input                    | Echo                   |
 * |--------------------------|------------------------|
 * | Fixed non-secret command | `seal> <command>`      |
 * | Starts with `:gen`       | `seal> :gen`           |
 * | Starts with `:fill`      | `seal> :fill`          |
 * | Other input              | `seal> [input hidden]` |
 *
 * @param command Raw input before trimming.
 */
QString CliEchoLine(const QString& command);

}  // namespace seal

#endif  // USE_QT_UI
