#pragma once

/**
 * @brief Append host diagnostics when browser consoles omit stderr.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Writes %LOCALAPPDATA%\seal\bridge-host-last-exit.log without rotation.
 * Failures are ignored. Group launch lines by pid; the last line records exit.
 */

namespace seal::browser_host
{

/**
 * @fn void writeExitLog(int code, const char* reason)
 * @brief Append a timestamped pid, exit code, and stable reason token.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @param code 0 may also record an informational line before exit.
 * @param reason Stable operator contract; do not rename tokens.
 */
void writeExitLog(int code, const char* reason);

/**
 * @fn void emitExitDiag(int code, const char* reason)
 * @brief Copy an exit diagnostic to stderr and the exit log.
 * @author Alex (<https://github.com/lextpf>)
 */
void emitExitDiag(int code, const char* reason);

}  // namespace seal::browser_host
