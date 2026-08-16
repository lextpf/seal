#pragma once

/**
 * @brief Best-effort exit diagnostics for the browser-spawned host.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The browser captures the host's stderr but never shows it in the extension's
 * service-worker console, which only reports that the native host exited. Host-only
 * failures, such as a bad launch origin, an unresolvable parent PID, or no bridge
 * pipe with a matching signer, therefore also append a line to
 * `%LOCALAPPDATA%\seal\bridge-host-last-exit.log`. That file is the operator's only
 * view of why a launch failed. Both calls are best effort and never fail loud, so a
 * logging error cannot mask the real exit cause.
 *
 * The file is appended to and never rotated, and one launch can write more than one
 * line: an informational note first, then the final exit line. Read the last line for
 * the outcome, and group the lines of one launch by their `pid=` field.
 */

namespace seal::browser_host
{

/**
 * @brief Append one timestamped `pid=.. exit=.. reason=..` line to the exit log.
 *
 * @param code    Exit code being reported, or 0 for an informational line written
 *                while the process continues, such as the unsigned-build `dev_mode_*`
 *                ownership notes.
 * @param reason  Diagnostic token, for example "bad_launch_origin". These tokens
 *                are a stable contract with the operator; do not rename them.
 */
void writeExitLog(int code, const char* reason);

/**
 * @brief Write one diagnostic line to stderr and to the exit log before exiting.
 *
 * @param code    Process exit code being reported.
 * @param reason  Diagnostic token, as for @ref writeExitLog.
 */
void emitExitDiag(int code, const char* reason);

}  // namespace seal::browser_host
