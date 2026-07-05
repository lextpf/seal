#pragma once

/**
 * @brief Best-effort exit diagnostics for the browser-spawned host.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The browser captures the host's stderr but never surfaces it in the
 * extension's service-worker console, so host-only failures (bad launch origin,
 * unknown parent PID, pipe enumeration) are also appended to
 * `%LOCALAPPDATA%\seal\bridge-host-last-exit.log`. Both calls are best-effort
 * and never fail loud, so a logging error can't mask the real exit cause.
 */

namespace seal::browser_host
{

/**
 * @brief Append one timestamped `pid=.. exit=.. reason=..` line to the exit log.
 *
 * @param code    Process exit code being reported.
 * @param reason  Stable diagnostic token (e.g. "bad_launch_origin").
 */
void writeExitLog(int code, const char* reason);

/**
 * @brief Emit one diagnostic line to stderr and the exit log before exiting.
 *
 * @param code    Process exit code being reported.
 * @param reason  Stable diagnostic token.
 */
void emitExitDiag(int code, const char* reason);

}  // namespace seal::browser_host
