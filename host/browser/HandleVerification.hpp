#pragma once

/**
 * @brief Prove that seal-browser's stdio handles come from a real browser.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Three fail-closed checks backing the "the bridge verifies us" half of the
 * mutual-authentication model. @ref getHandlePipeName reads a handle's kernel
 * object name; @ref parentOwnsPipe confirms the claimed parent process actually
 * holds that pipe object (defeating a re-parented puppet); @ref
 * isStdHandleFromProcess confirms a stdio handle is a pipe served by the parent
 * or a known signed browser (Chrome's split-process model). Each returns false
 * or empty on any failure, so callers fail closed in production.
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

namespace seal::browser_host
{

/**
 * @brief Kernel object name of a pipe handle, or empty on failure.
 *
 * Both ends of a pipe share this NT object name, so it is the key
 * @ref parentOwnsPipe matches against the parent's handle table. Empty means
 * "unverifiable"; callers fall back to the surrounding policy (fail closed in
 * production, soft-pass in dev).
 *
 * @param handle  Pipe handle to name.
 * @return The `\Device\NamedPipe\...` object name, or empty.
 */
std::wstring getHandlePipeName(HANDLE handle);

/**
 * @brief Whether @p parentPid holds a handle to the pipe named @p expectedPipeName.
 *
 * Enumerates the parent's handle table via NtQuerySystemInformation and looks
 * for the shared pipe object. True only when the parent genuinely owns the
 * other end - defeating puppets that re-parent via
 * PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. Best-effort; false on any failure.
 *
 * @param parentPid         PID of the claimed parent process.
 * @param expectedPipeName  Object name from @ref getHandlePipeName.
 * @return true iff the parent holds that pipe object.
 */
bool parentOwnsPipe(DWORD parentPid, const std::wstring& expectedPipeName);

/**
 * @brief Whether a stdio handle is a pipe served by a trusted process.
 *
 * Soft-passes anonymous pipes (the bridge-side parent check still applies) and
 * Chrome's utility-process split (accepts a server that is itself a known
 * signed browser). Untrusted servers - malware puppets - fail.
 *
 * @param handle       The stdin / stdout handle to check.
 * @param expectedPid  The resolved parent PID this handle should trace to.
 * @return true when the handle is a pipe from the parent or a signed browser.
 */
bool isStdHandleFromProcess(HANDLE handle, DWORD expectedPid);

}  // namespace seal::browser_host
