#pragma once

/**
 * @brief Prove that seal-browser's stdio handles come from a real browser.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Three checks that establish who really launched this process. They are the
 * counterpart to the signer gate in BridgePipe.hpp, which verifies the bridge:
 *
 * - @ref getHandlePipeName reads a handle's kernel object name.
 * - @ref parentOwnsPipe confirms the claimed parent process holds that same pipe
 *   object, which defeats a re-parented puppet.
 * - @ref isStdHandleFromProcess confirms a stdio handle is a pipe served by the
 *   parent or by a known signed browser, which Chrome's split-process model needs.
 *
 * @ref getHandlePipeName and @ref parentOwnsPipe return empty or false on any failure,
 * including an unusable NT call, so a signed build fails closed on an inconclusive
 * answer. @ref isStdHandleFromProcess is deliberately different: it soft-passes a pipe
 * whose server it cannot query (an anonymous pipe). See its two soft-pass rules below.
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
 * Both ends of a pipe share this NT object name, so it is the key that
 * @ref parentOwnsPipe matches against the parent's handle table. Empty means
 * unverifiable rather than wrong, and the caller applies its own policy: a signed
 * build fails closed, an unsigned build logs and continues.
 *
 * @param handle  Pipe handle to name.
 * @return The `\Device\NamedPipe\...` object name, or empty.
 */
std::wstring getHandlePipeName(HANDLE handle);

/**
 * @brief Whether @p parentPid holds a handle to the pipe named @p expectedPipeName.
 *
 * Enumerates the parent's handle table with NtQuerySystemInformation and looks for
 * the shared pipe object. It returns true only when the parent holds the other end,
 * which defeats a puppet that claims a browser parent through
 * PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. Best effort: false on any failure, so a
 * hardened or protected parent reads the same as an attacker.
 *
 * @param parentPid         PID of the claimed parent process.
 * @param expectedPipeName  Object name from @ref getHandlePipeName.
 * @return true iff the parent holds that pipe object.
 */
bool parentOwnsPipe(DWORD parentPid, const std::wstring& expectedPipeName);

/**
 * @brief Whether a stdio handle is a pipe served by a trusted process.
 *
 * Two soft-passes keep real browsers working. An anonymous pipe has no queryable
 * server, so it passes here and the bridge-side parent check carries the weight.
 * Chrome's utility-process split makes the pipe server and the parent two different
 * chrome.exe processes, so a server that is itself a known signed browser passes.
 * An untrusted server, such as a malware puppet, fails.
 *
 * @param handle       The stdin or stdout handle to check.
 * @param expectedPid  The resolved parent PID this handle should trace to.
 * @return true when the handle is a pipe from the parent or a signed browser.
 */
bool isStdHandleFromProcess(HANDLE handle, DWORD expectedPid);

}  // namespace seal::browser_host
