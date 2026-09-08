#pragma once

/**
 * @brief Verify stdio pipe ownership against the claimed browser parent.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * NT name and ownership query failures fail closed in signed builds.
 * isStdHandleFromProcess separately permits anonymous pipes with no queryable
 * server; parentOwnsPipe supplies the ownership check.
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
 * @fn std::wstring getHandlePipeName(HANDLE handle)
 * @brief Read the shared NT object name of a pipe's two ends.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return Empty on failure; signed callers fail closed, unsigned callers may continue.
 */
std::wstring getHandlePipeName(HANDLE handle);

/**
 * @fn bool parentOwnsPipe(DWORD parentPid, const std::wstring& expectedPipeName)
 * @brief Match a pipe object in the claimed parent's handle table.
 * @author Alex (<https://github.com/lextpf>)
 *
 * A claimed parent must hold a pipe with the same NT object name. The PID alone
 * is insufficient because PROC_THREAD_ATTRIBUTE_PARENT_PROCESS can set it.
 * The result is a snapshot; this function retains no parent handle.
 *
 * @return `false` on query failure, including protected parents.
 */
bool parentOwnsPipe(DWORD parentPid, const std::wstring& expectedPipeName);

/**
 * @fn bool isStdHandleFromProcess(HANDLE handle, DWORD expectedPid)
 * @brief Accept pipes served by the parent or a trusted browser process.
 * @author Alex (<https://github.com/lextpf>)
 *
 * An unqueryable pipe server passes here for anonymous pipes. A different
 * vendor-signed browser server permits the browser/utility process split.
 * parentOwnsPipe supplies the stricter ownership check.
 */
bool isStdHandleFromProcess(HANDLE handle, DWORD expectedPid);

}  // namespace seal::browser_host
