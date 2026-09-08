#pragma once

/**
 * @brief Authenticate the bridge pipe server with the host publisher's SPKI identity.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Release signing must use the same key for seal.exe and seal-browser.exe.
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
 * @fn HANDLE openBridgePipe(const std::string& expectedIdentity)
 * @brief Open the first reachable pipe with a matching server signer.
 * @author Alex (<https://github.com/lextpf>)
 *
 * Scans at most 32 candidates. Each busy candidate may wait 5 s; many decoys can
 * delay or hide the real pipe. Multiple valid seal instances resolve by scan order.
 *
 * @param expectedIdentity Empty skips signer checks in unsigned development builds.
 * @return Caller-owned overlapped handle, or INVALID_HANDLE_VALUE if none matches.
 */
HANDLE openBridgePipe(const std::string& expectedIdentity);

}  // namespace seal::browser_host
