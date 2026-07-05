#pragma once

/**
 * @brief Locate and signer-verify the seal bridge's named pipe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The "we verify the bridge" half of the mutual-authentication model: every
 * `\\.\pipe\seal-fill-*` candidate's server process must carry seal.exe's
 * Authenticode signer identity, so a same-user attacker who pre-creates a
 * sorting-earlier pipe cannot impersonate the bridge.
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
 * @brief Open the first `seal-fill-*` pipe whose server matches our signer.
 *
 * Scans the candidate pipes (bounded), flips each to message mode, and accepts
 * the one whose server process shares @p expectedIdentity (seal.exe's SPKI
 * thumbprint). An empty @p expectedIdentity is dev mode: the first reachable
 * candidate wins.
 *
 * @param expectedIdentity  seal.exe's signer identity, or empty in dev builds.
 * @return An open overlapped pipe handle, or INVALID_HANDLE_VALUE if none matched.
 */
HANDLE openBridgePipe(const std::string& expectedIdentity);

}  // namespace seal::browser_host
