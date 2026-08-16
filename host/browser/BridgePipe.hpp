#pragma once

/**
 * @brief Locate and signer-verify the seal bridge's named pipe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The host-verifies-the-bridge half of the mutual-authentication model: the server
 * process behind a `\\.\pipe\seal-fill-*` candidate has to carry the same publisher
 * SPKI thumbprint as this host binary. A same-user attacker can pre-create a pipe
 * that sorts earlier in the enumeration, but cannot sign it with seal's key. The
 * thumbprint identifies the publisher and not the file, so the check works only
 * because a release signs seal.exe and seal-browser.exe with the same key.
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
 * Scans a bounded number of candidate pipes, flips each to message mode, and accepts
 * the first whose server process shares @p expectedIdentity. An empty
 * @p expectedIdentity means an unsigned build, where the first reachable candidate
 * wins and the server signer check is skipped.
 *
 * Blocking. The scan tries at most 32 candidates, and every candidate that reports
 * `ERROR_PIPE_BUSY` costs up to a 5 s `WaitNamedPipeW`, so a namespace full of busy
 * decoys can delay the answer by minutes before the scan gives up.
 *
 * @param expectedIdentity  This host's own publisher SPKI thumbprint, or empty in an
 *                          unsigned build.
 * @return An open overlapped pipe handle owned by the caller, or INVALID_HANDLE_VALUE
 *         when no candidate matched.
 */
HANDLE openBridgePipe(const std::string& expectedIdentity);

}  // namespace seal::browser_host
