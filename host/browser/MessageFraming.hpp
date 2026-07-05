#pragma once

/**
 * @brief Length-prefixed message framing for the stdio and pipe channels.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * seal-browser is a parse-free relay: it moves opaque length-prefixed frames
 * between Chrome's native-messaging stdio (blocking) and the duplex bridge pipe
 * (overlapped, so the reverse reader and forward writer never serialize on one
 * synchronous file object). All four calls cap payloads at the shared 4 KB
 * limit and treat a bad length or short read as end-of-stream (empty vector or
 * false).
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <vector>

namespace seal::browser_host
{

/**
 * @brief Read one native-messaging frame from stdin (4-byte LE length + JSON).
 *
 * @param in  Stdin handle.
 * @return The payload bytes, or empty on EOF / oversize / read error.
 */
std::vector<char> readNativeMessage(HANDLE in);

/**
 * @brief Write one frame to stdout for the extension to consume.
 *
 * @param out      Stdout handle.
 * @param payload  Frame body; the 4-byte length prefix is prepended.
 * @return true on a complete write.
 */
bool writeNativeMessage(HANDLE out, const std::vector<char>& payload);

/**
 * @brief Length-prefixed overlapped write to the bridge pipe.
 *
 * @param pipe     Overlapped duplex pipe handle.
 * @param ev       Manual-reset event dedicated to the write direction.
 * @param payload  Frame body.
 * @return true on a complete write.
 */
bool writePipeMessage(HANDLE pipe, HANDLE ev, const std::vector<char>& payload);

/**
 * @brief Length-prefixed overlapped read from the bridge pipe, shutdown-aware.
 *
 * @param pipe           Overlapped duplex pipe handle.
 * @param ev             Manual-reset event dedicated to the read direction.
 * @param shutdownEvent  Signalled to wake a blocked read at teardown.
 * @return The payload bytes, or empty on EOF / shutdown / error.
 */
std::vector<char> readPipeMessage(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent);

}  // namespace seal::browser_host
