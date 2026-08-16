#pragma once

/**
 * @brief Length-prefixed message framing for the stdio and pipe channels.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * seal-browser is a parse-free relay, so these four calls move opaque frames of
 * 4-byte little-endian length plus payload. The stdio side is blocking; the bridge
 * pipe is overlapped, which keeps the reverse reader and the forward writer from
 * serializing on one synchronous file object.
 *
 * The bridge pipe runs in message mode (`PIPE_TYPE_MESSAGE` / `PIPE_READMODE_MESSAGE`),
 * so one frame travels as two messages: the 4-byte prefix, then the payload. A
 * message-mode read that asks for fewer bytes than the message holds fails with
 * `ERROR_MORE_DATA`, which readPipeMessage reports as end-of-stream. Both ends must
 * keep the prefix and the payload in separate I/O calls; see
 * `BrowserBridge::Impl::writeFramedMessage` in seal.exe.
 *
 * The two readers enforce the 4 KB frame cap shared with the bridge and report a
 * zero, oversized, or truncated frame as end-of-stream, so an empty result always
 * means "stop relaying". The writers send the payload they are given: they only
 * ever carry a frame that already came through a capped read.
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
 * @brief Read one native-messaging frame from stdin. Blocks until the browser sends.
 *
 * @param in  Stdin handle.
 * @return The payload bytes, or empty on end-of-file, oversize, or read error.
 */
std::vector<char> readNativeMessage(HANDLE in);

/**
 * @brief Write one frame to stdout for the extension to consume.
 *
 * @param out      Stdout handle.
 * @param payload  Frame body; this call prepends the 4-byte length prefix.
 * @return true on a complete write.
 */
bool writeNativeMessage(HANDLE out, const std::vector<char>& payload);

/**
 * @brief Length-prefixed overlapped write to the bridge pipe.
 *
 * @param pipe     Overlapped duplex pipe handle.
 * @param ev       Manual-reset event used by the write direction alone. Sharing it
 *                 with the read direction corrupts both completions.
 * @param payload  Frame body.
 * @return true on a complete write.
 */
bool writePipeMessage(HANDLE pipe, HANDLE ev, const std::vector<char>& payload);

/**
 * @brief Length-prefixed overlapped read from the bridge pipe, shutdown-aware.
 *
 * @param pipe           Overlapped duplex pipe handle.
 * @param ev             Manual-reset event used by the read direction alone.
 * @param shutdownEvent  Signalled to wake a blocked read at teardown.
 * @return The payload bytes, or empty on end-of-file, shutdown, or error. The
 *         caller separates shutdown from a dead pipe by testing shutdownEvent.
 */
std::vector<char> readPipeMessage(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent);

}  // namespace seal::browser_host
