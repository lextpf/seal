#pragma once

/**
 * @brief Relay opaque payloads with 4-byte little-endian lengths.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Stdio blocks; the duplex pipe uses overlapped I/O. Send the prefix and payload
 * as separate pipe messages. A read buffer smaller than one message yields
 * ERROR_MORE_DATA, which these readers treat as a failure.
 * Readers treat zero, oversized (>4096 bytes), or truncated frames as end-of-stream.
 * Writers rely on callers supplying payloads from capped reads.
 * Payload vectors use ordinary memory and are not wiped by these helpers.
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
 * @fn std::vector<char> readNativeMessage(HANDLE in)
 * @brief Block for one browser frame.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return Empty on EOF, invalid length, or read failure.
 */
std::vector<char> readNativeMessage(HANDLE in);

/**
 * @fn bool writeNativeMessage(HANDLE out, const std::vector<char>& payload)
 * @brief Send a length-prefixed frame to the extension.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @return `true` only for a complete write.
 */
bool writeNativeMessage(HANDLE out, const std::vector<char>& payload);

/**
 * @fn bool writePipeMessage(HANDLE pipe, HANDLE ev, const std::vector<char>& payload)
 * @brief Send a frame over the overlapped duplex pipe.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @param ev Caller-owned manual-reset event; write direction only.
 * @return `true` only for a complete write.
 */
bool writePipeMessage(HANDLE pipe, HANDLE ev, const std::vector<char>& payload);

/**
 * @fn std::vector<char> readPipeMessage(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent)
 * @brief Read a frame with deterministic shutdown wakeup.
 * @author Alex (<https://github.com/lextpf>)
 *
 * @param ev Caller-owned manual-reset event; read direction only.
 * @param shutdownEvent Signal to cancel a pending read; completion may win the race.
 * @return Empty on EOF, shutdown, or error; test shutdownEvent to distinguish shutdown.
 */
std::vector<char> readPipeMessage(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent);

}  // namespace seal::browser_host
