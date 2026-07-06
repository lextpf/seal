#include "MessageFraming.hpp"

#include <array>
#include <vector>

namespace seal::browser_host
{
namespace
{

constexpr DWORD kMaxMessageBytes = 4096;

bool readExact(HANDLE h, void* buf, DWORD n)
{
    DWORD total = 0;
    auto* p = static_cast<char*>(buf);
    while (total < n)
    {
        DWORD got = 0;
        if (!ReadFile(h, p + total, n - total, &got, nullptr))
        {
            return false;
        }
        if (got == 0)
        {
            return false;
        }
        total += got;
    }
    return true;
}

bool writeAll(HANDLE h, const void* buf, DWORD n)
{
    DWORD total = 0;
    const auto* p = static_cast<const char*>(buf);
    while (total < n)
    {
        DWORD wrote = 0;
        if (!WriteFile(h, p + total, n - total, &wrote, nullptr))
        {
            return false;
        }
        total += wrote;
    }
    return true;
}

// Overlapped write of exactly n bytes to the duplex bridge pipe. `ev` is a
// caller-owned manual-reset event dedicated to the write direction, so a
// concurrent overlapped read on the same handle never aliases it.
bool overlappedPipeWrite(HANDLE pipe, HANDLE ev, const void* buf, DWORD n)
{
    DWORD total = 0;
    const auto* p = static_cast<const char*>(buf);
    while (total < n)
    {
        OVERLAPPED ov{};
        ov.hEvent = ev;
        ResetEvent(ev);
        DWORD wrote = 0;
        if (!WriteFile(pipe, p + total, n - total, &wrote, &ov))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                return false;
            }
            if (!GetOverlappedResult(pipe, &ov, &wrote, TRUE))
            {
                return false;
            }
        }
        if (wrote == 0)
        {
            return false;
        }
        total += wrote;
    }
    return true;
}

// Overlapped read of exactly n bytes from the duplex bridge pipe, waking early
// when `shutdownEvent` is signaled -- deterministic teardown with no CancelIoEx
// timing race and no file-object-lock serialization against concurrent writes.
bool overlappedPipeRead(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent, void* buf, DWORD n)
{
    DWORD total = 0;
    auto* p = static_cast<char*>(buf);
    while (total < n)
    {
        OVERLAPPED ov{};
        ov.hEvent = ev;
        ResetEvent(ev);
        DWORD got = 0;
        if (!ReadFile(pipe, p + total, n - total, &got, &ov))
        {
            if (GetLastError() != ERROR_IO_PENDING)
            {
                return false;
            }
            const HANDLE waits[2] = {ev, shutdownEvent};
            const DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (w != WAIT_OBJECT_0)
            {
                CancelIoEx(pipe, &ov);
                GetOverlappedResult(pipe, &ov, &got, TRUE);  // drain the cancel
                return false;                                // shutdown / wait error
            }
            if (!GetOverlappedResult(pipe, &ov, &got, TRUE))
            {
                return false;
            }
        }
        if (got == 0)
        {
            return false;  // EOF
        }
        total += got;
    }
    return true;
}

// Little-endian 4-byte length codec shared by both wire framings.
std::array<unsigned char, 4> encodeLen(DWORD len)
{
    return {static_cast<unsigned char>(len & 0xff),
            static_cast<unsigned char>((len >> 8) & 0xff),
            static_cast<unsigned char>((len >> 16) & 0xff),
            static_cast<unsigned char>((len >> 24) & 0xff)};
}

DWORD decodeLen(const std::array<unsigned char, 4>& b)
{
    return static_cast<DWORD>(b[0]) | (static_cast<DWORD>(b[1]) << 8) |
           (static_cast<DWORD>(b[2]) << 16) | (static_cast<DWORD>(b[3]) << 24);
}

// Read one length-prefixed frame via `read(buf, n) -> bool`. Empty vector on
// EOF / oversized / read error -- the contract both public readers share.
template <typename ReadFn>
std::vector<char> readFrame(ReadFn read)
{
    std::array<unsigned char, 4> lenBytes{};
    if (!read(lenBytes.data(), 4))
    {
        return {};
    }
    const DWORD len = decodeLen(lenBytes);
    if (len == 0 || len > kMaxMessageBytes)
    {
        return {};
    }
    std::vector<char> payload(len);
    if (!read(payload.data(), len))
    {
        return {};
    }
    return payload;
}

// Write one length-prefixed frame via `write(buf, n) -> bool`.
template <typename WriteFn>
bool writeFrame(WriteFn write, const std::vector<char>& payload)
{
    const DWORD len = static_cast<DWORD>(payload.size());
    const std::array<unsigned char, 4> lenBytes = encodeLen(len);
    if (!write(lenBytes.data(), 4))
    {
        return false;
    }
    return write(payload.data(), len);
}

}  // namespace

// Read one Chrome native-messaging frame from stdin: 4-byte LE length +
// UTF-8 JSON. Empty vector on EOF, oversized, or read error.
std::vector<char> readNativeMessage(HANDLE in)
{
    return readFrame([in](void* buf, DWORD n) { return readExact(in, buf, n); });
}

// Forward one bridge payload to stdout (extension consumes the handshake).
bool writeNativeMessage(HANDLE out, const std::vector<char>& payload)
{
    return writeFrame([out](const void* buf, DWORD n) { return writeAll(out, buf, n); }, payload);
}

// Length-prefixed write to the bridge pipe (overlapped, message mode).
bool writePipeMessage(HANDLE pipe, HANDLE ev, const std::vector<char>& payload)
{
    return writeFrame([pipe, ev](const void* buf, DWORD n)
                      { return overlappedPipeWrite(pipe, ev, buf, n); },
                      payload);
}

// Length-prefixed read from the bridge pipe (overlapped, shutdown-aware).
std::vector<char> readPipeMessage(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent)
{
    return readFrame([pipe, ev, shutdownEvent](void* buf, DWORD n)
                     { return overlappedPipeRead(pipe, ev, shutdownEvent, buf, n); });
}

}  // namespace seal::browser_host
