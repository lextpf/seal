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

}  // namespace

// Read one Chrome native-messaging frame from stdin: 4-byte LE length +
// UTF-8 JSON. Empty vector on EOF, oversized, or read error.
std::vector<char> readNativeMessage(HANDLE in)
{
    std::array<unsigned char, 4> lenBytes{};
    if (!readExact(in, lenBytes.data(), 4))
    {
        return {};
    }
    const DWORD len = static_cast<DWORD>(lenBytes[0]) | (static_cast<DWORD>(lenBytes[1]) << 8) |
                      (static_cast<DWORD>(lenBytes[2]) << 16) |
                      (static_cast<DWORD>(lenBytes[3]) << 24);
    if (len == 0 || len > kMaxMessageBytes)
    {
        return {};
    }
    std::vector<char> payload(len);
    if (!readExact(in, payload.data(), len))
    {
        return {};
    }
    return payload;
}

// Length-prefixed write to the bridge pipe (overlapped, message mode).
bool writePipeMessage(HANDLE pipe, HANDLE ev, const std::vector<char>& payload)
{
    const DWORD len = static_cast<DWORD>(payload.size());
    std::array<unsigned char, 4> lenBytes{static_cast<unsigned char>(len & 0xff),
                                          static_cast<unsigned char>((len >> 8) & 0xff),
                                          static_cast<unsigned char>((len >> 16) & 0xff),
                                          static_cast<unsigned char>((len >> 24) & 0xff)};
    if (!overlappedPipeWrite(pipe, ev, lenBytes.data(), 4))
    {
        return false;
    }
    return overlappedPipeWrite(pipe, ev, payload.data(), len);
}

// Length-prefixed read from the bridge pipe (overlapped, shutdown-aware).
std::vector<char> readPipeMessage(HANDLE pipe, HANDLE ev, HANDLE shutdownEvent)
{
    std::array<unsigned char, 4> lenBytes{};
    if (!overlappedPipeRead(pipe, ev, shutdownEvent, lenBytes.data(), 4))
    {
        return {};
    }
    const DWORD len = static_cast<DWORD>(lenBytes[0]) | (static_cast<DWORD>(lenBytes[1]) << 8) |
                      (static_cast<DWORD>(lenBytes[2]) << 16) |
                      (static_cast<DWORD>(lenBytes[3]) << 24);
    if (len == 0 || len > kMaxMessageBytes)
    {
        return {};
    }
    std::vector<char> payload(len);
    if (!overlappedPipeRead(pipe, ev, shutdownEvent, payload.data(), len))
    {
        return {};
    }
    return payload;
}

// Forward one bridge payload to stdout (extension consumes the handshake).
bool writeNativeMessage(HANDLE out, const std::vector<char>& payload)
{
    const DWORD len = static_cast<DWORD>(payload.size());
    std::array<unsigned char, 4> lenBytes{static_cast<unsigned char>(len & 0xff),
                                          static_cast<unsigned char>((len >> 8) & 0xff),
                                          static_cast<unsigned char>((len >> 16) & 0xff),
                                          static_cast<unsigned char>((len >> 24) & 0xff)};
    if (!writeAll(out, lenBytes.data(), 4))
    {
        return false;
    }
    return writeAll(out, payload.data(), len);
}

}  // namespace seal::browser_host
