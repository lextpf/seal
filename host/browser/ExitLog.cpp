#include "ExitLog.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <string>

namespace seal::browser_host
{

// Append a timestamped exit line to %LOCALAPPDATA%\seal\bridge-host-last-exit.log.
// Chrome captures the host's stderr but does not show it in the service-worker
// console, where the extension only sees "Native host has exited.", so this file is
// the only way to diagnose a launch-origin, parent-PID, or pipe-enumeration failure.
//
// Best effort, and never fail loud: a logging error must not mask the real exit
// cause. Every failure path here returns without writing.
void writeExitLog(int code, const char* reason)
{
    wchar_t envBuf[MAX_PATH] = {};
    const DWORD envLen = GetEnvironmentVariableW(L"LOCALAPPDATA", envBuf, MAX_PATH);
    if (envLen == 0 || envLen >= MAX_PATH)
    {
        return;
    }
    std::wstring dir(envBuf, envLen);
    dir.append(L"\\seal");
    CreateDirectoryW(dir.c_str(), nullptr);  // no-op if it already exists

    const std::wstring path = dir + L"\\bridge-host-last-exit.log";
    HANDLE file = CreateFileW(path.c_str(),
                              FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr,
                              OPEN_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL,
                              nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return;
    }

    SYSTEMTIME st{};
    GetSystemTime(&st);
    char line[256] = {};
    const int n = std::snprintf(line,
                                sizeof(line),
                                "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ pid=%lu exit=%d reason=%s\n",
                                static_cast<unsigned>(st.wYear),
                                static_cast<unsigned>(st.wMonth),
                                static_cast<unsigned>(st.wDay),
                                static_cast<unsigned>(st.wHour),
                                static_cast<unsigned>(st.wMinute),
                                static_cast<unsigned>(st.wSecond),
                                static_cast<unsigned>(st.wMilliseconds),
                                GetCurrentProcessId(),
                                code,
                                reason ? reason : "<null>");
    if (n > 0)
    {
        DWORD written = 0;
        WriteFile(file, line, static_cast<DWORD>(n), &written, nullptr);
    }
    CloseHandle(file);
}

// One diagnostic line to stderr and to the exit log before the process exits.
// Stderr goes to the browser but never reaches the service-worker console, so the
// file is the copy an operator can read.
void emitExitDiag(int code, const char* reason)
{
    std::fprintf(stderr, "[seal-browser] exit=%d reason=%s\n", code, reason);
    std::fflush(stderr);
    writeExitLog(code, reason);
}

}  // namespace seal::browser_host
