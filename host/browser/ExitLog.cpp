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

// Append a timestamped exit line to
// %LOCALAPPDATA%\seal\bridge-host-last-exit.log so host-only failures
// (argv-origin, parent-pid, pipe enumeration) can be diagnosed without
// the host's stderr -- Chrome captures stderr but doesn't surface it in
// the SW console (the extension just sees "Native host has exited.").
//
// Best-effort; never fail-loud, so a logging error can't mask the real
// exit cause.
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

// One-line diag to stderr AND the exit log before exit. Stderr is the
// browser's channel but never reaches the SW console; the file is what
// the operator actually reads.
void emitExitDiag(int code, const char* reason)
{
    std::fprintf(stderr, "[seal-browser] exit=%d reason=%s\n", code, reason);
    std::fflush(stderr);
    writeExitLog(code, reason);
}

}  // namespace seal::browser_host
