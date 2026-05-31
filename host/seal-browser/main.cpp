// seal-browser - native-messaging stdio <-> named-pipe bridge.
//
// Spawned by the browser when the WebExtension calls connectNative().
// Reads Chrome native-messaging messages from stdin and forwards.
//
// Security model - mutual authentication, defence in depth:
//
//   Pipe ACL
//     Bridge grants only the current-user SID; cross-user connections
//     are refused at the OS layer.
//
//   We verify the bridge
//     Every `seal-fill-*` candidate is re-checked via
//     GetNamedPipeServerProcessId + WinVerifyTrust and refused unless the
//     server's signer matches ours. Defeats pipe-name impersonation by a
//     same-user attacker who pre-creates `seal-fill-0000...`.
//
//   The bridge verifies us
//     WinVerifyTrust + signer match on our path, plus a parent-is-signed-
//     browser check -- closes the "puppet a signed host" hole where
//     malware spawns this binary with attacker-controlled stdin.
//
//   Per-connection handshake
//     Bridge sends a token; we echo it. Stale tokens from prior seal runs
//     cannot connect because the pipe name itself embeds the token hash.
//
//   Launch-origin gate
//     argv[1] must be a native-messaging origin
//     (`chrome-extension://<pinned-id>/` or `moz-extension://...`).
//     Direct exec by malware never carries this argument.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <shellapi.h>
#include <winternl.h>

#include "../../src/SignerUtils.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cwctype>
#include <string>
#include <string_view>
#include <vector>

// NT-private types resolved at runtime via GetProcAddress (no ntdll
// import). Used to enumerate the parent's handles and match one against
// our stdin's pipe name -- a real browser launch owns both pipe ends; a
// puppet doesn't.
namespace nt
{

constexpr SYSTEM_INFORMATION_CLASS SystemExtendedHandleInformation =
    static_cast<SYSTEM_INFORMATION_CLASS>(64);
constexpr OBJECT_INFORMATION_CLASS ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);
constexpr NTSTATUS STATUS_INFO_LENGTH_MISMATCH_VALUE = static_cast<NTSTATUS>(0xC0000004);

struct SystemHandleTableEntryEx
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SystemHandleInformationEx
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SystemHandleTableEntryEx Handles[1];
};

struct ObjectNameInformationStruct
{
    UNICODE_STRING Name;
    WCHAR NameBuffer[1];
};

using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

inline NtQuerySystemInformationFn loadQuerySystem()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return nullptr;
    }
    return reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));
}

inline NtQueryObjectFn loadQueryObject()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr)
    {
        return nullptr;
    }
    return reinterpret_cast<NtQueryObjectFn>(GetProcAddress(ntdll, "NtQueryObject"));
}

}  // namespace nt

namespace
{

constexpr DWORD kMaxMessageBytes = 4096;
constexpr DWORD kConnectTimeoutMs = 5000;
// Candidate-pipe scan cap; only one should match our signer.
constexpr int kPipeBruteForceLimit = 32;

// Pinned Chrome extension origin (deterministic from the manifest "key";
// see src/CliModes.cpp kSealExtensionIdAscii). Update in lockstep if the
// key is ever regenerated.
constexpr std::wstring_view kPinnedChromeOrigin =
    L"chrome-extension://dfjclelhkideboildnjihgildihjjmdo/";
constexpr std::wstring_view kFirefoxOriginPrefix = L"moz-extension://";

// Wide prefix compare; we control the origin strings so case-sensitivity
// is fine.
bool hasPrefix(std::wstring_view full, std::wstring_view prefix) noexcept
{
    if (full.size() < prefix.size())
    {
        return false;
    }
    return full.compare(0, prefix.size(), prefix) == 0;
}

// Kernel-level pipe name for a handle. CreatePipe() pipes get an internal
// name like `\Device\NamedPipe\Win32Pipes.<tid>.<seq>`; both ends share
// it. Empty on any failure -- callers treat empty as "unverifiable" and
// fall back to the surrounding policy (fail closed in production, soft-
// pass in dev).
std::wstring getHandlePipeName(HANDLE handle)
{
    static const nt::NtQueryObjectFn queryObject = nt::loadQueryObject();
    if (queryObject == nullptr || handle == nullptr || handle == INVALID_HANDLE_VALUE)
    {
        return {};
    }
    std::vector<BYTE> buf(2048);
    ULONG returned = 0;
    NTSTATUS status = queryObject(
        handle, nt::ObjectNameInformation, buf.data(), static_cast<ULONG>(buf.size()), &returned);
    if (status == nt::STATUS_INFO_LENGTH_MISMATCH_VALUE)
    {
        buf.resize(returned == 0 ? buf.size() * 2 : returned);
        status = queryObject(handle,
                             nt::ObjectNameInformation,
                             buf.data(),
                             static_cast<ULONG>(buf.size()),
                             &returned);
    }
    if (status < 0 || returned < sizeof(UNICODE_STRING))
    {
        return {};
    }
    const auto* info = reinterpret_cast<nt::ObjectNameInformationStruct*>(buf.data());
    if (info->Name.Buffer == nullptr || info->Name.Length == 0)
    {
        return {};
    }
    return std::wstring(info->Name.Buffer, info->Name.Length / sizeof(wchar_t));
}

// Prove the parent owns the other end of `handle`. Both pipe ends share
// an NT object name; the parent's handle table contains that object IFF
// the parent created the pipe. Defeats puppet attacks that re-parent via
// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. Best-effort; false on failure.
bool parentOwnsPipe(DWORD parentPid, const std::wstring& expectedPipeName)
{
    if (expectedPipeName.empty() || parentPid == 0)
    {
        return false;
    }
    static const nt::NtQuerySystemInformationFn querySystem = nt::loadQuerySystem();
    if (querySystem == nullptr)
    {
        return false;
    }

    HANDLE parentHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, parentPid);
    if (parentHandle == nullptr)
    {
        return false;
    }

    // SystemExtendedHandleInformation: every handle in every process.
    // Start at 1 MB; resize-and-retry on STATUS_INFO_LENGTH_MISMATCH.
    std::vector<BYTE> buf(1 * 1024 * 1024);
    ULONG returned = 0;
    NTSTATUS status = nt::STATUS_INFO_LENGTH_MISMATCH_VALUE;
    for (int attempt = 0; attempt < 6 && status == nt::STATUS_INFO_LENGTH_MISMATCH_VALUE; ++attempt)
    {
        status = querySystem(nt::SystemExtendedHandleInformation,
                             buf.data(),
                             static_cast<ULONG>(buf.size()),
                             &returned);
        if (status == nt::STATUS_INFO_LENGTH_MISMATCH_VALUE)
        {
            buf.resize(buf.size() * 2);
        }
    }
    if (status < 0)
    {
        CloseHandle(parentHandle);
        return false;
    }

    const auto* info = reinterpret_cast<nt::SystemHandleInformationEx*>(buf.data());
    bool found = false;
    for (ULONG_PTR i = 0; i < info->NumberOfHandles && !found; ++i)
    {
        const auto& entry = info->Handles[i];
        if (entry.UniqueProcessId != parentPid)
        {
            continue;
        }
        // Duplicate into our process so we can query the name; skip
        // protected / pseudo handles where DuplicateHandle fails.
        HANDLE dup = nullptr;
        if (!DuplicateHandle(parentHandle,
                             reinterpret_cast<HANDLE>(entry.HandleValue),
                             GetCurrentProcess(),
                             &dup,
                             0,
                             FALSE,
                             DUPLICATE_SAME_ACCESS))
        {
            continue;
        }
        // Fast filter: only pipes can match. GetFileType is much cheaper
        // than NtQueryObject(ObjectNameInformation).
        if (GetFileType(dup) == FILE_TYPE_PIPE)
        {
            const std::wstring dupName = getHandlePipeName(dup);
            if (!dupName.empty() && dupName == expectedPipeName)
            {
                found = true;
            }
        }
        CloseHandle(dup);
    }
    CloseHandle(parentHandle);
    return found;
}

// Verify a stdio handle is a pipe from a trusted process. Soft-passes:
// (1) anonymous pipes -- GetNamedPipeServerProcessId fails, bridge-side
// parent check still applies; (2) Chrome's split-process model where the
// server (browser) and our parent (utility) are different chrome.exe --
// accept iff the server is itself a known signed browser. Untrusted
// servers (malware puppets) still fail.
bool isStdHandleFromProcess(HANDLE handle, DWORD expectedPid)
{
    if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    if (GetFileType(handle) != FILE_TYPE_PIPE)
    {
        return false;
    }
    DWORD serverPid = 0;
    if (!GetNamedPipeServerProcessId(handle, &serverPid))
    {
        return true;  // anonymous pipe -- soft-pass (see header comment).
    }
    if (serverPid == 0 || serverPid == expectedPid)
    {
        return true;
    }
    // Server diverged from parent -- accept only if it's a known signed
    // browser (Chrome's utility-process split).
    const std::wstring serverPath = seal::signer::resolveProcessPath(serverPid);
    if (serverPath.empty())
    {
        return false;
    }
    if (!seal::signer::isKnownBrowserImage(serverPath))
    {
        return false;
    }
    if (!seal::signer::winVerifyTrustOk(serverPath))
    {
        return false;
    }
    return true;
}

// argv[1] must be the native-messaging origin the browser passes:
// Chrome -> `chrome-extension://<id>/`, Firefox -> `moz-extension://<uuid>/`.
// Any other shape (raw exec, malware spawn) is rejected before we touch
// the bridge pipe.
bool isLegitimateLaunchOrigin()
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr)
    {
        return false;
    }
    bool ok = false;
    if (argc >= 2 && argv[1] != nullptr)
    {
        const std::wstring_view origin(argv[1]);
        if (origin == kPinnedChromeOrigin)
        {
            ok = true;
        }
        else if (hasPrefix(origin, kFirefoxOriginPrefix))
        {
            // Firefox uses a per-install UUID, so the scheme is the
            // strongest claim we can make here. The bridge still
            // requires the parent to be a signed firefox.exe.
            ok = true;
        }
    }
    LocalFree(static_cast<HLOCAL>(argv));
    return ok;
}

// Open the seal bridge pipe. Each `seal-fill-*` candidate's server must
// match our publisher's SPKI thumbprint -- a same-user attacker can pre-
// create a sorting-earlier pipe but cannot sign with seal's key. Dev mode
// (empty expectedIdentity) accepts the first pipe (mirrors bridge M6).
HANDLE openBridgePipe(const std::string& expectedIdentity)
{
    WIN32_FIND_DATAW data{};
    HANDLE find = FindFirstFileW(L"\\\\.\\pipe\\seal-fill-*", &data);
    if (find == INVALID_HANDLE_VALUE)
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE accepted = INVALID_HANDLE_VALUE;
    int tried = 0;
    do
    {
        if (++tried > kPipeBruteForceLimit)
        {
            break;
        }
        std::wstring fullName = L"\\\\.\\pipe\\";
        fullName += data.cFileName;

        HANDLE pipe = CreateFileW(
            fullName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE)
        {
            const DWORD err = GetLastError();
            if (err == ERROR_PIPE_BUSY)
            {
                if (WaitNamedPipeW(fullName.c_str(), kConnectTimeoutMs))
                {
                    pipe = CreateFileW(fullName.c_str(),
                                       GENERIC_READ | GENERIC_WRITE,
                                       0,
                                       nullptr,
                                       OPEN_EXISTING,
                                       0,
                                       nullptr);
                }
            }
            if (pipe == INVALID_HANDLE_VALUE)
            {
                continue;
            }
        }

        // Default client side is BYTE mode; flip to message mode so framed
        // reads/writes are atomic. Failure -> not a real seal bridge.
        DWORD mode = PIPE_READMODE_MESSAGE;
        if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr))
        {
            CloseHandle(pipe);
            continue;
        }

        // Signer gate. Without it, a same-user attacker who pre-created a
        // matching pipe would intercept the handshake + click reports.
        DWORD serverPid = 0;
        if (!GetNamedPipeServerProcessId(pipe, &serverPid) || serverPid == 0)
        {
            CloseHandle(pipe);
            continue;
        }
        if (!expectedIdentity.empty())
        {
            const std::wstring serverPath = seal::signer::resolveProcessPath(serverPid);
            if (serverPath.empty() || !seal::signer::winVerifyTrustOk(serverPath))
            {
                CloseHandle(pipe);
                continue;
            }
            const std::string serverIdentity =
                seal::signer::extractSignerIdentityFromFile(serverPath);
            if (serverIdentity.empty() || serverIdentity != expectedIdentity)
            {
                CloseHandle(pipe);
                continue;
            }
        }

        accepted = pipe;
        break;
    } while (FindNextFileW(find, &data));

    FindClose(find);
    return accepted;
}

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

// Length-prefixed write to the bridge pipe. Pipe is in message mode.
bool writePipeMessage(HANDLE pipe, const std::vector<char>& payload)
{
    const DWORD len = static_cast<DWORD>(payload.size());
    std::array<unsigned char, 4> lenBytes{static_cast<unsigned char>(len & 0xff),
                                          static_cast<unsigned char>((len >> 8) & 0xff),
                                          static_cast<unsigned char>((len >> 16) & 0xff),
                                          static_cast<unsigned char>((len >> 24) & 0xff)};
    if (!writeAll(pipe, lenBytes.data(), 4))
    {
        return false;
    }
    return writeAll(pipe, payload.data(), len);
}

// Length-prefixed read from the bridge pipe.
std::vector<char> readPipeMessage(HANDLE pipe)
{
    std::array<unsigned char, 4> lenBytes{};
    if (!readExact(pipe, lenBytes.data(), 4))
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
    if (!readExact(pipe, payload.data(), len))
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

}  // namespace

int wmain()
{
    if (!isLegitimateLaunchOrigin())
    {
        // Direct exec by malware lands here; the browser's launch always
        // passes the extension origin as argv[1].
        emitExitDiag(7, "bad_launch_origin");
        return 7;
    }

    HANDLE stdinHandle = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (stdinHandle == INVALID_HANDLE_VALUE || stdoutHandle == INVALID_HANDLE_VALUE)
    {
        emitExitDiag(1, "std_handle_invalid");
        return 1;
    }

    // Parent PID + stdio-server check (see isStdHandleFromProcess for
    // the soft-pass rules). OS-derived parent PID works without signing,
    // so dev/unsigned builds enforce this too.
    const DWORD ownPid = GetCurrentProcessId();
    const DWORD parentPid = seal::signer::resolveParentPid(ownPid);
    if (parentPid == 0)
    {
        emitExitDiag(8, "parent_pid_unknown");
        return 8;
    }
    if (!isStdHandleFromProcess(stdinHandle, parentPid))
    {
        emitExitDiag(9, "stdin_server_check_failed");
        return 9;
    }
    if (!isStdHandleFromProcess(stdoutHandle, parentPid))
    {
        emitExitDiag(10, "stdout_server_check_failed");
        return 10;
    }

    // SPKI thumbprint of our own publisher cert; empty in dev builds, in
    // which case openBridgePipe degrades to "first candidate wins".
    const std::string ownIdentity = seal::signer::readOwnSignerIdentity();
    const bool inProductionMode = !ownIdentity.empty();

    // Strict ownership check: enumerate the parent's handles and confirm
    // one points at our stdin's kernel pipe object. Closes the puppet
    // hole that isStdHandleFromProcess's anonymous-pipe soft-pass leaves
    // open. Production hard-fails; dev logs and continues.
    {
        const std::wstring stdinPipeName = getHandlePipeName(stdinHandle);
        const bool stdinOwnershipProven =
            !stdinPipeName.empty() && parentOwnsPipe(parentPid, stdinPipeName);
        if (!stdinOwnershipProven)
        {
            if (inProductionMode)
            {
                emitExitDiag(11, "stdin_parent_ownership_unverified");
                return 11;
            }
            // Dev: log only and continue; bridge signer + parent-image
            // checks remain in effect.
            writeExitLog(0, "dev_mode_stdin_ownership_skipped");
        }
        const std::wstring stdoutPipeName = getHandlePipeName(stdoutHandle);
        const bool stdoutOwnershipProven =
            !stdoutPipeName.empty() && parentOwnsPipe(parentPid, stdoutPipeName);
        if (!stdoutOwnershipProven)
        {
            if (inProductionMode)
            {
                emitExitDiag(12, "stdout_parent_ownership_unverified");
                return 12;
            }
            writeExitLog(0, "dev_mode_stdout_ownership_skipped");
        }
    }

    HANDLE pipe = openBridgePipe(ownIdentity);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        // No seal running, or no candidate pipe with a trusted signer.
        // Exit; browser respawns us on the next message.
        emitExitDiag(2, "bridge_pipe_not_found");
        return 2;
    }

    // Handshake: bridge -> extension.
    {
        std::vector<char> hs = readPipeMessage(pipe);
        if (hs.empty())
        {
            CloseHandle(pipe);
            emitExitDiag(3, "bridge_handshake_read_failed");
            return 3;
        }
        if (!writeNativeMessage(stdoutHandle, hs))
        {
            CloseHandle(pipe);
            emitExitDiag(4, "stdout_handshake_write_failed");
            return 4;
        }
    }

    // Echo: extension -> bridge.
    {
        std::vector<char> echo = readNativeMessage(stdinHandle);
        if (echo.empty())
        {
            CloseHandle(pipe);
            emitExitDiag(5, "stdin_handshake_echo_failed");
            return 5;
        }
        if (!writePipeMessage(pipe, echo))
        {
            CloseHandle(pipe);
            emitExitDiag(6, "bridge_handshake_echo_write_failed");
            return 6;
        }
    }

    // Main loop: extension -> bridge, no parsing (bridge validates strictly).
    const char* loopExitReason = "stdin_eof";  // browser closed our stdin
    while (true)
    {
        std::vector<char> msg = readNativeMessage(stdinHandle);
        if (msg.empty())
        {
            break;
        }
        if (!writePipeMessage(pipe, msg))
        {
            loopExitReason = "bridge_write_failed";
            break;
        }
    }

    CloseHandle(pipe);
    // Log the happy path too -- a clean-exit line is positive evidence
    // that the host launched, ran, and wasn't killed at a gate.
    writeExitLog(0, loopExitReason);
    return 0;
}
