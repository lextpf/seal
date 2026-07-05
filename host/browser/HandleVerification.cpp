#include "HandleVerification.hpp"

#include "../../src/SignerUtils.hpp"
#include "NtApi.hpp"

#include <vector>

namespace seal::browser_host
{

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

}  // namespace seal::browser_host
