#include "HandleVerification.hpp"

#include "../../src/SignerUtils.hpp"
#include "NtApi.hpp"

#include <vector>

namespace seal::browser_host
{

// Kernel object name of a pipe handle. A CreatePipe() pipe gets an internal name
// like `\Device\NamedPipe\Win32Pipes.<tid>.<seq>`, and both ends share it. Empty
// on any failure; the caller treats empty as unverifiable and applies its own
// policy (a signed build fails closed, an unsigned build continues).
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

// Prove the parent owns the other end of the pipe named `expectedPipeName`. Both
// ends share one NT object name, and that object appears in the parent's handle
// table only if the parent created the pipe. This defeats a puppet that claims a
// browser parent through PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. Best effort: any
// failure returns false.
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

    // SystemExtendedHandleInformation returns every handle in every process, so the
    // buffer starts at 1 MB and doubles on STATUS_INFO_LENGTH_MISMATCH. The attempt
    // cap bounds the growth when the system handle count keeps outrunning it.
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
        // Duplicate into this process to query the name. Protected and pseudo
        // handles fail DuplicateHandle and are skipped.
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
        // Fast filter: a pipe is the only type that can match, and GetFileType is
        // far cheaper than NtQueryObject(ObjectNameInformation) on every handle.
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

// Verify a stdio handle is a pipe served by a trusted process. Two soft-passes:
// an anonymous pipe fails GetNamedPipeServerProcessId and passes here, leaving the
// bridge-side parent check to carry the weight; Chrome's split-process model puts
// the server (browser) and the parent (utility) in different chrome.exe processes,
// so a server that is itself a known signed browser passes. An untrusted server,
// such as a malware puppet, fails.
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
        return true;  // anonymous pipe: soft-pass, see the comment above.
    }
    if (serverPid == 0 || serverPid == expectedPid)
    {
        return true;
    }
    // The server and the parent differ. Accept only a known browser image signed by
    // that browser's expected publisher, which is Chrome's utility-process split.
    const std::wstring serverPath = seal::signer::resolveProcessPath(serverPid);
    if (serverPath.empty())
    {
        return false;
    }
    if (!seal::signer::isTrustedBrowserImage(serverPath))
    {
        return false;
    }
    return true;
}

}  // namespace seal::browser_host
