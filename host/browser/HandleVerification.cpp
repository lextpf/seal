#include "HandleVerification.hpp"

#include "../../src/SignerUtils.hpp"
#include "NtApi.hpp"

#include <vector>

namespace seal::browser_host
{

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

    // Query all system handles; cap doubling retries if the handle count keeps growing.
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
        // Skip protected or pseudo handles that cannot be duplicated.
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
        // GetFileType cheaply rejects non-pipes before the NT object-name query.
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
        return true;  // The caller must verify parent ownership separately.
    }
    if (serverPid == 0 || serverPid == expectedPid)
    {
        return true;
    }
    // Allow the browser/utility process split only for a trusted browser server.
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
