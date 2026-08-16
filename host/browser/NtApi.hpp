#pragma once

/**
 * @brief Runtime-resolved ntdll entry points and their private types.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * seal-browser proves its stdio pipes came from a real browser, and not from a
 * re-parented puppet, by walking the claimed parent's handle table and matching an
 * entry against its own stdin pipe object. That needs two NT-private calls,
 * NtQuerySystemInformation and NtQueryObject, plus the undocumented structs they
 * fill. Both resolve at runtime through GetProcAddress, so the binary carries no
 * ntdll import. The loaders return nullptr when the export is missing and callers
 * fail closed.
 *
 * The struct and field names mirror the OS ABI layout verbatim. Do not rename them
 * to the project's naming convention.
 */

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <winternl.h>

namespace nt
{

// winternl.h declares neither info class nor this status, hence the raw values.
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
