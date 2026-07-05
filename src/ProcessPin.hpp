#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <cstdint>
#include <optional>
#include <string>

namespace seal::signer
{

/**
 * @class PinnedProcess
 * @brief Move-only RAII pin over a process handle that prevents PID recycling.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * Holds an OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) handle for the
 * object's lifetime. While the handle is open the kernel will not recycle the
 * PID, so pid()/imagePath() refer stably to the process that was pinned, and
 * alive() reports whether it is still running. Identity is anchored by the open
 * handle; alive() is consulted only for prompt teardown, never to decide which
 * process this is.
 */
class PinnedProcess
{
public:
    PinnedProcess() noexcept = default;

    /**
     * @brief Pin @p pid by opening a query handle. valid() is false on failure.
     * @param pid The process id to pin.
     */
    explicit PinnedProcess(DWORD pid) noexcept
        : m_Pid(pid),
          m_Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid))
    {
        // OpenProcess returns NULL (not INVALID_HANDLE_VALUE) on failure; the
        // INVALID_HANDLE_VALUE arm is defensive. valid() keys off nullptr only.
        // Capture GetLastError so a caller can distinguish ERROR_ACCESS_DENIED
        // (PPL / integrity boundary) from a gone process (ERROR_INVALID_PARAMETER).
        if (m_Handle == nullptr || m_Handle == INVALID_HANDLE_VALUE)
        {
            m_LastError = GetLastError();
            m_Handle = nullptr;
            m_Pid = 0;
        }
    }

    PinnedProcess(PinnedProcess&& o) noexcept
        : m_Pid(o.m_Pid),
          m_Handle(o.m_Handle),
          m_LastError(o.m_LastError)
    {
        o.m_Handle = nullptr;
        o.m_Pid = 0;
    }
    PinnedProcess& operator=(PinnedProcess&& o) noexcept
    {
        if (this != &o)
        {
            reset();
            m_Pid = o.m_Pid;
            m_Handle = o.m_Handle;
            m_LastError = o.m_LastError;
            o.m_Handle = nullptr;
            o.m_Pid = 0;
        }
        return *this;
    }
    PinnedProcess(const PinnedProcess&) = delete;
    PinnedProcess& operator=(const PinnedProcess&) = delete;
    ~PinnedProcess() { reset(); }

    /**
     * @brief Whether a live query handle is held.
     * @return true iff an OpenProcess handle is owned.
     */
    bool valid() const noexcept { return m_Handle != nullptr; }
    explicit operator bool() const noexcept { return valid(); }

    /**
     * @brief The pinned PID (0 if invalid). Stable while pinned: not recyclable.
     * @return The process id.
     */
    DWORD pid() const noexcept { return m_Pid; }

    /**
     * @brief OpenProcess failure code captured at construction (0 when valid()).
     * @return The GetLastError value from a failed construction, else 0.
     */
    DWORD lastError() const noexcept { return m_LastError; }

    /**
     * @brief On-disk image path queried from the held handle.
     * @return The image path, or an empty string if invalid or the query fails.
     */
    std::wstring imagePath() const
    {
        if (!valid())
        {
            return {};
        }
        wchar_t buf[MAX_PATH * 2]{};
        DWORD bufChars = sizeof(buf) / sizeof(buf[0]);
        if (!QueryFullProcessImageNameW(m_Handle, 0, buf, &bufChars))
        {
            return {};
        }
        return std::wstring(buf, bufChars);
    }

    /**
     * @brief Whether the pinned process is still running.
     * @return true iff GetExitCodeProcess yields STILL_ACTIVE.
     *
     * A process that genuinely exits with code 259 (== STILL_ACTIVE) reads as
     * alive - a Win32 footgun, but harmless here: a false "alive" only delays
     * teardown, identity is anchored by the open handle, and the subsequent
     * pipe read fails on the dead peer anyway.
     */
    bool alive() const noexcept
    {
        if (!valid())
        {
            return false;
        }
        DWORD code = 0;
        if (!GetExitCodeProcess(m_Handle, &code))
        {
            return false;
        }
        return code == STILL_ACTIVE;
    }

    /**
     * @brief Process creation time as a 64-bit FILETIME tick count.
     * @return The packed creation time, or std::nullopt if the query fails.
     *
     * GetProcessTimes is total under PROCESS_QUERY_LIMITED_INFORMATION for a
     * same-user handle, so nullopt is effectively unreachable in-threat-model;
     * callers nonetheless fail closed on nullopt.
     */
    std::optional<std::uint64_t> creationTime() const noexcept
    {
        if (!valid())
        {
            return std::nullopt;
        }
        FILETIME creation{}, exitT{}, kernelT{}, userT{};
        if (!GetProcessTimes(m_Handle, &creation, &exitT, &kernelT, &userT))
        {
            return std::nullopt;
        }
        return (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    }

private:
    void reset() noexcept
    {
        if (m_Handle != nullptr)
        {
            CloseHandle(m_Handle);
            m_Handle = nullptr;
        }
        m_Pid = 0;
    }

    DWORD m_Pid{0};
    HANDLE m_Handle{nullptr};
    DWORD m_LastError{0};
};

}  // namespace seal::signer
