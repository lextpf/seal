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
 * @brief Own a process query handle that prevents PID reuse while open.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * Moves transfer ownership and clear the source handle/PID. Identity rests on the
 * handle; alive only controls teardown. Concurrent const queries are safe;
 * mutation requires external synchronization.
 *
 * lastError records failed OpenProcess calls. Moving copies the error without
 * clearing the source; reset and destruction leave it unchanged.
 */
class PinnedProcess
{
public:
    /**
     * @fn PinnedProcess() noexcept
     * @brief Construct an invalid pin.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No handle is opened.
     */
    PinnedProcess() noexcept = default;

    /**
     * @fn PinnedProcess(DWORD pid) noexcept
     * @brief Open a process query handle.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Failure leaves the pin invalid with PID 0 and lastError from OpenProcess.
     * A failed open does not establish whether the process exited or access was denied.
     */
    explicit PinnedProcess(DWORD pid) noexcept
        : m_Pid(pid),
          m_Handle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid))
    {
        // OpenProcess reports failure with NULL, never INVALID_HANDLE_VALUE, so
        // the second arm is defensive and valid() keys off nullptr only.
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
    /**
     * @fn PinnedProcess(const PinnedProcess&)
     * @brief Copy construction is deleted: one object owns one handle.
     * @author Alex (<https://github.com/lextpf>)
     */
    PinnedProcess(const PinnedProcess&) = delete;
    /**
     * @fn PinnedProcess& operator=(const PinnedProcess&)
     * @brief Copy assignment is deleted: one object owns one handle.
     * @author Alex (<https://github.com/lextpf>)
     */
    PinnedProcess& operator=(const PinnedProcess&) = delete;
    /**
     * @fn ~PinnedProcess()
     * @brief Close the handle, which lets the kernel recycle the PID again.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~PinnedProcess() { reset(); }

    /**
     * @fn bool valid() const noexcept
     * @brief Whether a query handle is held.
     * @author Alex (<https://github.com/lextpf>)
     *
     * It says nothing about liveness.
     */
    bool valid() const noexcept { return m_Handle != nullptr; }
    /**
     * @fn operator bool() const noexcept
     * @brief Same test as valid(), for use in a boolean context.
     * @author Alex (<https://github.com/lextpf>)
     */
    explicit operator bool() const noexcept { return valid(); }

    /**
     * @fn DWORD pid() const noexcept
     * @brief The pinned PID, or 0 when invalid.
     * @author Alex (<https://github.com/lextpf>)
     *
     * It cannot be recycled while pinned.
     */
    DWORD pid() const noexcept { return m_Pid; }

    /**
     * @fn DWORD lastError() const noexcept
     * @brief The GetLastError value from a failed construction, else 0.
     * @author Alex (<https://github.com/lextpf>)
     */
    DWORD lastError() const noexcept { return m_LastError; }

    /**
     * @fn std::wstring imagePath() const
     * @brief Query the pinned process path without caching.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Returns Win32 form with on-disk casing; compare case-insensitively.
     *
     * @return Empty for an invalid pin or query failure.
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
     * @fn bool alive() const noexcept
     * @brief Check the exit code to estimate whether the process is running.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Exit code 259 is indistinguishable from running. This may delay teardown;
     * the open handle still pins identity. Invalid pins and query failures return false.
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
     * @fn std::optional<std::uint64_t> creationTime() const noexcept
     * @brief Query creation time in FILETIME ticks.
     * @author Alex (<https://github.com/lextpf>)
     *
     * One tick is 100 ns since 1601-01-01 UTC. Packs (high << 32) | low for comparison.
     *
     * @return `nullopt` for invalid pins or query failure; ancestry callers must fail closed.
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
