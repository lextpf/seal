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
 * object's lifetime. The kernel cannot recycle the PID while that handle is
 * open, so pid() and imagePath() keep pointing at the pinned process. Identity
 * rests on the open handle; alive() drives prompt teardown and never decides
 * which process this is.
 *
 * @par Ownership
 * Copying is deleted, so CloseHandle runs exactly once. A move transfers the
 * handle and leaves the source invalid: no handle, pid() == 0.
 *
 * @par Error reporting
 * A non-zero lastError() always comes from a failed OpenProcess call. A move
 * overwrites the destination's error with the source's value and leaves the
 * source's value in place, so moving a successful pin over a failed one resets
 * lastError() to 0. reset() and the destructor never touch the field. It stays
 * 0 for a default-constructed pin and for a moved-from pin that was valid.
 *
 * @par Thread safety
 * Mutation is not thread-safe. The const accessors only query the kernel
 * through the held handle, so concurrent const use of one object is safe.
 */
class PinnedProcess
{
public:
    /// @brief Construct an invalid pin. No handle is opened.
    PinnedProcess() noexcept = default;

    /**
     * @brief Pin @p pid by opening a query handle. valid() is false on failure.
     *
     * On failure the object keeps no handle, pid() reports 0, and lastError()
     * carries the GetLastError value. ERROR_ACCESS_DENIED means a protection or
     * integrity boundary; ERROR_INVALID_PARAMETER means the process is gone.
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

    /**
     * @brief Take over the handle of @p o, which is left invalid.
     * @param o Source pin. It holds no handle and reports pid() == 0 afterwards.
     */
    PinnedProcess(PinnedProcess&& o) noexcept
        : m_Pid(o.m_Pid),
          m_Handle(o.m_Handle),
          m_LastError(o.m_LastError)
    {
        o.m_Handle = nullptr;
        o.m_Pid = 0;
    }
    /**
     * @brief Close the current handle, then take over the handle of @p o.
     *
     * Self-assignment is a no-op and keeps the held handle open.
     *
     * @param o Source pin. It holds no handle and reports pid() == 0 afterwards.
     * @return Reference to this pin.
     */
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
    /// @brief Copy construction is deleted: one object owns one handle.
    PinnedProcess(const PinnedProcess&) = delete;
    /// @brief Copy assignment is deleted: one object owns one handle.
    PinnedProcess& operator=(const PinnedProcess&) = delete;
    /// @brief Close the handle, which lets the kernel recycle the PID again.
    ~PinnedProcess() { reset(); }

    /// @brief Whether a query handle is held. It says nothing about liveness.
    bool valid() const noexcept { return m_Handle != nullptr; }
    /// @brief Same test as valid(), for use in a boolean context.
    explicit operator bool() const noexcept { return valid(); }

    /// @brief The pinned PID, or 0 when invalid. It cannot be recycled while pinned.
    DWORD pid() const noexcept { return m_Pid; }

    /// @brief The GetLastError value from a failed construction, else 0.
    DWORD lastError() const noexcept { return m_LastError; }

    /**
     * @brief On-disk image path queried from the held handle.
     *
     * Queried on every call; nothing is cached. It asks for the Win32 form
     * (QueryFullProcessImageNameW flag 0), not the native NT device form. The
     * kernel reports the on-disk casing, so compare case-insensitively;
     * seal::signer::isKnownBrowserImage() does that.
     *
     * @return The image path, or an empty string when the pin is invalid or the
     *         query fails.
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
     *
     * A process that really exits with code 259 (== STILL_ACTIVE) reads as
     * alive. That Win32 ambiguity is harmless here: a false "alive" only delays
     * teardown, identity rests on the open handle, and the next pipe read fails
     * on the dead peer anyway.
     *
     * @return true only when GetExitCodeProcess yields STILL_ACTIVE. An invalid
     *         pin, and a failed query, both return false.
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
     *
     * The unit is the FILETIME tick: 100 nanoseconds since 1601-01-01 UTC. The
     * two FILETIME halves are packed as `(high << 32) | low`, so two processes
     * order the same way as their real creation order. The bridge ancestor walk
     * uses that order to reject a parent that started after its child.
     *
     * GetProcessTimes succeeds with PROCESS_QUERY_LIMITED_INFORMATION access on
     * a same-user handle, so a valid pin nearly always yields a value. Callers
     * still fail closed on std::nullopt instead of skipping the check.
     *
     * @return The packed creation time, or std::nullopt when the pin is
     *         invalid or the query fails.
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
