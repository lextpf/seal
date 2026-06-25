#pragma once

#include <cstdint>

namespace seal
{

/**
 * @brief Pure idle auto-lock decision.
 * @author Alex (https://github.com/lextpf)
 * @ingroup GUI
 *
 * Kept Qt-free so the policy is unit-testable in the no-Qt test target;
 * AutoLockController feeds it timestamps from the Qt event layer.
 *
 * @param lastActivityMs Monotonic milliseconds of the last user activity.
 * @param nowMs          Monotonic milliseconds now.
 * @param timeoutSecs    Idle timeout in seconds; `<= 0` disables idle locking.
 * @return `true` when the vault should lock.
 */
constexpr bool ShouldAutoLock(int64_t lastActivityMs, int64_t nowMs, int64_t timeoutSecs)
{
    if (timeoutSecs <= 0)
    {
        return false;
    }
    return (nowMs - lastActivityMs) >= timeoutSecs * 1000;
}

}  // namespace seal
