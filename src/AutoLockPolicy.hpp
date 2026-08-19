#pragma once

#include <cstdint>

namespace seal
{

/**
 * @brief Pure idle auto-lock decision.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Qt-free, so the policy is unit-testable in the no-Qt test target;
 * AutoLockController feeds it timestamps from the Qt event layer. Pure and
 * constexpr: it reads no clock, keeps no state, and clamps nothing.
 *
 * @par Decision
 * | Condition                                    | Result             |
 * |----------------------------------------------|--------------------|
 * | `timeoutSecs <= 0`                           | `false` (disabled) |
 * | `nowMs - lastActivityMs >= timeoutSecs*1000` | `true` (lock)      |
 * | otherwise                                    | `false` (idle)     |
 *
 * @f[
 *   \text{lock} \;=\; (\text{timeoutSecs} > 0)\;\land\;
 *   \bigl(\text{nowMs} - \text{lastActivityMs} \;\ge\; 1000 \cdot \text{timeoutSecs}\bigr)
 * @f]
 *
 * The decision is level-triggered, not edge-triggered: once the idle span
 * passes the timeout, the function keeps returning `true` for every later call
 * with the same inputs. AutoLockController therefore re-stamps its activity
 * clock when a lock fires, so one idle period produces one lock request instead
 * of one per poll tick.
 *
 * @pre @p lastActivityMs and @p nowMs come from the same monotonic clock.
 * @param lastActivityMs Monotonic milliseconds of the last user activity.
 * @param nowMs          Monotonic milliseconds now.
 * @param timeoutSecs    Idle timeout in seconds; `<= 0` disables idle locking.
 * @return `true` when the vault should lock. A @p nowMs that precedes
 *         @p lastActivityMs gives a negative span and returns `false`.
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
