#pragma once

#include <cstdint>

namespace seal
{

/**
 * @fn constexpr bool ShouldAutoLock(int64_t lastActivityMs, int64_t nowMs, int64_t timeoutSecs)
 * @brief Test whether the idle interval has reached its timeout.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * $$
 *   \text{lock} \;=\; (\text{timeoutSecs} > 0)\;\land\;
 *   \bigl(\text{nowMs} - \text{lastActivityMs} \;\ge\; 1000 \cdot \text{timeoutSecs}\bigr)
 * $$
 *
 * The result stays true after expiry; callers reset activity to suppress repeated requests.
 *
 * @param lastActivityMs Monotonic milliseconds of last activity.
 * @param nowMs Milliseconds from the same clock; an earlier timestamp returns false.
 * @param timeoutSecs Idle seconds; <= 0 disables locking.
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
