#pragma once

#include <atomic>
#include <memory>

namespace seal
{
/**
 * @class CancellationToken
 * @brief Read-only cooperative-cancellation flag polled by a background work body.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Utilities
 *
 * The owning AsyncRunner holds the writable `std::shared_ptr<std::atomic<bool>>`; the work body
 * receives this read-only view and polls `cancelled()`. A default-constructed token is never
 * cancelled (for tasks that do not support cancellation).
 */
class CancellationToken
{
public:
    /// @brief Construct a never-cancelled token.
    CancellationToken() = default;

    /**
     * @brief Construct a token over a shared cancellation flag (read-only).
     * @param flag Shared flag set by the owning AsyncRunner / AsyncHandle.
     */
    explicit CancellationToken(std::shared_ptr<const std::atomic<bool>> flag)
        : m_Flag(std::move(flag))
    {
    }

    /// @brief Whether cancellation has been requested.
    bool cancelled() const noexcept { return m_Flag && m_Flag->load(std::memory_order_acquire); }

private:
    std::shared_ptr<const std::atomic<bool>> m_Flag;
};
}  // namespace seal
