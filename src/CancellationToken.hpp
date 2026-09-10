#pragma once

#include <atomic>
#include <memory>

namespace seal
{
/**
 * @class CancellationToken
 * @brief Shared read-only cancellation state for background work.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup Utilities
 *
 * Copies keep the flag alive after AsyncRunner destruction. A default token never cancels.
 * `cancelled()` is thread-safe; its acquire load pairs with the handle's release store.
 * Cancellation does not interrupt blocking calls. Workers must check the token between
 * operations and release owned resources before returning.
 */
class CancellationToken
{
public:
    /**
     * @fn CancellationToken()
     * @brief Construct a never-cancelled token.
     * @author Alex (<https://github.com/lextpf>)
     */
    CancellationToken() = default;

    /**
     * @fn CancellationToken(std::shared_ptr<const std::atomic<bool>> flag)
     * @brief Share the cancellation flag without write access.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param flag `nullptr` yields a token that never cancels.
     */
    explicit CancellationToken(std::shared_ptr<const std::atomic<bool>> flag)
        : m_Flag(std::move(flag))
    {
    }

    /**
     * @fn bool cancelled() const noexcept
     * @brief Check whether cancellation has been requested.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return False when no flag is held; otherwise the shared flag value.
     */
    bool cancelled() const noexcept { return m_Flag && m_Flag->load(std::memory_order_acquire); }

private:
    std::shared_ptr<const std::atomic<bool>> m_Flag;
};
}  // namespace seal
