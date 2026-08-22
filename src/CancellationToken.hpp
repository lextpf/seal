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
 * gets this read-only view and polls cancelled(). A default-constructed token is never cancelled,
 * which is what a task without cancellation support uses.
 *
 * Every copy shares the flag, so a token can be passed by value into a decay-copied
 * `QtConcurrent::run` body. Holding a token keeps the flag alive, so polling stays safe after the
 * AsyncRunner that created it is gone.
 *
 * cancelled() is safe on any thread; its acquire load pairs with the release store in
 * AsyncHandle::cancel().
 *
 * @see AsyncHandle, AsyncRunner
 */
class CancellationToken
{
public:
    /// @brief Construct a never-cancelled token.
    CancellationToken() = default;

    /**
     * @brief Construct a token over a shared cancellation flag (read-only).
     *
     * A `std::shared_ptr<std::atomic<bool>>` converts implicitly to the const-qualified
     * parameter, so the caller keeps the only writable view of the flag.
     *
     * @param flag Shared flag set by the owning AsyncRunner or AsyncHandle. A null pointer
     *             yields a token that is never cancelled.
     */
    explicit CancellationToken(std::shared_ptr<const std::atomic<bool>> flag)
        : m_Flag(std::move(flag))
    {
    }

    /// @brief Whether cancellation has been requested. Returns `false` when no flag is held.
    bool cancelled() const noexcept { return m_Flag && m_Flag->load(std::memory_order_acquire); }

private:
    std::shared_ptr<const std::atomic<bool>> m_Flag;
};
}  // namespace seal
