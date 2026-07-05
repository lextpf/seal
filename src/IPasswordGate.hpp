#pragma once
#ifdef USE_QT_UI
#include <functional>
namespace seal
{
/// @brief Password gate: ensures the master password is available, else enqueues @p action (FIFO).
/// @ingroup ViewModel
class IPasswordGate
{
public:
    virtual ~IPasswordGate() = default;
    /**
     * @brief Ensure the master password is available, else enqueue @p action (FIFO).
     * @param action Deferred callable, re-run once the password is set.
     * @return true if the password is already set (caller proceeds inline); false if @p action
     *         was enqueued.
     *
     * @par Decision
     * | Master password | Returns | @p action                                 |
     * |-----------------|---------|-------------------------------------------|
     * | already set     | `true`  | not enqueued; caller runs it inline       |
     * | not set         | `false` | enqueued (FIFO); passwordRequired() fires |
     */
    virtual bool ensurePassword(std::function<void()> action) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
