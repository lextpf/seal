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
    /// @return true if the password is already set (caller proceeds inline); false if @p action was
    /// enqueued.
    virtual bool ensurePassword(std::function<void()> action) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
