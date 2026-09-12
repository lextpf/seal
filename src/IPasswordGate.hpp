#pragma once
#ifdef USE_QT_UI
#include <functional>
namespace seal
{
/**
 * @class IPasswordGate
 * @brief Defer key-dependent commands through the AppViewModel password queue.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * @pre Call on the GUI thread.
 */
class IPasswordGate
{
public:
    virtual ~IPasswordGate() = default;
    /**
     * @fn bool ensurePassword(std::function<void()> action)
     * @brief Queue an action and open the password prompt if the key is absent.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Copied callables must keep secrets in shared locked buffers and tolerate
     * destruction without execution; exit cleanup drops the queue. A queued action
     * must revalidate record indices and busy state because they can change during the prompt.
     *
     * | Password | Return | Action                       |
     * |----------|--------|------------------------------|
     * | Set      | True   | Caller proceeds inline       |
     * | Absent   | False  | Append to queue; open prompt |
     */
    virtual bool ensurePassword(std::function<void()> action) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
