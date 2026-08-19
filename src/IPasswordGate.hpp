#pragma once
#ifdef USE_QT_UI
#include <functional>
namespace seal
{
/**
 * @class IPasswordGate
 * @brief Password gate seam: run a master-password-dependent action now or later.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Collaborators that need the master key (TypeController, CliPanelViewModel)
 * pass their continuation through this seam instead of driving the password
 * dialog themselves. AppViewModel is the only implementation; it owns the
 * deferred-action queue and the dialog signal.
 *
 * Call every method on the GUI thread.
 */
class IPasswordGate
{
public:
    virtual ~IPasswordGate() = default;
    /**
     * @brief Ensure the master password is available, else enqueue @p action.
     *
     * The callable is copied into the implementation's queue, so a caller that
     * carries secrets must keep them in locked memory behind a shared_ptr. A
     * queued callable may never run: exit cleanup drops the whole queue, so the
     * callable must be safe to destroy unrun.
     *
     * @param action Deferred callable, re-run once the password is set.
     * @return true when the password is already set and the caller proceeds
     *         inline; false when @p action was enqueued.
     *
     * @par Decision
     * | Master password | Returns | @p action                                 |
     * |-----------------|---------|-------------------------------------------|
     * | already set     | `true`  | not enqueued; caller runs it inline       |
     * | not set         | `false` | queued at the tail; the dialog is opened  |
     */
    virtual bool ensurePassword(std::function<void()> action) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
