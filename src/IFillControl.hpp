#pragma once
#ifdef USE_QT_UI
namespace seal
{
/**
 * @class IFillControl
 * @brief Narrow fill-control seam: arm or cancel the auto-fill engine.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Collaborators that start a Ctrl+Click fill call it through this seam instead
 * of holding a FillController: AppViewModel through a nullable pointer,
 * CliPanelViewModel through a reference for its `:fill` builtin. TypeController
 * is the only implementation; it owns the password gating, the status feedback
 * and the window minimise that surround the engine call.
 *
 * Arming through this seam always produces the manual Ctrl+Click path. The
 * staged zero-gesture path is armed by StagingController straight on the
 * engine. @ref cancelIfArmed ends either path.
 *
 * @pre Call every method on the GUI thread.
 */
class IFillControl
{
public:
    virtual ~IFillControl() = default;

    /**
     * @brief Arm the auto-fill engine for the record at @p recordIndex.
     *
     * The implementation self-gates, so the caller must not check the master
     * password: the arm is deferred until that password is set. The call is
     * ignored without feedback when @p recordIndex is out of range or a
     * background operation is already running. A successful arm installs global
     * input hooks and minimises the visible windows, so it changes what the user
     * sees.
     *
     * @param recordIndex Position in the full record list, not the filtered
     *                    row; map a row with VaultListModel::recordIndexForRow.
     */
    virtual void armFor(int recordIndex) = 0;

    /**
     * @brief Cancel a fill that still waits for its completing click; a no-op
     *        otherwise.
     *
     * Cancels the manual path and the staged path while each waits for its
     * click. A fill that already types is not stopped, and a diagnose dry run
     * keeps running on purpose; seal::TypeController::cancelFill cancels
     * unconditionally. Safe to call repeatedly.
     */
    virtual void cancelIfArmed() = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
