#pragma once
#ifdef USE_QT_UI
namespace seal
{
/**
 * @class IFillControl
 * @brief Control manual Ctrl+Click filling through TypeController.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * The implementation owns password gating, status and window minimization.
 * StagingController arms navigation-based fills directly on the engine.
 *
 * @pre Call on the GUI thread.
 */
class IFillControl
{
public:
    virtual ~IFillControl() = default;

    /**
     * @fn void armFor(int recordIndex)
     * @brief Defer arming until a password is available, then install hooks and minimize windows.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Busy state or an invalid index makes this a silent no-op.
     *
     * @param recordIndex Full record index; map filtered rows with VaultListModel.
     */
    virtual void armFor(int recordIndex) = 0;

    /**
     * @fn void cancelIfArmed()
     * @brief Cancel manual or staged fills waiting for a click; safe to repeat.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Does not stop active typing or diagnosis. `TypeController::cancelFill()` also
     * cancels diagnosis.
     */
    virtual void cancelIfArmed() = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
