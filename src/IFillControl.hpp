#pragma once
#ifdef USE_QT_UI
namespace seal
{
/// @brief Narrow fill-control seam implemented by TypeController; used to arm/cancel the auto-fill
/// engine.
/// @ingroup ViewModel
class IFillControl
{
public:
    virtual ~IFillControl() = default;
    /// @brief Arm the auto-fill engine for the record at @p recordIndex.
    virtual void armFor(int recordIndex) = 0;
    /// @brief Cancel an armed or in-progress fill; no-op when not armed.
    virtual void cancelIfArmed() = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
