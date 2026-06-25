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
    virtual void armFor(int recordIndex) = 0;
    virtual void cancelIfArmed() = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
