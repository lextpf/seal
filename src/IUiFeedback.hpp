#pragma once
#ifdef USE_QT_UI
#include <QString>
namespace seal
{
/**
 * @class IUiFeedback
 * @brief Write non-secret application status through AppViewModel.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Call on the GUI thread. Setters emit change signals only when values change.
 */
class IUiFeedback
{
public:
    virtual ~IUiFeedback() = default;
    virtual void setStatus(const QString& text) = 0;
    /**
     * @fn void setLoading(bool on, const QString& caption = {})
     * @brief Caption is cleared when the loading cover is off.
     * @author Alex (<https://github.com/lextpf>)
     */
    virtual void setLoading(bool on, const QString& caption = {}) = 0;
    virtual void setBusy(bool busy) = 0;
    virtual bool isBusy() const = 0;
    /**
     * @fn void setCountdown(const QString& text)
     * @brief An empty string clears the countdown.
     * @author Alex (<https://github.com/lextpf>)
     */
    virtual void setCountdown(const QString& text) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
