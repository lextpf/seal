#pragma once
#ifdef USE_QT_UI
#include <QString>
namespace seal
{
/// @brief App-shell status sink: the single owner of status/loading/busy/countdown UI state.
/// @ingroup ViewModel
class IUiFeedback
{
public:
    virtual ~IUiFeedback() = default;
    virtual void setStatus(const QString& text) = 0;
    virtual void setLoading(bool on, const QString& caption = {}) = 0;
    virtual void setBusy(bool busy) = 0;
    virtual bool isBusy() const = 0;
    virtual void setCountdown(const QString& text) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
