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
    /// @brief Replace the status-bar text.
    virtual void setStatus(const QString& text) = 0;
    /// @brief Show/hide the loading cover; @p caption labels the spinner (ignored when off).
    virtual void setLoading(bool on, const QString& caption = {}) = 0;
    /// @brief Set the background-busy flag that drives the busy indicator.
    virtual void setBusy(bool busy) = 0;
    /// @brief Whether a background operation is currently in progress.
    virtual bool isBusy() const = 0;
    /// @brief Set the auto-fill countdown text (empty string clears it).
    virtual void setCountdown(const QString& text) = 0;
};
}  // namespace seal
#endif  // USE_QT_UI
