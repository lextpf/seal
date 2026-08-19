#pragma once
#ifdef USE_QT_UI
#include <QString>
namespace seal
{
/**
 * @class IUiFeedback
 * @brief App-shell status sink: the single owner of status/loading/busy/countdown UI state.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Collaborators without a view of their own (TypeController, CliPanelViewModel,
 * StagingController) write their user-visible state through this seam instead
 * of holding a reference to the hub ViewModel. TypeController and
 * StagingController also read isBusy() through it, to refuse an arm while
 * another operation runs.
 *
 * AppViewModel is the only implementation. The setters drive five of its
 * Q_PROPERTY values (statusText, isLoading, loadingCaption, isBusy,
 * countdownText) and emit their change signals. BridgeViewModel does not take
 * this seam: it emits its own `statusMessage` signal, which RunQMLMode connects
 * to setStatus().
 *
 * @par Threading
 * Call every method on the GUI thread. Each setter is idempotent: setting the
 * value the sink already holds emits nothing.
 */
class IUiFeedback
{
public:
    virtual ~IUiFeedback() = default;
    /// @brief Replace the status-bar text.
    virtual void setStatus(const QString& text) = 0;
    /// @brief Show/hide the loading cover; @p caption labels the spinner (cleared when off).
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
