#pragma once

#include "Probe.hpp"

namespace seal
{

/**
 * @brief Detects password fields via native Win32 edit style flags.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Resolves the topmost child window under the click via WindowFromPoint +
 * RealChildWindowFromPoint, then inspects:
 *  - `GWL_STYLE & ES_PASSWORD` (Tier-1 confidence 0.98 when set)
 *  - `EM_GETPASSWORDCHAR` (Tier-1 confidence 0.95 when nonzero)
 *  - Class name `Edit`/`RichEdit*`/`TEdit` with no password flag
 *    (Tier-2 confidence 0.55, verdict Username)
 *
 * Reliable on native Win32 dialogs even when the app exposes no UIA.
 *
 * @note **Stateless by design.** Win32 dialogs evaluate to the same
 *       answer on every call -- `GWL_STYLE` doesn't change between
 *       clicks, `EM_GETPASSWORDCHAR` returns the same character. There's
 *       nothing to cache, so the probe holds no fields and is cheap to
 *       construct directly on the stack alongside the other probes.
 */
class Win32StyleProbe : public IProbe
{
public:
    /**
     * @brief Inspect the click site's native Win32 edit style.
     *
     * Resolves the actual child window under the click point (the
     * top-level HWND in @c ctx is usually the dialog frame; the real
     * Edit control is several `Get_Real_ChildWindowFromPoint` hops
     * deeper), then checks the three signals in confidence order.
     *
     * @param ctx Click-site context (m_ClickPoint drives the
     *            RealChildWindowFromPoint chain).
     * @return Verdict::Password at 0.98 / 0.95 confidence on a hit,
     *         Verdict::Username at 0.55 on a bare-Edit fallback, or
     *         Verdict::Unknown when the click didn't land on a child
     *         window we recognise.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("win32_es_password").
    const char* name() const override { return "win32_es_password"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * Win32 style queries are a handful of `GetWindowLong` /
     * `SendMessage` calls; they return in microseconds. The 5 ms
     * budget is the soft cap for telemetry.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(5); }
};

}  // namespace seal
