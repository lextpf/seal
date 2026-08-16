#pragma once

#include "Probe.hpp"

namespace seal
{

/**
 * @class ImeStateProbe
 * @brief Supporting-evidence probe based on IME context state.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Password fields usually have IME disabled, even when the OS or thread
 * locale would turn it on. When `ImmGetContext` returns null for the target
 * window, the probe leans lightly toward Password. It never returns
 * Username, so it can only add to the password side of the vote. Tier-2 weak
 * signal (weight 0.3); it never short-circuits.
 *
 * @warning The signal is per window, not per field. The probe reads
 *          `ctx.m_TargetWindow` as-is, which in a browser is the renderer
 *          widget and not the clicked input, so every field on a page gives
 *          the same answer there. The signal is field-specific only on
 *          native Win32 dialogs, where each Edit control owns an HWND.
 *
 * @note Why the weight is low: plenty of legitimate password fields do have
 *       IME contexts (sites that reattach IME to support CJK passphrases, or
 *       that forget to opt out), and plenty of non-password fields disable
 *       IME for reasons unrelated to secrecy (numeric inputs, MAC-address
 *       fields). An absent IME context is a lean, not a decision.
 *
 * @par Tier-2 contribution
 * On a positive (IME context absent) the contribution to the password side
 * of the weighted vote is
 * @f[
 *   w \cdot c = 0.3 \times 0.3 = 0.09,
 * @f]
 * far below the @f$ 0.7 @f$ commit margin: this probe can only nudge a lead
 * another probe already carries, never decide on its own.
 */
class ImeStateProbe : public IProbe
{
public:
    /**
     * @brief Check whether the target window has an IME context.
     *
     * Reads @c ctx.m_TargetWindow with @c ImmGetContext and hands the
     * context straight back with @c ImmReleaseContext when one was returned,
     * so the call leaks nothing. A null context is the "lean toward
     * password" signal.
     *
     * @param ctx Click-site context; only m_TargetWindow is read.
     * @return Verdict::Password at confidence 0.3 with evidence
     *         `ime_context=disabled` when the window has no IME context;
     *         Verdict::Unknown with evidence `ime_context=enabled` when it
     *         has one; Verdict::Unknown with empty evidence when
     *         m_TargetWindow is null.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("ime_state").
    const char* name() const override { return "ime_state"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * `ImmGetContext` is a single cheap call into the window manager, so the
     * 2 ms budget is generous. Like every budget it is advisory only.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(2); }
};

}  // namespace seal
