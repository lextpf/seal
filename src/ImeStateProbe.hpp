#pragma once

#include "Probe.hpp"

namespace seal
{

/**
 * @brief Supporting-evidence probe based on IME context state.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Password fields typically have IME disabled even when the OS / thread
 * locale would otherwise turn it on. If the target window has no IME
 * context (`ImmGetContext` returns null) we lean very lightly toward
 * Password. Tier-2 weak signal (weight 0.3); never short-circuits.
 *
 * @note **Why intentionally Tier-2 and weak.** Plenty of legitimate
 *       password fields *do* have IME contexts (sites that explicitly
 *       reattach IME to support CJK passphrases, or simply forget to
 *       opt out), and plenty of non-password fields disable IME for
 *       reasons unrelated to secrecy (numeric inputs, MAC-address
 *       fields). So an absent IME context is a lean, not a decision;
 *       the probe's confidence 0.3 with weight 0.3 means it
 *       contributes 0.09 to a Tier-2 score on a positive -- enough to
 *       break a 0.5/0.5 tie in favour of password, not enough to
 *       drive a fill on its own.
 */
class ImeStateProbe : public IProbe
{
public:
    /**
     * @brief Check whether the target window has an IME context.
     *
     * Inspects @c ctx.m_TargetWindow via @c ImmGetContext. A null
     * context is the "lean toward password" signal; any other result
     * (or a missing target window) is Unknown.
     *
     * @param ctx Click-site context.
     * @return Verdict::Password at confidence 0.3 when IME is absent
     *         on the target window, Verdict::Unknown otherwise.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("ime_state").
    const char* name() const override { return "ime_state"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * `ImmGetContext` is a fast intra-process call; the 2 ms budget is
     * generous.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(2); }
};

}  // namespace seal
