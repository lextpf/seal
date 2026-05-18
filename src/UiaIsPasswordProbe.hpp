#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <memory>

namespace seal
{

/**
 * @brief Tier-1 strong-signal password-field probe (MSAA + UIA IsPassword).
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Inspects three near-ground-truth indicators in order:
 *  - MSAA `STATE_SYSTEM_PROTECTED` via `AccessibleObjectFromPoint`
 *    (Tier-1 confidence 0.97)
 *  - UIA `UIA_IsPasswordPropertyId == VARIANT_TRUE`
 *    (Tier-1 confidence 0.96)
 *  - UIA `LegacyIAccessiblePattern` state has `STATE_SYSTEM_PROTECTED`
 *    (Tier-1 confidence 0.95)
 *
 * If none fire, returns Verdict::Unknown with confidence 0; the caller's
 * FusionDecider then falls through to weaker probes (UiaMetadataProbe,
 * ImeStateProbe).
 *
 * Metadata-based signals (name / description / aria hint matching) are
 * intentionally excluded here -- UiaMetadataProbe owns Tier-2 metadata logic.
 *
 * The UIA singleton is lazy-initialised on first run() and cached for the
 * probe's lifetime; the first call pays the CoCreateInstance cost.
 */
class UiaIsPasswordProbe : public IProbe
{
public:
    /// @brief Construct the probe; UIA initialisation is deferred to the first run().
    UiaIsPasswordProbe();

    /// @brief Release the cached UIA singleton (if any) and PIMPL state.
    ~UiaIsPasswordProbe() override;

    UiaIsPasswordProbe(const UiaIsPasswordProbe&) = delete;
    UiaIsPasswordProbe& operator=(const UiaIsPasswordProbe&) = delete;
    UiaIsPasswordProbe(UiaIsPasswordProbe&&) = delete;
    UiaIsPasswordProbe& operator=(UiaIsPasswordProbe&&) = delete;

    /**
     * @brief Run the three ranked checks for password evidence.
     *
     * The three indicators are evaluated in confidence order; the first
     * one to fire decides the verdict. None of them is metadata-based,
     * so a positive result here is near-ground-truth ("the OS itself
     * says this is a password field").
     *
     * @param ctx Click-site context. m_TargetWindow and m_ClickPoint are
     *            both used (MSAA needs the screen point; UIA walks from
     *            the HWND).
     * @return Verdict::Password at confidence 0.95-0.97 on a hit, or
     *         Verdict::Unknown when none of the indicators are present
     *         (so the orchestrator falls through to UiaMetadataProbe
     *         and the Tier-2 weighted vote).
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("uia_is_password").
    const char* name() const override { return "uia_is_password"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * UIA queries cross a COM boundary and can stall on a slow provider
     * (large iframes, custom-control hosts). 50 ms is the typical
     * worst-case for a healthy provider; if the budget is exceeded the
     * orchestrator may cancel the probe on a future revision.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(50); }

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
