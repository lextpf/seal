#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <memory>

namespace seal
{

/**
 * @class UiaIsPasswordProbe
 * @brief Tier-1 strong-signal password-field probe (MSAA + UIA IsPassword).
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Inspects three near-ground-truth indicators, first hit wins:
 *  - MSAA `STATE_SYSTEM_PROTECTED` via `AccessibleObjectFromPoint`
 *  - UIA `UIA_IsPasswordPropertyId == VARIANT_TRUE`
 *  - UIA `LegacyIAccessiblePattern` state carrying `STATE_SYSTEM_PROTECTED`
 *
 * None of the three is a keyword heuristic: each is a declared field-type flag
 * read from the target application's MSAA or UIA provider. For a native USER32
 * control the OS default provider derives the flag from `ES_PASSWORD`. For web
 * content the provider is the browser, so the flag restates the page's own
 * `<input type=password>` and is not independent of the page. See the M5 note
 * in @ref FusionDecider.
 *
 * @par Ranked signals (first hit wins)
 * | # | Signal                       | Verdict  | Conf | Evidence token             |
 * |---|------------------------------|----------|------|----------------------------|
 * | 1 | MSAA state protected         | Password | 0.97 | msaa_state_protected       |
 * | 2 | UIA IsPassword == true       | Password | 0.96 | uia_is_password=true       |
 * | 3 | Legacy IAccessible protected | Password | 0.95 | uia_legacy_state_protected |
 *
 * With no hit the probe returns Verdict::Unknown at confidence 0. FusionDecider
 * skips an Unknown result in both passes, so this probe stops contributing: the
 * verdict then comes from whichever other Tier-1 probe short-circuits, or from
 * the Tier-2 weighted vote when none does. No probe is skipped as a result -
 * all five probes still run on every click.
 *
 * @par Overlap with UiaMetadataProbe
 * Metadata signals (name, description, aria hints) belong to
 * UiaMetadataProbe. This probe still calls @ref inspectElementPasswordState
 * with the control-type gate skipped, so when signals 2 and 3 both miss,
 * that helper's metadata fallback still runs: up to nine extra cross-process
 * property reads whose result this probe discards by source name, and which
 * UiaMetadataProbe then repeats.
 *
 * @par UIA singleton
 * The IUIAutomation instance is created on the first run() that reaches
 * phase 2 and cached for the probe's lifetime, so that call pays the
 * CoCreateInstance cost. A failure is latched: after one failed create the
 * probe never retries, every later call reports `uia_init_failed`, and only
 * the MSAA phase keeps working. The probe never calls CoInitializeEx - it
 * needs the calling thread to be inside an initialised COM apartment, which
 * is one reason a probe must stay on the Qt main thread.
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
     * @param ctx Click-site context. Only m_ClickPoint is read: both the
     *            MSAA AccessibleObjectFromPoint warm-up and the UIA
     *            ElementFromPoint lookup work from the screen point.
     *            m_TargetWindow is unused here.
     * @return Verdict::Password at confidence 0.95 to 0.97 on a hit, else
     *         Verdict::Unknown. The Unknown evidence names the stop point:
     *         `uia_init_failed` when the UIA singleton could not be created,
     *         `uia_element_from_point_failed` when ElementFromPoint returned
     *         nothing, and empty when UIA answered but reported no protected
     *         state.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("uia_is_password").
    const char* name() const override { return "uia_is_password"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * UIA queries cross a COM boundary and can stall on a slow provider
     * (large iframes, custom-control hosts); 50 ms is the typical worst case
     * for a healthy provider. The value is advisory: nothing measures the
     * call and nothing cancels an overrun, so a stalled provider stalls the
     * whole fusion pass. See IProbe::budget.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(50); }

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
