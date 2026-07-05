#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

namespace seal
{

class BrowserBridge;

/**
 * @brief Tier-1 candidate probe that consults the BrowserBridge in-memory map.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Returns Password at confidence 0.97 or Username at confidence 0.95 when the
 * bridge has a fresh entry matching the click's (browser-pid, x, y) within
 * jitter tolerance. Returns Unknown when the bridge is offline, disabled
 * (M8 panic mode), or has no recent matching entry.
 *
 * @par Result map
 * | Condition                            | Verdict  | Conf | Evidence token        |
 * |--------------------------------------|----------|------|-----------------------|
 * | Bridge null / not running / disabled | Unknown  | 0    | bridge_offline        |
 * | No fresh entry within tolerance      | Unknown  | 0    | no_recent_entry       |
 * | Entry verdict Password               | Password | 0.97 | bridge_match          |
 * | Entry verdict Username               | Username | 0.95 | bridge_match          |
 * | Entry verdict neither                | Unknown  | 0    | entry_unknown_verdict |
 *
 * The probe sets confidences high enough to qualify for Tier-1 short-
 * circuit, but FusionDecider's M5 rule requires agreement with at least
 * one other Tier-1 probe before honoring a bridge-alone verdict; that
 * gate lives in FusionDecider.cpp, not here. The reason for the M5
 * carve-out: a bridge-alone hit depends on a remote browser extension
 * that's outside seal's signed-binary trust boundary, so it needs a
 * second on-disk signal (Win32 style or UIA IsPassword) to corroborate
 * before it's allowed to drive a fill on its own.
 *
 * The probe does not own the BrowserBridge instance - FillController owns
 * the bridge and passes a non-owning pointer at construction time.
 */
class BrowserBridgeProbe : public IProbe
{
public:
    /**
     * @brief Construct the probe with a non-owning reference to the bridge.
     * @param bridge Pointer to the FillController-owned BrowserBridge. Must
     *               outlive this probe.
     */
    explicit BrowserBridgeProbe(BrowserBridge* bridge);

    /**
     * @brief Look up the click site in the bridge's in-memory map.
     *
     * Tries a quantised lookup with @c kLookupToleranceRawPx Chebyshev
     * radius (currently ~48 px) and the freshest match wins. The bridge
     * itself handles all the expiry / authentication / parent-process
     * checking; this probe just reads the cooked result.
     *
     * @verbatim
     *   Chebyshev match window, half-width kLookupToleranceRawPx = 48 px
     *   per axis (C = the stored entry's bucket center):
     *
     *        +--------------------------------+
     *        |                                |
     *        |               C                |
     *        |                                |
     *        +--------------------------------+
     *        <------ 48 px --+-- 48 px ------->
     *
     *   Accept when |x - cx| <= 48 AND |y - cy| <= 48, where
     *   cx = (quantX << 2) + 2 and cy = (quantY << 2) + 2 (kQuantShift = 2).
     *   Among all matches, the freshest (latest expiry) entry wins.
     * @endverbatim
     *
     * @param ctx Click-site context (m_TargetProcessId is used as the
     *            map key alongside the screen point).
     * @return Verdict::Password (conf 0.97), Verdict::Username (conf 0.95),
     *         or Verdict::Unknown with evidence describing the miss
     *         reason (bridge_offline, no_recent_entry, entry_unknown_verdict).
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key for this probe ("browser_extension").
    const char* name() const override { return "browser_extension"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * The probe's actual cost is a single map lookup with a tiny
     * neighbourhood scan - microseconds. The 5 ms budget is the soft
     * cap for telemetry; we'd be alarmed if a single lookup ever
     * approached it.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(5); }

private:
    BrowserBridge* m_Bridge;  ///< Non-owning pointer; FillController owns the bridge.
};

}  // namespace seal

#endif  // USE_QT_UI
