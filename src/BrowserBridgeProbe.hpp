#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

namespace seal
{

class BrowserBridge;

/**
 * @class BrowserBridgeProbe
 * @brief Tier-1 candidate probe that consults the BrowserBridge in-memory map.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Returns Password at confidence 0.97 or Username at confidence 0.95 when the
 * bridge holds a fresh entry matching the click's (browser-pid, x, y) within
 * tolerance. Returns Unknown when the bridge is offline, panic-disabled (M8),
 * or has no matching entry.
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
 * @par Why M5 exists
 * These confidences qualify for the Tier-1 short-circuit, but FusionDecider's
 * M5 rule still requires a second Tier-1 probe to agree. That gate lives in
 * FusionDecider.cpp, not here. A bridge-alone hit rests on a browser extension
 * outside seal's signed-binary trust boundary, so an on-disk signal (Win32
 * style or UIA IsPassword) must corroborate it before it drives a fill.
 *
 * @par Ownership
 * FillController owns the BrowserBridge and passes a non-owning pointer at
 * construction.
 *
 * @note The probe reports only the verdict and a short evidence token. The
 *       matched entry's host stays off the evidence channel because it leaks
 *       a browsing pattern into the log; FillController reads that host
 *       directly from @ref BrowserBridge::lookup for the URL-binding gate.
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
     * Runs one quantised lookup with a Chebyshev radius of
     * @c kLookupToleranceRawPx (48 px); the freshest match wins. The bridge has
     * already applied expiry, peer authentication and the ancestor check, so
     * this probe only reads the result.
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
     * The real cost is one bounded map scan, in microseconds. The 5 ms value is an
     * advisory budget - nothing measures the call - chosen so the five declared
     * budgets stay inside the 300 ms pass deadline.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(5); }

private:
    BrowserBridge* m_Bridge;  ///< Non-owning pointer; FillController owns the bridge.
};

}  // namespace seal

#endif  // USE_QT_UI
