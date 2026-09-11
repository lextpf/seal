#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

namespace seal
{

class BrowserBridge;

/**
 * @class BrowserBridgeProbe
 * @brief Read browser click evidence from the bridge.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * M5 requires an on-disk tier-1 corroborator; extension evidence alone cannot
 * short-circuit fusion or release a staged fill. The borrowed bridge must outlive this probe.
 * Hosts stay outside evidence logs; FillController reads them for URL binding.
 *
 * | Condition                            | Verdict  | Conf | Evidence token        |
 * |--------------------------------------|----------|------|-----------------------|
 * | bridge null / not running / disabled | Unknown  | 0    | bridge_offline        |
 * | no fresh entry within tolerance      | Unknown  | 0    | no_recent_entry       |
 * | entry verdict Password               | Password | 0.97 | bridge_match          |
 * | entry verdict Username               | Username | 0.95 | bridge_match          |
 * | entry verdict neither                | Unknown  | 0    | entry_unknown_verdict |
 */
class BrowserBridgeProbe : public IProbe
{
public:
    /**
     * @fn BrowserBridgeProbe(BrowserBridge* bridge)
     * @brief Borrow a bridge that must outlive this probe.
     * @author Alex (<https://github.com/lextpf>)
     */
    explicit BrowserBridgeProbe(BrowserBridge* bridge);

    /**
     * @fn ProbeResult run(const ProbeContext& ctx) override
     * @brief Read the freshest validated bridge entry within the click tolerance.
     * @author Alex (<https://github.com/lextpf>)
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
     * @param ctx m_TargetProcessId and raw screen point select the entry.
     * @return Verdict and miss reason as listed in the type table.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    const char* name() const override { return "browser_extension"; }

    /**
     * @fn std::chrono::milliseconds budget() const override
     * @brief Advisory 5 ms budget for a bounded map scan.
     * @author Alex (<https://github.com/lextpf>)
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(5); }

private:
    BrowserBridge* m_Bridge;  ///< Non-owning pointer; FillController owns the bridge.
};

}  // namespace seal

#endif  // USE_QT_UI
