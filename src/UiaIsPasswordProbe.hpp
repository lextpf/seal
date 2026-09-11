#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <memory>

namespace seal
{

/**
 * @class UiaIsPasswordProbe
 * @brief Read explicit MSAA and UIA password flags.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Native providers derive flags from ES_PASSWORD; browser providers derive them
 * from the page DOM. Browser evidence is not independent of the page.
 *
 * Unknown contributes no vote. The shared UIA helper may still read nine
 * metadata properties after explicit flags miss; this probe discards that result.
 *
 * The first phase-2 run creates and caches IUIAutomation. Failed creation is
 * latched, leaving only MSAA on later calls. The caller must initialize COM
 * and keep the probe on that apartment's thread.
 *
 * | # | Signal                       | Verdict  | Conf | Evidence token             |
 * |---|------------------------------|----------|------|----------------------------|
 * | 1 | MSAA state protected         | Password | 0.97 | msaa_state_protected       |
 * | 2 | UIA IsPassword == true       | Password | 0.96 | uia_is_password=true       |
 * | 3 | Legacy IAccessible protected | Password | 0.95 | uia_legacy_state_protected |
 */
class UiaIsPasswordProbe : public IProbe
{
public:
    /**
     * @fn UiaIsPasswordProbe()
     * @brief Construct the probe; UIA initialisation is deferred to the first run().
     * @author Alex (<https://github.com/lextpf>)
     */
    UiaIsPasswordProbe();

    /**
     * @fn ~UiaIsPasswordProbe()
     * @brief Release the cached UIA singleton (if any) and PIMPL state.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~UiaIsPasswordProbe() override;

    UiaIsPasswordProbe(const UiaIsPasswordProbe&) = delete;
    UiaIsPasswordProbe& operator=(const UiaIsPasswordProbe&) = delete;
    UiaIsPasswordProbe(UiaIsPasswordProbe&&) = delete;
    UiaIsPasswordProbe& operator=(UiaIsPasswordProbe&&) = delete;

    /**
     * @fn ProbeResult run(const ProbeContext& ctx)
     * @brief Inspect explicit password flags at the raw screen point.
     * @author Alex (<https://github.com/lextpf>)
     *
     * m_TargetWindow is unused.
     * @return Password at 0.95-0.97 on a hit. Unknown uses uia_init_failed or
     *         uia_element_from_point_failed on setup failure; otherwise evidence is empty.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    const char* name() const override { return "uia_is_password"; }

    /**
     * @fn std::chrono::milliseconds budget() const
     * @brief Advisory 50 ms budget; provider calls can exceed it.
     * @author Alex (<https://github.com/lextpf>)
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(50); }

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
