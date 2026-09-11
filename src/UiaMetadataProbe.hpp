#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <memory>

namespace seal
{

/**
 * @class UiaMetadataProbe
 * @brief Classify fields from metadata, bounded tree walks, and form peers.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * MSAA tests password keywords only for text and combo-box roles. UIA keywords
 * cover English and German. Ancestors are capped at 8 levels; descendant DFS
 * at 6 levels and 64 inspected nodes.
 *
 * Form inference needs two inputs and a clicked peer identified by CompareElements
 * or the first containing rectangle. An identified password/username peer keeps
 * its kind. An unclassified peer becomes Password if another is username and none
 * is password; otherwise it becomes Username, including fully ambiguous forms.
 *
 * Hit and ancestor metadata reject IsPassword/LegacyState sources. Descendant
 * and peer paths may report those same sources as tier-2 evidence.
 * IUIAutomation creation is cached; failure leaves only the MSAA phase.
 *
 * The largest vote is 0.6 * 0.7 = 0.42, below the 0.7 margin. Page-controlled
 * metadata requires corroboration.
 *
 * @verbatim
 *   run(ctx)
 *     |
 *     +-- phase 1  MSAA name / description ----- match -> return Password
 *     |
 *     +-- ensureInitialized()  fail -----------> Unknown uia_init_failed
 *     +-- ElementFromPoint     fail -----------> Unknown uia_element_from_point_failed
 *     |
 *     +-- phase 2a hit-element metadata -------- match -> return verdict
 *     |
 *     +-- get_RawViewWalker    fail -----------> Unknown uia_raw_walker_failed
 *     |
 *     +-- phase 2b ancestor walk --------------- match -> return verdict
 *     +-- phase 2c descendant DFS -------------- match -> return verdict
 *     +-- phase 2d form-context peers ---------- match -> return verdict
 *     |
 *     +-> Unknown all_signals_unknown
 * @endverbatim
 *
 * | Phase | Path                    | Verdict             | Conf | Evidence stem        |
 * |-------|-------------------------|---------------------|------|----------------------|
 * | 1     | MSAA name / description | Password            | 0.65 | msaa_*_match         |
 * | 2a    | Hit-element metadata    | Password / Username | 0.70 | uia_meta_*           |
 * | 2b    | Ancestor walk           | Password / Username | 0.65 | uia_ancestor_*       |
 * | 2c    | Descendant DFS          | Password            | 0.70 | uia_descendant_match |
 * | 2d    | Form-context peers      | Password / Username | 0.40 | form_*               |
 */
class UiaMetadataProbe : public IProbe
{
public:
    /**
     * @fn UiaMetadataProbe()
     * @brief Construct the probe; UIA initialisation is deferred to the first run().
     * @author Alex (<https://github.com/lextpf>)
     */
    UiaMetadataProbe();

    /**
     * @fn ~UiaMetadataProbe()
     * @brief Release the cached UIA singleton (if any) and PIMPL state.
     * @author Alex (<https://github.com/lextpf>)
     */
    ~UiaMetadataProbe() override;

    UiaMetadataProbe(const UiaMetadataProbe&) = delete;
    UiaMetadataProbe& operator=(const UiaMetadataProbe&) = delete;
    UiaMetadataProbe(UiaMetadataProbe&&) = delete;
    UiaMetadataProbe& operator=(UiaMetadataProbe&&) = delete;

    /**
     * @fn ProbeResult run(const ProbeContext& ctx)
     * @brief Return the first match from the ordered metadata paths.
     * @author Alex (<https://github.com/lextpf>)
     *
     * m_ClickPoint drives MSAA, UIA, and geometry checks; m_TargetWindow is unused.
     * @return Confidence and evidence from the type table and flow diagram.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    const char* name() const override { return "uia_metadata"; }

    /**
     * @fn std::chrono::milliseconds budget() const
     * @brief Advisory 150 ms budget.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Depth and node limits bound query counts, not provider response time.
     * A stalled provider blocks the fusion pass.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(150); }

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
