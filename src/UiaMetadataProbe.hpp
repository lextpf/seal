#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <memory>

namespace seal
{

/**
 * @class UiaMetadataProbe
 * @brief Tier-2 broad-signal UIA probe (metadata, tree walks, form context).
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Runs the lower-confidence detection paths and returns at the first match:
 *   - MSAA accName / accDescription against the password hint table, but only when the MSAA
 *     role is ROLE_SYSTEM_TEXT or ROLE_SYSTEM_COMBOBOX. This phase tests password keywords
 *     only, so it never returns Username.
 *   - UIA metadata properties (AutomationId, Name, HelpText, ...) scanned for password and
 *     username keywords. The keyword tables live in UiaCommon.cpp and hold English and
 *     German entries only; no other language is recognised.
 *   - Ancestor walk of at most kMaxUiaAncestorDepth (8) parents, probing every parent whose
 *     bounding rect still contains the click point.
 *   - Descendant DFS via searchDescendantsForPassword, bounded by kMaxUiaDescendantDepth
 *     (6) levels and kMaxUiaDescendantNodes (64) inspected nodes.
 *   - Form-context peer inference via findFormAncestor + enumerateFormInputs
 *
 * @par Detection paths (first match wins)
 * | Phase | Path                    | Verdict             | Conf | Evidence stem        |
 * |-------|-------------------------|---------------------|------|----------------------|
 * | 1     | MSAA name / description | Password            | 0.65 | msaa_*_match         |
 * | 2a    | Hit-element metadata    | Password / Username | 0.70 | uia_meta_*           |
 * | 2b    | Ancestor walk           | Password / Username | 0.65 | uia_ancestor_*       |
 * | 2c    | Descendant DFS          | Password            | 0.70 | uia_descendant_match |
 * | 2d    | Form-context peers      | Password / Username | 0.40 | form_*               |
 *
 * Three setup failures cut the cascade short before the later phases run:
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
 * @par Form-context rules (phase 2d)
 * The path needs a form-like ancestor and at least two enumerated inputs. The clicked input
 * is the peer that CompareElements matches, or, when the hit element is a wrapper outside
 * the enumeration, the first peer whose rect contains the click point. When no peer is
 * identified nothing is inferred and the phase leaves the verdict Unknown. Once a peer is
 * identified:
 * - The peer looks like a password field: Password.
 * - The peer looks like a username field: Username.
 * - Peer unclassified, another peer looks like a username and none looks like a password:
 *   Password.
 * - Peer unclassified, any other peer looks like a password: Username.
 * - Peer unclassified, no peer classified at all: Username (`form_ambiguous_default_usr`).
 *
 * @par Tier-1 boundary
 * Tier-1 strong signals (UIA IsPassword, LegacyIAccessible state, MSAA
 * STATE_SYSTEM_PROTECTED) belong to UiaIsPasswordProbe. Phases 2a and 2b discard a password
 * observation whose source is "IsPassword" or "LegacyState" so that evidence stays Tier-1.
 * Phases 2c and 2d apply no such filter, so an IsPassword or LegacyState hit reached through
 * the descendant DFS or a form peer is reported as this probe's own Tier-2 evidence, at
 * confidence 0.70 and 0.40. Phase 2d compares each peer against the hit element, so it can
 * re-report the clicked element itself as `form_clicked_self_pwd`, which UiaIsPasswordProbe
 * also inspected.
 *
 * @par UIA singleton
 * Created on the first run() that reaches phase 2 and cached for the probe's lifetime, so
 * that call pays the CoCreateInstance cost. A failure is latched: after one failed create
 * the probe only ever runs phase 1 and reports `uia_init_failed`.
 *
 * @note Why Tier-2: each signal here (a name match, one ancestor's class string, a form
 *       peer) is too weak on its own to drive a fill, and any one of them can be falsified
 *       by a page that names a button `signinForm` or puts `aria-label="password"` on a
 *       benign element. Weight 0.6 times this probe's best confidence 0.7 is 0.42, below
 *       the 0.7 commit margin, so the probe can never decide a fill alone: another probe
 *       has to agree in the Tier-2 vote.
 */
class UiaMetadataProbe : public IProbe
{
public:
    /// @brief Construct the probe; UIA initialisation is deferred to the first run().
    UiaMetadataProbe();

    /// @brief Release the cached UIA singleton (if any) and PIMPL state.
    ~UiaMetadataProbe() override;

    UiaMetadataProbe(const UiaMetadataProbe&) = delete;
    UiaMetadataProbe& operator=(const UiaMetadataProbe&) = delete;
    UiaMetadataProbe(UiaMetadataProbe&&) = delete;
    UiaMetadataProbe& operator=(UiaMetadataProbe&&) = delete;

    /**
     * @brief Run the five Tier-2 detection paths in order.
     *
     * The first positive signal stops the search. The evidence string
     * records which path matched, so weight-tuning telemetry can attribute
     * confidence to a specific signal.
     *
     * @param ctx Click-site context. m_ClickPoint drives every path: it
     *            seeds the UIA ElementFromPoint hit and the MSAA lookup, and
     *            its x/y feed the ancestor and descendant bounding-rect
     *            filtering. m_TargetWindow is unused here.
     * @return Verdict::Password or Verdict::Username when a signal fires, at
     *         confidence 0.4 to 0.7 depending on the path (form-context peer
     *         inference is weakest at 0.4; hit-element and descendant
     *         metadata are strongest at 0.7), else Verdict::Unknown. The
     *         Unknown evidence names the stop point: `uia_init_failed`,
     *         `uia_element_from_point_failed`, `uia_raw_walker_failed`, or
     *         `all_signals_unknown` when every path ran without a match.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("uia_metadata").
    const char* name() const override { return "uia_metadata"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * Heavier than UiaIsPasswordProbe (50 ms) because this probe also walks
     * the ancestor chain, a descendant subtree and the form peers; 150 ms is
     * the typical worst case for a real-world login form. The depth and node
     * caps bound how many cross-process calls happen, not how long one of
     * them takes, and nothing enforces the budget: a stalled provider stalls
     * the whole fusion pass.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(150); }

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
