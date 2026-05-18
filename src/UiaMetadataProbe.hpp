#pragma once

#ifdef USE_QT_UI

#include "Probe.hpp"

#include <memory>

namespace seal
{

/**
 * @brief Tier-2 broad-signal UIA probe (metadata, tree walks, form context).
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Runs the lower-confidence detection paths that the existing
 * FillController::probeIsPassword and probeFormContext together cover:
 *   - MSAA accName / accDescription matched against the password hint table
 *   - UIA metadata properties (AutomationId, Name, HelpText, ...) scanned
 *     for password / username keywords in 17+ languages
 *   - Ancestor walk (depth <= kMaxUiaAncestorDepth) checking each
 *     bounding-box-containing parent for password / username evidence
 *   - Descendant DFS (depth <= kMaxUiaDescendantDepth) via
 *     searchDescendantsForPassword
 *   - Form-context peer inference via findFormAncestor + enumerateFormInputs
 *
 * Tier-1 strong signals (UIA IsPassword, LegacyIAccessible state, MSAA
 * STATE_SYSTEM_PROTECTED) are NOT handled here -- see UiaIsPasswordProbe for
 * those.
 *
 * The UIA singleton is lazy-initialised on first run() and cached for the
 * probe's lifetime; the first call pays the CoCreateInstance cost.
 *
 * @note **Why Tier-2?** Each individual signal here (a name match, a
 *       single ancestor's class string, an IME hint) is too weak on its
 *       own to drive a fill -- and any one of them can be falsified by
 *       a malicious page that names a button `signinForm` or sticks
 *       `aria-label="password"` on a benign element. The probe earns
 *       its keep by aggregating MULTIPLE such signals, but the result
 *       still has to combine with another Tier-1 or Tier-2 signal in
 *       FusionDecider before it crosses the 0.7 commit margin. Keeping
 *       it Tier-2 prevents single-signal false positives from short-
 *       circuiting the fusion.
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
     * The probe walks (1) MSAA name / description, (2) UIA metadata
     * properties via @c StringPropertyProbe table, (3) the ancestor
     * chain up to @c kMaxUiaAncestorDepth, (4) a bounded descendant
     * DFS, and (5) form-context peer enumeration. The first positive
     * signal stops the search; the evidence string records WHICH path
     * matched so weight-tuning telemetry can attribute confidence to
     * specific signals.
     *
     * @param ctx Click-site context. m_TargetWindow seeds the UIA tree
     *            walk; m_ClickPoint is used for bounding-rect filtering.
     * @return Verdict::Password / Verdict::Username at confidence
     *         ~0.6-0.7 when a signal fires (Tier-2 threshold), or
     *         Verdict::Unknown when none of the five paths produced a
     *         match.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("uia_metadata").
    const char* name() const override { return "uia_metadata"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * Heavier than UiaIsPasswordProbe (50 ms) because this probe walks
     * the ancestor + descendant tree. 150 ms is the typical worst-case
     * for a real-world login form; the @c kMaxUiaDescendantNodes / depth
     * caps keep a pathological tree from blowing past this.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(150); }

private:
    struct Impl;
    std::unique_ptr<Impl> m_Impl;
};

}  // namespace seal

#endif  // USE_QT_UI
