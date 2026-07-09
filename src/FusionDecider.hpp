#pragma once

#include "Probe.hpp"

#include <span>

namespace seal
{

/**
 * @brief The verdict plus how it was reached.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * @ref FusionDecider::decide returns only @ref m_Verdict; the zero-gesture
 * auto-fill path needs to know *how* a password verdict was reached so it
 * can refuse to auto-type a secret unless an on-disk probe corroborated the
 * bridge. A weighted-vote-only verdict (where the bridge alone cleared the
 * margin) has both flags false and must NOT release a secret automatically.
 */
struct FusionOutcome
{
    Verdict m_Verdict = Verdict::Unknown;
    bool m_Tier1ShortCircuit = false;   ///< A Tier-1 short-circuit decided the verdict.
    bool m_BridgeCorroborated = false;  ///< Bridge Tier-1 hit agreed with an on-disk Tier-1 probe.
};

/**
 * @brief Combines ProbeResult instances into a single Verdict.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Two-tier fusion: a Tier-1 short-circuit for high-confidence individual
 * probe hits, with a Tier-2 weighted-vote fallback when no probe wins
 * outright. The orchestrator in FillController runs every probe in the
 * registry, hands the results to @ref decide, and uses the returned
 * Verdict to pick which credential field to type.
 *
 * ## :material-chart-tree: Decision Tree
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * flowchart TD
 *     classDef gate fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
 *     classDef hit fill:#1e4a3a,stroke:#22c55e,color:#e2e8f0
 *     classDef fail fill:#4a3520,stroke:#f59e0b,color:#e2e8f0
 *     classDef unk fill:#3a1e3a,stroke:#a855f7,color:#e2e8f0
 *
 *     S([results]):::gate
 *     T1{Any Tier-1 probe<br/>conf >= 0.95?}:::gate
 *     CONF{All Tier-1 hits<br/>agree?}:::gate
 *     BRIDGE{Sole hit is<br/>browser_extension?}:::gate
 *     T2[Tier-2 weighted vote<br/>sum weight * conf<br/>per verdict]:::gate
 *     MARGIN{score margin<br/>>= 0.7?}:::gate
 *     OUT_T1([Verdict<br/>= Tier-1 winner]):::hit
 *     OUT_T2([Verdict<br/>= Tier-2 winner]):::hit
 *     OUT_UNK([Verdict::Unknown]):::unk
 *
 *     S --> T1
 *     T1 -->|no| T2
 *     T1 -->|yes| CONF
 *     CONF -->|no| T2
 *     CONF -->|yes| BRIDGE
 *     BRIDGE -->|yes, M5| T2
 *     BRIDGE -->|no| OUT_T1
 *     T2 --> MARGIN
 *     MARGIN -->|yes| OUT_T2
 *     MARGIN -->|no| OUT_UNK
 * ```
 *
 * ## :material-tier: Tier semantics
 *
 * - **Tier-1 (short-circuit eligible)** - BrowserBridgeProbe,
 *   Win32StyleProbe, UiaIsPasswordProbe. Each can decide the verdict
 *   single-handedly at confidence >= 0.95, *unless* the only Tier-1
 *   hit is the browser-extension probe (rule M5: the bridge alone is
 *   never decisive because its trust depends on a remote extension).
 * - **Tier-2 (weighted vote only)** - UiaMetadataProbe (weight 0.6)
 *   and ImeStateProbe (weight 0.3). They contribute to the weighted
 *   sum but never short-circuit, even at confidence 1.0.
 *
 * When no probe short-circuits, the Tier-2 weighted vote sums
 * `weight * confidence` over *every* probe with a known profile - the
 * three Tier-1 probes (weights 0.9 / 0.7 / 0.85) included, not only the
 * two Tier-2-only probes above.
 *
 * @par Probe weight profiles (kProfiles, FusionDecider.cpp)
 * | Probe (`m_ProbeName`) | C++ class          | Tier | Weight | Tier-1? |
 * |-----------------------|--------------------|:----:|:------:|:-------:|
 * | `browser_extension`   | BrowserBridgeProbe |  1   |  0.90  |  yes*   |
 * | `win32_es_password`   | Win32StyleProbe    |  1   |  0.70  |  yes    |
 * | `uia_is_password`     | UiaIsPasswordProbe |  1   |  0.85  |  yes    |
 * | `uia_metadata`        | UiaMetadataProbe   |  2   |  0.60  |  no     |
 * | `ime_state`           | ImeStateProbe      |  2   |  0.30  |  no     |
 *
 * `*` browser_extension is Tier-1 eligible but rule M5 forbids it from
 * short-circuiting alone - an on-disk Tier-1 probe must corroborate.
 *
 * @note In a browser the only on-disk corroborator that fires is
 *       UiaIsPasswordProbe, whose verdict derives from the same page DOM
 *       (`<input type=password>`) as browser_extension - so M5 corroboration
 *       is NOT page-independent there. It hardens against a lying extension,
 *       not a hostile page; strict host binding (FillController's release
 *       gates) is what prevents wrong-site release.
 *
 * @par Tier-2 weighted vote
 * With @f$ w_i @f$ the probe weight and @f$ c_i @f$ its confidence in
 * @f$ [0,1] @f$, summing over every non-Unknown probe with a known profile:
 * @f[
 *   S_P = \sum_i w_i c_i \,[\,v_i = \text{Password}\,], \qquad
 *   S_U = \sum_i w_i c_i \,[\,v_i = \text{Username}\,]
 * @f]
 * @f[
 *   \text{verdict} =
 *   \begin{cases}
 *     \text{Password} & S_P - S_U \ge 0.7 \\[2pt]
 *     \text{Username} & S_U - S_P \ge 0.7 \\[2pt]
 *     \text{Unknown}  & \text{otherwise}
 *   \end{cases}
 * @f]
 *
 * ## :material-target: Tunable constants
 *
 * The 0.95 short-circuit threshold, the 0.7 commit margin, and the
 * per-probe Tier-2 weights are compile-time constants in
 * @c FusionDecider.cpp. Tuning happens by reading @c logFill telemetry
 * (every fill writes one @c event=fill.decide line with full per-probe
 * verdict and confidence) and adjusting the constants in code - not
 * via a runtime config file. Keeping these constants out of user
 * config prevents a confused user from disabling the M5 gate.
 *
 * @note Probes that emit @c Verdict::Unknown are skipped completely in
 *       both passes: they neither count toward the Tier-1 short-circuit
 *       nor contribute to the Tier-2 sum. The orchestrator interprets
 *       a final @c Verdict::Unknown from @ref decide as "no signal" and
 *       falls back to the sequential "username first, then password"
 *       UX in FillController.
 */
class FusionDecider
{
public:
    /**
     * @brief Fuse probe results into a final Verdict.
     *
     * Applies the Tier-1 short-circuit gates first (any-hit, conflict
     * detection, M5 bridge-alone block) and falls through to the
     * Tier-2 weighted vote only when no probe wins outright. Verdict
     * is committed only when the leading Tier-2 score beats the runner
     * up by at least the margin constant; otherwise returns Unknown
     * so the caller can pick a safer default.
     *
     * @param results One ProbeResult per probe that ran (any order).
     *                Probes whose name is not in the per-probe weight
     *                table are silently ignored.
     * @return Verdict::Password / Verdict::Username / Verdict::Unknown.
     *         Unknown means the caller should fall through to the sequential
     *         fallback in FillController.
     */
    Verdict decide(std::span<const ProbeResult> results) const;

    /**
     * @brief Fuse probe results, also reporting how the verdict was reached.
     *
     * Identical verdict to @ref decide (which delegates here), plus the
     * @ref FusionOutcome::m_Tier1ShortCircuit and
     * @ref FusionOutcome::m_BridgeCorroborated flags. The auto-fill path
     * gates a secret release on `m_Tier1ShortCircuit && m_BridgeCorroborated`
     * so the browser extension (outside the signed-binary trust boundary,
     * rule M5) can never solo-decide an auto-typed secret via the Tier-2
     * vote. The manual Ctrl+Click path keeps using @ref decide unchanged.
     *
     * @param results One ProbeResult per probe that ran (any order).
     * @return The verdict and its provenance flags.
     */
    FusionOutcome decideDetailed(std::span<const ProbeResult> results) const;
};

}  // namespace seal
