#pragma once

#include "Probe.hpp"

#include <span>

namespace seal
{

/**
 * @struct FusionOutcome
 * @brief Verdict plus how it was reached.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * The zero-gesture auto-fill path needs to know how a verdict was reached, so it refuses to
 * type a secret unless an on-disk probe corroborated the bridge. A verdict that only cleared
 * the Tier-2 margin carries both flags false and never releases a secret automatically.
 *
 * @par Flag combinations
 * | ShortCircuit | Corroborated | How the verdict was reached                  |
 * |--------------|--------------|----------------------------------------------|
 * | false        | false        | Tier-2 weighted vote, or no signal at all.   |
 * | true         | false        | On-disk Tier-1 only; the bridge did not hit. |
 * | true         | true         | Bridge Tier-1 plus an agreeing on-disk hit.  |
 *
 * The fourth combination (false / true) cannot occur: corroboration is
 * recorded only inside an accepted short-circuit.
 */
struct FusionOutcome
{
    Verdict m_Verdict = Verdict::Unknown;  ///< Fused classification; Unknown when nothing decided.
    bool m_Tier1ShortCircuit = false;      ///< A Tier-1 short-circuit decided the verdict.
    bool m_BridgeCorroborated = false;     ///< Bridge Tier-1 hit agreed with an on-disk Tier-1 hit.
};

/**
 * @class FusionDecider
 * @brief Combines ProbeResult values into a single Verdict.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Two-tier fusion: a Tier-1 short-circuit for high-confidence single-probe
 * hits, with a Tier-2 weighted vote when no probe wins outright.
 * FillController runs every probe in the registry, hands the results to
 * @ref decideDetailed, and types the credential field the Verdict names.
 * @ref decide is the flag-free wrapper; its only production caller is the Ctrl+Click
 * diagnose report, and the unit tests use it as well.
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
 *     BRIDGE{All Tier-1 hits<br/>from browser_extension?}:::gate
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
 *   Win32StyleProbe, UiaIsPasswordProbe. One of them can decide the verdict
 *   alone at confidence >= 0.95, unless every Tier-1 hit came from the
 *   browser-extension probe (rule M5: its trust depends on a remote
 *   extension, so it is never decisive alone). M-numbers refer to the
 *   mitigation index in BrowserBridge.hpp. Eligibility is per probe, not per
 *   verdict: Win32StyleProbe reaches 0.95 only on Password (its Username
 *   verdict is 0.55) and UiaIsPasswordProbe never emits Username.
 * - **Tier-2 (vote only)** - UiaMetadataProbe (weight 0.6) and ImeStateProbe
 *   (weight 0.3). They never short-circuit, even at confidence 1.0.
 *
 * When no probe short-circuits, the vote sums `weight * confidence` over
 * every probe with a known profile, the three Tier-1 probes included.
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
 * `*` browser_extension is Tier-1 eligible, but rule M5 forbids it from
 * short-circuiting alone: an on-disk Tier-1 probe must corroborate.
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
 * The 0.95 short-circuit threshold, the 0.7 commit margin and the per-probe
 * Tier-2 weights are compile-time constants in @c FusionDecider.cpp. Tune them
 * from @c logFill telemetry: every fill writes one @c event=fill.decide line
 * carrying each probe's verdict, confidence and evidence. They are deliberately
 * not runtime config, so a user cannot disable the M5 gate.
 *
 * @par Purity
 * FusionDecider holds no state. Both entry points are const, allocate
 * nothing and read @p results once per pass, so equal input yields equal
 * output and concurrent calls on one instance are safe. Result order does
 * not matter, and a probe name that appears twice is counted twice.
 *
 * @note In a browser the only on-disk corroborator that fires is
 *       UiaIsPasswordProbe, whose verdict comes from the same page DOM
 *       (`<input type=password>`) as browser_extension, so M5 corroboration
 *       is not page-independent there. It hardens against a lying extension,
 *       not against a hostile page; FillController's host-binding release
 *       gates are what prevent wrong-site release.
 *
 * @note One Tier-1 hit at confidence >= 0.95 short-circuits, unless that hit is
 *       browser_extension, which needs an agreeing on-disk Tier-1 hit (M5).
 *       browser_extension is also the only Tier-1 probe that emits Username at
 *       or above 0.95, so a Username short-circuit cannot happen today: the
 *       bridge's Username hit is blocked alone and no on-disk probe can agree
 *       with it. So @ref FusionOutcome::m_Tier1ShortCircuit implies Password and
 *       the auto-fill gate cannot release a username. Nothing here enforces it:
 *       raising a Username confidence above 0.95 in Win32StyleProbe or
 *       UiaIsPasswordProbe would end the invariant silently.
 *
 * @note Probes that emit @c Verdict::Unknown are skipped in both passes:
 *       they neither short-circuit nor add to the Tier-2 sum. FillController
 *       reads a final @c Verdict::Unknown as "no signal" and falls back to
 *       its sequential "username first, then password" flow.
 *
 * @see ProbeResult, IProbe, FusionOutcome, BrowserBridge
 */
class FusionDecider
{
public:
    /**
     * @brief Fuse probe results into a final Verdict.
     *
     * Wrapper over @ref decideDetailed that drops the provenance flags. Use
     * it only where those flags do not matter; both fill paths call
     * @ref decideDetailed directly.
     *
     * A Tier-2 margin exactly equal to the commit constant still commits:
     * the comparison is `>=`, not `>`.
     *
     * @param results One ProbeResult per probe that ran, in any order. A
     *                result whose @c m_ProbeName is null, empty, or absent
     *                from the per-probe weight table is ignored in both
     *                passes; an empty span yields Unknown.
     * @return Verdict::Password, Verdict::Username or Verdict::Unknown.
     *         Unknown tells the caller to use FillController's sequential
     *         fallback.
     */
    Verdict decide(std::span<const ProbeResult> results) const;

    /**
     * @brief Fuse probe results, also reporting how the verdict was reached.
     *
     * Same verdict as @ref decide (which delegates here), plus the two
     * provenance flags.
     *
     * The auto-fill path releases a secret only when
     * `m_Tier1ShortCircuit && m_BridgeCorroborated`, so the browser
     * extension - outside the signed-binary trust boundary, rule M5 - can
     * never solo-decide an auto-typed secret through the Tier-2 vote.
     *
     * The manual Ctrl+Click path applies the same conjunction, but only when
     * releasing a password into a window the bridge knows
     * (`reason=weak_fusion_manual`). A target with no bridge entry, and
     * every username release, ignores both flags.
     *
     * @param results One ProbeResult per probe that ran, in any order; same
     *                filtering rules as @ref decide.
     * @return The verdict and its provenance flags. Both flags are false
     *         whenever the Tier-2 vote decided the verdict, and
     *         @ref FusionOutcome::m_BridgeCorroborated is never true while
     *         @ref FusionOutcome::m_Tier1ShortCircuit is false.
     */
    FusionOutcome decideDetailed(std::span<const ProbeResult> results) const;
};

}  // namespace seal
