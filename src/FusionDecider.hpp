#pragma once

#include "Probe.hpp"

#include <span>

namespace seal
{

/**
 * @struct FusionOutcome
 * @brief Fused verdict and release provenance.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Auto release requires both flags. Tier-2 outcomes carry neither.
 * Corroboration is recorded only inside an accepted short-circuit.
 *
 * | ShortCircuit | Corroborated | How the verdict was reached                  |
 * |--------------|--------------|----------------------------------------------|
 * | False        | False        | Tier-2 weighted vote, or no signal at all.   |
 * | True         | False        | On-disk tier-1 only; the bridge did not hit. |
 * | True         | True         | Bridge tier-1 plus an agreeing on-disk hit.  |
 */
struct FusionOutcome
{
    Verdict m_Verdict = Verdict::Unknown;  ///< Fused classification; Unknown when nothing decided.
    bool m_Tier1ShortCircuit = false;      ///< A tier-1 short-circuit decided the verdict.
    bool m_BridgeCorroborated = false;     ///< Bridge tier-1 hit agreed with an on-disk tier-1 hit.
};

/**
 * @class FusionDecider
 * @brief Fuse tier-1 agreement or a weighted vote into one verdict.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Tier-1 hits need confidence >= 0.95 and must agree. The bridge cannot
 * short-circuit alone. All known non-Unknown results participate in tier-2.
 * Thresholds and weights are compile-time constants.
 *
 * With weights w_i and confidence c_i in [0,1]:
 * $$
 * S_P = \sum_i w_i c_i \,[\,v_i = \text{Password}\,], \qquad
 * S_U = \sum_i w_i c_i \,[\,v_i = \text{Username}\,]
 * $$
 * $$
 * \text{verdict} =
 * \begin{cases}
 *   \text{Password} & S_P - S_U \ge 0.7 \\[2pt]
 *   \text{Username} & S_U - S_P \ge 0.7 \\[2pt]
 *   \text{Unknown}  & \text{otherwise}
 * \end{cases}
 * $$
 *
 * Stateless and allocation-free; concurrent calls are safe. Order does not matter;
 * duplicate probe names are counted twice.
 *
 * Browser UIA corroboration reads the same DOM password flag as the extension.
 * Corroboration checks the extension report; host binding prevents wrong-site release.
 * Only the bridge emits Username at tier-1 confidence, so the current profiles
 * cannot short-circuit to Username. Raising another probe's username confidence
 * would change that property.
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
 * | Probe (`m_ProbeName`) | C++ class          | Tier | Weight | Tier-1? |
 * |-----------------------|--------------------|------|--------|---------|
 * | `browser_extension`   | BrowserBridgeProbe | 1    | 0.90   | Yes*    |
 * | `win32_es_password`   | Win32StyleProbe    | 1    | 0.70   | Yes     |
 * | `uia_is_password`     | UiaIsPasswordProbe | 1    | 0.85   | Yes     |
 * | `uia_metadata`        | UiaMetadataProbe   | 2    | 0.60   | No      |
 * | `ime_state`           | ImeStateProbe      | 2    | 0.30   | No      |
 */
class FusionDecider
{
public:
    /**
     * @fn Verdict decide(std::span<const ProbeResult> results) const
     * @brief Fuse results without release provenance.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param results Unknown, empty, or null probe names are ignored; order is irrelevant.
     * @return Unknown for an empty span or insufficient evidence.
     * @warning Use decideDetailed for credential release.
     */
    Verdict decide(std::span<const ProbeResult> results) const;

    /**
     * @fn FusionOutcome decideDetailed(std::span<const ProbeResult> results) const
     * @brief Fuse results and retain the provenance required for release gates.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Staged auto release requires both flags and must still validate site, visit, and
     * focus. This result classifies the field only.
     *
     * @return Both flags false for tier-2; corroborated implies short-circuit.
     */
    FusionOutcome decideDetailed(std::span<const ProbeResult> results) const;
};

}  // namespace seal
