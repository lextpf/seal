#pragma once

#include <chrono>
#include <cstdint>
#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace seal
{

/**
 * @brief Verdict of a single field-detection probe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Probes emit one Verdict per Ctrl+Click target. The orchestrator in
 * FillController combines all probes' verdicts via FusionDecider into a
 * final fill decision.
 *
 * ## :material-state-machine: Verdict Lifecycle
 *
 * - Each probe produces exactly one Verdict per click.
 * - Probes never "abstain" implicitly: Unknown is a first-class verdict
 *   that explicitly says "no signal here," and the fusion logic treats it
 *   distinctly from Password / Username (it neither short-circuits nor
 *   contributes to the weighted Tier-2 vote).
 * - Verdict is intentionally an `enum class : std::uint8_t` so it can be
 *   stored in tight per-result structures without padding surprises.
 */
enum class Verdict : std::uint8_t
{
    Password,  ///< Probe is confident this click landed on a password field.
    Username,  ///< Probe is confident this is a username / email / login field.
    Unknown    ///< Probe ran but produced no actionable signal.
};

/**
 * @brief Result emitted by an IProbe for one Ctrl+Click target.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Probes never log directly; the orchestrator in FillController writes
 * one logfmt line per result using seal::diag::joinFields. Keep
 * m_Evidence short and ASCII-safe; it is fed through
 * seal::diag::sanitizeAscii at log time.
 *
 * ## :material-format-list-bulleted: Fields
 *
 * - **m_Verdict** - Password / Username / Unknown.
 * - **m_Confidence** - probe-defined [0.0, 1.0]; Tier-1 short-circuit
 *   threshold is 0.95 (see FusionDecider).
 * - **m_ProbeName** - stable static string literal; used both as a log
 *   field and as the lookup key into FusionDecider's per-probe weight
 *   table. Must match exactly across probe code, decider code, and
 *   weight-tuning telemetry.
 * - **m_Evidence** - free-form short summary for telemetry. Sanitised at
 *   log time to ASCII-safe single-word tokens. Stay under ~64 bytes.
 *
 * @note Default-constructed ProbeResult is the "probe didn't run" shape:
 *       Unknown verdict, zero confidence, empty name and evidence.
 *       Probes that early-exit on a context invariant can return it as-is.
 */
struct ProbeResult
{
    Verdict m_Verdict = Verdict::Unknown;  ///< Final per-probe classification.
    float m_Confidence = 0.0f;             ///< Range [0.0, 1.0].
    const char* m_ProbeName = "";          ///< Static string literal owned by the probe.
    std::string m_Evidence;                ///< Short summary for telemetry (sanitised at log time).
};

/**
 * @brief Resolved click-site data handed to every probe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Built once per fusion pass in FillController::runProbeRegistryDetailed()
 * so probes share a consistent HWND/PID view even if the foreground window
 * changes mid-run. Probes should read `m_TargetWindow` from this snapshot
 * rather than re-resolving the top-level window themselves - the shared
 * snapshot guarantees every probe in a single fusion pass agrees on what
 * window the user clicked on, even when an Esc dismisses a tooltip or a
 * focus-stealing dialog races the click. A probe may fall back to
 * `WindowFromPoint(m_ClickPoint)` only when `m_TargetWindow` is null (as
 * `Win32StyleProbe` does), since that re-resolves the same click point.
 */
struct ProbeContext
{
    POINT m_ClickPoint{};                              ///< Screen coords (raw mouse hook output).
    HWND m_TargetWindow = nullptr;                     ///< Result of WindowFromPoint(clickPoint).
    DWORD m_TargetProcessId = 0;                       ///< Owner PID of m_TargetWindow.
    std::chrono::steady_clock::time_point m_Deadline;  ///< Hard deadline; probes may early-exit.
};

/**
 * @brief Field-detection probe interface.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Implementations must be re-entrant (one instance shared across calls)
 * and thread-safe with respect to their own state. Probes are called
 * from the Qt main thread or a QThreadPool worker.
 *
 * ## :material-handshake: Contract
 *
 * Every concrete probe must satisfy ALL of these or the fusion layer's
 * guarantees collapse:
 *
 * - **Never throws.** The orchestrator runs probes back-to-back in a
 *   single sequential pass; a thrown exception would abort the whole
 *   fusion and silently lose the fill. Probes must catch internally and
 *   degrade to `Verdict::Unknown`.
 * - **Returns inside `budget()`.** The orchestrator may cancel a probe
 *   that exceeds its declared budget (e.g. via `ctx.m_Deadline`). Probes
 *   should poll the deadline on heavy work and bail with Unknown.
 * - **Re-entrant.** A single probe instance is reused across every click;
 *   any mutable cache must be guarded with the probe's own synchronisation.
 * - **No side effects in the probe call itself.** Probes inspect the
 *   click site (read-only). They never call SendInput, never modify the
 *   bridge map, never write to logs. The orchestrator logs on their
 *   behalf using the ProbeResult.
 *
 * ## :material-format-list-bulleted: Concrete probes
 *
 * - `BrowserBridgeProbe`   (Tier-1) - consults the WebExtension bridge map.
 * - `Win32StyleProbe`      (Tier-1) - inspects GWL_STYLE / EM_GETPASSWORDCHAR.
 * - `UiaIsPasswordProbe`   (Tier-1) - MSAA STATE_SYSTEM_PROTECTED + UIA IsPassword.
 * - `UiaMetadataProbe`     (Tier-2) - UIA name / metadata / form-context heuristics.
 * - `ImeStateProbe`        (Tier-2) - IME context absent => weak password lean.
 *
 * Tier-1 probes can short-circuit fusion when they hit at confidence >= 0.95.
 * Tier-2 probes contribute to the weighted vote regardless. See
 * `FusionDecider` for the exact decision tree.
 */
class IProbe
{
public:
    virtual ~IProbe() = default;

    /**
     * @brief Inspect the click site and emit a verdict.
     *
     * Called once per Ctrl+Click target. Implementations should:
     *   - Read the shared ProbeContext (prefer `m_TargetWindow` over re-resolving).
     *   - Bail early with `Verdict::Unknown` if the context is unusable
     *     (no target window, hostile integrity level, etc.).
     *   - Populate `m_ProbeName` with the same string `name()` returns,
     *     so log lines and FusionDecider's weight table key match.
     *
     * @param ctx Click-site context (already resolved by the caller).
     * @return Populated ProbeResult; never throws.
     *
     * @note This is the only hot-path method on the interface. Keep it
     *       inside `budget()` - the orchestrator may cancel a probe
     *       that overshoots its declared budget on a future revision,
     *       and even today the synchronous probe loop blocks the fill
     *       from starting until every probe returns.
     */
    virtual ProbeResult run(const ProbeContext& ctx) = 0;

    /**
     * @brief Stable identifier for this probe; used as the FusionDecider lookup key.
     *
     * Returned string MUST be a static literal with program lifetime --
     * ProbeResult stores it as `const char*` without copying. The same
     * literal MUST appear in FusionDecider's per-probe weight table or
     * the probe will silently fall out of the Tier-2 vote.
     *
     * @return Static C string literal (e.g. "win32_es_password").
     */
    virtual const char* name() const = 0;

    /**
     * @brief Soft per-call budget; the orchestrator may cancel a probe that exceeds it.
     *
     * Today the orchestrator runs probes sequentially and does not enforce
     * the budget mechanically; the budget is advisory and used for
     * telemetry / threshold tuning. Future versions may parallelise the
     * registry and cancel any probe that exceeds its budget. Probes should
     * keep their own deadline inside `ctx.m_Deadline` and self-cancel.
     *
     * @return The per-call budget in milliseconds.
     */
    virtual std::chrono::milliseconds budget() const = 0;
};

}  // namespace seal
