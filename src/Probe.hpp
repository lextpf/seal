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
 * @enum Verdict
 * @brief Verdict of a single field-detection probe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Probes emit one Verdict per click target. FillController fuses them through
 * FusionDecider into one fill decision. The manual Ctrl+Click path and the
 * staged zero-gesture path, which fires on a plain click, use the same probes.
 *
 * ## :material-state-machine: Verdict Lifecycle
 *
 * - Each probe produces exactly one Verdict per click.
 * - Unknown is a first-class verdict meaning "no signal here", not an
 *   implicit abstention: fusion neither short-circuits on it nor counts it
 *   in the weighted Tier-2 vote.
 * - The underlying type is fixed at `std::uint8_t` so a ProbeResult packs
 *   without padding surprises.
 */
enum class Verdict : std::uint8_t
{
    Password,  ///< Probe is confident this click landed on a password field.
    Username,  ///< Probe is confident this is a username / email / login field.
    Unknown    ///< Probe ran but produced no actionable signal.
};

/**
 * @struct ProbeResult
 * @brief Result emitted by an IProbe for one click target.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Probes never log directly. FillController::runProbeRegistryDetailed() emits
 * one `event=fill.decide` line per fusion pass, not one line per result: every
 * probe contributes `<m_ProbeName>_verdict`, `<m_ProbeName>_conf` and, when
 * non-empty, `<m_ProbeName>_evidence` fields to that single line.
 *
 * ## :material-format-list-bulleted: Fields
 *
 * - **m_Verdict** - Password / Username / Unknown.
 * - **m_Confidence** - probe-defined [0.0, 1.0]; the Tier-1 short-circuit
 *   threshold is 0.95 (see FusionDecider). Nothing clamps the value, and
 *   FusionDecider multiplies it straight into the probe weight, so a figure
 *   above 1.0 inflates that probe's Tier-2 vote.
 * - **m_ProbeName** - stable static string literal, used as the log field
 *   prefix and as the lookup key into FusionDecider's per-probe weight
 *   table. It must match exactly across probe code, decider code and
 *   weight-tuning telemetry.
 * - **m_Evidence** - short free-form summary for telemetry.
 *   seal::diag::sanitizeAscii rewrites it at log time: every byte outside
 *   printable ASCII becomes `?`, and anything past 96 characters is cut to
 *   `...`. Spaces survive, so evidence that contains one (for example
 *   `class=Edit style=ES_PASSWORD`) becomes several logfmt tokens.
 *
 * @note A default-constructed ProbeResult is the neutral "no signal" shape:
 *       Unknown verdict, zero confidence, empty name and evidence. A probe
 *       that early-exits on a context invariant must still set m_ProbeName
 *       first: an empty name matches no weight-table entry, so the result
 *       drops out of fusion and its log fields lose their prefix.
 */
struct ProbeResult
{
    Verdict m_Verdict = Verdict::Unknown;  ///< Final per-probe classification.
    float m_Confidence = 0.0f;             ///< Range [0.0, 1.0].
    const char* m_ProbeName = "";          ///< Static string literal owned by the probe.
    std::string m_Evidence;                ///< Short summary for telemetry (sanitised at log time).
};

/**
 * @struct ProbeContext
 * @brief Resolved click-site data handed to every probe.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * FillController::runProbeRegistryDetailed() builds one snapshot per fusion
 * pass and passes it by const reference to all five probes, so every probe
 * in a pass agrees on which window the user clicked.
 *
 * @par Reading the target window
 * Read `m_TargetWindow` from the snapshot instead of calling
 * `WindowFromPoint` again: a second call can return a different window when
 * a tooltip closes or another window takes the foreground between two
 * probes. A probe may call `WindowFromPoint(m_ClickPoint)` itself only when
 * `m_TargetWindow` is null, as `Win32StyleProbe` does, because that resolves
 * the same click point.
 *
 * @note `m_TargetWindow` is raw `WindowFromPoint` output: the deepest
 *       visible, enabled window containing the point. It is not necessarily
 *       the top-level frame, nor necessarily the innermost edit control.
 *       Win32StyleProbe drills further with `RealChildWindowFromPoint`;
 *       ImeStateProbe reads this window as-is, so in a browser it queries
 *       the renderer widget rather than the clicked input.
 *
 * @note The snapshot holds a raw HWND and PID; a probe validates neither
 *       again. A window destroyed mid-pass leaves a stale handle, on which
 *       every Win32 call a probe makes fails safely into `Verdict::Unknown`.
 */
struct ProbeContext
{
    POINT m_ClickPoint{};           ///< Screen coords (raw mouse hook output).
    HWND m_TargetWindow = nullptr;  ///< Result of WindowFromPoint(m_ClickPoint); may be null.
    DWORD m_TargetProcessId = 0;    ///< Owner PID of m_TargetWindow; 0 when that window is null.

    /// Advisory deadline: fusion-pass start plus 300 ms. Nothing enforces it.
    /// No probe reads it, the orchestrator never cancels a probe, and no log
    /// line carries it. The field is reserved for a future orchestrator that
    /// skips or cancels an over-budget probe. Today it only records the 300 ms
    /// envelope the summed probe budgets fit inside.
    std::chrono::steady_clock::time_point m_Deadline;
};

/**
 * @class IProbe
 * @brief Field-detection probe interface.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * FillController owns one instance of each probe and reuses it for every
 * click, so a probe must tolerate repeated calls with a different context.
 *
 * @par Threading
 * Every probe runs on the Qt main thread: the low-level mouse hook posts a
 * queued call to `performType`, `performTypeAuto` or `performDiagnose`, and
 * the registry runs inside that slot. Probes therefore need no internal
 * locking, but they must not be moved to another thread either - the two UIA
 * probes cache a COM pointer bound to the main thread's apartment.
 *
 * ## :material-handshake: Contract
 *
 * A concrete probe must satisfy all of these, or the fusion layer's
 * guarantees collapse:
 *
 * - **Never throws.** The orchestrator runs probes back-to-back in one
 *   sequential pass; a thrown exception aborts the whole fusion and silently
 *   loses the fill. Catch internally and degrade to `Verdict::Unknown`.
 * - **Returns quickly.** `budget()` is advisory: nothing times a probe and
 *   nothing cancels one. The five probes run in a fixed sequence on the main
 *   thread and the keystrokes cannot start until the last one returns, so an
 *   overrunning probe stalls the whole fill and freezes the UI. Bound every
 *   loop and every cross-process call.
 * - **Owns its own state.** A probe instance outlives one click, so any
 *   cache it keeps must stay valid across clicks and across target
 *   processes. The UIA probes cache only the automation object, never a
 *   per-click element.
 * - **Read-only at the click site.** Probes never call SendInput, never
 *   modify the verdict map, and emit no telemetry line of their own: the
 *   orchestrator writes the single `event=fill.decide` line from the
 *   returned ProbeResult. The one exception is the shared descendant walk in
 *   `UiaCommon.cpp`, which traces a match through `qCDebug(logFill)`.
 *
 * Probes are not free of observable effects either:
 * `AccessibleObjectFromPoint` sends `WM_GETOBJECT` into the target process,
 * which makes Chromium build its lazy accessibility tree. UiaIsPasswordProbe
 * and UiaMetadataProbe both depend on that.
 *
 * ## :material-format-list-bulleted: Concrete probes
 *
 * Run order is fixed in FillController::runProbeRegistryDetailed():
 *
 * 1. `BrowserBridgeProbe`  (Tier-1) - consults the browser-extension verdict map.
 * 2. `Win32StyleProbe`     (Tier-1) - inspects GWL_STYLE / EM_GETPASSWORDCHAR.
 * 3. `UiaIsPasswordProbe`  (Tier-1) - MSAA STATE_SYSTEM_PROTECTED + UIA IsPassword.
 * 4. `UiaMetadataProbe`    (Tier-2) - UIA name / metadata / form-context heuristics.
 * 5. `ImeStateProbe`       (Tier-2) - IME context absent => weak password lean.
 *
 * The order is not a fusion input - FusionDecider reads the results as an
 * unordered set. It matters only for cost: probes 3 and 4 each send
 * `WM_GETOBJECT` through `AccessibleObjectFromPoint`, so running probe 3 first
 * means probe 4 meets an accessibility tree Chromium has already started to
 * build. Probe 4 warms the tree itself as well, so a different order changes
 * latency, not which element probe 4 resolves.
 *
 * Tier-1 probes can short-circuit fusion when they hit at confidence >= 0.95;
 * Tier-2 probes only ever vote. See `FusionDecider` for the decision tree.
 */
class IProbe
{
public:
    virtual ~IProbe() = default;

    /**
     * @brief Inspect the click site and emit a verdict.
     *
     * Called once per fusion pass. An implementation should read the shared
     * ProbeContext rather than re-resolving the window, bail out with
     * `Verdict::Unknown` when the context is unusable (no target window, no
     * reachable UIA or MSAA provider), and set `m_ProbeName` to the same
     * string `name()` returns so the log fields and the weight-table key
     * match.
     *
     * @param ctx Click-site context, valid for the duration of the call
     *            only; a probe must not store the HWND or the point past the
     *            return.
     * @return Populated ProbeResult; never throws.
     *
     * @note The probe loop is synchronous, so the fill cannot start until
     *       every probe has returned. Keep the call inside `budget()`.
     */
    virtual ProbeResult run(const ProbeContext& ctx) = 0;

    /**
     * @brief Stable identifier for this probe; the FusionDecider lookup key.
     *
     * The returned string must be a static literal with program lifetime:
     * ProbeResult stores it as `const char*` without copying. The same
     * literal must appear in FusionDecider's per-probe weight table, or the
     * probe drops out of fusion entirely - an unknown name is skipped in
     * both the Tier-1 short-circuit pass and the Tier-2 vote, so the probe
     * still costs its full run time but can never change a verdict.
     *
     * @return Static C string literal, for example "win32_es_password".
     */
    virtual const char* name() const = 0;

    /**
     * @brief Soft per-call budget the probe is expected to hold itself to.
     *
     * Nothing measures the call and nothing cancels an overrun; the budget
     * documents the expectation and is the number to compare against when
     * tuning. The five declared budgets sum to 212 ms (5 + 5 + 50 + 150 + 2),
     * inside the 300 ms `ctx.m_Deadline` for the whole pass, so a pass that
     * respects every budget also respects the deadline.
     *
     * @return The per-call budget in milliseconds. Constant per probe; the
     *         value does not depend on the click site.
     */
    virtual std::chrono::milliseconds budget() const = 0;
};

}  // namespace seal
