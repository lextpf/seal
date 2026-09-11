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
 * @brief Field classification shared by manual and staged fill.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Unknown contributes neither a tier-1 short-circuit nor a weighted vote.
 */
enum class Verdict : std::uint8_t
{
    Password,  ///< Probe is confident this click landed on a password field.
    Username,  ///< Probe is confident this is a username / email / login field.
    Unknown    ///< Probe ran but produced no actionable signal.
};

/**
 * @struct ProbeResult
 * @brief One probe result for the orchestrator's combined decision log.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Confidence must be in [0,1]; fusion does not clamp it. The probe name must match
 * the static name and weight-table key even on early exits.
 * Evidence is sanitized to printable ASCII and capped at 96 characters;
 * spaces survive and can create multiple logfmt tokens.
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
 * @brief Immutable click snapshot shared by all probes in one pass.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Reuse m_TargetWindow; call WindowFromPoint only if it is null to avoid resolving
 * different windows mid-pass. The raw result may be a container rather than an
 * edit control. Probes do not revalidate the HWND/PID; failed API reads must
 * degrade to Unknown.
 */
struct ProbeContext
{
    POINT m_ClickPoint{};           ///< Screen coords (raw mouse hook output).
    HWND m_TargetWindow = nullptr;  ///< Result of WindowFromPoint(m_ClickPoint); may be null.
    DWORD m_TargetProcessId = 0;    ///< Owner PID of m_TargetWindow; 0 when that window is null.

    /**
     * Advisory deadline, 300 ms after the pass starts. Probes do not read it,
     * and the orchestrator neither skips nor cancels work when it expires.
     */
    std::chrono::steady_clock::time_point m_Deadline;
};

/**
 * @class IProbe
 * @brief Reusable read-only field probes run sequentially on the GUI thread.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Catch failures internally and return Unknown. Budgets are advisory; bound loops
 * and cross-process work because overruns block the GUI. UIA objects belong to
 * the initialized main-thread COM apartment and must not move to another thread.
 * Cache automation state, never per-click elements.
 *
 * The orchestrator logs results. The shared UIA descendant walk also traces
 * matches. AccessibleObjectFromPoint sends WM_GETOBJECT and can initialize a
 * browser's lazy accessibility tree.
 *
 * Run order is bridge, Win32 style, UIA IsPassword, UIA metadata, then IME.
 * Fusion ignores order, but the first UIA probe may reduce the next probe's cost.
 */
class IProbe
{
public:
    virtual ~IProbe() = default;

    /**
     * @fn ProbeResult run(const ProbeContext& ctx)
     * @brief Inspect the shared snapshot without retaining click state.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Set m_ProbeName to name() on every result, including Unknown.
     *
     * @param ctx Valid only during the call.
     * @return Unknown if the context/provider is unusable; never throw.
     */
    virtual ProbeResult run(const ProbeContext& ctx) = 0;

    /**
     * @fn const char* name() const
     * @brief Static probe identifier matching the fusion weight-table key.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Unknown names are ignored in both fusion passes.
     *
     * @return String literal with process lifetime.
     */
    virtual const char* name() const = 0;

    /**
     * @fn std::chrono::milliseconds budget() const
     * @brief Advisory per-call budget in milliseconds.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Nothing times or cancels overruns. Declared budgets total 212 ms
     * (5 + 5 + 50 + 150 + 2), within the advisory 300 ms pass deadline.
     */
    virtual std::chrono::milliseconds budget() const = 0;
};

}  // namespace seal
