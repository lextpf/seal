#pragma once

#include "Probe.hpp"

namespace seal
{

/**
 * @class Win32StyleProbe
 * @brief Detects password fields via native Win32 edit style flags.
 * @author Alex (https://github.com/lextpf)
 * @ingroup FillController
 *
 * Drills down to the actual edit control under the click with
 * RealChildWindowFromPoint, starting from the shared `m_TargetWindow` (or
 * `WindowFromPoint` when that snapshot is null), then reads the style bits.
 * Reliable on native Win32 dialogs even when the app exposes no UIA.
 *
 * @par Signal precedence (first match wins)
 * | # | Signal                            | Verdict  | Conf | Evidence suffix   |
 * |:-:|-----------------------------------|----------|:----:|-------------------|
 * | 1 | `GWL_STYLE & ES_PASSWORD` bit set | Password | 0.98 | style=ES_PASSWORD |
 * | 2 | `EM_GETPASSWORDCHAR` != 0         | Password | 0.95 | mask_char_set     |
 * | 3 | edit-like class, no password flag | Username | 0.55 | no_password_style |
 * | - | class not edit-like               | Unknown  | 0.00 | (suffix omitted)  |
 * | - | no HWND under the click           | Unknown  | 0.00 | (evidence empty)  |
 *
 * Every row that resolved an HWND prefixes its evidence with
 * `class=<class name>`, so rows 1 to 3 land in the log line as two logfmt
 * tokens. Non-ASCII characters in the class name become `?`.
 *
 * Edit-like classes: `Edit`, `RichEdit`, `RichEdit20A`, `RichEdit20W`,
 * `RICHEDIT50W`, `TEdit` (Delphi VCL).
 *
 * @par Click-site resolution
 * @code
 *   start = m_TargetWindow, or WindowFromPoint(clickPoint) if null
 *       |
 *       v   drillDown(): RealChildWindowFromPoint loop,
 *       |               descend until child == self | null
 *       v
 *   deepest child HWND --- null ---> Verdict::Unknown
 *       |
 *       v
 *   GetClassNameW -> isEditLikeClass(cls)?
 *       no  -> Verdict::Unknown   (evidence "class=<cls>")
 *       yes -> evaluate signals 1..3 (see table)
 * @endcode
 *
 * @par Cost and blocking
 * `EM_GETPASSWORDCHAR` leaves through `SendMessageW`, which blocks until the
 * thread that owns the target window answers. There is no timeout and
 * nothing enforces the 5 ms budget, so a hung target window stalls the whole
 * fusion pass. The style read and the class-name read cannot block.
 *
 * @note The class name is read into a 64-character buffer. A longer name is
 *       truncated, which only changes the evidence text: the edit-like test
 *       compares against short exact names. When `GetClassNameW` fails the
 *       buffer stays empty, the class is not edit-like, and the evidence is
 *       the bare token `class=`.
 *
 * @note A Username answer here is deliberately 0.55, below the 0.95 Tier-1
 *       threshold, so it can only ever vote in the Tier-2 pass with weight
 *       0.7. Only the Password answers are Tier-1 strength.
 *
 * @note Stateless by design. Win32 dialogs give the same answer on every
 *       call: `GWL_STYLE` does not change between clicks and
 *       `EM_GETPASSWORDCHAR` returns the same character. There is nothing to
 *       cache, so the probe holds no fields and no PIMPL, unlike the two UIA
 *       probes; FillController keeps it as a plain member alongside them.
 */
class Win32StyleProbe : public IProbe
{
public:
    /**
     * @brief Inspect the click site's native Win32 edit style.
     *
     * `ctx.m_TargetWindow` is raw `WindowFromPoint` output, which on a
     * native dialog can still be a container rather than the Edit control,
     * so the probe drills down with `RealChildWindowFromPoint` until the
     * returned child stops changing, then checks the three signals in
     * confidence order.
     *
     * @param ctx Click-site context. m_TargetWindow seeds the drill-down and
     *            m_ClickPoint drives every `RealChildWindowFromPoint` hop;
     *            the point is converted to client coordinates once per level.
     * @return Verdict::Password at 0.98 or 0.95 confidence on a hit,
     *         Verdict::Username at 0.55 on a bare-Edit fallback, or
     *         Verdict::Unknown when the click did not land on a child window
     *         this probe recognises.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    /// @brief FusionDecider lookup key ("win32_es_password").
    const char* name() const override { return "win32_es_password"; }

    /**
     * @brief Per-call budget in milliseconds.
     *
     * Win32 style queries are a handful of `GetWindowLong` / `SendMessage`
     * calls and return in microseconds. The 5 ms budget is the soft cap for
     * telemetry.
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(5); }
};

}  // namespace seal
