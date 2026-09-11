#pragma once

#include "Probe.hpp"

namespace seal
{

/**
 * @class Win32StyleProbe
 * @brief Classify native edit controls from style and password-mask state.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Starts from the shared target, resolving WindowFromPoint only if null.
 * Recognized classes are Edit, RichEdit, RichEdit20A, RichEdit20W, RICHEDIT50W,
 * and TEdit. HWND evidence includes a sanitized class name capped at 64 characters;
 * class-query failure produces Unknown with class=.
 *
 * EM_GETPASSWORDCHAR uses blocking SendMessageW with no timeout. A hung target
 * can stall the entire fusion pass; the 5 ms budget is advisory.
 * Username confidence stays below the tier-1 threshold.
 *
 * @verbatim
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
 * @endverbatim
 *
 * | # | Signal                            | Verdict  | Conf | Evidence suffix   |
 * |---|-----------------------------------|----------|------|-------------------|
 * | 1 | `GWL_STYLE & ES_PASSWORD` bit set | Password | 0.98 | Style=ES_PASSWORD |
 * | 2 | `EM_GETPASSWORDCHAR` != 0         | Password | 0.95 | mask_char_set     |
 * | 3 | Edit-like class, no password flag | Username | 0.55 | no_password_style |
 * |---| Class not edit-like               | Unknown  | 0.00 | (suffix omitted)  |
 * |---| No HWND under the click           | Unknown  | 0.00 | (evidence empty)  |
 */
class Win32StyleProbe : public IProbe
{
public:
    /**
     * @fn ProbeResult run(const ProbeContext& ctx)
     * @brief Descend to the native edit control and evaluate its password signals.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Converts the raw screen point to client coordinates at each level.
     *
     * @return Verdict and confidence from the type table.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    const char* name() const override { return "win32_es_password"; }

    /**
     * @fn std::chrono::milliseconds budget() const
     * @brief Advisory 5 ms budget; blocking target calls can exceed it.
     * @author Alex (<https://github.com/lextpf>)
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(5); }
};

}  // namespace seal
