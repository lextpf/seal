#pragma once

#include "Probe.hpp"

namespace seal
{

/**
 * @class ImeStateProbe
 * @brief Add weak password evidence when the target has no IME context.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup FillController
 *
 * Reads the window, not the field: browser inputs share the renderer's result.
 * Password fields can enable IME and non-password fields can disable it.
 *
 * $$
 * w \cdot c = 0.3 \times 0.3 = 0.09
 * $$
 *
 * This is below the 0.7 commit margin and cannot decide a fill alone.
 */
class ImeStateProbe : public IProbe
{
public:
    /**
     * @fn ProbeResult run(const ProbeContext& ctx)
     * @brief Inspect the shared target window and release any acquired IME context.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @return Password at 0.3 if no context exists; Unknown otherwise. A null target
     *         produces empty evidence; other results name enabled or disabled state.
     */
    ProbeResult run(const ProbeContext& ctx) override;

    const char* name() const override { return "ime_state"; }

    /**
     * @fn std::chrono::milliseconds budget() const
     * @brief Advisory 2 ms budget.
     * @author Alex (<https://github.com/lextpf>)
     */
    std::chrono::milliseconds budget() const override { return std::chrono::milliseconds(2); }
};

}  // namespace seal
