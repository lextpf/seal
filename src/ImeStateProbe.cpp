#include "ImeStateProbe.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <imm.h>
#include <windows.h>

namespace seal
{

ProbeResult ImeStateProbe::run(const ProbeContext& ctx)
{
    ProbeResult result;
    result.m_ProbeName = name();

    if (ctx.m_TargetWindow == nullptr)
    {
        return result;
    }

    HIMC imc = ImmGetContext(ctx.m_TargetWindow);
    const bool hasContext = (imc != nullptr);
    if (imc != nullptr)
    {
        ImmReleaseContext(ctx.m_TargetWindow, imc);
    }

    if (!hasContext)
    {
        // Field has explicitly disabled IME -- mild Password signal.
        result.m_Verdict = Verdict::Password;
        result.m_Confidence = 0.3F;
        result.m_Evidence = "ime_context=disabled";
        return result;
    }

    result.m_Evidence = "ime_context=enabled";
    return result;
}

}  // namespace seal
