#ifdef USE_QT_UI

#include "BrowserBridgeProbe.hpp"

#include "BrowserBridge.hpp"
#include "Diagnostics.hpp"

namespace seal
{

BrowserBridgeProbe::BrowserBridgeProbe(BrowserBridge* bridge)
    : m_Bridge(bridge)
{
}

ProbeResult BrowserBridgeProbe::run(const ProbeContext& ctx)
{
    ProbeResult result;
    result.m_ProbeName = name();

    if (m_Bridge == nullptr || !m_Bridge->isRunning() || m_Bridge->isDisabled())
    {
        result.m_Evidence = "bridge_offline";
        return result;
    }

    const auto entry = m_Bridge->lookup(ctx.m_TargetProcessId, ctx.m_ClickPoint);
    if (!entry.has_value())
    {
        result.m_Evidence = "no_recent_entry";
        return result;
    }

    if (entry->m_Verdict == Verdict::Password)
    {
        result.m_Verdict = Verdict::Password;
        result.m_Confidence = 0.97F;
    }
    else if (entry->m_Verdict == Verdict::Username)
    {
        result.m_Verdict = Verdict::Username;
        result.m_Confidence = 0.95F;
    }
    else
    {
        result.m_Evidence = "entry_unknown_verdict";
        return result;
    }

    // entry->m_UrlHost is deliberately omitted: it's privacy-sensitive
    // (browsing pattern leak) and FillController reads it directly via
    // BrowserBridge::lookup() -- no need on the probe evidence channel.
    result.m_Evidence = "bridge_match";
    return result;
}

}  // namespace seal

#endif  // USE_QT_UI
