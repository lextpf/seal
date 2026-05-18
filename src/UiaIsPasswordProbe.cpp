#include "UiaIsPasswordProbe.hpp"

#include "UiaCommon.hpp"

#ifdef USE_QT_UI

#include <QtCore/QString>

#include <objbase.h>
#include <oleacc.h>
#include <UIAutomation.h>
#include <wrl/client.h>

namespace seal
{

struct UiaIsPasswordProbe::Impl
{
    Microsoft::WRL::ComPtr<IUIAutomation> m_Automation;
    bool m_Initialized = false;
    bool m_InitFailed = false;

    bool ensureInitialized()
    {
        if (m_Initialized)
        {
            return true;
        }
        if (m_InitFailed)
        {
            return false;
        }
        const HRESULT hr = CoCreateInstance(
            __uuidof(CUIAutomation), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&m_Automation));
        if (FAILED(hr) || !m_Automation)
        {
            m_InitFailed = true;
            return false;
        }
        m_Initialized = true;
        return true;
    }
};

UiaIsPasswordProbe::UiaIsPasswordProbe()
    : m_Impl(std::make_unique<Impl>())
{
}

UiaIsPasswordProbe::~UiaIsPasswordProbe() = default;

ProbeResult UiaIsPasswordProbe::run(const ProbeContext& ctx)
{
    ProbeResult result;
    result.m_ProbeName = name();

    // Phase 1: MSAA via AccessibleObjectFromPoint. This sends WM_GETOBJECT,
    // which triggers Chromium-based browsers' lazy a11y tree build; without
    // it, UIA's ElementFromPoint returns a generic renderer pane. MSAA's
    // STATE_SYSTEM_PROTECTED identifies password fields directly.
    const POINT pt = ctx.m_ClickPoint;
    IAccessible* msaa = nullptr;
    VARIANT varChild;
    VariantInit(&varChild);
    HRESULT hr = AccessibleObjectFromPoint(pt, &msaa, &varChild);
    if (SUCCEEDED(hr) && (msaa != nullptr))
    {
        VARIANT state;
        VariantInit(&state);
        hr = msaa->get_accState(varChild, &state);
        const bool protectedFlagSet =
            SUCCEEDED(hr) && state.vt == VT_I4 && ((state.lVal & STATE_SYSTEM_PROTECTED) != 0);
        VariantClear(&state);

        if (protectedFlagSet)
        {
            msaa->Release();
            VariantClear(&varChild);
            result.m_Verdict = Verdict::Password;
            result.m_Confidence = 0.97F;
            result.m_Evidence = "msaa_state_protected";
            return result;
        }

        // accName / accDescription hint matching belongs to
        // UiaMetadataProbe (Tier-2); intentionally skipped here.
        msaa->Release();
    }
    VariantClear(&varChild);

    // Phase 2: UIA IsPassword / LegacyState. The MSAA call warmed the a11y
    // tree so ElementFromPoint should now return the real input even in
    // browsers with lazy UIA providers.
    if (!m_Impl->ensureInitialized())
    {
        result.m_Evidence = "uia_init_failed";
        return result;
    }

    IUIAutomationElement* element = nullptr;
    hr = m_Impl->m_Automation->ElementFromPoint(pt, &element);
    if (FAILED(hr) || (element == nullptr))
    {
        result.m_Evidence = "uia_element_from_point_failed";
        if (element != nullptr)
        {
            element->Release();
        }
        return result;
    }

    // inspectElementPasswordState yields m_Source "IsPassword" or
    // "LegacyState" for the strong UIA signals; we accept only those and
    // leave its weaker metadata fallback to UiaMetadataProbe.
    const UiaHintObservation obs =
        inspectElementPasswordState(element, /*skipControlTypeGate=*/true);
    element->Release();

    if (obs.m_Matched && obs.m_Source == QStringLiteral("IsPassword"))
    {
        result.m_Verdict = Verdict::Password;
        result.m_Confidence = 0.96F;
        result.m_Evidence = "uia_is_password=true";
        return result;
    }
    if (obs.m_Matched && obs.m_Source == QStringLiteral("LegacyState"))
    {
        result.m_Verdict = Verdict::Password;
        result.m_Confidence = 0.95F;
        result.m_Evidence = "uia_legacy_state_protected";
        return result;
    }

    // No Tier-1 signal; leave Unknown for FusionDecider + UiaMetadataProbe.
    return result;
}

}  // namespace seal

#endif  // USE_QT_UI
