#include "UiaMetadataProbe.hpp"

#include "UiaCommon.hpp"

#ifdef USE_QT_UI

#include <QtCore/QString>

#include <objbase.h>
#include <oleacc.h>
#include <UIAutomation.h>
#include <wrl/client.h>

#include <string>
#include <vector>

namespace seal
{

namespace
{

// Tier-1 sources owned by UiaIsPasswordProbe. Ignored here so the
// FusionDecider Tier-1 short-circuit stays the sole owner of those signals.
bool isTier1Source(const QString& source)
{
    return source == QStringLiteral("IsPassword") || source == QStringLiteral("LegacyState");
}

// MSAA accName / accDescription fast-path. true = matched and populated.
bool runMsaaHintPath(POINT pt, ProbeResult& result)
{
    IAccessible* msaa = nullptr;
    VARIANT varChild;
    VariantInit(&varChild);
    HRESULT hr = AccessibleObjectFromPoint(pt, &msaa, &varChild);
    if (FAILED(hr) || (msaa == nullptr))
    {
        VariantClear(&varChild);
        return false;
    }

    VARIANT role;
    VariantInit(&role);
    hr = msaa->get_accRole(varChild, &role);
    const bool editableRole = SUCCEEDED(hr) && role.vt == VT_I4 &&
                              (role.lVal == ROLE_SYSTEM_TEXT || role.lVal == ROLE_SYSTEM_COMBOBOX);
    VariantClear(&role);

    bool matched = false;
    if (editableRole)
    {
        BSTR bstrName = nullptr;
        if (SUCCEEDED(msaa->get_accName(varChild, &bstrName)))
        {
            const QString nameStr = takeBstr(bstrName);
            if (containsPasswordHint(nameStr))
            {
                result.m_Verdict = Verdict::Password;
                result.m_Confidence = 0.65F;
                result.m_Evidence = "msaa_name_match";
                matched = true;
            }
        }

        if (!matched)
        {
            BSTR bstrDesc = nullptr;
            if (SUCCEEDED(msaa->get_accDescription(varChild, &bstrDesc)))
            {
                const QString descStr = takeBstr(bstrDesc);
                if (containsPasswordHint(descStr))
                {
                    result.m_Verdict = Verdict::Password;
                    result.m_Confidence = 0.65F;
                    result.m_Evidence = "msaa_desc_match";
                    matched = true;
                }
            }
        }
    }

    msaa->Release();
    VariantClear(&varChild);
    return matched;
}

// Form-context peer inference (formerly FillController::probeFormContext).
// Returns Password/Username at confidence 0.4, or leaves Unknown.
void runFormContextPath(IUIAutomation* automation,
                        IUIAutomationTreeWalker* walker,
                        IUIAutomationElement* hit,
                        LONG x,
                        LONG y,
                        ProbeResult& result)
{
    if ((automation == nullptr) || (walker == nullptr) || (hit == nullptr))
    {
        return;
    }

    IUIAutomationElement* formAncestor = findFormAncestor(walker, hit);
    if (formAncestor == nullptr)
    {
        return;
    }

    std::vector<IUIAutomationElement*> peers;
    enumerateFormInputs(walker, formAncestor, peers);
    formAncestor->Release();

    if (peers.size() < 2)
    {
        for (auto* peer : peers)
        {
            peer->Release();
        }
        return;
    }

    struct PeerClass
    {
        bool m_Pwd = false;
        bool m_Usr = false;
        bool m_IsClicked = false;
    };
    std::vector<PeerClass> classes(peers.size());

    for (size_t i = 0; i < peers.size(); ++i)
    {
        classes[i].m_Pwd =
            inspectElementPasswordState(peers[i], /*skipControlTypeGate=*/true).m_Matched;
        classes[i].m_Usr = inspectElementUsernameState(peers[i]).m_Matched;

        BOOL same = FALSE;
        if (SUCCEEDED(automation->CompareElements(peers[i], hit, &same)) && (same != 0))
        {
            classes[i].m_IsClicked = true;
        }
    }

    // Geometric fallback: when `hit` is a wrapper not in the enumeration,
    // pick the peer whose bounding rect contains the click point.
    int clickedIdx = -1;
    for (size_t i = 0; i < classes.size(); ++i)
    {
        if (classes[i].m_IsClicked)
        {
            clickedIdx = static_cast<int>(i);
            break;
        }
    }
    if (clickedIdx < 0)
    {
        for (size_t i = 0; i < peers.size(); ++i)
        {
            RECT rect{};
            if (tryGetCurrentBoundingRect(peers[i], &rect) && rectContainsPoint(rect, x, y))
            {
                clickedIdx = static_cast<int>(i);
                break;
            }
        }
    }

    if (clickedIdx >= 0)
    {
        const PeerClass& clicked = classes[clickedIdx];
        if (clicked.m_Pwd)
        {
            result.m_Verdict = Verdict::Password;
            result.m_Confidence = 0.4F;
            result.m_Evidence = "form_clicked_self_pwd";
        }
        else if (clicked.m_Usr)
        {
            result.m_Verdict = Verdict::Username;
            result.m_Confidence = 0.4F;
            result.m_Evidence = "form_clicked_self_usr";
        }
        else
        {
            bool anyPwd = false;
            bool anyUsr = false;
            for (size_t i = 0; i < classes.size(); ++i)
            {
                if (static_cast<int>(i) == clickedIdx)
                {
                    continue;
                }
                if (classes[i].m_Pwd)
                {
                    anyPwd = true;
                }
                if (classes[i].m_Usr)
                {
                    anyUsr = true;
                }
            }

            if (anyUsr && !anyPwd)
            {
                result.m_Verdict = Verdict::Password;
                result.m_Confidence = 0.4F;
                result.m_Evidence = "form_peer_usr_implies_self_pwd";
            }
            else if (anyPwd)
            {
                result.m_Verdict = Verdict::Username;
                result.m_Confidence = 0.4F;
                result.m_Evidence = "form_peer_pwd_implies_self_usr";
            }
            else
            {
                result.m_Verdict = Verdict::Username;
                result.m_Confidence = 0.4F;
                result.m_Evidence = "form_ambiguous_default_usr";
            }
        }
    }
    // clickedIdx < 0 -> nothing to infer; leave result Unknown.

    for (auto* peer : peers)
    {
        peer->Release();
    }
}

}  // namespace

struct UiaMetadataProbe::Impl
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

UiaMetadataProbe::UiaMetadataProbe()
    : m_Impl(std::make_unique<Impl>())
{
}

UiaMetadataProbe::~UiaMetadataProbe() = default;

ProbeResult UiaMetadataProbe::run(const ProbeContext& ctx)
{
    ProbeResult result;
    result.m_ProbeName = name();

    const POINT pt = ctx.m_ClickPoint;
    const LONG x = pt.x;
    const LONG y = pt.y;

    // Phase 1: MSAA accName / accDescription hint match. The sibling
    // UiaIsPasswordProbe already warmed the a11y tree and handled
    // STATE_SYSTEM_PROTECTED; here we cover Tier-2 name/description metadata.
    if (runMsaaHintPath(pt, result))
    {
        return result;
    }

    // Phase 2: UIA metadata + tree-walk + form-context.
    if (!m_Impl->ensureInitialized())
    {
        result.m_Evidence = "uia_init_failed";
        return result;
    }

    IUIAutomationElement* element = nullptr;
    HRESULT hr = m_Impl->m_Automation->ElementFromPoint(pt, &element);
    if (FAILED(hr) || (element == nullptr))
    {
        result.m_Evidence = "uia_element_from_point_failed";
        if (element != nullptr)
        {
            element->Release();
        }
        return result;
    }

    // Phase 2a: hit-element metadata. Filter out Tier-1 sources
    // ("IsPassword", "LegacyState") - those belong to UiaIsPasswordProbe.
    {
        const UiaHintObservation passwordObs =
            inspectElementPasswordState(element, /*skipControlTypeGate=*/true);
        if (passwordObs.m_Matched && !isTier1Source(passwordObs.m_Source))
        {
            result.m_Verdict = Verdict::Password;
            result.m_Confidence = 0.7F;
            result.m_Evidence =
                std::string("uia_meta_password source=") + passwordObs.m_Source.toStdString();
            element->Release();
            return result;
        }

        const UiaHintObservation usernameObs = inspectElementUsernameState(element);
        if (usernameObs.m_Matched)
        {
            result.m_Verdict = Verdict::Username;
            result.m_Confidence = 0.7F;
            result.m_Evidence =
                std::string("uia_meta_username source=") + usernameObs.m_Source.toStdString();
            element->Release();
            return result;
        }
    }

    IUIAutomationTreeWalker* rawWalker = nullptr;
    hr = m_Impl->m_Automation->get_RawViewWalker(&rawWalker);
    if (FAILED(hr) || (rawWalker == nullptr))
    {
        result.m_Evidence = "uia_raw_walker_failed";
        if (rawWalker != nullptr)
        {
            rawWalker->Release();
        }
        element->Release();
        return result;
    }

    // Phase 2b: ancestor walk. Browser hits often land on placeholder text
    // or a renderer wrapper; walk up parents whose rect still contains the
    // click point and probe them.
    {
        IUIAutomationElement* current = element;
        current->AddRef();
        for (int depth = 0; depth < kMaxUiaAncestorDepth; ++depth)
        {
            IUIAutomationElement* parent = nullptr;
            hr = rawWalker->GetParentElement(current, &parent);
            current->Release();
            current = nullptr;

            if (FAILED(hr) || (parent == nullptr))
            {
                break;
            }

            RECT rect{};
            if (tryGetCurrentBoundingRect(parent, &rect) && !rectContainsPoint(rect, x, y))
            {
                current = parent;
                continue;
            }

            const UiaHintObservation passwordObs =
                inspectElementPasswordState(parent, /*skipControlTypeGate=*/true);
            if (passwordObs.m_Matched && !isTier1Source(passwordObs.m_Source))
            {
                result.m_Verdict = Verdict::Password;
                result.m_Confidence = 0.65F;
                result.m_Evidence = std::string("uia_ancestor_password depth=") +
                                    std::to_string(depth + 1) +
                                    " source=" + passwordObs.m_Source.toStdString();
                parent->Release();
                rawWalker->Release();
                element->Release();
                return result;
            }

            const UiaHintObservation usernameObs = inspectElementUsernameState(parent);
            if (usernameObs.m_Matched)
            {
                result.m_Verdict = Verdict::Username;
                result.m_Confidence = 0.65F;
                result.m_Evidence = std::string("uia_ancestor_username depth=") +
                                    std::to_string(depth + 1) +
                                    " source=" + usernameObs.m_Source.toStdString();
                parent->Release();
                rawWalker->Release();
                element->Release();
                return result;
            }

            current = parent;
        }
        if (current != nullptr)
        {
            current->Release();
        }
    }

    // Phase 2c: bounded descendant DFS for a marked password descendant.
    {
        int nodesRemaining = kMaxUiaDescendantNodes;
        bool descendantObservedAny = false;
        const bool descendantMatched = searchDescendantsForPassword(
            rawWalker, element, x, y, 0, nodesRemaining, descendantObservedAny);
        if (descendantMatched)
        {
            result.m_Verdict = Verdict::Password;
            result.m_Confidence = 0.7F;
            result.m_Evidence = "uia_descendant_match";
            rawWalker->Release();
            element->Release();
            return result;
        }
    }

    // Phase 2d: form-context peer inference. Reuses the Impl's cached UIA
    // singleton so CompareElements has a usable handle.
    runFormContextPath(m_Impl->m_Automation.Get(), rawWalker, element, x, y, result);

    rawWalker->Release();
    element->Release();

    if (result.m_Verdict == Verdict::Unknown)
    {
        result.m_Evidence = "all_signals_unknown";
    }
    return result;
}

}  // namespace seal

#endif  // USE_QT_UI
