#ifdef USE_QT_UI

#include "UiaCommon.hpp"

#include "Logging.hpp"

#include <oleacc.h>
#include <array>

namespace seal
{

namespace
{

// Shared by password and username scans. Order is first-match-wins.
const std::array<StringPropertyProbe, 9> kHintPropertyProbes = {{
    {UIA_AutomationIdPropertyId, "AutomationId"},
    {UIA_NamePropertyId, "Name"},
    {UIA_HelpTextPropertyId, "HelpText"},
    {UIA_FullDescriptionPropertyId, "FullDescription"},
    {UIA_LocalizedControlTypePropertyId, "LocalizedControlType"},
    {UIA_ClassNamePropertyId, "ClassName"},
    {UIA_ItemTypePropertyId, "ItemType"},
    {UIA_AriaRolePropertyId, "AriaRole"},
    {UIA_AriaPropertiesPropertyId, "AriaProperties"},
}};

}  // namespace

QString takeBstr(BSTR text)
{
    if (!text)
        return {};
    QString out = QString::fromWCharArray(text, SysStringLen(text));
    SysFreeString(text);
    return out;
}

QString currentStringProperty(IUIAutomationElement* element, PROPERTYID propertyId)
{
    if (!element)
        return {};

    VARIANT val;
    VariantInit(&val);

    QString out;
    const HRESULT hr = element->GetCurrentPropertyValue(propertyId, &val);
    if (SUCCEEDED(hr))
    {
        if (val.vt == VT_BSTR && val.bstrVal)
            out = QString::fromWCharArray(val.bstrVal, SysStringLen(val.bstrVal));
        else if (val.vt == (VT_BSTR | VT_BYREF) && val.pbstrVal && *val.pbstrVal)
            out = QString::fromWCharArray(*val.pbstrVal, SysStringLen(*val.pbstrVal));
    }

    VariantClear(&val);
    return out;
}

bool containsPasswordHint(const QString& rawText)
{
    const QString text = rawText.trimmed().toLower();
    if (text.isEmpty())
        return false;

    // Substring-match against lowercased UIA property values. \u escapes
    // keep the source ASCII-only (MSVC codepage-independent). ASCII
    // fallback variants cover sites that strip diacritics.
    static const std::array<QStringView, 27> kPasswordHints = {
        QStringView{u"password"},     QStringView{u"passwd"},   QStringView{u"passcode"},
        QStringView{u"pwd"},          QStringView{u"passwort"}, QStringView{u"kennwort"},
        QStringView{u"contraseña"},    // es
        QStringView{u"mot de passe"},  // fr
        QStringView{u"motdepasse"},    // fr (compact)
        QStringView{u"senha"},         // pt
        QStringView{u"wachtwoord"},    // nl
        QStringView{u"hasło"},         // pl
        QStringView{u"haslo"},         // pl (ASCII fallback)
        QStringView{u"lösenord"},      // sv
        QStringView{u"losenord"},      // sv (ASCII fallback)
        QStringView{u"passord"},       // no
        QStringView{u"adgangskode"},   // da
        QStringView{u"salasana"},      // fi
        QStringView{u"heslo"},         // cs
        QStringView{u"jelszó"},        // hu
        QStringView{u"jelszo"},        // hu (ASCII fallback)
        QStringView{u"şifre"},         // tr
        QStringView{u"sifre"},         // tr (ASCII fallback)
    };

    for (const QStringView hint : kPasswordHints)
    {
        if (text.contains(hint))
            return true;
    }

    return false;
}

bool containsUsernameHint(const QString& rawText)
{
    const QString text = rawText.trimmed().toLower();
    if (text.isEmpty())
        return false;

    // Compound forms only -- bare "user" would false-positive on user-agent,
    // user-profile-pic, etc. Multi-word entries contain-match the full
    // lowercased property value.
    static const std::array<QStringView, 28> kUsernameHints = {
        QStringView{u"username"},
        QStringView{u"user-name"},
        QStringView{u"userid"},
        QStringView{u"user-id"},
        QStringView{u"e-mail"},
        QStringView{u"email"},
        QStringView{u"login"},
        QStringView{u"account"},
        QStringView{u"benutzer"},
        QStringView{u"benutzername"},
        QStringView{u"anmelden"},
        QStringView{u"anmeldung"},
        QStringView{u"nutzer"},
        QStringView{u"konto"},
        QStringView{u"kennung"},
        QStringView{u"usuario"},             // es
        QStringView{u"correo electrónico"},  // es
        QStringView{u"iniciar sesión"},      // es
        QStringView{u"cuenta"},              // es
        QStringView{u"utilisateur"},         // fr
        QStringView{u"nom d'utilisateur"},   // fr
        QStringView{u"identifiant"},         // fr
        QStringView{u"courriel"},            // fr
        QStringView{u"compte"},              // fr
        QStringView{u"nome utente"},         // it
        QStringView{u"accesso"},             // it
        QStringView{u"nome de usuário"},     // pt
        QStringView{u"usuário"},             // pt
    };

    for (const QStringView hint : kUsernameHints)
    {
        if (text.contains(hint))
            return true;
    }

    return false;
}

bool isEditLikeControlType(IUIAutomationElement* element)
{
    CONTROLTYPEID controlType = 0;
    if (FAILED(element->get_CurrentControlType(&controlType)))
        return false;
    return controlType == UIA_EditControlTypeId || controlType == UIA_CustomControlTypeId ||
           controlType == UIA_PaneControlTypeId || controlType == UIA_DocumentControlTypeId;
}

UiaHintObservation inspectPasswordHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate)
{
    UiaHintObservation observation;
    if (!element)
        return observation;

    if (!skipControlTypeGate && !isEditLikeControlType(element))
        return observation;

    for (const StringPropertyProbe& probe : kHintPropertyProbes)
    {
        const QString value = currentStringProperty(element, probe.m_PropertyId);
        if (!containsPasswordHint(value))
            continue;

        observation.m_Observed = true;
        observation.m_Matched = true;
        observation.m_Source = QString::fromLatin1(probe.m_Label);
        observation.m_MatchedText = value;
        return observation;
    }

    return observation;
}

UiaHintObservation inspectUsernameHintMetadata(IUIAutomationElement* element,
                                               bool skipControlTypeGate)
{
    UiaHintObservation observation;
    if (!element)
        return observation;

    if (!skipControlTypeGate && !isEditLikeControlType(element))
        return observation;

    for (const StringPropertyProbe& probe : kHintPropertyProbes)
    {
        const QString value = currentStringProperty(element, probe.m_PropertyId);
        if (!containsUsernameHint(value))
            continue;

        observation.m_Observed = true;
        observation.m_Matched = true;
        observation.m_Source = QString::fromLatin1(probe.m_Label);
        observation.m_MatchedText = value;
        return observation;
    }

    return observation;
}

const char* controlTypeToString(CONTROLTYPEID controlType)
{
    switch (controlType)
    {
        case UIA_ButtonControlTypeId:
            return "Button";
        case UIA_CustomControlTypeId:
            return "Custom";
        case UIA_DocumentControlTypeId:
            return "Document";
        case UIA_EditControlTypeId:
            return "Edit";
        case UIA_GroupControlTypeId:
            return "Group";
        case UIA_HyperlinkControlTypeId:
            return "Hyperlink";
        case UIA_ImageControlTypeId:
            return "Image";
        case UIA_ListControlTypeId:
            return "List";
        case UIA_ListItemControlTypeId:
            return "ListItem";
        case UIA_MenuControlTypeId:
            return "Menu";
        case UIA_MenuBarControlTypeId:
            return "MenuBar";
        case UIA_MenuItemControlTypeId:
            return "MenuItem";
        case UIA_PaneControlTypeId:
            return "Pane";
        case UIA_RadioButtonControlTypeId:
            return "RadioButton";
        case UIA_ScrollBarControlTypeId:
            return "ScrollBar";
        case UIA_SliderControlTypeId:
            return "Slider";
        case UIA_SpinnerControlTypeId:
            return "Spinner";
        case UIA_StatusBarControlTypeId:
            return "StatusBar";
        case UIA_TabControlTypeId:
            return "Tab";
        case UIA_TabItemControlTypeId:
            return "TabItem";
        case UIA_TextControlTypeId:
            return "Text";
        case UIA_TitleBarControlTypeId:
            return "TitleBar";
        case UIA_ToolBarControlTypeId:
            return "ToolBar";
        case UIA_ToolTipControlTypeId:
            return "ToolTip";
        case UIA_WindowControlTypeId:
            return "Window";
        default:
            return "Unknown";
    }
}

bool rectContainsPoint(const RECT& rect, LONG x, LONG y)
{
    return x >= rect.left && x < rect.right && y >= rect.top && y < rect.bottom;
}

bool tryGetCurrentBoundingRect(IUIAutomationElement* element, RECT* rect)
{
    if (!element || !rect)
        return false;

    RECT current{};
    if (FAILED(element->get_CurrentBoundingRectangle(&current)))
        return false;
    if (current.left >= current.right || current.top >= current.bottom)
        return false;

    *rect = current;
    return true;
}

UiaHintObservation inspectElementPasswordState(IUIAutomationElement* element,
                                               bool skipControlTypeGate)
{
    UiaHintObservation observation;
    if (!element)
        return observation;

    VARIANT val;
    VariantInit(&val);
    HRESULT hr = element->GetCurrentPropertyValue(UIA_IsPasswordPropertyId, &val);
    if (SUCCEEDED(hr) && val.vt == VT_BOOL)
    {
        observation.m_Observed = true;
        observation.m_Matched = (val.boolVal == VARIANT_TRUE);
        observation.m_Source = QStringLiteral("IsPassword");
    }
    VariantClear(&val);

    if (observation.m_Matched)
        return observation;

    IUnknown* patternUnknown = nullptr;
    hr = element->GetCurrentPattern(UIA_LegacyIAccessiblePatternId, &patternUnknown);
    if (SUCCEEDED(hr) && patternUnknown)
    {
        auto* legacyPattern = static_cast<IUIAutomationLegacyIAccessiblePattern*>(nullptr);
        hr = patternUnknown->QueryInterface(IID_PPV_ARGS(&legacyPattern));
        patternUnknown->Release();
        if (SUCCEEDED(hr) && legacyPattern)
        {
            DWORD legacyState = 0;
            if (SUCCEEDED(legacyPattern->get_CurrentState(&legacyState)))
            {
                observation.m_Observed = true;
                if (legacyState & STATE_SYSTEM_PROTECTED)
                {
                    observation.m_Matched = true;
                    observation.m_Source = QStringLiteral("LegacyState");
                }
            }
            legacyPattern->Release();
        }
    }

    if (observation.m_Matched)
        return observation;

    UiaHintObservation metadataObservation =
        inspectPasswordHintMetadata(element, skipControlTypeGate);
    if (metadataObservation.m_Matched)
        return metadataObservation;

    return observation;
}

UiaHintObservation inspectElementUsernameState(IUIAutomationElement* element)
{
    // No UIA IsUsername property -- metadata-keyword-only. Permissive
    // control type because form callers may pass non-Edit wrappers.
    return inspectUsernameHintMetadata(element, /*skipControlTypeGate=*/true);
}

QString describeAutomationElement(IUIAutomationElement* element)
{
    if (!element)
        return QStringLiteral("<null>");

    CONTROLTYPEID controlType = 0;
    element->get_CurrentControlType(&controlType);

    BSTR frameworkId = nullptr;
    BSTR className = nullptr;
    BSTR name = nullptr;
    BSTR automationId = nullptr;
    BSTR localizedControlType = nullptr;
    element->get_CurrentFrameworkId(&frameworkId);
    element->get_CurrentClassName(&className);
    element->get_CurrentName(&name);
    element->get_CurrentAutomationId(&automationId);
    element->get_CurrentLocalizedControlType(&localizedControlType);

    RECT rect{};
    QString rectText = QStringLiteral("<none>");
    if (tryGetCurrentBoundingRect(element, &rect))
    {
        rectText = QStringLiteral("[%1,%2 %3x%4]")
                       .arg(rect.left)
                       .arg(rect.top)
                       .arg(rect.right - rect.left)
                       .arg(rect.bottom - rect.top);
    }

    return QStringLiteral("%1(%2) framework=\"%3\" class=\"%4\" name=\"%5\" id=\"%6\" rect=%7")
        .arg(QString::fromLatin1(controlTypeToString(controlType)))
        .arg(takeBstr(localizedControlType))
        .arg(takeBstr(frameworkId))
        .arg(takeBstr(className))
        .arg(takeBstr(name))
        .arg(takeBstr(automationId))
        .arg(rectText);
}

bool searchDescendantsForPassword(IUIAutomationTreeWalker* walker,
                                  IUIAutomationElement* root,
                                  LONG x,
                                  LONG y,
                                  int depth,
                                  int& nodesRemaining,
                                  bool& observedAny)
{
    if (!walker || !root || depth >= kMaxUiaDescendantDepth || nodesRemaining <= 0)
        return false;

    IUIAutomationElement* child = nullptr;
    HRESULT hr = walker->GetFirstChildElement(root, &child);
    if (FAILED(hr) || !child)
        return false;

    while (child && nodesRemaining > 0)
    {
        IUIAutomationElement* next = nullptr;
        walker->GetNextSiblingElement(child, &next);

        bool shouldInspect = true;
        RECT rect{};
        if (tryGetCurrentBoundingRect(child, &rect))
            shouldInspect = rectContainsPoint(rect, x, y);

        if (shouldInspect)
        {
            --nodesRemaining;
            UiaHintObservation observation = inspectElementPasswordState(child);
            observedAny = observedAny || observation.m_Observed;
            if (observation.m_Matched)
            {
                qCDebug(logFill) << "probeIsPassword: descendant matched via"
                                 << (observation.m_Source.isEmpty() ? QStringLiteral("<unknown>")
                                                                    : observation.m_Source)
                                 << (observation.m_MatchedText.isEmpty()
                                         ? QStringLiteral("")
                                         : observation.m_MatchedText)
                                 << describeAutomationElement(child);
                child->Release();
                if (next)
                    next->Release();
                return true;
            }

            if (searchDescendantsForPassword(
                    walker, child, x, y, depth + 1, nodesRemaining, observedAny))
            {
                child->Release();
                if (next)
                    next->Release();
                return true;
            }
        }

        child->Release();
        child = next;
    }

    return false;
}

// Walk up from `start` for a form-like container: ancestor with >=2 direct
// Edit/Custom children and a bounding rect <= half the primary monitor
// (the cap prevents landing on <body> for short pages). Caller owns the
// returned element.
IUIAutomationElement* findFormAncestor(IUIAutomationTreeWalker* walker, IUIAutomationElement* start)
{
    if (!walker || !start)
        return nullptr;

    const LONG screenW = GetSystemMetrics(SM_CXSCREEN);
    const LONG screenH = GetSystemMetrics(SM_CYSCREEN);
    const long long halfMonitorArea =
        static_cast<long long>(screenW) * static_cast<long long>(screenH) / 2;

    constexpr int kMaxFormAncestorDepth = 12;
    constexpr int kMinPeers = 2;

    IUIAutomationElement* current = start;
    current->AddRef();

    for (int depth = 0; depth < kMaxFormAncestorDepth; ++depth)
    {
        IUIAutomationElement* parent = nullptr;
        HRESULT hr = walker->GetParentElement(current, &parent);
        current->Release();
        current = nullptr;

        if (FAILED(hr) || !parent)
            return nullptr;

        RECT rect{};
        if (tryGetCurrentBoundingRect(parent, &rect))
        {
            const long long area = static_cast<long long>(rect.right - rect.left) *
                                   static_cast<long long>(rect.bottom - rect.top);
            if (area > halfMonitorArea)
            {
                parent->Release();
                return nullptr;
            }
        }

        // Count Edit/Custom children at one level (cheap).
        int peerCount = 0;
        IUIAutomationElement* child = nullptr;
        if (SUCCEEDED(walker->GetFirstChildElement(parent, &child)) && child)
        {
            while (child)
            {
                CONTROLTYPEID ct = 0;
                if (SUCCEEDED(child->get_CurrentControlType(&ct)) &&
                    (ct == UIA_EditControlTypeId || ct == UIA_CustomControlTypeId))
                {
                    ++peerCount;
                }

                IUIAutomationElement* next = nullptr;
                walker->GetNextSiblingElement(child, &next);
                child->Release();
                child = next;
            }
        }

        if (peerCount >= kMinPeers)
            return parent;  // ownership transfer to caller

        current = parent;
    }

    if (current)
        current->Release();
    return nullptr;
}

// Bounded DFS collecting Edit/Custom controls under `root`. Each entry in
// `out` is AddRef'd; caller Releases every element.
void enumerateFormInputs(IUIAutomationTreeWalker* walker,
                         IUIAutomationElement* root,
                         std::vector<IUIAutomationElement*>& out)
{
    constexpr size_t kMaxFormInputs = 32;
    constexpr int kMaxDescendantDepth = 6;

    if (!walker || !root)
        return;

    struct Frame
    {
        IUIAutomationElement* elem;
        int depth;
    };
    std::vector<Frame> stack;

    IUIAutomationElement* firstChild = nullptr;
    if (FAILED(walker->GetFirstChildElement(root, &firstChild)) || !firstChild)
        return;
    stack.push_back({firstChild, 1});

    while (!stack.empty() && out.size() < kMaxFormInputs)
    {
        Frame f = stack.back();
        stack.pop_back();

        // Push sibling first so the stack DFS stays depth-first.
        IUIAutomationElement* sibling = nullptr;
        walker->GetNextSiblingElement(f.elem, &sibling);
        if (sibling)
            stack.push_back({sibling, f.depth});

        CONTROLTYPEID ct = 0;
        if (SUCCEEDED(f.elem->get_CurrentControlType(&ct)) &&
            (ct == UIA_EditControlTypeId || ct == UIA_CustomControlTypeId))
        {
            f.elem->AddRef();
            out.push_back(f.elem);
        }

        if (f.depth < kMaxDescendantDepth)
        {
            IUIAutomationElement* firstC = nullptr;
            if (SUCCEEDED(walker->GetFirstChildElement(f.elem, &firstC)) && firstC)
                stack.push_back({firstC, f.depth + 1});
        }

        f.elem->Release();
    }

    // Release remaining frames if we hit the budget cap.
    for (Frame& f : stack)
        f.elem->Release();
}

}  // namespace seal

#endif  // USE_QT_UI
