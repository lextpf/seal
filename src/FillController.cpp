#ifdef USE_QT_UI

#include "FillController.h"
#include "Clipboard.h"
#include "Logging.h"

#include <QtCore/QThread>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <oleacc.h>
#include <array>
#include <memory>

namespace seal
{

namespace
{

constexpr int kMaxUiaAncestorDepth = 8;
constexpr int kMaxUiaDescendantDepth = 6;
constexpr int kMaxUiaDescendantNodes = 64;

struct UiaPasswordObservation
{
    bool observed = false;
    bool isPassword = false;
    QString source;
    QString matchedText;
};

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

    static const std::array<QStringView, 5> kPasswordHints = {
        QStringView{u"password"},
        QStringView{u"passwort"},
        QStringView{u"passwd"},
        QStringView{u"pwd"},
        QStringView{u"kennwort"},
    };

    for (const QStringView hint : kPasswordHints)
    {
        if (text.contains(hint))
            return true;
    }

    return false;
}

UiaPasswordObservation inspectPasswordHintMetadata(IUIAutomationElement* element,
                                                   bool skipControlTypeGate = false)
{
    UiaPasswordObservation observation;
    if (!element)
        return observation;

    if (!skipControlTypeGate)
    {
        CONTROLTYPEID controlType = 0;
        if (FAILED(element->get_CurrentControlType(&controlType)))
            controlType = 0;

        const bool editableLike =
            controlType == UIA_EditControlTypeId || controlType == UIA_CustomControlTypeId ||
            controlType == UIA_PaneControlTypeId || controlType == UIA_DocumentControlTypeId;
        if (!editableLike)
            return observation;
    }

    struct StringPropertyProbe
    {
        PROPERTYID propertyId;
        const char* label;
    };

    static const std::array<StringPropertyProbe, 7> kPropertyProbes = {{
        {UIA_AutomationIdPropertyId, "AutomationId"},
        {UIA_NamePropertyId, "Name"},
        {UIA_HelpTextPropertyId, "HelpText"},
        {UIA_FullDescriptionPropertyId, "FullDescription"},
        {UIA_ItemTypePropertyId, "ItemType"},
        {UIA_AriaRolePropertyId, "AriaRole"},
        {UIA_AriaPropertiesPropertyId, "AriaProperties"},
    }};

    for (const StringPropertyProbe& probe : kPropertyProbes)
    {
        const QString value = currentStringProperty(element, probe.propertyId);
        if (!containsPasswordHint(value))
            continue;

        observation.observed = true;
        observation.isPassword = true;
        observation.source = QString::fromLatin1(probe.label);
        observation.matchedText = value;
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

UiaPasswordObservation inspectElementPasswordState(IUIAutomationElement* element,
                                                   bool skipControlTypeGate = false)
{
    UiaPasswordObservation observation;
    if (!element)
        return observation;

    VARIANT val;
    VariantInit(&val);
    HRESULT hr = element->GetCurrentPropertyValue(UIA_IsPasswordPropertyId, &val);
    if (SUCCEEDED(hr) && val.vt == VT_BOOL)
    {
        observation.observed = true;
        observation.isPassword = (val.boolVal == VARIANT_TRUE);
        observation.source = QStringLiteral("IsPassword");
    }
    VariantClear(&val);

    if (observation.isPassword)
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
                observation.observed = true;
                if (legacyState & STATE_SYSTEM_PROTECTED)
                {
                    observation.isPassword = true;
                    observation.source = QStringLiteral("LegacyState");
                }
            }
            legacyPattern->Release();
        }
    }

    if (observation.isPassword)
        return observation;

    UiaPasswordObservation metadataObservation =
        inspectPasswordHintMetadata(element, skipControlTypeGate);
    if (metadataObservation.isPassword)
        return metadataObservation;

    return observation;
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
            UiaPasswordObservation observation = inspectElementPasswordState(child);
            observedAny = observedAny || observation.observed;
            if (observation.isPassword)
            {
                qCDebug(logFill) << "probeIsPassword: descendant matched via"
                                 << (observation.source.isEmpty() ? QStringLiteral("<unknown>")
                                                                  : observation.source)
                                 << (observation.matchedText.isEmpty() ? QStringLiteral("")
                                                                       : observation.matchedText)
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

}  // namespace

// Only one controller can own the global hooks at a time.
// Windows global low-level hooks are per-thread and cannot be multiplexed;
// a second FillController installing hooks would silently replace the first
// controller's hook chain, breaking cancel/timeout for the original session.
std::atomic<FillController*> FillController::s_instance{nullptr};

FillController::FillController(QObject* parent)
    : QObject(parent)
{
    m_TimeoutTimer.setInterval(1000);
    connect(&m_TimeoutTimer, &QTimer::timeout, this, &FillController::onTimeoutTick);
}

FillController::~FillController()
{
    // Ensure hooks are removed even if the caller forgot to cancel().
    if (m_State.load() != State::Idle)
        cancel();
}

bool FillController::isArmed() const
{
    return m_State.load() == State::Armed;
}

QString FillController::fillStatusText() const
{
    return m_StatusText;
}

int FillController::countdownSeconds() const
{
    return m_RemainingSeconds;
}

FillController::State FillController::state() const
{
    return m_State.load();
}

static const char* stateToString(FillController::State s)
{
    switch (s)
    {
        case FillController::State::Idle:
            return "Idle";
        case FillController::State::Armed:
            return "Armed";
        case FillController::State::Typing:
            return "Typing";
        default:
            return "Unknown";
    }
}

void FillController::transitionTo(State newState)
{
    qCDebug(logFill) << "state:" << stateToString(m_State.load()) << "->"
                     << stateToString(newState);
    bool wasArmed = isArmed();
    m_State.store(newState);
    bool nowArmed = isArmed();

    updateStatusText();

    // Only emit armedChanged when the armed/disarmed boundary is crossed,
    // not on every internal state change (e.g. Armed -> Typing -> Armed).
    // Firing on every transition would spam QML property bindings and cause
    // unnecessary UI redraws for states that look identical to the front-end.
    if (wasArmed != nowArmed)
        emit armedChanged();
}

void FillController::updateStatusText()
{
    QString prev = m_StatusText;
    switch (m_State.load())
    {
        case State::Idle:
            m_StatusText.clear();
            break;
        case State::Armed:
            if (m_TypedFields == TypedNone)
                m_StatusText = QStringLiteral("Ctrl+Click to fill credentials");
            else if (m_TypedFields & TypedUsername)
                m_StatusText = QStringLiteral("Ctrl+Click to fill password");
            else
                m_StatusText = QStringLiteral("Ctrl+Click to fill username");
            break;
        case State::Typing:
            m_StatusText = QStringLiteral("Typing...");
            break;
    }
    if (m_StatusText != prev)
        emit fillStatusTextChanged();
}

bool FillController::arm(
    int recordIndex,
    const std::vector<seal::VaultRecord>& records,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw,
    const uint64_t& ownerGeneration)
{
    // If already armed (e.g. user clicked a different record), tear down
    // the previous session before starting a new one.
    if (m_State.load() != State::Idle)
        cancel();

    // Borrow pointers - the caller (Backend) owns these and must
    // keep them alive until fillCompleted / fillCancelled / fillError.
    // Snapshot the generation counter so performType() can detect stale
    // pointers if the owner mutates records between arm() and the fill.
    m_RecordIndex = recordIndex;
    m_Records = &records;
    m_MasterPw = &masterPw;
    m_OwnerGeneration = &ownerGeneration;
    m_SnapshotGeneration = ownerGeneration;
    m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
    m_PendingTarget.store(TypeTarget::Auto);
    m_TypedFields = TypedNone;

    // Lazy-init the UI Automation client for password field detection.
    // Qt's main thread is STA (OleInitialize for drag-and-drop), so
    // CoCreateInstance for the in-process UIA server is safe here.
    if (!m_UIA)
    {
        HRESULT hr = CoCreateInstance(__uuidof(CUIAutomation),
                                      nullptr,
                                      CLSCTX_INPROC_SERVER,
                                      __uuidof(IUIAutomation),
                                      reinterpret_cast<void**>(&m_UIA));
        if (FAILED(hr))
        {
            qCWarning(logFill) << "UIA CoCreateInstance failed: 0x" << Qt::hex << hr
                               << "- will fall back to sequential detection";
            m_UIA = nullptr;
        }
    }

    // Register as the singleton so the static hook callbacks can find us.
    s_instance.store(this);
    installHooks();

    if (!m_MouseHook || !m_KeyboardHook)
    {
        qCWarning(logFill) << "hook install failed: mouse=" << !!m_MouseHook
                           << "keyboard=" << !!m_KeyboardHook;
        removeHooks();
        m_RecordIndex = -1;
        m_Records = nullptr;
        m_MasterPw = nullptr;
        emit fillError(QStringLiteral("Failed to install input hooks"));
        return false;
    }

    transitionTo(State::Armed);

    qCInfo(logFill) << "armed: recordIndex=" << m_RecordIndex << "timeout=" << FILL_TIMEOUT_SECONDS
                    << "s";
    emit countdownSecondsChanged();
    m_TimeoutTimer.start();
    return true;
}

void FillController::cancel()
{
    if (m_State.load() == State::Idle)
        return;

    qCInfo(logFill) << "cancel: from state" << stateToString(m_State.load());
    m_TimeoutTimer.stop();
    removeHooks();
    transitionTo(State::Idle);

    // Clear borrowed pointers and generation snapshot so we don't dangle.
    m_RecordIndex = -1;
    m_Records = nullptr;
    m_MasterPw = nullptr;
    m_OwnerGeneration = nullptr;
    m_SnapshotGeneration = 0;
    m_TypedFields = TypedNone;
    if (m_UIA)
    {
        m_UIA->Release();
        m_UIA = nullptr;
    }
    m_RemainingSeconds = 0;
    emit countdownSecondsChanged();
    emit fillCancelled();
}

void FillController::onTimeoutTick()
{
    // Only tick while armed - the timer should already be stopped in
    // other states, but guard defensively.
    if (m_State.load() != State::Armed)
        return;

    m_RemainingSeconds--;
    emit countdownSecondsChanged();

    // Auto-cancel if the user hasn't clicked within the timeout window.
    if (m_RemainingSeconds <= 0)
    {
        qCInfo(logFill) << "timeout: auto-cancel";
        cancel();
    }
}

void FillController::installHooks()
{
    // WH_MOUSE_LL / WH_KEYBOARD_LL are desktop-wide low-level hooks that
    // intercept input before it reaches any window. Passing nullptr for hMod
    // and 0 for dwThreadId means "all threads on the current desktop" - the
    // hook DLL is our own process, and low-level hooks don't require injection
    // into a separate module.
    m_MouseHook = SetWindowsHookExW(WH_MOUSE_LL, mouseHookProc, nullptr, 0);
    m_KeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, keyboardHookProc, nullptr, 0);
    qCDebug(logFill) << "hooks installed";
}

void FillController::removeHooks()
{
    if (m_MouseHook)
    {
        UnhookWindowsHookEx(m_MouseHook);
        m_MouseHook = nullptr;
    }
    if (m_KeyboardHook)
    {
        UnhookWindowsHookEx(m_KeyboardHook);
        m_KeyboardHook = nullptr;
    }
    // Clear the singleton so stale hook callbacks (if any are still in
    // the message queue) won't dereference a dead pointer.
    s_instance.store(nullptr);
    qCDebug(logFill) << "hooks removed";
}

LRESULT CALLBACK FillController::mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Load the singleton pointer exactly once into a local. This prevents a
    // TOCTOU race where cancel() on the main thread nulls s_instance between
    // two separate atomic loads in this callback, which would cause us to
    // dereference nullptr on the second access.
    auto* self = s_instance.load();
    if (nCode >= 0 && self && wParam == WM_LBUTTONDOWN)
    {
        bool ctrlDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        State curState = self->m_State.load();

        if (ctrlDown && curState == State::Armed)
        {
            // Capture the click coordinates so performType() can probe the
            // UIA element at this screen position for password detection.
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);

            // Modifier key overrides let the user force a specific field:
            // Shift forces password, Alt forces username.
            // Without either modifier, UIA auto-detection decides in performType().
            bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            bool altDown = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;

            TypeTarget target;
            if (shiftDown)
                target = TypeTarget::Password;
            else if (altDown)
                target = TypeTarget::Username;
            else
                target = TypeTarget::Auto;

            self->m_PendingTarget.store(target);
            qCInfo(logFill) << "Ctrl+Click detected: target="
                            << (target == TypeTarget::Username   ? "username"
                                : target == TypeTarget::Password ? "password"
                                                                 : "auto");

            // Queue performType on the Qt event loop. Low-level hook callbacks
            // run on the thread that installed the hook but inside the OS hook
            // dispatcher - doing Qt signal/slot work or blocking here would
            // deadlock or corrupt Qt state. QueuedConnection posts to the
            // event loop so performType runs in a normal call frame.
            QMetaObject::invokeMethod(self, "performType", Qt::QueuedConnection);

            // Return 1 (non-zero) to swallow the click so the target app
            // never receives the WM_LBUTTONDOWN. Without this, the Ctrl+Click
            // would activate whatever button or link is under the cursor.
            return 1;
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

LRESULT CALLBACK FillController::keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Same single-load TOCTOU guard as mouseHookProc (see comment there).
    auto* self = s_instance.load();
    if (nCode >= 0 && self && wParam == WM_KEYDOWN)
    {
        auto* khs = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // Esc while armed -> queued cancel. Must use QueuedConnection for
        // the same reason as mouseHookProc: can't call Qt methods from
        // inside the OS hook dispatcher.
        if (khs->vkCode == VK_ESCAPE && self->m_State.load() == State::Armed)
        {
            QMetaObject::invokeMethod(self, "cancel", Qt::QueuedConnection);
            return 1;
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

void FillController::performType()
{
    if (m_State.load() != State::Armed)
        return;

    TypeTarget pendingTarget = m_PendingTarget.load();
    transitionTo(State::Typing);
    m_TimeoutTimer.stop();

    // Poll for Ctrl release before sending keystrokes. If we type while
    // Ctrl is still held, the target app interprets them as Ctrl+shortcuts
    // (e.g. Ctrl+A = select-all instead of typing 'a').
    // We use a 2-second timeout for a stuck Ctrl key (e.g. physical key
    // jammed or remote-desktop weirdness) - beyond that we proceed anyway
    // rather than hang indefinitely.
    auto* poll = new QTimer(this);
    poll->setInterval(20);
    connect(
        poll,
        &QTimer::timeout,
        this,
        [this, pendingTarget, poll, elapsedMs = 0]() mutable
        {
            elapsedMs += 20;
            bool ctrlStillDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
            if (ctrlStillDown && elapsedMs < 2000)
                return;  // Keep polling - Ctrl not yet released.

            poll->stop();
            poll->deleteLater();

            // Guard against cancel() being called while we were polling.
            if (m_State.load() != State::Typing)
                return;

            // Resolve the target field. Shift/Alt overrides are already
            // resolved in the hook; Auto means we probe the clicked element
            // via Windows UI Automation to detect password fields.
            TypeTarget target = pendingTarget;
            if (target == TypeTarget::Auto)
            {
                int probe = probeIsPassword(m_ClickX.load(), m_ClickY.load());
                if (probe > 0)
                {
                    target = TypeTarget::Password;
                    qCInfo(logFill) << "UIA probe: password field detected";
                }
                else if (probe == 0)
                {
                    target = TypeTarget::Username;
                    qCInfo(logFill) << "UIA probe: non-password field detected";
                }
                else
                {
                    // Probe failed - fall back to whichever field hasn't been
                    // typed yet. If neither has been typed, default to Username
                    // (original sequential behavior).
                    if (m_TypedFields & TypedUsername)
                        target = TypeTarget::Password;
                    else
                        target = TypeTarget::Username;
                    qCInfo(logFill) << "UIA probe failed: falling back to"
                                    << (target == TypeTarget::Username ? "username" : "password");
                }
            }

            // Validate the generation counter: if the owner mutated the
            // records vector (add/delete/load) since we armed, the borrowed
            // pointers may reference reallocated or freed storage.
            if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
            {
                qCWarning(logFill)
                    << "performType: records generation changed (" << m_SnapshotGeneration << " -> "
                    << *m_OwnerGeneration << ") - cancelling";
                emit fillError(QStringLiteral("Credential data was modified while fill was armed"));
                cancel();
                return;
            }

            // On-demand decrypt: the credential is AES-encrypted at rest and
            // only decrypted into VirtualLock'd memory for the brief window
            // needed to send keystrokes. The plaintext is wiped immediately
            // after typing (see cred.cleanse() + trimWorkingSet below).
            seal::DecryptedCredential cred;
            const auto* records = m_Records;
            const auto* masterPw = m_MasterPw;
            const int recordIndex = m_RecordIndex;
            if (!records || !masterPw || recordIndex < 0 ||
                recordIndex >= static_cast<int>(records->size()))
            {
                qCWarning(logFill) << "performType: record became unavailable";
                emit fillError(QStringLiteral("Selected credential is no longer available"));
                cancel();
                return;
            }

            const seal::VaultRecord& record = (*records)[recordIndex];
            if (record.deleted)
            {
                qCWarning(logFill) << "performType: record was deleted while armed";
                emit fillError(QStringLiteral("Selected credential was deleted"));
                cancel();
                return;
            }

            try
            {
                cred = seal::decryptCredentialOnDemand(record, *masterPw);
            }
            catch (const std::exception& e)
            {
                qCWarning(logFill) << "performType: decrypt failed:" << e.what();
                emit fillError(QString("Decrypt failed: %1").arg(e.what()));
                cancel();
                return;
            }
            catch (...)
            {
                qCWarning(logFill) << "performType: decrypt failed (unknown)";
                emit fillError(QStringLiteral("Decrypt failed"));
                cancel();
                return;
            }

            // Warn: auto-fill sends real keystrokes through the normal input
            // pipeline. If third-party keyboard hooks are present, credentials
            // could be intercepted. The master password is protected by the
            // secure desktop dialog, but SendInput-based fill is inherently exposed.
            qCDebug(logFill)
                << "performType: note - auto-fill keystrokes pass through global hook chain";

            // Type the selected field via synthesized keystrokes (SendInput).
            bool success = false;
            if (target == TypeTarget::Username)
                success = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);
            else
                success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);

            // Wipe plaintext immediately after typing. cleanse() overwrites
            // the decrypted buffers with zeros, then trimWorkingSet() calls
            // SetProcessWorkingSetSize(-1,-1) to flush dirty pages out of
            // physical RAM so the plaintext can't be recovered from a memory
            // dump or swap file.
            cred.cleanse();
            seal::Cryptography::trimWorkingSet();

            if (!success)
            {
                qCWarning(logFill) << "performType: SendInput failed";
                emit fillError(QStringLiteral("Failed to send keystrokes"));
                cancel();
                return;
            }

            QString service = QString::fromUtf8(record.platform.c_str());

            // Track which field was typed and check for completion.
            if (target == TypeTarget::Username)
                m_TypedFields |= TypedUsername;
            else
                m_TypedFields |= TypedPassword;

            qCInfo(logFill) << "performType:"
                            << (target == TypeTarget::Username ? "username" : "password")
                            << "typed for" << service << "(typedFields=" << m_TypedFields << ")";

            if (m_TypedFields == TypedBoth)
            {
                // Both fields typed - fill complete. Tear down hooks and
                // notify the backend so it can restore the window.
                m_TimeoutTimer.stop();
                removeHooks();
                if (m_UIA)
                {
                    m_UIA->Release();
                    m_UIA = nullptr;
                }
                transitionTo(State::Idle);
                m_RecordIndex = -1;
                m_Records = nullptr;
                m_MasterPw = nullptr;
                m_TypedFields = TypedNone;
                m_RemainingSeconds = 0;
                emit countdownSecondsChanged();
                emit fillCompleted(QString("Filled credentials for '%1'").arg(service));
            }
            else
            {
                // One field remains - reset countdown and stay armed.
                m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
                emit countdownSecondsChanged();
                transitionTo(State::Armed);
                m_TimeoutTimer.start();
            }
        });
    poll->start();
}

int FillController::probeIsPassword(LONG x, LONG y)
{
    POINT pt = {x, y};

    // Phase 1: MSAA probe via AccessibleObjectFromPoint.
    // This sends WM_GETOBJECT to the target window, which triggers lazy
    // accessibility tree creation in Chromium-based browsers (Chrome, Edge,
    // Electron apps). Without this, UIA's ElementFromPoint returns a generic
    // renderer pane instead of the actual DOM element.
    // MSAA's STATE_SYSTEM_PROTECTED flag directly identifies password fields.
    IAccessible* pAcc = nullptr;
    VARIANT varChild;
    VariantInit(&varChild);
    HRESULT hr = AccessibleObjectFromPoint(pt, &pAcc, &varChild);
    if (SUCCEEDED(hr) && pAcc)
    {
        VARIANT state;
        VariantInit(&state);
        hr = pAcc->get_accState(varChild, &state);
        if (SUCCEEDED(hr) && state.vt == VT_I4 && (state.lVal & STATE_SYSTEM_PROTECTED))
        {
            qCDebug(logFill) << "probeIsPassword: MSAA STATE_SYSTEM_PROTECTED detected";
            VariantClear(&state);
            pAcc->Release();
            VariantClear(&varChild);
            return 1;
        }
        VariantClear(&state);

        // Phase 1b: heuristic check on MSAA accessible-name and -description.
        // Some sites use type="text" with JS-driven masking instead of
        // type="password", so STATE_SYSTEM_PROTECTED is never set. The HTML
        // placeholder, label, and aria-describedby text are still exposed
        // through accName / accDescription and often contain recognizable
        // password keywords (e.g. placeholder="Passwort").
        VARIANT role;
        VariantInit(&role);
        hr = pAcc->get_accRole(varChild, &role);
        const bool editableRole =
            SUCCEEDED(hr) && role.vt == VT_I4 &&
            (role.lVal == ROLE_SYSTEM_TEXT || role.lVal == ROLE_SYSTEM_COMBOBOX);
        VariantClear(&role);

        if (editableRole)
        {
            BSTR bstrName = nullptr;
            if (SUCCEEDED(pAcc->get_accName(varChild, &bstrName)))
            {
                const QString nameStr = takeBstr(bstrName);
                if (containsPasswordHint(nameStr))
                {
                    qCDebug(logFill) << "probeIsPassword: MSAA accName matched:" << nameStr;
                    pAcc->Release();
                    VariantClear(&varChild);
                    return 1;
                }
            }

            BSTR bstrDesc = nullptr;
            if (SUCCEEDED(pAcc->get_accDescription(varChild, &bstrDesc)))
            {
                const QString descStr = takeBstr(bstrDesc);
                if (containsPasswordHint(descStr))
                {
                    qCDebug(logFill) << "probeIsPassword: MSAA accDescription matched:" << descStr;
                    pAcc->Release();
                    VariantClear(&varChild);
                    return 1;
                }
            }
        }

        pAcc->Release();
    }
    VariantClear(&varChild);

    // Phase 2: UIA probe. The MSAA call above warmed the accessibility tree,
    // so ElementFromPoint should now return the actual input element even in
    // browsers that lazily initialize their UIA providers.
    if (!m_UIA)
        return -1;

    IUIAutomationElement* element = nullptr;
    hr = m_UIA->ElementFromPoint(pt, &element);
    if (FAILED(hr) || !element)
    {
        qCDebug(logFill) << "probeIsPassword: ElementFromPoint failed: 0x" << Qt::hex << hr;
        return -1;
    }

    qCDebug(logFill) << "probeIsPassword: UIA hit element =" << describeAutomationElement(element);

    bool observedAny = false;
    UiaPasswordObservation hitObservation = inspectElementPasswordState(element);
    observedAny = hitObservation.observed;
    if (hitObservation.isPassword)
    {
        qCDebug(logFill) << "probeIsPassword: UIA hit element matched via"
                         << (hitObservation.source.isEmpty() ? QStringLiteral("<unknown>")
                                                             : hitObservation.source)
                         << (hitObservation.matchedText.isEmpty() ? QStringLiteral("")
                                                                  : hitObservation.matchedText);
        element->Release();
        return 1;
    }

    IUIAutomationTreeWalker* rawWalker = nullptr;
    hr = m_UIA->get_RawViewWalker(&rawWalker);
    if (FAILED(hr) || !rawWalker)
    {
        qCDebug(logFill) << "probeIsPassword: get_RawViewWalker failed: 0x" << Qt::hex << hr;
        element->Release();
        return observedAny ? 0 : -1;
    }

    // Browser hits often land on placeholder text or a renderer wrapper
    // instead of the password edit itself. Walk both directions around the
    // hit node so an empty password field still resolves correctly.
    IUIAutomationElement* current = element;
    current->AddRef();
    for (int depth = 0; depth < kMaxUiaAncestorDepth; ++depth)
    {
        IUIAutomationElement* parent = nullptr;
        hr = rawWalker->GetParentElement(current, &parent);
        current->Release();
        current = nullptr;

        if (FAILED(hr) || !parent)
            break;

        RECT rect{};
        if (tryGetCurrentBoundingRect(parent, &rect) && !rectContainsPoint(rect, x, y))
        {
            current = parent;
            continue;
        }

        UiaPasswordObservation observation =
            inspectElementPasswordState(parent, /*skipControlTypeGate=*/true);
        observedAny = observedAny || observation.observed;
        if (observation.isPassword)
        {
            qCDebug(logFill) << "probeIsPassword: ancestor matched at depth" << (depth + 1) << "via"
                             << (observation.source.isEmpty() ? QStringLiteral("<unknown>")
                                                              : observation.source)
                             << (observation.matchedText.isEmpty() ? QStringLiteral("")
                                                                   : observation.matchedText)
                             << describeAutomationElement(parent);
            parent->Release();
            rawWalker->Release();
            element->Release();
            return 1;
        }

        current = parent;
    }
    if (current)
        current->Release();

    int nodesRemaining = kMaxUiaDescendantNodes;
    const bool descendantMatched =
        searchDescendantsForPassword(rawWalker, element, x, y, 0, nodesRemaining, observedAny);
    rawWalker->Release();
    element->Release();

    if (descendantMatched)
        return 1;

    qCDebug(logFill) << "probeIsPassword: UIA IsPassword=false on inspected path";
    return observedAny ? 0 : -1;
}

}  // namespace seal

#endif  // USE_QT_UI
