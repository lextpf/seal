#ifdef USE_QT_UI

#include "FillController.hpp"
#include "AutoStagePolicy.hpp"
#include "Clipboard.hpp"
#include "Diagnostics.hpp"
#include "FusionDecider.hpp"
#include "Logging.hpp"
#include "SignerUtils.hpp"
#include "UrlBinding.hpp"

#include <QtCore/QThread>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <array>
#include <chrono>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <bcrypt.h>

namespace seal
{

namespace
{

// One-way fingerprint for logs: correlate repeated URL-binding mismatches on
// the same site without echoing the user's hostname (= browsing history) into
// shared logs. 8 hex chars (32-bit SHA-256 prefix) suffices for correlation;
// the goal is log-artifact privacy, not unforgeability against brute-force.
std::string hostLogFingerprint(std::string_view host)
{
    if (host.empty())
    {
        return "none";
    }
    std::array<unsigned char, 32> digest{};
    const NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE,
                                       nullptr,
                                       0,
                                       reinterpret_cast<UCHAR*>(const_cast<char*>(host.data())),
                                       static_cast<ULONG>(host.size()),
                                       digest.data(),
                                       static_cast<ULONG>(digest.size()));
    if (!BCRYPT_SUCCESS(status))
    {
        return "hash_failed";
    }
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(8, '\0');
    for (std::size_t i = 0; i < 4; ++i)
    {
        out[2 * i] = kHex[(digest[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHex[digest[i] & 0x0F];
    }
    return out;
}

// Bounded wait for the async bridge entry for a nav-armed plain click. The
// content.js report for the click travels browser -> SW -> host -> pipe
// (~75 ms observed); cap at ~5x that, then fail closed. Polled at 20 ms on
// the GUI thread (never a blocking Sleep).
constexpr int kAutoBridgeWaitMs = 400;

// Convert a wide (UTF-16) secret span to a UTF-8 std::string for the wire.
// The result is a TRANSIENT plaintext copy the caller wipes after sending.
std::string wideToUtf8(const wchar_t* data, std::size_t len)
{
    if (data == nullptr || len == 0)
    {
        return {};
    }
    const int wideLen = static_cast<int>(len);
    const int need = WideCharToMultiByte(CP_UTF8, 0, data, wideLen, nullptr, 0, nullptr, nullptr);
    if (need <= 0)
    {
        return {};
    }
    std::string out(static_cast<std::size_t>(need), '\0');
    WideCharToMultiByte(CP_UTF8, 0, data, wideLen, out.data(), need, nullptr, nullptr);
    return out;
}

}  // namespace

// Only one controller can own the global hooks. WH_*_LL hooks are per-thread
// and cannot be multiplexed; a second install would silently replace the
// first chain, breaking cancel/timeout for the original session.
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
    m_BrowserBridge.stop();
}

void FillController::disableBridge()
{
    m_BrowserBridge.disable();
}

void FillController::enableBridge()
{
    m_BrowserBridge.enable();
    // Start the bridge unconditionally when enabled, not just on arm/
    // armDiagnose: the extension's connectNative opens a persistent port at
    // browser load, so an absent pipe forces retries into exponential backoff
    // (tens of s); pre-starting keeps one channel live for the first Ctrl+Click.
    if (!m_BrowserBridge.isRunning())
    {
        (void)m_BrowserBridge.start();
    }
}

bool FillController::isBridgeEnabled() const
{
    return !m_BrowserBridge.isDisabled();
}

bool FillController::isBridgePeerAuthEnforced() const
{
    return m_BrowserBridge.isPeerAuthEnforced();
}

bool FillController::isBridgePeerConnected() const
{
    return m_BrowserBridge.isPeerConnected();
}

bool FillController::isBridgeChromeConnected() const
{
    return m_BrowserBridge.isPeerConnected(seal::signer::BrowserKind::Chrome);
}

bool FillController::isBridgeBraveConnected() const
{
    return m_BrowserBridge.isPeerConnected(seal::signer::BrowserKind::Brave);
}

bool FillController::isArmed() const
{
    const State s = m_State.load();
    return s == State::Armed || s == State::AutoArmed;
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
        case FillController::State::Diagnose:
            return "Diagnose";
        case FillController::State::AutoArmed:
            return "AutoArmed";
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
        case State::Diagnose:
            m_StatusText = QStringLiteral("Ctrl+Click any field to test detection");
            break;
        case State::AutoArmed:
            if (m_TypedFields & TypedUsername)
                m_StatusText = QStringLiteral("Click the password field to fill");
            else
                m_StatusText = QStringLiteral("Click the login field to fill");
            break;
    }
    if (m_StatusText != prev)
        emit fillStatusTextChanged();
}

bool FillController::arm(int recordIndex,
                         const std::vector<seal::VaultRecord>& records,
                         seal::CredentialSession& session,
                         const uint64_t& ownerGeneration)
{
    return armInternal(recordIndex, records, session, ownerGeneration, State::Armed);
}

bool FillController::armAuto(int recordIndex,
                             const std::vector<seal::VaultRecord>& records,
                             seal::CredentialSession& session,
                             const uint64_t& ownerGeneration)
{
    return armInternal(recordIndex, records, session, ownerGeneration, State::AutoArmed);
}

bool FillController::armInternal(int recordIndex,
                                 const std::vector<seal::VaultRecord>& records,
                                 seal::CredentialSession& session,
                                 const uint64_t& ownerGeneration,
                                 State targetState)
{
    // If already armed (user clicked a different record, or a nav re-staged),
    // tear down first. This also enforces manual/auto mutual exclusion: the
    // two never share a live armed window.
    if (m_State.load() != State::Idle)
        cancel();

    m_AutoMode.store(targetState == State::AutoArmed);

    // Borrow (no copy): records can be huge - a copy doubles the SeLockMemoryPrivilege
    // quota + double-cleanse on cancel. Session stays DPAPI-protected while armed
    // (performType() unlocks only around the decrypt); caller keeps records+session alive
    // until fill completes. Snapshot ownerGeneration; performType() bails if it moved (race).
    m_RecordIndex = recordIndex;
    m_Records = &records;
    m_Session = &session;
    m_OwnerGeneration = &ownerGeneration;
    m_SnapshotGeneration = ownerGeneration;
    m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
    m_PendingTarget.store(TypeTarget::Auto);
    m_TypedFields = TypedNone;

    // Start the bridge (no-op if running). Non-fatal: other probes still work.
    if (!m_BrowserBridge.isRunning() && !m_BrowserBridge.isDisabled())
    {
        (void)m_BrowserBridge.start();
    }

    // Singleton registration - static hook callbacks dispatch through it.
    s_instance.store(this);
    installHooks();

    if (!m_MouseHook || !m_KeyboardHook)
    {
        qCWarning(logFill) << "hook install failed: mouse=" << !!m_MouseHook
                           << "keyboard=" << !!m_KeyboardHook;
        removeHooks();
        m_RecordIndex = -1;
        m_Records = nullptr;
        m_Session = nullptr;
        emit fillError(QStringLiteral("Failed to install input hooks"));
        return false;
    }

    transitionTo(targetState);

    qCInfo(logFill) << "armed: recordIndex=" << m_RecordIndex
                    << "mode=" << (targetState == State::AutoArmed ? "auto" : "manual")
                    << "timeout=" << FILL_TIMEOUT_SECONDS << "s";
    emit countdownSecondsChanged();
    m_TimeoutTimer.start();
    return true;
}

std::optional<seal::NavSnapshot> FillController::takeNavSince(std::uint64_t& lastSeenSeq)
{
    return m_BrowserBridge.takeNavSince(lastSeenSeq);
}

bool FillController::injectUsername(int recordIndex,
                                    const std::vector<seal::VaultRecord>& records,
                                    seal::CredentialSession& session,
                                    const std::string& host,
                                    const std::string& visit,
                                    DWORD browserPid)
{
    if (recordIndex < 0 || recordIndex >= static_cast<int>(records.size()))
    {
        return false;
    }
    const seal::VaultRecord& record = records[recordIndex];
    if (record.deleted)
    {
        return false;
    }
    if (visit.empty())
    {
        return false;
    }
    // Host binding (fail-closed): same strict browser secret-release matcher as
    // the selector + password gate. Bare labels do not release into a browser.
    if (!seal::url::platformMatchesHostForSecretRelease(record.platform, host))
    {
        qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.autostage.username", "result=skip", "reason=host_mismatch"}));
        return false;
    }
    if (m_BrowserBridge.isDisabled())
    {
        return false;  // M8.
    }

    // JIT-decrypt only the username into locked memory; the master key is plaintext
    // only for this decrypt. Then convert to a transient UTF-8 copy for the wire
    // and wipe it after the send.
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> username;
    try
    {
        auto access = session.unlock();
        if (!access.ok())
        {
            qCWarning(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=fill.autostage.username", "result=fail", "reason=dpapi_unprotect"}));
            return false;
        }
        username = seal::decryptUsernameOnDemand(record, access.password());
    }
    catch (const std::exception& e)
    {
        qCWarning(logFill) << "injectUsername: decrypt failed:" << e.what();
        return false;
    }
    catch (...)
    {
        qCWarning(logFill) << "injectUsername: decrypt failed (unknown)";
        return false;
    }

    std::string usernameUtf8 = wideToUtf8(username.data(), username.size());
    seal::Cryptography::cleanseString(username);
    seal::Cryptography::trimWorkingSet();

    const bool sent = !usernameUtf8.empty() &&
                      m_BrowserBridge.sendFillUsername(browserPid, host, visit, usernameUtf8);
    if (!usernameUtf8.empty())
    {
        SecureZeroMemory(usernameUtf8.data(), usernameUtf8.size());
    }

    qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=fill.autostage.username",
         seal::diag::kv("result", std::string_view(sent ? "ok" : "fail")),
         seal::diag::kv("host_len", static_cast<unsigned int>(host.size()))}));
    return sent;
}

void FillController::cancel()
{
    const State prevState = m_State.load();
    if (prevState == State::Idle)
        return;

    qCInfo(logFill) << "cancel: from state" << stateToString(prevState);
    m_TimeoutTimer.stop();
    removeHooks();
    transitionTo(State::Idle);

    // Clear borrowed pointers + generation snapshot to avoid dangling.
    m_RecordIndex = -1;
    m_Records = nullptr;
    m_Session = nullptr;
    m_OwnerGeneration = nullptr;
    m_SnapshotGeneration = 0;
    m_TypedFields = TypedNone;
    m_RemainingSeconds = 0;
    m_AutoMode.store(false);
    m_AutoFillInFlight.store(false);
    emit countdownSecondsChanged();
    // Route cancellation by mode: diagnose never bound a credential, so
    // fillCancelled would confuse the "fill aborted" UI toast.
    if (prevState == State::Diagnose)
        emit diagnoseCancelled();
    else
        emit fillCancelled();
}

bool FillController::armDiagnose()
{
    if (m_State.load() != State::Idle)
        cancel();

    // Diagnose never decrypts or types, so skip the borrow + generation
    // snapshot. Fields stay default-cleared.
    m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
    m_PendingTarget.store(TypeTarget::Auto);
    m_TypedFields = TypedNone;

    if (!m_BrowserBridge.isRunning() && !m_BrowserBridge.isDisabled())
    {
        (void)m_BrowserBridge.start();
    }

    s_instance.store(this);
    installHooks();
    if (!m_MouseHook || !m_KeyboardHook)
    {
        qCWarning(logFill) << "diagnose hook install failed: mouse=" << !!m_MouseHook
                           << "keyboard=" << !!m_KeyboardHook;
        removeHooks();
        emit fillError(QStringLiteral("Failed to install input hooks"));
        return false;
    }

    transitionTo(State::Diagnose);
    qCInfo(logFill) << "diagnose armed: timeout=" << FILL_TIMEOUT_SECONDS << "s";
    emit countdownSecondsChanged();
    m_TimeoutTimer.start();
    return true;
}

void FillController::onTimeoutTick()
{
    // Tick while waiting for the click; Armed/Diagnose share the UX.
    const State curState = m_State.load();
    if (curState != State::Armed && curState != State::Diagnose)
        return;

    m_RemainingSeconds--;
    emit countdownSecondsChanged();

    if (m_RemainingSeconds <= 0)
    {
        qCInfo(logFill) << "timeout: auto-cancel";
        cancel();
    }
}

void FillController::installHooks()
{
    // WH_MOUSE_LL / WH_KEYBOARD_LL: desktop-wide low-level hooks that
    // intercept input before any window sees it. hMod=nullptr/threadId=0
    // means "all threads on the current desktop"; low-level hooks don't
    // need cross-module injection.
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
    // Clear singleton so any in-flight callback can't deref a dead pointer.
    s_instance.store(nullptr);
    qCDebug(logFill) << "hooks removed";
}

LRESULT CALLBACK FillController::mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // Load s_instance once; cancel() on the main thread can null it between
    // two separate loads (TOCTOU) -> deref nullptr on the second access.
    auto* self = s_instance.load();
    if (nCode >= 0 && self && wParam == WM_LBUTTONDOWN)
    {
        bool ctrlDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        State curState = self->m_State.load();

        if (ctrlDown && curState == State::Armed)
        {
            // Capture click coords for performType()'s UIA probe.
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);

            // Modifier overrides: Shift=password, Alt=username.
            // Neither -> UIA auto-detect in performType().
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

            // Queue performType on the Qt event loop. We're inside the OS
            // hook dispatcher; calling Qt directly here would deadlock or
            // corrupt state. QueuedConnection defers to a normal call frame.
            QMetaObject::invokeMethod(self, "performType", Qt::QueuedConnection);

            // Return 1 swallows the click so the target app never sees the
            // WM_LBUTTONDOWN - otherwise Ctrl+Click would activate whatever
            // is under the cursor.
            return 1;
        }

        if (ctrlDown && curState == State::Diagnose)
        {
            // Mirror Armed coord capture but route to performDiagnose --
            // probe-only, no keystrokes, so shift/alt are irrelevant.
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);
            qCInfo(logFill) << "Ctrl+Click detected: diagnose dry-run";
            QMetaObject::invokeMethod(self, "performDiagnose", Qt::QueuedConnection);
            return 1;
        }

        // Staged auto-fill: a PLAIN left click (no Ctrl) while AutoArmed. A
        // Ctrl-held click in this state falls through to CallNextHookEx, so a
        // user mid-manual-flow is never double-triggered.
        if (!ctrlDown && curState == State::AutoArmed)
        {
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            // Reject synthetic/injected input: a web page cannot forge a real
            // hardware click, but a local process's SendInput can. An injected
            // click must never release a staged secret.
            if ((mhs->flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED)) != 0)
            {
                return CallNextHookEx(nullptr, nCode, wParam, lParam);
            }
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);
            self->m_PendingTarget.store(TypeTarget::Auto);
            QMetaObject::invokeMethod(self, "performTypeAuto", Qt::QueuedConnection);
            // Do NOT swallow (unlike Ctrl+Click, which returns 1): the plain
            // click must focus the field normally. performTypeAuto validates
            // the fail-closed gates and is a silent no-op if this click did
            // not land on a bridge-classified login field.
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
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

        // Esc while waiting -> queued cancel (same hook-dispatcher reason
        // as mouseHookProc). Armed and Diagnose share this UX.
        const State curState = self->m_State.load();
        if (khs->vkCode == VK_ESCAPE && (curState == State::Armed || curState == State::Diagnose ||
                                         curState == State::AutoArmed))
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

    // Wait for Ctrl release before typing - otherwise keystrokes register
    // as Ctrl-shortcuts (Ctrl+A = select-all). 2 s cap for a stuck key
    // (jammed physical key, RDP weirdness); we proceed anyway after that.
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

            // Guard against cancel() during polling.
            if (m_State.load() != State::Typing)
                return;

            const POINT manualClickPoint{m_ClickX.load(), m_ClickY.load()};
            HWND manualClickWindow = WindowFromPoint(manualClickPoint);
            DWORD manualClickPid = 0;
            if (manualClickWindow != nullptr)
            {
                GetWindowThreadProcessId(manualClickWindow, &manualClickPid);
            }
            DWORD manualForegroundPid = 0;
            HWND manualForegroundWindow = GetForegroundWindow();
            if (manualForegroundWindow != nullptr)
            {
                GetWindowThreadProcessId(manualForegroundWindow, &manualForegroundPid);
            }
            if (manualClickPid == 0 || manualForegroundPid == 0 ||
                manualForegroundPid != manualClickPid)
            {
                qCWarning(logFill).noquote() << QString::fromStdString(
                    seal::diag::joinFields({"event=fill.manual.release",
                                            "result=blocked",
                                            "reason=manual_foreground_pid_mismatch"}));
                emit fillError(QStringLiteral("Focused window changed before typing."));
                cancel();
                return;
            }

            // Resolve target. Shift/Alt already resolved in the hook; Auto
            // means probe the element via UI Automation. Compute the detailed
            // fusion outcome once: Auto resolution reads its verdict, and the
            // browser password M5 gate below reuses its corroboration flags.
            const seal::FusionOutcome fusion =
                runProbeRegistryDetailed(m_ClickX.load(), m_ClickY.load());
            TypeTarget target = pendingTarget;
            if (target == TypeTarget::Auto)
            {
                const seal::Verdict verdict = fusion.m_Verdict;
                if (verdict == seal::Verdict::Password)
                {
                    target = TypeTarget::Password;
                }
                else if (verdict == seal::Verdict::Username)
                {
                    target = TypeTarget::Username;
                }
                else
                {
                    // All probes Unknown / under the FusionDecider margin.
                    // Fall back to whichever field hasn't been typed yet;
                    // default Username when neither has.
                    if (m_TypedFields & TypedUsername)
                    {
                        target = TypeTarget::Password;
                    }
                    else
                    {
                        target = TypeTarget::Username;
                    }
                    qCInfo(logFill) << "fill.decide: registry unknown, falling back to"
                                    << (target == TypeTarget::Username ? "username" : "password");
                }
            }

            // Generation check: any owner mutation (add/delete/load) since
            // arm may have reallocated or freed our borrowed pointers.
            if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
            {
                qCWarning(logFill)
                    << "performType: records generation changed (" << m_SnapshotGeneration << " -> "
                    << *m_OwnerGeneration << ") - cancelling";
                emit fillError(QStringLiteral("Credential data was modified while fill was armed"));
                cancel();
                return;
            }

            // Validate the borrowed record before the shared decrypt/type.
            const auto* records = m_Records;
            const int recordIndex = m_RecordIndex;
            if (!records || !m_Session || recordIndex < 0 ||
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

            // URL/platform binding (phishing resistance): browser fills require a fresh
            // bridge URL and the shared tiered matcher. Domain records stay TLD-sensitive;
            // non-browser targets still fill without URL context.
            if (manualClickPid != 0)
            {
                const auto bridgeEntry = m_BrowserBridge.lookup(manualClickPid, manualClickPoint);
                if (bridgeEntry.has_value() && !bridgeEntry->m_UrlHost.isEmpty())
                {
                    const std::string manualPageHost = bridgeEntry->m_UrlHost.toStdString();
                    if (!seal::url::platformMatchesHostForSecretRelease(record.platform,
                                                                        manualPageHost))
                    {
                        qCWarning(logFill).noquote() << QString::fromStdString(
                            seal::diag::joinFields(
                                {"event=fill.url_mismatch_block",
                                 seal::diag::kv(
                                     "record_fp",
                                     hostLogFingerprint(seal::url::extractHost(record.platform))),
                                 seal::diag::kv(
                                     "page_fp",
                                     hostLogFingerprint(seal::url::extractHost(manualPageHost)))}));
                        emit fillError(QStringLiteral(
                            "Site mismatch: selected record does not match this site."));
                        cancel();
                        return;
                    }
                    // Cross-document replay veto: the cached entry (from the
                    // earlier focus-click - the Ctrl+Click is swallowed by the
                    // hook, so no fresh report exists for it) must belong to the
                    // document now loaded in this browser. Blocks only on a
                    // positive mismatch; an older extension that omits the click
                    // token falls back to the host check above.
                    const std::optional<std::string> curVisit =
                        m_BrowserBridge.currentVisit(manualClickPid);
                    if (curVisit.has_value() &&
                        !seal::visitAuthorizes(bridgeEntry->m_Visit, *curVisit))
                    {
                        qCWarning(logFill).noquote() << QString::fromStdString(
                            seal::diag::joinFields({"event=fill.url_mismatch_block",
                                                    "result=blocked",
                                                    "reason=visit_mismatch_manual"}));
                        emit fillError(QStringLiteral(
                            "Site changed since the field was detected. Click the field again."));
                        cancel();
                        return;
                    }
                    // M5 corroboration for the PASSWORD release: a browser
                    // password fill must be backed by an on-disk Tier-1 probe,
                    // not the bridge (extension) alone - parity with the staged
                    // auto path (see performTypeAuto's G-corroborate gate). The
                    // username half (less sensitive, weaker on-disk signal)
                    // keeps the host+visit binding only.
                    if (target == TypeTarget::Password &&
                        !(fusion.m_Tier1ShortCircuit && fusion.m_BridgeCorroborated))
                    {
                        qCWarning(logFill).noquote() << QString::fromStdString(
                            seal::diag::joinFields({"event=fill.url_mismatch_block",
                                                    "result=blocked",
                                                    "reason=weak_fusion_manual"}));
                        emit fillError(QStringLiteral(
                            "Could not confirm a password field here. Click the field again."));
                        cancel();
                        return;
                    }
                }
                else
                {
                    const std::wstring imagePath = seal::signer::resolveProcessPath(manualClickPid);
                    if (seal::signer::isKnownBrowserImage(imagePath))
                    {
                        qCWarning(logFill).noquote() << QString::fromStdString(
                            seal::diag::joinFields({"event=fill.url_mismatch_block",
                                                    "result=blocked",
                                                    "reason=no_bridge_entry_manual"}));
                        emit fillError(QStringLiteral(
                            "Browser site could not be verified. Check the companion extension."));
                        cancel();
                        return;
                    }
                }
            }

            decryptAndTypeField(record, target);
        });
    poll->start();
}

void FillController::decryptAndTypeField(const seal::VaultRecord& record, TypeTarget target)
{
    // On-demand decrypt into VirtualLock'd memory; plaintext wiped immediately
    // after typing (cred.cleanse + trimWorkingSet below). Callers have already
    // validated the record (and, for the auto path, the fail-closed gates).
    seal::DecryptedCredential cred;
    try
    {
        // Master key is plaintext ONLY for this decrypt; the Access window
        // re-protects on scope exit, before cred is typed and cleansed below.
        auto access = m_Session->unlock();
        if (!access.ok())
        {
            qCWarning(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
            emit fillError(QStringLiteral("Could not access the master key."));
            cancel();
            return;
        }
        cred = seal::decryptCredentialOnDemand(record, access.password());
    }
    catch (const std::exception& e)
    {
        qCWarning(logFill) << "decryptAndTypeField: decrypt failed:" << e.what();
        emit fillError(QString("Decrypt failed: %1").arg(e.what()));
        cancel();
        return;
    }
    catch (...)
    {
        qCWarning(logFill) << "decryptAndTypeField: decrypt failed (unknown)";
        emit fillError(QStringLiteral("Decrypt failed"));
        cancel();
        return;
    }

    // Warn: SendInput keystrokes pass through every global hook in the chain,
    // so a third-party keylogger could intercept the credential. The master-
    // password dialog uses the secure desktop, but the fill path is exposed.
    qCDebug(logFill) << "decryptAndTypeField: note - keystrokes pass through global hook chain";

    // Send the selected field via SendInput.
    bool success = false;
    if (target == TypeTarget::Username)
        success = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);
    else
        success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);

    // Wipe immediately: cleanse() zeros the decrypted buffers and
    // trimWorkingSet() (SetProcessWorkingSetSize(-1,-1)) flushes the dirty
    // pages so a dump or swap file can't recover plaintext.
    cred.cleanse();
    seal::Cryptography::trimWorkingSet();

    if (!success)
    {
        qCWarning(logFill) << "decryptAndTypeField: SendInput failed";
        emit fillError(QStringLiteral("Failed to send keystrokes"));
        cancel();
        return;
    }

    QString service = QString::fromUtf8(record.platform.c_str());

    // Track which field was typed.
    if (target == TypeTarget::Username)
        m_TypedFields |= TypedUsername;
    else
        m_TypedFields |= TypedPassword;

    qCInfo(logFill) << "fill: " << (target == TypeTarget::Username ? "username" : "password")
                    << "typed for" << service << "(typedFields=" << m_TypedFields << ")";

    // Staged (auto) mode is one-click-one-fill: after the clicked field is
    // filled it DISARMS - a later click never re-arms or re-types. Manual
    // Ctrl+Click mode keeps its two-field flow (stay armed for the other field
    // until both are typed).
    const bool complete = (m_TypedFields == TypedBoth) || m_AutoMode.load();
    if (complete)
    {
        // Done: tear down hooks; backend restores window.
        m_TimeoutTimer.stop();
        removeHooks();
        transitionTo(State::Idle);
        m_RecordIndex = -1;
        m_Records = nullptr;
        m_Session = nullptr;
        m_TypedFields = TypedNone;
        m_RemainingSeconds = 0;
        m_AutoMode.store(false);
        m_AutoFillInFlight.store(false);
        emit countdownSecondsChanged();
        emit fillCompleted(QString("Filled credentials for '%1'").arg(service));
    }
    else
    {
        // Manual mode, one field remains: reset countdown, stay Armed for the
        // other field's Ctrl+Click.
        m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
        m_AutoFillInFlight.store(false);
        emit countdownSecondsChanged();
        transitionTo(State::Armed);
        m_TimeoutTimer.start();
    }
}

void FillController::performTypeAuto()
{
    if (m_State.load() != State::AutoArmed)
        return;
    // Single-flight: ignore overlapping clicks while one completion runs.
    if (m_AutoFillInFlight.exchange(true))
        return;

    // The content.js report for THIS click travels async (browser -> SW ->
    // host -> pipe), so the bridge entry is usually not in the map at
    // physical-click time. Poll briefly for it, then validate. Never Sleep the
    // GUI thread (matches performType's Ctrl-release poll pattern).
    auto* poll = new QTimer(this);
    poll->setInterval(20);
    connect(
        poll,
        &QTimer::timeout,
        this,
        [this, poll, elapsedMs = 0]() mutable
        {
            elapsedMs += 20;

            // Cancelled (Esc / timeout / re-stage) during the wait.
            if (m_State.load() != State::AutoArmed)
            {
                poll->stop();
                poll->deleteLater();
                m_AutoFillInFlight.store(false);
                return;
            }

            const POINT clickPoint{m_ClickX.load(), m_ClickY.load()};
            HWND clickWindow = WindowFromPoint(clickPoint);
            DWORD clickPid = 0;
            if (clickWindow != nullptr)
                GetWindowThreadProcessId(clickWindow, &clickPid);

            std::optional<seal::BridgeEntry> entry;
            if (clickPid != 0)
                entry = m_BrowserBridge.lookup(clickPid, clickPoint);

            // G-classification: no bridge entry means the click did not land on
            // a bridge-classified login field (text/other are never inserted).
            if (!entry.has_value())
            {
                if (elapsedMs < kAutoBridgeWaitMs)
                    return;  // Keep waiting for the async report.
                poll->stop();
                poll->deleteLater();
                qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.release", "result=blocked", "reason=no_bridge_entry"}));
                m_AutoFillInFlight.store(false);
                return;  // Silent no-op; stay AutoArmed for a real login click.
            }

            poll->stop();
            poll->deleteLater();

            // G-foreground (dual-PID): the click window AND the foreground
            // window must both belong to the same, bridge-validated browser
            // PID. SendInput targets the focused window, so a focus-steal
            // between click and type is refused here.
            DWORD fgPid = 0;
            HWND fg = GetForegroundWindow();
            if (fg != nullptr)
                GetWindowThreadProcessId(fg, &fgPid);
            if (fgPid == 0 || fgPid != clickPid)
            {
                qCWarning(logFill).noquote() << QString::fromStdString(
                    seal::diag::joinFields({"event=fill.autostage.release",
                                            "result=blocked",
                                            "reason=foreground_pid_mismatch"}));
                m_AutoFillInFlight.store(false);
                return;  // Stay AutoArmed; no secret released.
            }

            // Validate the borrowed record.
            const auto* records = m_Records;
            const int recordIndex = m_RecordIndex;
            if (!records || !m_Session || recordIndex < 0 ||
                recordIndex >= static_cast<int>(records->size()))
            {
                emit fillError(QStringLiteral("Selected credential is no longer available"));
                cancel();
                return;
            }
            const seal::VaultRecord& record = (*records)[recordIndex];
            if (record.deleted)
            {
                emit fillError(QStringLiteral("Selected credential was deleted"));
                cancel();
                return;
            }

            // G-URL (fail-closed): the fresh entry's host must bind to the staged record
            // under the SAME strict secret-release matcher the selector uses. Unlike the
            // manual fail-open veto, no match => abort before decrypt (no plaintext).
            const std::string pageHost =
                entry->m_UrlHost.isEmpty() ? std::string() : entry->m_UrlHost.toStdString();
            if (pageHost.empty() ||
                !seal::url::platformMatchesHostForSecretRelease(record.platform, pageHost))
            {
                qCWarning(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.release",
                     "result=blocked",
                     "reason=host_mismatch",
                     seal::diag::kv("record_fp",
                                    hostLogFingerprint(seal::url::extractHost(record.platform))),
                     seal::diag::kv("page_fp",
                                    hostLogFingerprint(seal::url::extractHost(pageHost)))}));
                emit fillError(
                    QStringLiteral("Site mismatch: the staged record does not match this site."));
                cancel();
                return;
            }

            // G-visit (fail-closed): the authorizing entry must belong to the
            // document currently loaded in this browser. A stale entry from a
            // prior document (an earlier page at the same coordinates that was
            // navigated away from) is refused before decrypt. The release click
            // itself produces a fresh same-document entry, so this holds on the
            // armed page and fails after any navigation (whose login page mints
            // a new token). Both tokens must be known and equal.
            const std::optional<std::string> curVisit = m_BrowserBridge.currentVisit(clickPid);
            if (entry->m_Visit.empty() || !curVisit.has_value() ||
                !seal::visitAuthorizes(entry->m_Visit, *curVisit))
            {
                qCWarning(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.release", "result=blocked", "reason=visit_mismatch"}));
                emit fillError(
                    QStringLiteral("Page changed since the field was detected. Try again."));
                cancel();
                return;
            }

            // Generation abort: any owner mutation since arm may have
            // reallocated or freed the borrowed pointers.
            if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
            {
                emit fillError(QStringLiteral("Credential data was modified while fill was armed"));
                cancel();
                return;
            }

            // G-corroborate (M5): the fused verdict must be decisive AND on-disk
            // corroborated. This refuses a bridge-alone hit (e.g. a lying/compromised
            // extension planting a Password entry that aliases a metadata-stripped
            // text field): the password releases only when an on-disk Tier-1 probe
            // also reads Password. NOTE: in a browser the sole on-disk corroborator
            // is UiaIsPasswordProbe, whose IsPassword/Protected verdict is itself
            // derived from the page DOM (<input type=password>) - the same fact the
            // bridge classified. So this is NOT an independent check against a
            // *hostile page* (a page showing a real password input satisfies it); it
            // hardens against a lying *extension*. What actually prevents wrong-site
            // release is the strict host binding above (G-URL). No fallback here.
            transitionTo(State::Typing);
            const seal::FusionOutcome outcome =
                runProbeRegistryDetailed(clickPoint.x, clickPoint.y);
            if (outcome.m_Verdict == seal::Verdict::Unknown ||
                !(outcome.m_Tier1ShortCircuit && outcome.m_BridgeCorroborated))
            {
                qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.release", "result=blocked", "reason=weak_fusion"}));
                // No secret released; return to AutoArmed to allow a retry.
                m_AutoFillInFlight.store(false);
                m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
                emit countdownSecondsChanged();
                transitionTo(State::AutoArmed);
                m_TimeoutTimer.start();
                return;
            }

            // Staged mode releases the PASSWORD only; the username half is the DOM
            // injection (once per visit, via StagingController). Typing it here would
            // double-fill and burn the one staged click on the wrong credential, so a
            // Username fuse is a silent no-op (stay AutoArmed). Manual still types either.
            if (outcome.m_Verdict != seal::Verdict::Password)
            {
                qCInfo(logFill).noquote() << QString::fromStdString(
                    seal::diag::joinFields({"event=fill.autostage.release",
                                            "result=blocked",
                                            "reason=not_password_field"}));
                m_AutoFillInFlight.store(false);
                m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
                emit countdownSecondsChanged();
                transitionTo(State::AutoArmed);
                m_TimeoutTimer.start();
                return;
            }
            qCInfo(logFill).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=fill.autostage.release", "result=ok"}));
            // decryptAndTypeField clears m_AutoFillInFlight on every exit path.
            decryptAndTypeField(record, TypeTarget::Password);
        });
    poll->start();
}

seal::Verdict FillController::runProbeRegistry(LONG x, LONG y)
{
    return runProbeRegistryDetailed(x, y).m_Verdict;
}

seal::FusionOutcome FillController::runProbeRegistryDetailed(LONG x, LONG y)
{
    using seal::ProbeContext;
    using seal::ProbeResult;
    using seal::Verdict;

    ProbeContext ctx;
    ctx.m_ClickPoint = POINT{x, y};
    ctx.m_TargetWindow = WindowFromPoint(ctx.m_ClickPoint);
    if (ctx.m_TargetWindow != nullptr)
    {
        GetWindowThreadProcessId(ctx.m_TargetWindow, &ctx.m_TargetProcessId);
    }
    ctx.m_Deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);

    std::array<ProbeResult, 5> results = {
        m_BrowserBridgeProbe.run(ctx),
        m_Win32StyleProbe.run(ctx),
        m_UiaIsPassword.run(ctx),
        m_UiaMetadata.run(ctx),
        m_ImeStateProbe.run(ctx),
    };

    const seal::FusionOutcome outcome = m_FusionDecider.decideDetailed(results);

    // One summary line per click; per-probe fields let weight tuning be driven
    // from logFill telemetry. corroborated= lets the auto path's refusals be
    // read from the same line.
    QString line =
        QStringLiteral("event=fill.decide chosen=%1 corroborated=%2")
            .arg(outcome.m_Verdict == Verdict::Password   ? QStringLiteral("password")
                 : outcome.m_Verdict == Verdict::Username ? QStringLiteral("username")
                                                          : QStringLiteral("unknown"))
            .arg(outcome.m_BridgeCorroborated ? QStringLiteral("1") : QStringLiteral("0"));
    for (const ProbeResult& r : results)
    {
        const QString verdictText = r.m_Verdict == Verdict::Password   ? QStringLiteral("password")
                                    : r.m_Verdict == Verdict::Username ? QStringLiteral("username")
                                                                       : QStringLiteral("unknown");
        line += QString(" %1_verdict=%2 %1_conf=%3")
                    .arg(QString::fromLatin1(r.m_ProbeName))
                    .arg(verdictText)
                    .arg(QString::number(r.m_Confidence, 'f', 2));
        if (!r.m_Evidence.empty())
        {
            line += QString(" %1_evidence=%2")
                        .arg(QString::fromLatin1(r.m_ProbeName))
                        .arg(QString::fromStdString(seal::diag::sanitizeAscii(r.m_Evidence)));
        }
    }
    qCInfo(logFill).noquote() << line;

    return outcome;
}

void FillController::performDiagnose()
{
    using seal::ProbeContext;
    using seal::ProbeResult;
    using seal::Verdict;

    if (m_State.load() != State::Diagnose)
        return;

    m_TimeoutTimer.stop();

    const POINT clickPoint{m_ClickX.load(), m_ClickY.load()};

    auto runOnce = [&]()
    {
        ProbeContext ctx;
        ctx.m_ClickPoint = clickPoint;
        ctx.m_TargetWindow = WindowFromPoint(ctx.m_ClickPoint);
        if (ctx.m_TargetWindow != nullptr)
        {
            GetWindowThreadProcessId(ctx.m_TargetWindow, &ctx.m_TargetProcessId);
        }
        ctx.m_Deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(300);
        return std::make_pair(ctx,
                              std::array<ProbeResult, 5>{
                                  m_BrowserBridgeProbe.run(ctx),
                                  m_Win32StyleProbe.run(ctx),
                                  m_UiaIsPassword.run(ctx),
                                  m_UiaMetadata.run(ctx),
                                  m_ImeStateProbe.run(ctx),
                              });
    };

    auto [ctx, results] = runOnce();

    // Race-mitigation: only the browser_extension probe (index 0) rides the async
    // content.js -> SW -> host -> bridge path, which a busy/just-woken SW can land
    // AFTER the Ctrl+Click. On a live peer but Unknown, wait ~75 ms and re-probe.
    // The fill path's Ctrl-release poll already absorbs this; diagnose probes now.
    if (results[0].m_Verdict == Verdict::Unknown && m_BrowserBridge.isPeerConnected())
    {
        Sleep(75);  // synchronous on the Qt thread; trivially short.
        auto retry = runOnce();
        ctx = retry.first;
        results = retry.second;
    }

    const Verdict verdict = m_FusionDecider.decide(results);

    auto verdictText = [](Verdict v)
    {
        return v == Verdict::Password   ? QStringLiteral("password")
               : v == Verdict::Username ? QStringLiteral("username")
                                        : QStringLiteral("unknown");
    };

    // User-facing summary - one line per probe, free-form (the QML popup
    // renders this as a <pre>; nothing downstream parses it).
    QString summary;
    summary += QStringLiteral("Fused verdict: %1\n").arg(verdictText(verdict));
    summary += QStringLiteral("Click point: (%1, %2)\n").arg(clickPoint.x).arg(clickPoint.y);
    summary += QStringLiteral("Target window PID: %1\n").arg(ctx.m_TargetProcessId);

    // Bridge connectivity / cache state - key for triaging a
    // "browser_extension: unknown": disambiguates "no host ever connected"
    // vs "connected but didn't report this click" vs "reported elsewhere".
    summary += QStringLiteral("\nBridge:\n");
    summary += QStringLiteral("  running: %1\n").arg(m_BrowserBridge.isRunning() ? "yes" : "no");
    summary += QStringLiteral("  disabled: %1\n").arg(m_BrowserBridge.isDisabled() ? "yes" : "no");
    summary += QStringLiteral("  peer connected: %1\n")
                   .arg(m_BrowserBridge.isPeerConnected() ? "yes" : "no");
    summary += QStringLiteral("  cached entries: %1\n").arg(m_BrowserBridge.mapEntryCount());

    summary += QStringLiteral("\nPer-probe results:\n");
    for (const ProbeResult& r : results)
    {
        summary += QStringLiteral("  - %1: %2 (conf %3)")
                       .arg(QString::fromLatin1(r.m_ProbeName))
                       .arg(verdictText(r.m_Verdict))
                       .arg(QString::number(r.m_Confidence, 'f', 2));
        if (!r.m_Evidence.empty())
        {
            summary += QStringLiteral(" [%1]").arg(
                QString::fromStdString(seal::diag::sanitizeAscii(r.m_Evidence)));
        }
        summary += QLatin1Char('\n');
    }

    // URL host is privacy-sensitive, but diagnose is user-initiated for
    // one specific click - showing the host in the popup is appropriate.
    // Logs still get the redacted form via the probe's bridge_match.
    if (ctx.m_TargetProcessId != 0)
    {
        const auto entry = m_BrowserBridge.lookup(ctx.m_TargetProcessId, clickPoint);
        if (entry.has_value() && !entry->m_UrlHost.isEmpty())
        {
            summary += QStringLiteral("\nBridge URL host: %1\n").arg(entry->m_UrlHost);
        }
    }

    // Redacted logfmt mirror so operators see the diagnose event without
    // leaking the URL host. Includes raw click_x/y + target_pid for cross-
    // reference against fill.bridge.msg's x/y/qx/qy - mismatches there
    // diagnose "report arrived but lookup missed" situations.
    QString line =
        QStringLiteral("event=fill.diagnose chosen=%1 click_x=%2 click_y=%3 target_pid=%4")
            .arg(verdictText(verdict))
            .arg(clickPoint.x)
            .arg(clickPoint.y)
            .arg(ctx.m_TargetProcessId);
    for (const ProbeResult& r : results)
    {
        line += QString(" %1_verdict=%2 %1_conf=%3")
                    .arg(QString::fromLatin1(r.m_ProbeName))
                    .arg(verdictText(r.m_Verdict))
                    .arg(QString::number(r.m_Confidence, 'f', 2));
    }
    qCInfo(logFill).noquote() << line;

    removeHooks();
    transitionTo(State::Idle);
    m_RemainingSeconds = 0;
    emit countdownSecondsChanged();
    emit diagnoseCompleted(summary);
}

}  // namespace seal

#endif  // USE_QT_UI
