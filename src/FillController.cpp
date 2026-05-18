#ifdef USE_QT_UI

#include "FillController.hpp"
#include "Clipboard.hpp"
#include "Diagnostics.hpp"
#include "FusionDecider.hpp"
#include "Logging.hpp"
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

// Short, one-way fingerprint for logs: correlate repeated URL-binding
// mismatches against the same site without echoing the user's hostname
// (= browsing history) into shared log files. 8 hex chars (32 bits of
// SHA-256 prefix) is plenty for correlation; the goal is privacy of the
// log artifact, not unforgeability against a brute-force replay.
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
    // Start the bridge unconditionally when enabled, not only on
    // arm/armDiagnose. The extension's connectNative establishes a
    // persistent port at browser load time; if our named pipe doesn't
    // exist yet, every retry hits an exponential backoff that grows to
    // tens of seconds before the next attempt. Pre-starting the pipe
    // means the extension can connect once and stay connected for the
    // app's lifetime, so the first Ctrl+Click after seal launch already
    // has a live channel to populate the verdict map.
    if (!m_BrowserBridge.isRunning())
    {
        (void)m_BrowserBridge.start();
    }
}

bool FillController::isBridgeEnabled() const
{
    return !m_BrowserBridge.isDisabled();
}

bool FillController::isBridgePeerConnected() const
{
    return m_BrowserBridge.isPeerConnected();
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
        case FillController::State::Diagnose:
            return "Diagnose";
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
    // If already armed (user clicked a different record), tear down first.
    if (m_State.load() != State::Idle)
        cancel();

    // Borrow (no copy): masterPw is locked_allocator-backed and records can
    // be huge -- copying would double the SeLockMemoryPrivilege quota and
    // force double-cleanse on cancel. Caller (Backend) keeps them alive
    // until fillCompleted / fillCancelled / fillError.
    //
    // Borrowing races with vault mutations between Ctrl+Click and keystroke
    // send. We snapshot ownerGeneration here; performType() bails via
    // fillError() if the live counter has moved.
    m_RecordIndex = recordIndex;
    m_Records = &records;
    m_MasterPw = &masterPw;
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

    // Singleton registration -- static hook callbacks dispatch through it.
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
    m_MasterPw = nullptr;
    m_OwnerGeneration = nullptr;
    m_SnapshotGeneration = 0;
    m_TypedFields = TypedNone;
    m_RemainingSeconds = 0;
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
            // WM_LBUTTONDOWN -- otherwise Ctrl+Click would activate whatever
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
        if (khs->vkCode == VK_ESCAPE && (curState == State::Armed || curState == State::Diagnose))
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

    // Wait for Ctrl release before typing -- otherwise keystrokes register
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

            // Resolve target. Shift/Alt already resolved in the hook; Auto
            // means probe the element via UI Automation.
            TypeTarget target = pendingTarget;
            if (target == TypeTarget::Auto)
            {
                const seal::Verdict verdict = runProbeRegistry(m_ClickX.load(), m_ClickY.load());
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

            // On-demand decrypt into VirtualLock'd memory; plaintext wiped
            // immediately after typing (cred.cleanse + trimWorkingSet below).
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

            // URL/platform binding -- phishing resistance. Compare the
            // bridge-reported page host against the record's platform
            // label via extractKey's fuzzy reduction (TLD/case/stop-word
            // strip): "PayPal", "paypal.com", "https://login.paypal.com",
            // "My PayPal" all collapse to "paypal". A mismatch CANCELS the
            // fill, so a record labelled "Paypal" cannot type into a
            // typosquat. Skipped silently when no bridge entry exists for
            // the click, or when the platform reduces to an empty key
            // (caller fails open). The check runs BEFORE on-demand
            // decryption so a phishing mismatch never produces plaintext.
            const POINT urlClickPoint{m_ClickX.load(), m_ClickY.load()};
            HWND urlFocusWindow = WindowFromPoint(urlClickPoint);
            DWORD urlFocusPid = 0;
            if (urlFocusWindow != nullptr)
            {
                GetWindowThreadProcessId(urlFocusWindow, &urlFocusPid);
            }
            if (urlFocusPid != 0)
            {
                const auto bridgeEntry = m_BrowserBridge.lookup(urlFocusPid, urlClickPoint);
                if (bridgeEntry.has_value() && !bridgeEntry->m_UrlHost.isEmpty())
                {
                    const std::string recordKey = seal::url::extractKey(record.platform);
                    const std::string pageKey =
                        seal::url::extractKey(bridgeEntry->m_UrlHost.toStdString());
                    if (!recordKey.empty() && !pageKey.empty() &&
                        !seal::url::keysMatch(recordKey, pageKey))
                    {
                        // Keys are already privacy-friendly (no TLD, path,
                        // or subdomain noise); the log line still uses
                        // SHA-256 fingerprints for shared bug reports. The
                        // user-facing message keeps human-readable keys
                        // so the operator can see what tried where.
                        qCWarning(logFill).noquote()
                            << QString::fromStdString(seal::diag::joinFields(
                                   {"event=fill.url_mismatch_block",
                                    seal::diag::kv("record_key_fp", hostLogFingerprint(recordKey)),
                                    seal::diag::kv("page_key_fp", hostLogFingerprint(pageKey))}));
                        emit fillError(QString("Site mismatch: '%1' record cannot fill on '%2'. "
                                               "Cancel and re-arm a record that matches this site.")
                                           .arg(QString::fromStdString(recordKey),
                                                QString::fromStdString(pageKey)));
                        cancel();
                        return;
                    }
                }
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

            // Warn: SendInput keystrokes pass through every global hook in
            // the chain, so a third-party keylogger could intercept the
            // credential. The master-password dialog uses the secure
            // desktop, but the fill path itself is inherently exposed.
            qCDebug(logFill)
                << "performType: note - auto-fill keystrokes pass through global hook chain";

            // Send the selected field via SendInput.
            bool success = false;
            if (target == TypeTarget::Username)
                success = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);
            else
                success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);

            // Wipe immediately: cleanse() zeros the decrypted buffers and
            // trimWorkingSet() (SetProcessWorkingSetSize(-1,-1)) flushes the
            // dirty pages so a dump or swap file can't recover plaintext.
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

            // Track which field was typed.
            if (target == TypeTarget::Username)
                m_TypedFields |= TypedUsername;
            else
                m_TypedFields |= TypedPassword;

            qCInfo(logFill) << "performType:"
                            << (target == TypeTarget::Username ? "username" : "password")
                            << "typed for" << service << "(typedFields=" << m_TypedFields << ")";

            if (m_TypedFields == TypedBoth)
            {
                // Both fields typed: tear down hooks; backend restores window.
                m_TimeoutTimer.stop();
                removeHooks();
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
                // One field remains: reset countdown, stay armed.
                m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
                emit countdownSecondsChanged();
                transitionTo(State::Armed);
                m_TimeoutTimer.start();
            }
        });
    poll->start();
}

seal::Verdict FillController::runProbeRegistry(LONG x, LONG y)
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

    const Verdict verdict = m_FusionDecider.decide(results);

    // One summary line per Ctrl+Click; per-probe fields let weight tuning
    // be driven from logFill telemetry.
    QString line = QStringLiteral("event=fill.decide chosen=%1")
                       .arg(verdict == Verdict::Password   ? QStringLiteral("password")
                            : verdict == Verdict::Username ? QStringLiteral("username")
                                                           : QStringLiteral("unknown"));
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

    return verdict;
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

    // Race-mitigation: only the browser_extension probe (index 0) depends
    // on async content.js -> SW -> host -> bridge delivery, and a busy or
    // just-woken SW can land that report AFTER the Ctrl+Click. If we have
    // a live peer but Unknown, give it ~75 ms and re-probe. The fill path
    // doesn't need this -- its Ctrl-release poll already adds delay --
    // but diagnose probes immediately and would lose the race.
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

    // User-facing summary -- one line per probe, free-form (the QML popup
    // renders this as a <pre>; nothing downstream parses it).
    QString summary;
    summary += QStringLiteral("Fused verdict: %1\n").arg(verdictText(verdict));
    summary += QStringLiteral("Click point: (%1, %2)\n").arg(clickPoint.x).arg(clickPoint.y);
    summary += QStringLiteral("Target window PID: %1\n").arg(ctx.m_TargetProcessId);

    // Bridge connectivity / cache state -- key for triaging a
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
    // one specific click -- showing the host in the popup is appropriate.
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
    // reference against fill.bridge.msg's x/y/qx/qy -- mismatches there
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
