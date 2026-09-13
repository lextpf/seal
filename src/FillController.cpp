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

// use a 32-bit SHA-256 prefix to correlate hosts without logging browsing history.
// this redaction does not resist hostname brute-force.
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

// poll on the GUI thread while the click report crosses the extension and host.
constexpr int kAutoBridgeWaitMs = 400;

// the caller must wipe this transient UTF-8 plaintext copy after sending.
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

std::atomic<FillController*> FillController::s_instance{nullptr};

FillController::FillController(QObject* parent)
    : QObject(parent)
{
    m_TimeoutTimer.setInterval(1000);
    connect(&m_TimeoutTimer, &QTimer::timeout, this, &FillController::onTimeoutTick);
}

FillController::~FillController()
{
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
    // start eagerly so the first click does not wait for extension reconnect backoff.
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

bool FillController::isBridgeBrowserConnected(seal::signer::BrowserKind kind) const
{
    return m_BrowserBridge.isPeerConnected(kind);
}

bool FillController::isBridgeChromeConnected() const
{
    return isBridgeBrowserConnected(seal::signer::BrowserKind::Chrome);
}

bool FillController::isBridgeBraveConnected() const
{
    return isBridgeBrowserConnected(seal::signer::BrowserKind::Brave);
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

    // notify only when isArmed changes.
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
    if (m_State.load() != State::Idle)
        cancel();

    m_AutoMode.store(targetState == State::AutoArmed);

    // borrow state through completion; generation checks reject owner mutations before decrypt.
    m_RecordIndex = recordIndex;
    m_Records = &records;
    m_Session = &session;
    m_OwnerGeneration = &ownerGeneration;
    m_SnapshotGeneration = ownerGeneration;
    m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
    m_PendingTarget.store(TypeTarget::Auto);
    m_TypedFields = TypedNone;

    // bridge startup failure leaves native field probes available.
    if (!m_BrowserBridge.isRunning() && !m_BrowserBridge.isDisabled())
    {
        (void)m_BrowserBridge.start();
    }

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

    // keep the session unlock scoped to decrypt; wipe the UTF-8 copy after send.
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
    // diagnose cancellation must not show a credential-fill cancellation toast.
    if (prevState == State::Diagnose)
        emit diagnoseCancelled();
    else
        emit fillCancelled();
}

bool FillController::armDiagnose()
{
    if (m_State.load() != State::Idle)
        cancel();

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
    // null hMod and zero threadId install desktop-wide low-level hooks without module injection.
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

    s_instance.store(nullptr);
    qCDebug(logFill) << "hooks removed";
}

LRESULT CALLBACK FillController::mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    // load once; cancellation may clear the singleton between separate loads.
    auto* self = s_instance.load();
    if (nCode >= 0 && self && wParam == WM_LBUTTONDOWN)
    {
        bool ctrlDown = (GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0;
        State curState = self->m_State.load();

        if (ctrlDown && curState == State::Armed)
        {
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);

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

            // defer beyond the OS hook dispatcher so credential work does not stall
            // all desktop input or reenter the controller from a hook callback.
            QMetaObject::invokeMethod(self, "performType", Qt::QueuedConnection);

            // swallow ctrl+click to prevent activation of the target control.
            return 1;
        }

        if (ctrlDown && curState == State::Diagnose)
        {
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);
            qCInfo(logFill) << "Ctrl+Click detected: diagnose dry-run";
            QMetaObject::invokeMethod(self, "performDiagnose", Qt::QueuedConnection);
            return 1;
        }

        if (!ctrlDown && curState == State::AutoArmed)
        {
            auto* mhs = reinterpret_cast<MSLLHOOKSTRUCT*>(lParam);
            // reject SendInput clicks from local processes before releasing staged secrets.
            if ((mhs->flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED)) != 0)
            {
                return CallNextHookEx(nullptr, nCode, wParam, lParam);
            }
            self->m_ClickX.store(mhs->pt.x);
            self->m_ClickY.store(mhs->pt.y);
            self->m_PendingTarget.store(TypeTarget::Auto);
            QMetaObject::invokeMethod(self, "performTypeAuto", Qt::QueuedConnection);
            // pass plain clicks through so the target field receives focus.
            return CallNextHookEx(nullptr, nCode, wParam, lParam);
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

LRESULT CALLBACK FillController::keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    auto* self = s_instance.load();
    if (nCode >= 0 && self && wParam == WM_KEYDOWN)
    {
        auto* khs = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);

        // esc cannot interrupt Typing once keystrokes are in flight.
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

    // wait up to 2 s to avoid ctrl shortcuts; proceed after the cap even if ctrl stays down.
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
                return;  // keep polling - ctrl not yet released.

            poll->stop();
            poll->deleteLater();

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

            // classify the clicked field once; an Auto target takes the field from the verdict.
            const seal::Verdict verdict = runProbeRegistry(m_ClickX.load(), m_ClickY.load());
            TypeTarget target = pendingTarget;
            if (target == TypeTarget::Auto)
            {
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

            // check generation before dereferencing the borrowed record.
            if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
            {
                qCWarning(logFill)
                    << "performType: records generation changed (" << m_SnapshotGeneration << " -> "
                    << *m_OwnerGeneration << ") - cancelling";
                emit fillError(QStringLiteral("Credential data was modified while fill was armed"));
                cancel();
                return;
            }

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

            // the record choice and the physical ctrl+click authorize this release.
            qCInfo(logFill).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=fill.manual.release", "result=ok"}));

            decryptAndTypeField(record, target);
        });
    poll->start();
}

void FillController::decryptAndTypeField(const seal::VaultRecord& record, TypeTarget target)
{
    // callers have already validated the record and release gates.
    seal::DecryptedCredential cred;
    try
    {
        // re-protect the master key before typing.
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

    // SendInput traverses global hooks; third-party keyloggers can observe the credential.
    qCDebug(logFill) << "decryptAndTypeField: note - keystrokes pass through global hook chain";

    bool success = false;
    if (target == TypeTarget::Username)
        success = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);
    else
        success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);

    // cleanse removes plaintext. working-set trimming cannot clear locked pages.
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

    if (target == TypeTarget::Username)
        m_TypedFields |= TypedUsername;
    else
        m_TypedFields |= TypedPassword;

    qCInfo(logFill) << "fill: " << (target == TypeTarget::Username ? "username" : "password")
                    << "typed for" << service << "(typedFields=" << m_TypedFields << ")";

    const bool complete = (m_TypedFields == TypedBoth) || m_AutoMode.load();
    if (complete)
    {
        // keep seal minimized after success so the filled application retains focus.
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

    if (m_AutoFillInFlight.exchange(true))
        return;

    // poll without blocking the GUI while the asynchronous click report arrives.
    auto* poll = new QTimer(this);
    poll->setInterval(20);
    connect(
        poll,
        &QTimer::timeout,
        this,
        [this, poll, elapsedMs = 0]() mutable
        {
            elapsedMs += 20;

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

            if (!entry.has_value())
            {
                if (elapsedMs < kAutoBridgeWaitMs)
                    return;  // keep waiting for the async report.
                poll->stop();
                poll->deleteLater();
                qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.release", "result=blocked", "reason=no_bridge_entry"}));
                m_AutoFillInFlight.store(false);
                return;  // silent no-op; stay AutoArmed for a real login click.
            }

            poll->stop();
            poll->deleteLater();

            // SendInput follows focus; require the click and foreground windows to
            // belong to the validated browser before decrypt.
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
                return;  // stay AutoArmed; no secret released.
            }

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

            // require both document tokens to be present and equal before decrypt.
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

            if (m_OwnerGeneration && *m_OwnerGeneration != m_SnapshotGeneration)
            {
                emit fillError(QStringLiteral("Credential data was modified while fill was armed"));
                cancel();
                return;
            }

            // M5: require an on-disk tier-1 corroborator. UIA reads the same DOM password
            // property, so it resists a lying extension but cannot establish page trust.
            // the strict host gate prevents wrong-site release.
            transitionTo(State::Typing);
            const seal::FusionOutcome outcome =
                runProbeRegistryDetailed(clickPoint.x, clickPoint.y);
            if (outcome.m_Verdict == seal::Verdict::Unknown ||
                !(outcome.m_Tier1ShortCircuit && outcome.m_BridgeCorroborated))
            {
                qCInfo(logFill).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=fill.autostage.release", "result=blocked", "reason=weak_fusion"}));

                m_AutoFillInFlight.store(false);
                m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
                emit countdownSecondsChanged();
                transitionTo(State::AutoArmed);
                m_TimeoutTimer.start();
                return;
            }

            // ignore Username verdicts; the extension owns username injection for this visit.
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

    // diagnose has no ctrl-release wait; give a connected bridge 75 ms to report, then retry.
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

    // the popup renders this free-form text as preformatted output.
    QString summary;
    summary += QStringLiteral("Fused verdict: %1\n").arg(verdictText(verdict));
    summary += QStringLiteral("Click point: (%1, %2)\n").arg(clickPoint.x).arg(clickPoint.y);
    summary += QStringLiteral("Target window PID: %1\n").arg(ctx.m_TargetProcessId);

    // distinguish disconnected peers from empty or nonmatching click reports.
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

    // the user-requested popup may show the host; logs still use redaction.
    if (ctx.m_TargetProcessId != 0)
    {
        const auto entry = m_BrowserBridge.lookup(ctx.m_TargetProcessId, clickPoint);
        if (entry.has_value() && !entry->m_UrlHost.isEmpty())
        {
            summary += QStringLiteral("\nBridge URL host: %1\n").arg(entry->m_UrlHost);
        }
    }

    // log raw coordinates for report/lookup correlation, but redact the host.
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
