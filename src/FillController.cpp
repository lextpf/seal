#ifdef USE_QT_UI

#include "FillController.h"
#include "Clipboard.h"
#include "Logging.h"

#include <QtCore/QThread>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <memory>

namespace seal
{

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
    State s = m_State.load();
    return s == State::ArmedUsername || s == State::ArmedPassword;
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
        case FillController::State::ArmedUsername:
            return "ArmedUsername";
        case FillController::State::ArmedPassword:
            return "ArmedPassword";
        case FillController::State::Typing:
            return "Typing";
    }
    return "Unknown";
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
    // not on every internal state change (e.g. ArmedUsername -> ArmedPassword).
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
        case State::ArmedUsername:
            m_StatusText = QStringLiteral("Ctrl+Click to fill username");
            break;
        case State::ArmedPassword:
            m_StatusText = QStringLiteral("Ctrl+Click to fill password");
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
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    // If already armed (e.g. user clicked a different record), tear down
    // the previous session before starting a new one.
    if (m_State.load() != State::Idle)
        cancel();

    // Borrow pointers - the caller (Backend) owns these and must
    // keep them alive until fillCompleted / fillCancelled / fillError.
    // This is a borrowed-pointer contract: Backend owns the records vector
    // and the master password; we never copy or free them. If Backend is
    // destroyed before the fill finishes, these dangle - hence the guard
    // in cancel() and the destructor.
    m_RecordIndex = recordIndex;
    m_Records = &records;
    m_MasterPw = &masterPw;
    m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
    m_PendingTarget.store(TypeTarget::Username);

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

    transitionTo(State::ArmedUsername);

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

    // Clear borrowed pointers so we don't dangle.
    m_RecordIndex = -1;
    m_Records = nullptr;
    m_MasterPw = nullptr;
    m_RemainingSeconds = 0;
    emit countdownSecondsChanged();
    emit fillCancelled();
}

void FillController::onTimeoutTick()
{
    // Don't tick while idle or mid-type - the timer should already be
    // stopped in those states, but guard defensively.
    State curState = m_State.load();
    if (curState == State::Idle || curState == State::Typing)
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

        if (ctrlDown && (curState == State::ArmedUsername || curState == State::ArmedPassword))
        {
            // Modifier key overrides let the user re-fill a field without
            // re-arming: Shift forces password, Alt forces username.
            // Without either modifier, follow the natural armed state.
            bool shiftDown = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            bool altDown = (GetAsyncKeyState(VK_MENU) & 0x8000) != 0;

            TypeTarget target;
            if (shiftDown)
            {
                target = TypeTarget::Password;
            }
            else if (altDown)
            {
                target = TypeTarget::Username;
            }
            else
            {
                target = (curState == State::ArmedUsername) ? TypeTarget::Username
                                                            : TypeTarget::Password;
            }

            self->m_PendingTarget.store(target);
            qCInfo(logFill) << "Ctrl+Click detected: target="
                            << (target == TypeTarget::Username ? "username" : "password");

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
        State curState = self->m_State.load();
        if (khs->vkCode == VK_ESCAPE &&
            (curState == State::ArmedUsername || curState == State::ArmedPassword))
        {
            QMetaObject::invokeMethod(self, "cancel", Qt::QueuedConnection);
            return 1;
        }
    }
    return CallNextHookEx(nullptr, nCode, wParam, lParam);
}

void FillController::performType()
{
    State curState = m_State.load();
    if (curState != State::ArmedUsername && curState != State::ArmedPassword)
        return;

    TypeTarget target = m_PendingTarget.load();
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
    connect(poll,
            &QTimer::timeout,
            this,
            [this, target, poll, elapsedMs = 0]() mutable
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
                {
                    success = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);
                }
                else
                {
                    success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);
                }

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

                if (target == TypeTarget::Username)
                {
                    qCInfo(logFill) << "performType: username typed for" << service;
                    // Username typed - reset the countdown and transition to
                    // ArmedPassword so the user can Ctrl+Click the password field.
                    m_RemainingSeconds = FILL_TIMEOUT_SECONDS;
                    emit countdownSecondsChanged();
                    transitionTo(State::ArmedPassword);
                    m_TimeoutTimer.start();
                }
                else
                {
                    qCInfo(logFill) << "performType: password typed for" << service;
                    // Password typed - both phases complete. Tear down hooks and
                    // notify the backend so it can restore the window.
                    m_TimeoutTimer.stop();
                    removeHooks();
                    transitionTo(State::Idle);
                    m_RecordIndex = -1;
                    m_Records = nullptr;
                    m_MasterPw = nullptr;
                    m_RemainingSeconds = 0;
                    emit countdownSecondsChanged();
                    emit fillCompleted(QString("Filled credentials for '%1'").arg(service));
                }
            });
    poll->start();
}

}  // namespace seal

#endif  // USE_QT_UI
