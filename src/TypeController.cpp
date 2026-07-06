#ifdef USE_QT_UI

#include "TypeController.hpp"

#include "AsyncRunner.hpp"
#include "Clipboard.hpp"
#include "CredentialSession.hpp"
#include "Cryptography.hpp"
#include "Diagnostics.hpp"
#include "FillController.hpp"
#include "Logging.hpp"
#include "Vault.hpp"

#include <QtCore/QString>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <windows.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>

namespace seal
{

// Settle delays between username keystrokes, Tab, and password keystrokes.
constexpr DWORD kFieldSettleDelayMs = 200;   // Wait for target field to process username
constexpr DWORD kTabKeySettleDelayMs = 100;  // Wait for Tab to advance focus

// Decrypt a record's credential on demand, logging a mode-tagged failure line.
// Returns false (leaving `cred` empty) on any decrypt error. Shared preamble
// for doTypeLogin/doTypePassword; `modeField` is the literal "mode=login" or
// "mode=password" token.
static bool decryptForType(
    const seal::VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw,
    const char* modeField,
    seal::DecryptedCredential& cred)
{
    try
    {
        cred = seal::decryptCredentialOnDemand(record, masterPw);
        return true;
    }
    catch (const std::exception& e)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.type.decrypt.fail", modeField, seal::diag::errorFields(e.what())}));
        return false;
    }
    catch (...)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=fill.type.decrypt.fail", modeField, "reason=unknown"}));
        return false;
    }
}

// Types username + Tab + password into the focused window. Works on
// snapshots so the worker never touches the controller's shared state.
static bool doTypeLogin(
    const seal::VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    seal::DecryptedCredential cred;
    if (!decryptForType(record, masterPw, "mode=login", cred))
    {
        return false;
    }

    bool success1 = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);

    if (!success1)
    {
        cred.cleanse();
        return false;
    }

    // Let the target field register the username before Tab.
    Sleep(kFieldSettleDelayMs);

    // Tab down + up via SendInput; injects hardware-level events that work
    // even on apps that ignore WM_CHAR.
    INPUT tabInput[2] = {};
    tabInput[0].type = INPUT_KEYBOARD;
    tabInput[0].ki.wVk = VK_TAB;
    tabInput[1].type = INPUT_KEYBOARD;
    tabInput[1].ki.wVk = VK_TAB;
    tabInput[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, tabInput, sizeof(INPUT));
    Sleep(kTabKeySettleDelayMs);

    const bool success2 = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);
    cred.cleanse();
    return success2;
}

// Types only the password into the focused window. Same snapshot
// discipline as doTypeLogin so the worker stays off the controller's state.
static bool doTypePassword(
    const seal::VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    seal::DecryptedCredential cred;
    if (!decryptForType(record, masterPw, "mode=password", cred))
    {
        return false;
    }

    const bool success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);
    cred.cleanse();
    return success;
}

TypeController::TypeController(seal::CredentialWorkspace& workspace,
                               seal::IUiFeedback& ui,
                               seal::IPasswordGate& gate,
                               seal::FillController& engine,
                               seal::AsyncRunner& asyncRunner,
                               QObject* parent)
    : QObject(parent),
      m_Workspace(workspace),
      m_Ui(ui),
      m_Gate(gate),
      m_Engine(engine),
      m_Async(asyncRunner)
{
    // Relay FillController state to QML so the UI can react to fill progress.
    connect(&m_Engine, &FillController::armedChanged, this, &TypeController::fillArmedChanged);
    connect(&m_Engine,
            &FillController::fillStatusTextChanged,
            this,
            &TypeController::fillStatusTextChanged);
    connect(&m_Engine,
            &FillController::countdownSecondsChanged,
            this,
            &TypeController::fillCountdownSecondsChanged);

    // Fill complete/cancel: stay minimized so seal doesn't steal focus from
    // the target app. Only restore on error so the user sees what went wrong.
    connect(&m_Engine,
            &FillController::fillCompleted,
            this,
            [this](const QString& msg) { m_Ui.setStatus(msg); });
    connect(&m_Engine,
            &FillController::fillError,
            this,
            [this](const QString& msg)
            {
                emit errorOccurred("Fill Error", msg);
                m_Ui.setStatus("Fill failed");
                for (QWindow* w : QGuiApplication::topLevelWindows())
                {
                    w->showNormal();
                    w->raise();
                    w->requestActivate();
                }
            });
    connect(&m_Engine,
            &FillController::fillCancelled,
            this,
            [this]() { m_Ui.setStatus("Fill cancelled"); });
}

bool TypeController::isFillArmed() const
{
    return m_Engine.isArmed();
}

QString TypeController::fillStatusText() const
{
    return m_Engine.fillStatusText();
}

int TypeController::fillCountdownSeconds() const
{
    return m_Engine.countdownSeconds();
}

void TypeController::typeLogin(int index)
{
    if (index < 0 || index >= (int)m_Workspace.records().size())
        return;
    if (!m_Gate.ensurePassword([this, index]() { typeLogin(index); }))
    {
        return;
    }
    if (m_Ui.isBusy() || m_Engine.isArmed())
        return;

    scheduleTypingAction(index, TypingMode::Login, "Login");
}

void TypeController::typePassword(int index)
{
    if (index < 0 || index >= (int)m_Workspace.records().size())
        return;
    if (!m_Gate.ensurePassword([this, index]() { typePassword(index); }))
    {
        return;
    }
    if (m_Ui.isBusy() || m_Engine.isArmed())
        return;

    scheduleTypingAction(index, TypingMode::Password, "Password");
}

void TypeController::scheduleTypingAction(int index, TypingMode mode, const QString& label)
{
    // Callers (typeLogin, typePassword) early-return on isBusy(); no
    // overlapping timers can reach this point.
    Q_ASSERT(!m_Ui.isBusy());
    m_Ui.setBusy(true);

    const std::string opId =
        seal::diag::nextOpId(mode == TypingMode::Login ? "fill_type_login" : "fill_type_password");
    const auto started = std::chrono::steady_clock::now();
    const char* modeToken = mode == TypingMode::Login ? "login" : "password";
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.type.begin",
                                "result=start",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("mode", modeToken),
                                seal::diag::kv("index", index),
                                "countdown_s=3"}));

    // 3 s countdown lets the user focus the target field before
    // keystrokes start arriving.
    int remaining = 3;
    m_Ui.setCountdown(QString("Typing in %1...").arg(remaining));

    auto* timer = new QTimer(this);
    timer->setInterval(1000);

    connect(
        timer,
        &QTimer::timeout,
        this,
        [this, timer, index, mode, label, remaining, opId, started, modeToken]() mutable
        {
            remaining--;
            if (remaining > 0)
            {
                m_Ui.setCountdown(QString("Typing in %1...").arg(remaining));
            }
            else
            {
                timer->stop();
                timer->deleteLater();

                if (index < 0 || index >= (int)m_Workspace.records().size())
                {
                    qCWarning(logBackend).noquote()
                        << QString::fromStdString(seal::diag::joinFields(
                               {"event=fill.type.finish",
                                "result=fail",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("mode", modeToken),
                                "reason=record_missing",
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                    m_Ui.setCountdown(QString());
                    m_Ui.setBusy(false);
                    return;
                }

                m_Ui.setCountdown("Typing...");

                QString service = QString::fromUtf8(m_Workspace.records()[index].platform.c_str());

                // Run typing on a worker so the GUI loop stays responsive across the
                // Sleep()s between keystrokes. Snapshot record + password into the
                // worker's captures (the GUI thread may mutate them meanwhile); the
                // clone is taken in a tight unlock() window. basic_secure_string is move-only.
                auto record = m_Workspace.records()[index];
                seal::basic_secure_string<wchar_t> clonedPw;
                {
                    auto access = m_Workspace.session().unlock();
                    if (!access.ok())
                    {
                        qCWarning(logBackend).noquote()
                            << QString::fromStdString(seal::diag::joinFields(
                                   {"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
                        m_Ui.setStatus(QStringLiteral("Could not access the master key."));
                        m_Ui.setCountdown(QString());
                        m_Ui.setBusy(false);
                        return;
                    }
                    clonedPw.assign(access.password().begin(), access.password().end());
                }

                // shared_ptr so the work body is copyable (QtConcurrent::run decay-copies
                // the callable); the secret bytes stay in the locked buffer. The clone was
                // taken inside the GUI-thread session().unlock() window above.
                using SecureWide =
                    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;
                auto pw = std::make_shared<SecureWide>(std::move(clonedPw));

                m_Async.run(
                    this,
                    [pw, record, mode]() -> bool
                    {
                        const bool ok = (mode == TypingMode::Login) ? doTypeLogin(record, *pw)
                                                                    : doTypePassword(record, *pw);
                        seal::Cryptography::cleanseString(*pw);
                        return ok;
                    },
                    [this, label, service, opId, started, modeToken](bool ok)
                    {
                        m_Ui.setCountdown(QString());
                        m_Ui.setBusy(false);
                        if (ok)
                        {
                            qCInfo(logBackend).noquote()
                                << QString::fromStdString(seal::diag::joinFields(
                                       {"event=fill.type.finish",
                                        "result=ok",
                                        seal::diag::kv("op", opId),
                                        seal::diag::kv("mode", modeToken),
                                        seal::diag::kv("service_len", service.size()),
                                        seal::diag::kv("duration_ms",
                                                       seal::diag::elapsedMs(started))}));
                        }
                        else
                        {
                            qCWarning(logBackend).noquote()
                                << QString::fromStdString(seal::diag::joinFields(
                                       {"event=fill.type.finish",
                                        "result=fail",
                                        seal::diag::kv("op", opId),
                                        seal::diag::kv("mode", modeToken),
                                        "reason=type_sequence_failed",
                                        seal::diag::kv("duration_ms",
                                                       seal::diag::elapsedMs(started))}));
                            m_Ui.setStatus(QString("%1 typing failed").arg(label));
                            return;
                        }
                        m_Ui.setStatus(QString("%1 typed for '%2'").arg(label, service));
                    });
            }
        });

    timer->start();
}

void TypeController::doArm(int index)
{
    if (index < 0 || index >= (int)m_Workspace.records().size())
        return;
    if (m_Ui.isBusy())
        return;

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.arm.begin", seal::diag::kv("index", index)}));

    // The session stays DPAPI-protected while armed: arm() borrows the session
    // and performType() opens its own scoped unlock() only around the on-demand
    // decrypt, so the master key is plaintext for the decrypt instant rather
    // than the entire armed window.
    bool armed =
        m_Engine.arm(index, m_Workspace.records(), m_Workspace.session(), m_Workspace.generation());
    if (!armed)
    {
        qCWarning(logBackend).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=fill.arm.finish",
                                                              "result=fail",
                                                              seal::diag::kv("index", index),
                                                              "reason=controller_rejected"}));
        return;
    }
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.arm.finish",
                                "result=ok",
                                seal::diag::kv("index", index),
                                seal::diag::kv("generation", m_Workspace.generation())}));
    m_Ui.setStatus("Fill armed - Ctrl+Click target field");

    // Minimize so the target app is visible/clickable. Stays minimized
    // after complete/cancel; restored only on error.
    for (QWindow* w : QGuiApplication::topLevelWindows())
    {
        if (w->isVisible())
        {
            w->showMinimized();
        }
    }
}

void TypeController::armFor(int recordIndex)
{
    if (!m_Gate.ensurePassword([this, recordIndex]() { doArm(recordIndex); }))
    {
        return;
    }
    doArm(recordIndex);
}

void TypeController::cancelFill()
{
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.cancel.request"}));
    m_Engine.cancel();
}

void TypeController::cancelIfArmed()
{
    if (m_Engine.isArmed())
    {
        m_Engine.cancel();
    }
}

}  // namespace seal

#endif  // USE_QT_UI
