#ifdef USE_QT_UI

#include "Backend.hpp"

#include "CliDispatch.hpp"
#include "CliHandler.hpp"
#include "Clipboard.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "FillController.hpp"
#include "Logging.hpp"
#include "NativeDialogs.hpp"
#include "QrCapture.hpp"
#include "ScopedDpapiUnprotect.hpp"
#include "Utils.hpp"
#include "VaultModel.hpp"
#include "WindowChrome.hpp"
#include "WindowController.hpp"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QString>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

// Concrete alias used throughout this file.
using ScopedDpapiUnprotect =
    seal::ScopedDpapiUnprotect<seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>>;

namespace seal
{

basic_secure_string<wchar_t, locked_allocator<wchar_t>> Backend::qstringToSecureWide(
    const QString& qstr)
{
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> result;
    if (qstr.isEmpty())
        return result;

    // Copy directly from the QString internal buffer into locked (non-pageable)
    // memory, avoiding the intermediate heap-allocated std::wstring that
    // toStdWString() would create. On Windows sizeof(wchar_t) == sizeof(QChar).
    static_assert(sizeof(wchar_t) == sizeof(QChar), "wchar_t/QChar size mismatch");
    const auto* src = reinterpret_cast<const wchar_t*>(qstr.data());
    result.s.assign(src, src + qstr.size());
    return result;
}

Backend::Backend(QObject* parent)
    : QObject(parent),
      m_Model(new VaultListModel(this)),
      m_FillController(new FillController(this)),
      m_WindowController(new WindowController(this))
{
    m_Model->setRecords(&m_Records, &m_RecordsGeneration);

    // Relay WindowController state to QML.
    connect(m_WindowController,
            &WindowController::alwaysOnTopChanged,
            this,
            &Backend::alwaysOnTopChanged);
    connect(m_WindowController, &WindowController::compactChanged, this, &Backend::compactChanged);

    // Relay FillController state to QML so the UI can react to fill progress.
    connect(m_FillController, &FillController::armedChanged, this, &Backend::fillArmedChanged);
    connect(m_FillController,
            &FillController::fillStatusTextChanged,
            this,
            &Backend::fillStatusTextChanged);
    connect(m_FillController,
            &FillController::countdownSecondsChanged,
            this,
            &Backend::fillCountdownSecondsChanged);

    // Fill complete/cancel: stay minimized so seal doesn't steal focus from
    // the app the user fills credentials into. Only restore on error
    // so the user can see what went wrong.
    connect(m_FillController,
            &FillController::fillCompleted,
            this,
            [this](const QString& msg)
            {
                m_DPAPIGuard.reprotect();
                setStatus(msg);
            });
    connect(m_FillController,
            &FillController::fillError,
            this,
            [this](const QString& msg)
            {
                m_DPAPIGuard.reprotect();
                emit errorOccurred("Fill Error", msg);
                setStatus("Fill failed");
                for (QWindow* w : QGuiApplication::topLevelWindows())
                {
                    w->showNormal();
                    w->raise();
                    w->requestActivate();
                }
            });
    connect(m_FillController,
            &FillController::fillCancelled,
            this,
            [this]()
            {
                m_DPAPIGuard.reprotect();
                setStatus("Fill cancelled");
            });
}

Backend::~Backend()
{
    try
    {
        cleanup();
    }
    catch (...)
    {
    }
}

VaultListModel* Backend::vaultModel() const
{
    return m_Model;
}

bool Backend::vaultLoaded() const
{
    return !m_CurrentVaultPath.isEmpty() || !m_Records.empty();
}

QString Backend::vaultFileName() const
{
    if (m_CurrentVaultPath.isEmpty())
        return {};
    return QFileInfo(m_CurrentVaultPath).fileName();
}

bool Backend::hasSelection() const
{
    return m_SelectedIndex >= 0;
}

int Backend::selectedIndex() const
{
    return m_SelectedIndex;
}

void Backend::setSelectedIndex(int index)
{
    if (m_SelectedIndex == index)
        return;
    m_SelectedIndex = index;
    emit selectionChanged();
}

QString Backend::statusText() const
{
    return m_StatusText;
}

bool Backend::isPasswordSet() const
{
    return m_PasswordSet;
}

QString Backend::searchFilter() const
{
    return m_SearchFilter;
}

void Backend::setSearchFilter(const QString& filter)
{
    if (m_SearchFilter == filter)
        return;
    m_SearchFilter = filter;
    m_Model->setFilter(filter);
    emit searchFilterChanged();
}

QString Backend::countdownText() const
{
    return m_CountdownText;
}

bool Backend::isBusy() const
{
    return m_Busy;
}

// Fill state is delegated entirely to the controller.
bool Backend::isFillArmed() const
{
    return m_FillController->isArmed();
}
QString Backend::fillStatusText() const
{
    return m_FillController->fillStatusText();
}
int Backend::fillCountdownSeconds() const
{
    return m_FillController->countdownSeconds();
}

bool Backend::ensurePassword()
{
    if (m_PasswordSet)
        return true;

    // Signal the QML layer to show the password dialog.
    // The caller should have already stashed a lambda in m_PendingAction
    // so submitPassword() can resume the operation once the user enters it.
    emit passwordRequired();
    return false;
}

void Backend::submitPassword(QString password)
{
    auto wide = qstringToSecureWide(password);
    // Wipe the input QString to reduce plaintext residency in pageable memory.
    password.fill(QChar(0));
    m_Password = std::move(wide);
    // Wrap the password in a DPAPI guard: when "protected", the memory is
    // encrypted in-place by the OS, making it unreadable even if the process
    // memory is dumped.
    m_DPAPIGuard = seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>(&m_Password);
    m_PasswordSet = true;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=auth.password.set",
                                "result=ok",
                                "source=manual_entry",
                                seal::diag::kv("pending_action", m_PendingAction != nullptr)}));
    setStatus("Password set");
    emit passwordSetChanged();

    // Resume the action that was waiting for a password (e.g. loadVault, addAccount).
    // The pending-action pattern: callers stash a lambda in m_PendingAction
    // before triggering the password dialog.
    if (m_PendingAction)
    {
        auto action = std::move(m_PendingAction);
        m_PendingAction = nullptr;
        action();
    }
}

void Backend::requestQrCapture()
{
    const std::string opId = seal::diag::nextOpId("qr_capture");
    const auto started = std::chrono::steady_clock::now();

    // If a QR capture is already running, don't start another one.
    if (m_QrThread && m_QrThread->isRunning())
    {
        qCWarning(logBackend).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=qr.capture.skip",
                                                              "result=skip",
                                                              seal::diag::kv("op", opId),
                                                              "reason=already_in_progress"}));
        return;
    }

    // AllowSetForegroundWindow(ASFW_ANY) grants any process permission to
    // steal foreground focus. Without this, the QR scanner's OpenCV window
    // would open behind our window because Windows blocks background
    // processes from taking the foreground.
    AllowSetForegroundWindow(ASFW_ANY);

    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=qr.capture.begin", "result=start", seal::diag::kv("op", opId), "worker=true"}));

    // Run the blocking OpenCV capture on a worker thread so the Qt event
    // loop stays responsive. captureQrFromWebcam() can block for up to
    // 60 seconds (capture timeout); doing that on the GUI thread would
    // freeze the entire UI.
    m_QrThread = QThread::create(
        [this, opId, started]()
        {
            seal::secure_string<> qrResult = seal::captureQrFromWebcam();

            // Deliver the result back to the GUI thread via a queued invocation
            // so all signal emissions happen on the correct thread.
            QMetaObject::invokeMethod(
                this,
                [this, opId, started, result = std::move(qrResult)]() mutable
                {
                    if (result.empty())
                    {
                        qCWarning(logBackend).noquote()
                            << QString::fromStdString(seal::diag::joinFields(
                                   {"event=qr.capture.finish",
                                    "result=fail",
                                    seal::diag::kv("op", opId),
                                    "reason=empty_or_cancelled",
                                    seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                                    seal::diag::kv("payload_len", 0)}));
                        setStatus("QR capture failed or cancelled");
                        emit qrCaptureFinished(false);
                        return;
                    }

                    // Convert the UTF-8 QR result to a QString for pre-filling the
                    // password dialog. Don't set m_Password yet - let the user confirm.
                    QString captured = QString::fromUtf8(result.data(), (int)result.size());
                    // result auto-wipes on scope exit

                    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                        {"event=qr.capture.finish",
                         "result=ok",
                         seal::diag::kv("op", opId),
                         seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                         seal::diag::kv("payload_len", captured.size()),
                         "confirmation_required=true"}));
                    setStatus("QR captured - confirm password");
                    emit qrCaptureFinished(true);

                    // Signal the QML layer to re-open the password dialog with the
                    // captured text pre-filled.
                    emit qrTextReady(captured);

                    // Wipe the local QString copy so the raw QR text doesn't linger
                    // on the heap after the signal delivers it to QML.
                    captured.fill(QChar(0));
                },
                Qt::QueuedConnection);
        });

    // Null out the member when the thread finishes so we know it's done.
    connect(m_QrThread,
            &QThread::finished,
            this,
            [this]()
            {
                m_QrThread->deleteLater();
                m_QrThread = nullptr;
            });
    m_QrThread->start();
}

void Backend::setStatus(const QString& text)
{
    if (m_StatusText == text)
        return;
    m_StatusText = text;
    emit statusTextChanged();
}

void Backend::refreshModel()
{
    m_Model->refresh();
    setSelectedIndex(-1);
}

void Backend::cancelFillIfArmed()
{
    if (m_FillController->isArmed())
    {
        m_FillController->cancel();
        m_DPAPIGuard.reprotect();
    }
}

void Backend::loadVaultFromPath(const QString& filePath, bool isAutoLoad)
{
    const std::string opId = seal::diag::nextOpId("vault_load");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = seal::diag::pathSummary(filePath.toUtf8().toStdString());

    // Cancel any active fill before replacing the records vector,
    // otherwise FillController's borrowed pointer to m_Records would dangle.
    cancelFillIfArmed();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.load.begin",
                                "result=start",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("auto", isAutoLoad),
                                pathMeta}));
    try
    {
        ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
        m_Records = seal::loadVaultIndex(filePath, m_Password);
        ++m_RecordsGeneration;
        m_CurrentVaultPath = filePath;
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.load.finish",
             "result=ok",
             seal::diag::kv("op", opId),
             seal::diag::kv("record_count", m_Records.size()),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
        refreshModel();
        if (isAutoLoad)
            setStatus(QString("Auto-loaded %1 account(s) from %2")
                          .arg(m_Records.size())
                          .arg(QFileInfo(filePath).fileName()));
        else
            setStatus(QString("Loaded %1 account(s) from vault").arg(m_Records.size()));
        emit vaultLoadedChanged();
        emit vaultFileNameChanged();
    }
    catch (const std::runtime_error& e)
    {
        if (std::string(e.what()) == "Wrong password")
        {
            // Wrong-password retry flow:
            // 1. Destroy the DPAPI guard and wipe the bad password.
            // 2. Clear passwordSet so the UI knows no valid key is loaded.
            // 3. Stash a lambda that re-attempts this same load once the
            //    user enters a new password (the pending-action pattern).
            // 4. Signal QML to re-show the password dialog with an error hint.
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=vault.load.finish",
                 "result=retry",
                 seal::diag::kv("op", opId),
                 "reason=wrong_password",
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
            m_DPAPIGuard = {};
            seal::Cryptography::cleanseString(m_Password);
            m_PasswordSet = false;
            emit passwordSetChanged();
            m_PendingAction = [this, filePath, isAutoLoad]()
            { loadVaultFromPath(filePath, isAutoLoad); };
            emit passwordRetryRequired("Wrong password - try again.");
            return;
        }
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.load.finish",
             "result=fail",
             seal::diag::kv("op", opId),
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
        emit errorOccurred("Error", QString("Failed to load vault: %1").arg(e.what()));
        setStatus("Failed to load vault");
    }
}

void Backend::loadVault()
{
    // Defer to password dialog if the master key isn't available yet.
    // The lambda captures `this` and re-invokes loadVault() once the
    // user supplies the password.
    if (!m_PasswordSet)
    {
        m_PendingAction = [this]() { loadVault(); };
        ensurePassword();
        return;
    }

    QString fileName =
        seal::OpenFileDialog("Load Vault File", "seal Vault (*.seal)|*.seal|All Files (*)|*.*|");
    if (fileName.isEmpty())
        return;

    loadVaultFromPath(fileName);
}

void Backend::saveVault()
{
    if (!m_PasswordSet)
    {
        m_PendingAction = [this]() { saveVault(); };
        ensurePassword();
        return;
    }

    // Re-use the existing path, or prompt for a new one on first save.
    QString fileName = m_CurrentVaultPath;
    if (fileName.isEmpty())
    {
        fileName = seal::SaveFileDialog("Save Vault File",
                                        "seal Vault (*.seal)|*.seal|All Files (*)|*.*|");
    }
    if (fileName.isEmpty())
        return;

    if (!fileName.endsWith(".seal", Qt::CaseInsensitive))
        fileName += ".seal";

    const std::string opId = seal::diag::nextOpId("vault_save");
    const auto started = std::chrono::steady_clock::now();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.save.begin",
                                "result=start",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("record_count", m_Records.size()),
                                seal::diag::pathSummary(fileName.toUtf8().toStdString())}));
    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    bool saveOk = seal::saveVaultV2(fileName, m_Records, m_Password);
    if (saveOk)
    {
        m_CurrentVaultPath = fileName;

        // Clear dirty flags and purge soft-deleted records now that
        // they've been committed to disk.
        for (auto& rec : m_Records)
            rec.dirty = false;
        cancelFillIfArmed();
        std::erase_if(m_Records, [](const seal::VaultRecord& r) { return r.deleted; });

        refreshModel();
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.save.finish",
             "result=ok",
             seal::diag::kv("op", opId),
             seal::diag::kv("record_count", m_Records.size()),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
        setStatus(QString("Saved %1 account(s) to vault").arg(m_Records.size()));
        emit vaultLoadedChanged();
        emit vaultFileNameChanged();
    }
    else
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.save.finish",
             "result=fail",
             seal::diag::kv("op", opId),
             "reason=save_failed",
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
        emit errorOccurred("Error", "Failed to save vault file");
        setStatus("Failed to save vault");
    }
}

void Backend::unloadVault()
{
    // Cancel any active fill before clearing records, otherwise
    // FillController's borrowed pointer to m_Records would dangle.
    cancelFillIfArmed();
    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=vault.unload", "result=ok", seal::diag::kv("record_count", m_Records.size())}));
    m_Records.clear();
    ++m_RecordsGeneration;
    m_CurrentVaultPath.clear();
    refreshModel();
    setStatus("Vault unloaded");
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
}

void Backend::addAccount(const QString& service, const QString& username, const QString& password)
{
    if (service.isEmpty() || username.isEmpty() || password.isEmpty())
    {
        emit errorOccurred("Warning", "All fields are required");
        return;
    }

    if (!m_PasswordSet)
    {
        // Convert credentials to locked-page memory before capture so
        // plaintext doesn't sit in pageable heap while the password dialog
        // is open. shared_ptr makes the lambda copyable (std::function
        // requires it) while keeping the secret in a single locked allocation.
        auto secUser =
            std::make_shared<seal::basic_secure_string<wchar_t>>(qstringToSecureWide(username));
        auto secPass =
            std::make_shared<seal::basic_secure_string<wchar_t>>(qstringToSecureWide(password));
        m_PendingAction = [this, service, secUser, secPass]()
        {
            // Encrypt directly from locked memory - no round-trip through
            // pageable QString.  The shared_ptrs keep the secure strings
            // alive across the std::function copy boundary.
            cancelFillIfArmed();
            ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
            seal::VaultRecord newRecord = seal::encryptCredential(
                service.toUtf8().toStdString(), *secUser, *secPass, m_Password);
            seal::Cryptography::cleanseString(*secUser, *secPass);
            m_Records.push_back(std::move(newRecord));
            ++m_RecordsGeneration;
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=vault.record.add",
                                        "result=ok",
                                        "deferred=true",
                                        seal::diag::kv("total_records", m_Records.size()),
                                        seal::diag::kv("service_len", service.size())}));
            refreshModel();
            setStatus("Account added");
            emit vaultLoadedChanged();
            emit vaultFileNameChanged();
        };
        ensurePassword();
        return;
    }

    // Convert to locked-page wide strings so plaintext doesn't sit in
    // pageable memory any longer than necessary.
    auto secUsername = qstringToSecureWide(username);
    auto secPassword = qstringToSecureWide(password);

    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    seal::VaultRecord newRecord = seal::encryptCredential(
        service.toUtf8().toStdString(), secUsername, secPassword, m_Password);

    seal::Cryptography::cleanseString(secUsername, secPassword);

    cancelFillIfArmed();
    m_Records.push_back(std::move(newRecord));
    ++m_RecordsGeneration;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.add",
                                "result=ok",
                                "deferred=false",
                                seal::diag::kv("total_records", m_Records.size()),
                                seal::diag::kv("service_len", service.size())}));
    refreshModel();
    setStatus("Account added");
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
}

void Backend::editAccount(int index,
                          const QString& service,
                          const QString& username,
                          const QString& password)
{
    if (index < 0 || index >= (int)m_Records.size())
        return;

    if (service.isEmpty() || username.isEmpty() || password.isEmpty())
    {
        emit errorOccurred("Warning", "All fields are required");
        return;
    }

    if (!m_PasswordSet)
    {
        // Capture only the index (not username/password) to avoid holding
        // plaintext credentials in pageable heap memory. After the master
        // password is entered, re-decrypt and re-show the edit dialog so
        // the user can re-enter their changes.
        m_PendingAction = [this, index]()
        {
            QVariantMap data = decryptAccountForEdit(index);
            if (!data.isEmpty())
                emit editAccountReady(data);
        };
        ensurePassword();
        return;
    }

    auto secUsername = qstringToSecureWide(username);
    auto secPassword = qstringToSecureWide(password);

    // Replace the record entirely - re-encrypt with a fresh salt/IV.
    cancelFillIfArmed();
    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    m_Records[index] = seal::encryptCredential(
        service.toUtf8().toStdString(), secUsername, secPassword, m_Password);
    ++m_RecordsGeneration;

    seal::Cryptography::cleanseString(secUsername, secPassword);

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.edit",
                                "result=ok",
                                seal::diag::kv("index", index),
                                seal::diag::kv("service_len", service.size())}));
    refreshModel();
    setStatus("Account updated");
}

void Backend::deleteAccount(int index)
{
    if (index < 0 || index >= (int)m_Records.size())
        return;

    // Soft-delete, flag the record so it's excluded from the model
    // immediately, but keep it around until saveVault() commits to disk.
    cancelFillIfArmed();
    m_Records[index].deleted = true;
    m_Records[index].dirty = true;
    ++m_RecordsGeneration;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.delete",
                                "result=ok",
                                "mode=soft_delete",
                                seal::diag::kv("index", index)}));
    refreshModel();
    setStatus("Account deleted");

    // If every record is now deleted, notify QML so it can show the
    // empty-vault state.
    bool anyVisible = false;
    for (const auto& rec : m_Records)
    {
        if (!rec.deleted)
        {
            anyVisible = true;
            break;
        }
    }
    if (!anyVisible)
    {
        emit vaultLoadedChanged();
        emit vaultFileNameChanged();
    }
}

QVariantMap Backend::decryptAccountForEdit(int index)
{
    qCDebug(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.edit_decrypt.request", seal::diag::kv("index", index)}));
    QVariantMap result;
    if (index < 0 || index >= (int)m_Records.size())
        return result;

    // If no password yet, defer the decrypt and deliver the result
    // asynchronously via editAccountReady once the user enters it.
    if (!m_PasswordSet)
    {
        m_PendingAction = [this, index]()
        {
            QVariantMap data;
            try
            {
                if (index < 0 || index >= static_cast<int>(m_Records.size()))
                {
                    qCWarning(logBackend).noquote() << QString::fromStdString(
                        seal::diag::joinFields({"event=credential.edit_decrypt.finish",
                                                "result=fail",
                                                "deferred=true",
                                                "reason=record_missing"}));
                    emit errorOccurred("Error", "Selected account no longer exists");
                    return;
                }

                const seal::VaultRecord& record = m_Records[index];
                ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
                seal::DecryptedCredential cred =
                    seal::decryptCredentialOnDemand(record, m_Password);
                data["service"] = QString::fromUtf8(record.platform.c_str());
                data["username"] =
                    QString::fromWCharArray(cred.username.data(), (int)cred.username.size());
                data["password"] =
                    QString::fromWCharArray(cred.password.data(), (int)cred.password.size());
                data["editIndex"] = index;
                cred.cleanse();
                emit editAccountReady(data);
                // Null-fill the QStrings so plaintext doesn't linger in
                // Qt's Copy-On-Write heap after the signal delivers copies to QML.
                data["username"] = QString();
                data["password"] = QString();
            }
            catch (const std::exception& e)
            {
                qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=credential.edit_decrypt.finish",
                     "result=fail",
                     "deferred=true",
                     seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                     seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
                emit errorOccurred("Error",
                                   QString("Failed to decrypt credential: %1").arg(e.what()));
            }
        };
        ensurePassword();
        return result;
    }

    try
    {
        // On-demand decrypt - credential blob stays encrypted at rest.
        const seal::VaultRecord& record = m_Records[index];
        ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
        seal::DecryptedCredential cred = seal::decryptCredentialOnDemand(record, m_Password);

        result["service"] = QString::fromUtf8(record.platform.c_str());
        result["username"] =
            QString::fromWCharArray(cred.username.data(), (int)cred.username.size());
        result["password"] =
            QString::fromWCharArray(cred.password.data(), (int)cred.password.size());

        cred.cleanse();
    }
    catch (const std::exception& e)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=credential.edit_decrypt.finish",
             "result=fail",
             "deferred=false",
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
        emit errorOccurred("Error", QString("Failed to decrypt credential: %1").arg(e.what()));
    }
    // Caller (Main.qml) copies username/password into dialog properties,
    // not wipeable, but short-lived. The dialog's onClosed handler
    // clears its own copies (see AccountDialog.qml).
    return result;
}

// Delays used in doTypeLogin to give the target application time to process
// input between the username keystrokes, the Tab key, and the password.
constexpr DWORD kFieldSettleDelayMs = 200;   // Wait for target field to process username
constexpr DWORD kTabKeySettleDelayMs = 100;  // Wait for Tab to advance focus

// Types username + tab + password into the currently focused window.
// Takes a snapshot of the record and password so the worker thread
// never touches Backend's shared state.
static bool doTypeLogin(
    const seal::VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    seal::DecryptedCredential cred;
    try
    {
        cred = seal::decryptCredentialOnDemand(record, masterPw);
    }
    catch (const std::exception& e)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.type.decrypt.fail",
             "mode=login",
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
        return false;
    }
    catch (...)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.type.decrypt.fail", "mode=login", "reason=unknown"}));
        return false;
    }

    bool success1 = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);

    if (!success1)
    {
        cred.cleanse();
        return false;
    }

    // Brief pause so the target field registers the username keystrokes
    // before we send Tab to advance to the password field.
    Sleep(kFieldSettleDelayMs);

    // Synthesize a Tab key-down + key-up via SendInput to move focus to
    // the password field. SendInput injects hardware-level events into the
    // input stream, which works even when the target app ignores WM_CHAR.
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

// Types only the password into the currently focused window.
// Takes a snapshot of the record and password so the worker thread
// never touches Backend's shared state.
static bool doTypePassword(
    const seal::VaultRecord& record,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    seal::DecryptedCredential cred;
    try
    {
        cred = seal::decryptCredentialOnDemand(record, masterPw);
    }
    catch (const std::exception& e)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.type.decrypt.fail",
             "mode=password",
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
        return false;
    }
    catch (...)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=fill.type.decrypt.fail", "mode=password", "reason=unknown"}));
        return false;
    }

    const bool success = seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);
    cred.cleanse();
    return success;
}

void Backend::typeLogin(int index)
{
    if (index < 0 || index >= (int)m_Records.size())
        return;
    if (!m_PasswordSet)
    {
        m_PendingAction = [this, index]() { typeLogin(index); };
        ensurePassword();
        return;
    }
    if (m_Busy || m_FillController->isArmed())
        return;

    scheduleTypingAction(index, TypingMode::Login, "Login");
}

void Backend::typePassword(int index)
{
    if (index < 0 || index >= (int)m_Records.size())
        return;
    if (!m_PasswordSet)
    {
        m_PendingAction = [this, index]() { typePassword(index); };
        ensurePassword();
        return;
    }
    if (m_Busy || m_FillController->isArmed())
        return;

    scheduleTypingAction(index, TypingMode::Password, "Password");
}

void Backend::scheduleTypingAction(int index, TypingMode mode, const QString& label)
{
    // Callers (typeLogin, typePassword) guard with `if (m_Busy) return;`
    // before reaching this point, so overlapping timers cannot occur.
    Q_ASSERT(!m_Busy);
    m_Busy = true;
    emit busyChanged();

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

    // 3-second countdown gives the user time to focus the target field
    // in the external application before keystrokes start arriving.
    int remaining = 3;
    m_CountdownText = QString("Typing in %1...").arg(remaining);
    emit countdownTextChanged();

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
                m_CountdownText = QString("Typing in %1...").arg(remaining);
                emit countdownTextChanged();
            }
            else
            {
                timer->stop();
                timer->deleteLater();

                if (index < 0 || index >= (int)m_Records.size())
                {
                    qCWarning(logBackend).noquote()
                        << QString::fromStdString(seal::diag::joinFields(
                               {"event=fill.type.finish",
                                "result=fail",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("mode", modeToken),
                                "reason=record_missing",
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                    m_CountdownText.clear();
                    emit countdownTextChanged();
                    m_Busy = false;
                    emit busyChanged();
                    return;
                }

                m_CountdownText = "Typing...";
                emit countdownTextChanged();

                QString service = QString::fromUtf8(m_Records[index].platform.c_str());

                // Run the blocking typing sequence on a worker thread so
                // the GUI event loop stays responsive during Sleep() calls
                // between username, Tab, and password keystrokes.
                //
                // Snapshot the record and password into the worker's captures
                // so the thread never touches m_Records or m_Password directly.
                // The GUI thread could process events that mutate those members
                // while the worker is running.
                m_DPAPIGuard.unprotect();
                try
                {
                    auto record = m_Records[index];
                    seal::basic_secure_string<wchar_t> pw;
                    pw.s.assign(m_Password.s.begin(), m_Password.s.end());
                    auto success = std::make_shared<std::atomic<bool>>(false);

                    auto* worker = QThread::create(
                        [record = std::move(record), pw = std::move(pw), mode, success]() mutable
                        {
                            bool ok = false;
                            if (mode == Backend::TypingMode::Login)
                                ok = doTypeLogin(record, pw);
                            else
                                ok = doTypePassword(record, pw);
                            success->store(ok, std::memory_order_release);
                            seal::Cryptography::cleanseString(pw);
                        });
                    connect(worker,
                            &QThread::finished,
                            this,
                            [this, worker, label, service, opId, started, modeToken, success]()
                            {
                                worker->deleteLater();
                                m_DPAPIGuard.reprotect();
                                m_CountdownText.clear();
                                emit countdownTextChanged();
                                m_Busy = false;
                                emit busyChanged();
                                const bool ok = success->load(std::memory_order_acquire);
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
                                    setStatus(QString("%1 typing failed").arg(label));
                                    return;
                                }
                                setStatus(QString("%1 typed for '%2'").arg(label, service));
                            });
                    worker->start();
                }
                catch (...)
                {
                    m_DPAPIGuard.reprotect();
                    throw;
                }
            }
        });

    timer->start();
}

void Backend::encryptDirectory()
{
    if (!m_PasswordSet)
    {
        m_PendingAction = [this]() { encryptDirectory(); };
        ensurePassword();
        return;
    }

    QString dirPath = seal::OpenFolderDialog("Select Directory to Encrypt");
    if (dirPath.isEmpty())
        return;

    const std::string opId = seal::diag::nextOpId("dir_encrypt");
    const auto started = std::chrono::steady_clock::now();
    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    int count = seal::encryptDirectory(dirPath, m_Password);
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=directory.encrypt.finish",
                                "result=ok",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("count", count),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                                seal::diag::pathSummary(dirPath.toUtf8().toStdString())}));
    setStatus(QString("Encrypted %1 file(s)").arg(count));
    emit infoMessage("Success", QString("Encrypted %1 file(s) in directory").arg(count));
}

void Backend::decryptDirectory()
{
    if (!m_PasswordSet)
    {
        m_PendingAction = [this]() { decryptDirectory(); };
        ensurePassword();
        return;
    }

    QString dirPath = seal::OpenFolderDialog("Select Directory to Decrypt");
    if (dirPath.isEmpty())
        return;

    const std::string opId = seal::diag::nextOpId("dir_decrypt");
    const auto started = std::chrono::steady_clock::now();
    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    int count = seal::decryptDirectory(dirPath, m_Password);
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=directory.decrypt.finish",
                                "result=ok",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("count", count),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                                seal::diag::pathSummary(dirPath.toUtf8().toStdString())}));
    setStatus(QString("Decrypted %1 file(s)").arg(count));
    emit infoMessage("Success", QString("Decrypted %1 file(s) in directory").arg(count));
}

void Backend::autoLoadVault()
{
    if (!m_CurrentVaultPath.isEmpty())
        return;

    // Search for a .seal vault file in well-known locations, in priority order:
    // 1. Next to the executable   2. Current working directory   3. Home directory
    QStringList searchPaths;
    searchPaths << QCoreApplication::applicationDirPath() << QDir::currentPath()
                << QDir::homePath();

    QString foundVaultPath;

    for (const QString& searchPath : searchPaths)
    {
        QDir dir(searchPath);
        QFileInfoList files = dir.entryInfoList(QStringList() << "*.seal", QDir::Files);

        if (!files.isEmpty())
            foundVaultPath = files.first().absoluteFilePath();
        if (!foundVaultPath.isEmpty())
            break;
    }

    if (foundVaultPath.isEmpty())
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=vault.autoload.scan",
                                    "result=none",
                                    seal::diag::kv("search_roots", searchPaths.size())}));
        return;
    }

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.autoload.scan",
                                "result=found",
                                seal::diag::kv("search_roots", searchPaths.size()),
                                seal::diag::pathSummary(foundVaultPath.toUtf8().toStdString())}));
    if (!m_PasswordSet)
    {
        // Capture the discovered path so the deferred action can load it
        // after the user supplies the master password.
        m_PendingAction = [this, foundVaultPath]() { loadVaultFromPath(foundVaultPath, true); };
        ensurePassword();
        return;
    }

    loadVaultFromPath(foundVaultPath, true);
}

void Backend::armFill(int index)
{
    if (index < 0 || index >= (int)m_Records.size())
        return;
    if (!m_PasswordSet)
    {
        m_PendingAction = [this, index]() { armFill(index); };
        ensurePassword();
        return;
    }
    if (m_Busy)
        return;

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.arm.begin", seal::diag::kv("index", index)}));
    m_DPAPIGuard.unprotect();
    bool armed = false;
    try
    {
        armed = m_FillController->arm(index, m_Records, m_Password, m_RecordsGeneration);
    }
    catch (...)
    {
        m_DPAPIGuard.reprotect();
        throw;
    }
    if (!armed)
    {
        // If hook install failed, don't apply "armed" UI state/minimize behavior.
        // fillError may already have reprotected, but this is harmless if unchanged.
        m_DPAPIGuard.reprotect();
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
                                seal::diag::kv("generation", m_RecordsGeneration)}));
    setStatus("Fill armed - Ctrl+Click target field");

    // Safety net: reprotect the DPAPI guard after a generous window even if
    // the fill completion signals are somehow never delivered. The fill
    // controller's 30s timeout should always fire cancel -> fillCancelled ->
    // reprotect(), but this ensures the password isn't left unprotected
    // indefinitely in case signal dispatch fails.
    static constexpr int DPAPI_SAFETY_NET_MS = 60000;  // 60 seconds
    QTimer::singleShot(DPAPI_SAFETY_NET_MS,
                       this,
                       [this]()
                       {
                           if (m_PasswordSet && !m_FillController->isArmed())
                           {
                               m_DPAPIGuard.reprotect();
                           }
                       });

    // Minimize so the user can see and click the target application.
    // Stays minimized after fill completes or is cancelled; only restored on error.
    for (QWindow* w : QGuiApplication::topLevelWindows())
    {
        if (w->isVisible())
        {
            w->showMinimized();
        }
    }
}

void Backend::cancelFill()
{
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=fill.cancel.request"}));
    m_FillController->cancel();
}

void Backend::cleanup()
{
    const auto started = std::chrono::steady_clock::now();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.cleanup.begin", "result=start"}));

    // Wait for any active QR capture thread to finish before destroying
    // members it may reference. Without this, the thread could call
    // QMetaObject::invokeMethod(this, ...) on a dangling pointer.
    if (m_QrThread && m_QrThread->isRunning())
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=app.cleanup.qr_thread.wait", "result=start"}));
        m_QrThread->requestInterruption();
        if (!m_QrThread->wait(5000))
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=app.cleanup.qr_thread.wait", "result=fail", "reason=timeout_terminate"}));
            m_QrThread->terminate();
            m_QrThread->wait();
        }
    }

    m_FillController->cancel();

    // If the user configured an auto-encrypt directory, encrypt it now
    // before we wipe the master password.
    if (!m_AutoEncryptDirectory.isEmpty() && m_PasswordSet)
    {
        try
        {
            ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
            int count = seal::encryptDirectory(m_AutoEncryptDirectory, m_Password);
            qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=app.cleanup.auto_encrypt.finish",
                 "result=ok",
                 seal::diag::kv("count", count),
                 seal::diag::pathSummary(m_AutoEncryptDirectory.toUtf8().toStdString())}));
            setStatus(QString("Auto-encrypted %1 file(s) in directory").arg(count));
        }
        catch (const std::exception& e)
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=app.cleanup.auto_encrypt.finish",
                 "result=fail",
                 seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                 seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
        }
    }

    // Wipe the master password from locked memory so it doesn't persist
    // after the application exits.
    if (m_PasswordSet)
    {
        m_DPAPIGuard = {};
        seal::Cryptography::cleanseString(m_Password);
        m_PasswordSet = false;
        emit passwordSetChanged();
    }

    seal::Cryptography::trimWorkingSet();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.cleanup.finish",
                                "result=ok",
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
}

void Backend::updateWindowTheme(bool dark)
{
    m_WindowController->updateWindowTheme(dark);
}

void Backend::startWindowDrag()
{
    m_WindowController->startWindowDrag();
}

bool Backend::isAlwaysOnTop() const
{
    return m_WindowController->isAlwaysOnTop();
}

void Backend::toggleAlwaysOnTop()
{
    m_WindowController->toggleAlwaysOnTop();
}

void Backend::lockVault()
{
    if (!m_PasswordSet)
        return;

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.lock", "result=ok"}));
    m_FillController->cancel();
    m_DPAPIGuard = {};
    seal::Cryptography::cleanseString(m_Password);
    m_PasswordSet = false;
    emit passwordSetChanged();
    setStatus("Vault locked - password required for next action");
}

bool Backend::isCompact() const
{
    return m_WindowController->isCompact();
}

void Backend::toggleCompact()
{
    m_WindowController->toggleCompact();
}

bool Backend::isCliMode() const
{
    return m_CliMode;
}

void Backend::toggleCliMode()
{
    m_CliMode = !m_CliMode;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=cli.mode.toggle", seal::diag::kv("state", m_CliMode)}));
    emit cliModeChanged();

    if (m_CliMode && !m_CliWelcomeShown)
    {
        m_CliWelcomeShown = true;
        emit cliOutputReady(QStringLiteral("seal - Interactive Mode"));
        emit cliOutputReady(
            QStringLiteral("Commands: :help | :open | :copy | :clear | :gen | :fill | :cls | :qr"));
        emit cliOutputReady(
            QStringLiteral("Type text to encrypt, paste hex to decrypt, or enter a file path."));
        emit cliOutputReady(QString{});
    }
}

void Backend::executeCliCommand(const QString& command)
{
    QString trimmed = command.trimmed();
    if (trimmed.isEmpty())
    {
        return;
    }

    std::string input = trimmed.toStdString();
    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=cli.command.begin", seal::diag::kv("input_len", input.size())}));

    // --- Built-in commands (no password needed) ---
    seal::CliCallbacks cb;
    cb.output = [this](const QString& s) { emit cliOutputReady(s); };
    cb.clearOutput = [this]() { emit cliOutputCleared(); };
    cb.requestQrCapture = [this]() { requestQrCapture(); };
    cb.armFill = [this](int i) { armFill(i); };
    cb.records = &m_Records;

    if (seal::HandleCliBuiltin(trimmed, cb))
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=cli.command.finish", "result=builtin"}));
        return;
    }

    // --- Password-requiring commands ---

    if (!m_PasswordSet)
    {
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=cli.command.finish", "result=defer", "reason=password_required"}));
        m_PendingAction = [this, command]() { executeCliCommand(command); };
        ensurePassword();
        return;
    }

    try
    {
        ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
        std::string stripped = seal::utils::stripQuotes(seal::utils::trim(input));

        // Strip control characters that may survive from clipboard paste.
        std::erase_if(stripped, [](unsigned char c) { return c < 32 || c == 127; });

        // Remove trailing path separators so GetFileAttributesA does not reject
        // non-root directory paths like "C:\folder\sub\".
        while (stripped.size() > 1 && (stripped.back() == '\\' || stripped.back() == '/') &&
               !(stripped.size() == 3 && stripped[1] == ':'))
        {
            stripped.pop_back();
        }

        seal::CliDispatchCallbacks dcb{
            .output = [this](const QString& s) { emit cliOutputReady(s); }, .password = m_Password};

        // Priority 1: file or directory path
        if (seal::utils::isDirectoryA(stripped))
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=directory",
                                        seal::diag::pathSummary(stripped)}));
            seal::CliDispatchDirectory(stripped, dcb);
            return;
        }
        if (seal::utils::fileExistsA(stripped))
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=file",
                                        seal::diag::pathSummary(stripped)}));
            seal::CliDispatchFile(stripped, dcb);
            return;
        }

        // Priority 2: hex token -> decrypt
        auto hexTokens = seal::utils::extractHexTokens(input);
        if (!hexTokens.empty())
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=hex",
                                        seal::diag::kv("token_count", hexTokens.size())}));
            seal::CliDispatchHexTokens(input, dcb);
            return;
        }

        // Priority 2b: base64-encoded ciphertext -> decrypt
        if (seal::utils::isBase64(input) && seal::CliDispatchBase64(input, dcb))
        {
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=cli.command.finish",
                                        "result=dispatch",
                                        "route=base64",
                                        seal::diag::kv("input_len", input.size())}));
            return;
        }

        // Priority 3: plain text -> encrypt (show both hex and base64)
        qCInfo(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=cli.command.finish",
                                    "result=dispatch",
                                    "route=encrypt",
                                    seal::diag::kv("input_len", input.size())}));
        seal::CliDispatchEncrypt(input, dcb);
    }
    catch (const std::exception& ex)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=cli.command.finish",
             "result=fail",
             seal::diag::kv("reason", seal::diag::reasonFromMessage(ex.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(ex.what())),
             seal::diag::kv("input_len", input.size())}));
        emit cliOutputReady(QString("Error: %1").arg(QString::fromUtf8(ex.what())));
    }
}

void Backend::handleQrResultForCli(const QString& text)
{
    std::string narrow = text.toStdString();
    (void)seal::Clipboard::copyWithTTL(narrow);
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=cli.qr.capture.finish",
                                "result=ok",
                                seal::diag::kv("payload_len", text.size()),
                                "copied=true"}));
    seal::Cryptography::cleanseString(narrow);
    // Mask the QR text in CLI output - value is on the clipboard (TTL-scrubbed).
    emit cliOutputReady(
        QString("(QR captured) %1  [copied]").arg(QString(text.size(), QChar('*'))));
}

}  // namespace seal

#endif  // USE_QT_UI
