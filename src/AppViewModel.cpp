#ifdef USE_QT_UI

#include "AppViewModel.hpp"

#include "AsyncRunner.hpp"
#include "AutoLockController.hpp"
#include "CliModes.hpp"
#include "CliPanelViewModel.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "Logging.hpp"
#include "NativeDialogs.hpp"
#include "QrCapture.hpp"
#include "VaultModel.hpp"

#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QtCore/QThread>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>

namespace seal
{

basic_secure_string<wchar_t, locked_allocator<wchar_t>> AppViewModel::qstringToSecureWide(
    const QString& qstr)
{
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> result;
    if (qstr.isEmpty())
        return result;

    // Copy directly into locked memory; toStdWString() would heap-allocate
    // an intermediate plaintext std::wstring. wchar_t==QChar on Windows.
    static_assert(sizeof(wchar_t) == sizeof(QChar), "wchar_t/QChar size mismatch");
    const auto* src = reinterpret_cast<const wchar_t*>(qstr.data());
    result.assign(src, src + qstr.size());
    return result;
}

AppViewModel::AppViewModel(seal::CredentialWorkspace& workspace,
                           seal::AsyncRunner& asyncRunner,
                           QObject* parent)
    : QObject(parent),
      m_Model(new VaultListModel(this)),
      m_Workspace(workspace),
      m_Async(asyncRunner)
{
    m_Model->setRecords(&m_Workspace.records(), &m_Workspace.generation());

    // Auto-lock collaborator: wipes the master password on idle timeout or
    // Windows session lock (Win+L). lockVault() already cancels an armed
    // fill, so the borrowed-pointer discipline holds.
    m_AutoLock = new AutoLockController(this);
    connect(m_AutoLock,
            &AutoLockController::lockRequested,
            this,
            [this](const QString& reason)
            {
                if (!m_Workspace.isPasswordSet())
                {
                    return;
                }
                lockVault();
                setStatus(reason);
            });
}

AppViewModel::~AppViewModel()
{
    try
    {
        cleanup();
    }
    catch (...)
    {
    }
}

VaultListModel* AppViewModel::vaultModel() const
{
    return m_Model;
}

bool AppViewModel::vaultLoaded() const
{
    return !m_CurrentVaultPath.isEmpty() || !m_Workspace.empty();
}

QString AppViewModel::vaultFileName() const
{
    if (m_CurrentVaultPath.isEmpty())
        return {};
    return QFileInfo(m_CurrentVaultPath).fileName();
}

bool AppViewModel::hasSelection() const
{
    return m_SelectedIndex >= 0;
}

int AppViewModel::selectedIndex() const
{
    return m_SelectedIndex;
}

void AppViewModel::setSelectedIndex(int index)
{
    if (m_SelectedIndex == index)
        return;
    m_SelectedIndex = index;
    emit selectionChanged();
}

QString AppViewModel::statusText() const
{
    return m_StatusText;
}

bool AppViewModel::isPasswordSet() const
{
    return m_Workspace.isPasswordSet();
}

QString AppViewModel::searchFilter() const
{
    return m_SearchFilter;
}

void AppViewModel::setSearchFilter(const QString& filter)
{
    if (m_SearchFilter == filter)
        return;
    m_SearchFilter = filter;
    m_Model->setFilter(filter);
    emit searchFilterChanged();
}

int AppViewModel::sortMode() const
{
    return m_Model->sortMode();
}

void AppViewModel::setSortMode(int mode)
{
    if (m_Model->sortMode() == mode)
    {
        return;
    }
    m_Model->setSortMode(mode);
    emit sortModeChanged();
}

QString AppViewModel::countdownText() const
{
    return m_CountdownText;
}

bool AppViewModel::isBusy() const
{
    return m_Busy;
}

bool AppViewModel::isLoading() const
{
    return m_Loading;
}

QString AppViewModel::loadingCaption() const
{
    return m_LoadingCaption;
}

bool AppViewModel::ensurePassword(std::function<void()> action)
{
    if (m_Workspace.isPasswordSet())
    {
        return true;
    }

    m_PendingActions.push_back(std::move(action));
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.pending_action.enqueue",
                                "result=ok",
                                seal::diag::kv("depth", m_PendingActions.size())}));
    emit passwordRequired();
    return false;
}

void AppViewModel::drainPendingActions()
{
    while (!m_PendingActions.empty())
    {
        auto action = std::move(m_PendingActions.front());
        m_PendingActions.pop_front();
        action();
    }
}

size_t AppViewModel::pendingActionDepth() const
{
    return m_PendingActions.size();
}

void AppViewModel::submitPassword(QString password)
{
    auto wide = qstringToSecureWide(password);
    // Wipe the input QString to reduce plaintext residency in pageable memory.
    password.fill(QChar(0));
    // CredentialSession takes ownership and wraps the buffer in a DPAPI guard:
    // while "protected", the OS encrypts the memory in-place so a process dump
    // cannot read it.
    m_Workspace.adoptPassword(std::move(wide));
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=auth.password.set",
                                "result=ok",
                                "source=manual_entry",
                                seal::diag::kv("pending_depth", pendingActionDepth())}));
    setStatus("Password set");
    emit passwordSetChanged();

    // Drain all queued actions (FIFO) that were deferred while waiting for
    // the password.
    drainPendingActions();
}

namespace
{
// File-local result struct for the QR capture worker.
struct QrOutcome
{
    QString text;
    bool success = false;
};
}  // namespace

void AppViewModel::requestQrCapture()
{
    const std::string opId = seal::diag::nextOpId("qr_capture");
    const auto started = std::chrono::steady_clock::now();

    if (m_QrActive)
    {
        qCWarning(logBackend).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=qr.capture.skip",
                                                              "result=skip",
                                                              seal::diag::kv("op", opId),
                                                              "reason=already_in_progress"}));
        return;
    }

    // ASFW_ANY lets any process take the foreground; without it, the QR
    // scanner's OpenCV window would open behind ours.
    AllowSetForegroundWindow(ASFW_ANY);

    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=qr.capture.begin", "result=start", seal::diag::kv("op", opId), "worker=true"}));

    m_QrActive = true;

    // Run captureQrFromWebcam() on the async pool; it can block for up
    // to 60 s, which would freeze the UI if done on the GUI thread.
    // The CancellationToken lets callers cancel via m_QrHandle.cancel().
    m_QrHandle = m_Async.runCancellable(
        this,
        [opId](seal::CancellationToken token) -> QrOutcome
        {
            seal::secure_string<> qrResult = seal::captureQrFromWebcam(std::move(token));
            if (qrResult.empty())
            {
                return {};
            }
            // Pre-fill the password dialog with the QR text; don't commit to
            // the session yet - the user confirms. QrOutcome carries a QString
            // consistent with the existing invokeMethod flow (handleQrResult
            // performs the TTL-clipboard-copy + cleanse + masked-append).
            QString captured = QString::fromUtf8(qrResult.data(), (int)qrResult.size());
            // qrResult auto-wipes on scope exit (locked allocator).
            return {std::move(captured), true};
        },
        [this, opId, started](QrOutcome r)
        {
            m_QrActive = false;
            if (!r.success)
            {
                qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=qr.capture.finish",
                     "result=fail",
                     seal::diag::kv("op", opId),
                     "reason=empty_or_cancelled",
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                     seal::diag::kv("payload_len", 0)}));
                setStatus("QR capture failed or cancelled");
                if (m_Cli && m_Cli->isCliMode())
                {
                    m_Cli->handleQrFailure();
                }
                else
                {
                    emit qrCaptureFinished(false);
                }
                return;
            }

            qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=qr.capture.finish",
                 "result=ok",
                 seal::diag::kv("op", opId),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                 seal::diag::kv("payload_len", r.text.size()),
                 "confirmation_required=true"}));
            setStatus("QR captured - confirm password");
            if (m_Cli && m_Cli->isCliMode())
            {
                m_Cli->handleQrResult(r.text);
            }
            else
            {
                emit qrCaptureFinished(true);

                // Re-open the password dialog with the captured text.
                emit qrTextReady(r.text);
            }

            // Wipe the local copy so the QR text doesn't linger in the heap
            // after QML receives its copy.
            r.text.fill(QChar(0));
        });
}

void AppViewModel::setStatus(const QString& text)
{
    if (m_StatusText == text)
        return;
    m_StatusText = text;
    emit statusTextChanged();
}

void AppViewModel::setLoading(bool on, const QString& caption)
{
    const QString next = on ? caption : QString();
    if (m_Loading == on && m_LoadingCaption == next)
        return;
    m_Loading = on;
    m_LoadingCaption = next;
    emit loadingChanged();
}

void AppViewModel::setBusy(bool busy)
{
    if (m_Busy != busy)
    {
        m_Busy = busy;
        emit busyChanged();
    }
}

void AppViewModel::setCountdown(const QString& text)
{
    if (m_CountdownText != text)
    {
        m_CountdownText = text;
        emit countdownTextChanged();
    }
}

void AppViewModel::setFillControl(IFillControl* fill)
{
    m_Fill = fill;
}

void AppViewModel::refreshModel()
{
    m_Model->refresh();
    setSelectedIndex(-1);
}

void AppViewModel::cancelFillIfArmed()
{
    if (m_Fill)
    {
        m_Fill->cancelIfArmed();
    }
}

void AppViewModel::loadVaultFromPath(const QString& filePath, bool isAutoLoad)
{
    if (m_LoadWorkerActive)
    {
        // A load worker is already in flight; ignore the re-entrant dispatch.
        return;
    }

    const std::string opId = seal::diag::nextOpId("vault_load");
    const auto started = std::chrono::steady_clock::now();
    const std::string pathMeta = seal::diag::pathSummary(filePath.toUtf8().toStdString());

    // Cancel any active fill before the records are swapped on completion;
    // FillController's borrowed pointer would otherwise dangle.
    cancelFillIfArmed();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.load.begin",
                                "result=start",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("auto", isAutoLoad),
                                pathMeta}));

    // Clone the master password into a worker-owned secure string inside a
    // tight GUI-thread unlock() window, so the session is re-protected before
    // the worker starts and never touched off-thread. basic_secure_string is
    // move-only, hence the explicit element copy.
    seal::basic_secure_string<wchar_t> workerPassword;
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
            emit errorOccurred(QStringLiteral("Vault error"),
                               QStringLiteral("Could not access the master key."));
            setStatus("Failed to load vault");
            return;
        }
        workerPassword.assign(access.password().begin(), access.password().end());
    }

    const std::filesystem::path vaultPath{filePath.toStdWString()};

    m_LoadWorkerActive = true;
    setLoading(true, QStringLiteral("Decrypting vault..."));

    // The scrypt KDF + per-record AES decrypt runs off the GUI thread so the
    // loading spinner can animate; results marshal back via AsyncRunner.
    struct LoadOutcome
    {
        std::vector<seal::VaultRecord> records;
        bool ok = false;
        bool wrongPassword = false;
        QString message;
    };

    // shared_ptr so the work body is copyable (QtConcurrent::run decay-copies
    // the callable); the secret bytes stay in the locked buffer. The clone was
    // taken inside the GUI-thread session().unlock() window above.
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;
    auto pw = std::make_shared<SecureWide>(std::move(workerPassword));

    m_Async.run(
        this,
        [pw, vaultPath]() -> LoadOutcome
        {
            LoadOutcome r;
            try
            {
                r.records = seal::loadVaultIndex(vaultPath, *pw);
                r.ok = true;
            }
            catch (const std::exception& e)
            {
                r.wrongPassword = std::string(e.what()) == "Wrong password";
                r.message = QString::fromUtf8(e.what());
            }
            seal::Cryptography::cleanseString(*pw);  // wipe the locked clone
            return r;
        },
        [this, filePath, isAutoLoad, opId, started](LoadOutcome r)
        {
            m_LoadWorkerActive = false;

            if (r.ok)
            {
                try
                {
                    m_Workspace.replaceRecords(std::move(r.records));
                    m_Workspace.setVaultPath(std::filesystem::path{filePath.toStdWString()});
                }
                catch (const std::exception& e)
                {
                    qCWarning(logBackend).noquote()
                        << QString::fromStdString(seal::diag::joinFields(
                               {"event=vault.load.finish",
                                "result=fail",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                                seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what())),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                    setLoading(false);
                    emit errorOccurred("Error", QString("Failed to load vault: %1").arg(e.what()));
                    setStatus("Failed to load vault");
                    return;
                }
                m_CurrentVaultPath = filePath;
                const size_t recordCount = m_Workspace.records().size();
                qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=vault.load.finish",
                     "result=ok",
                     seal::diag::kv("op", opId),
                     seal::diag::kv("record_count", recordCount),
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                refreshModel();
                if (isAutoLoad)
                    setStatus(QString("Auto-loaded %1 account(s) from %2")
                                  .arg(recordCount)
                                  .arg(QFileInfo(filePath).fileName()));
                else
                    setStatus(QString("Loaded %1 account(s) from vault").arg(recordCount));
                setLoading(false);
                emit vaultLoadedChanged();
                emit vaultFileNameChanged();
                return;
            }
            if (r.wrongPassword)
            {
                // Wrong-password retry: drop the guard, wipe the bad
                // password, clear passwordSet, stash a pending-action
                // lambda to redo this load, and signal QML to re-show
                // the dialog with an error hint.
                qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=vault.load.finish",
                     "result=retry",
                     seal::diag::kv("op", opId),
                     "reason=wrong_password",
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                m_Workspace.clearPassword();
                emit passwordSetChanged();
                m_PendingActions.push_front([this, filePath, isAutoLoad]()
                                            { loadVaultFromPath(filePath, isAutoLoad); });
                setLoading(false);
                emit passwordRetryRequired("Wrong password - try again.");
                return;
            }
            const QByteArray detailBytes = r.message.toUtf8();
            const char* detail = detailBytes.constData();
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=vault.load.finish",
                 "result=fail",
                 seal::diag::kv("op", opId),
                 seal::diag::kv("reason", seal::diag::reasonFromMessage(detail)),
                 seal::diag::kv("detail", seal::diag::sanitizeAscii(detail)),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
            setLoading(false);
            emit errorOccurred("Error", QString("Failed to load vault: %1").arg(r.message));
            setStatus("Failed to load vault");
        });
}

void AppViewModel::loadVault()
{
    if (!ensurePassword([this]() { loadVault(); }))
    {
        return;
    }

    QString fileName =
        seal::OpenFileDialog("Load Vault File", "seal Vault (*.seal)|*.seal|All Files (*)|*.*|");
    if (fileName.isEmpty())
        return;

    loadVaultFromPath(fileName);
}

void AppViewModel::saveVault()
{
    if (!ensurePassword([this]() { saveVault(); }))
    {
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
                                seal::diag::kv("record_count", m_Workspace.records().size()),
                                seal::diag::pathSummary(fileName.toUtf8().toStdString())}));

    // Point the workspace at the (possibly newly chosen) target before saving;
    // workspace.save() opens its own Access window and writes to vaultPath().
    m_Workspace.setVaultPath(std::filesystem::path{fileName.toStdWString()});

    // FillController borrows records; save() clears dirty flags and purges
    // soft-deletes, so cancel any armed fill before the mutation.
    cancelFillIfArmed();

    bool saveOk = false;
    try
    {
        saveOk = m_Workspace.save();
    }
    catch (const std::exception&)
    {
        qCWarning(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
        emit errorOccurred(QStringLiteral("Vault error"),
                           QStringLiteral("Could not access the master key."));
        setStatus("Failed to save vault");
        return;
    }
    if (saveOk)
    {
        m_CurrentVaultPath = fileName;

        refreshModel();
        const size_t recordCount = m_Workspace.records().size();
        qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.save.finish",
             "result=ok",
             seal::diag::kv("op", opId),
             seal::diag::kv("record_count", recordCount),
             seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
        setStatus(QString("Saved %1 account(s) to vault").arg(recordCount));
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

void AppViewModel::unloadVault()
{
    // Cancel any active fill so FillController's borrowed pointer to the
    // workspace records does not dangle once we clear.
    cancelFillIfArmed();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.unload",
                                "result=ok",
                                seal::diag::kv("record_count", m_Workspace.records().size())}));
    m_Workspace.clearRecords();
    m_CurrentVaultPath.clear();
    refreshModel();
    setStatus("Vault unloaded");
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
}

void AppViewModel::addAccount(const QString& service,
                              const QString& username,
                              const QString& password)
{
    if (service.isEmpty() || username.isEmpty() || password.isEmpty())
    {
        emit errorOccurred("Warning", "All fields are required");
        return;
    }

    if (!m_Workspace.isPasswordSet())
    {
        // Move credentials into locked-page memory before the dialog opens
        // so plaintext doesn't sit in pageable heap. shared_ptr makes the
        // lambda std::function-copyable without duplicating the secret.
        auto secUser =
            std::make_shared<seal::basic_secure_string<wchar_t>>(qstringToSecureWide(username));
        auto secPass =
            std::make_shared<seal::basic_secure_string<wchar_t>>(qstringToSecureWide(password));
        if (!ensurePassword(
                [this, service, secUser, secPass]()
                {
                    // Encrypt directly from locked memory - no pageable-QString
                    // round-trip. shared_ptrs keep the secrets alive across the
                    // std::function copy boundary.
                    cancelFillIfArmed();
                    try
                    {
                        m_Workspace.addRecord(service.toUtf8().toStdString(), *secUser, *secPass);
                    }
                    catch (const std::exception& e)
                    {
                        seal::Cryptography::cleanseString(*secUser, *secPass);
                        qCWarning(logBackend).noquote() << QString::fromStdString(
                            seal::diag::joinFields(
                                {"event=vault.record.add",
                                 "result=fail",
                                 "deferred=true",
                                 seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
                                 seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
                        emit errorOccurred("Error",
                                           QString("Failed to add account: %1").arg(e.what()));
                        return;
                    }
                    seal::Cryptography::cleanseString(*secUser, *secPass);
                    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                        {"event=vault.record.add",
                         "result=ok",
                         "deferred=true",
                         seal::diag::kv("total_records", m_Workspace.records().size()),
                         seal::diag::kv("service_len", service.size())}));
                    refreshModel();
                    setStatus("Account added");
                    emit vaultLoadedChanged();
                    emit vaultFileNameChanged();
                }))
        {
            return;
        }
    }

    // Locked-page wide strings minimise plaintext residency.
    auto secUsername = qstringToSecureWide(username);
    auto secPassword = qstringToSecureWide(password);

    cancelFillIfArmed();
    try
    {
        m_Workspace.addRecord(service.toUtf8().toStdString(), secUsername, secPassword);
    }
    catch (const std::exception& e)
    {
        seal::Cryptography::cleanseString(secUsername, secPassword);
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.record.add",
             "result=fail",
             "deferred=false",
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
        emit errorOccurred("Error", QString("Failed to add account: %1").arg(e.what()));
        return;
    }

    seal::Cryptography::cleanseString(secUsername, secPassword);

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.add",
                                "result=ok",
                                "deferred=false",
                                seal::diag::kv("total_records", m_Workspace.records().size()),
                                seal::diag::kv("service_len", service.size())}));
    refreshModel();
    setStatus("Account added");
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
}

void AppViewModel::editAccountWithSecureFields(
    int index,
    const QString& service,
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
    bool hasUsername,
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool hasPassword)
{
    if (index < 0 || index >= (int)m_Workspace.records().size())
        return;

    if (!m_Workspace.isPasswordSet())
        return;

    try
    {
        // FillController borrows records; editRecord replaces one in place.
        cancelFillIfArmed();

        // The workspace owns the keep-current decrypt: a null field pointer
        // means "reuse the stored value".
        m_Workspace.editRecord(static_cast<size_t>(index),
                               service.toUtf8().toStdString(),
                               hasUsername ? &username : nullptr,
                               hasPassword ? &password : nullptr);
    }
    catch (const std::exception& e)
    {
        seal::Cryptography::cleanseString(username, password);
        qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
            {"event=vault.record.edit",
             "result=fail",
             seal::diag::kv("index", index),
             seal::diag::kv("reason", seal::diag::reasonFromMessage(e.what())),
             seal::diag::kv("detail", seal::diag::sanitizeAscii(e.what()))}));
        emit errorOccurred("Error", QString("Failed to update account: %1").arg(e.what()));
        return;
    }

    seal::Cryptography::cleanseString(username, password);

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.edit",
                                "result=ok",
                                seal::diag::kv("index", index),
                                seal::diag::kv("service_len", service.size()),
                                seal::diag::kv("username_changed", hasUsername),
                                seal::diag::kv("password_changed", hasPassword)}));
    refreshModel();
    setStatus("Account updated");
}

void AppViewModel::editAccount(int index,
                               const QString& service,
                               const QString& username,
                               const QString& password)
{
    if (index < 0 || index >= (int)m_Workspace.records().size())
        return;

    if (service.isEmpty())
    {
        emit errorOccurred("Warning", "Service is required");
        return;
    }

    const bool hasUsername = !username.isEmpty();
    const bool hasPassword = !password.isEmpty();

    auto secUsername =
        hasUsername ? qstringToSecureWide(username) : seal::basic_secure_string<wchar_t>{};
    auto secPassword =
        hasPassword ? qstringToSecureWide(password) : seal::basic_secure_string<wchar_t>{};

    if (!m_Workspace.isPasswordSet())
    {
        auto pendingUsername =
            std::make_shared<seal::basic_secure_string<wchar_t>>(std::move(secUsername));
        auto pendingPassword =
            std::make_shared<seal::basic_secure_string<wchar_t>>(std::move(secPassword));

        if (!ensurePassword(
                [this, index, service, pendingUsername, hasUsername, pendingPassword, hasPassword]()
                {
                    editAccountWithSecureFields(index,
                                                service,
                                                *pendingUsername,
                                                hasUsername,
                                                *pendingPassword,
                                                hasPassword);
                }))
        {
            return;
        }
    }

    editAccountWithSecureFields(index, service, secUsername, hasUsername, secPassword, hasPassword);
}

void AppViewModel::deleteAccount(int index)
{
    if (index < 0 || index >= (int)m_Workspace.records().size())
        return;

    // Soft-delete: hide from the model immediately but keep the record
    // until saveVault() commits to disk.
    cancelFillIfArmed();
    m_Workspace.markDeleted(static_cast<size_t>(index));
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.delete",
                                "result=ok",
                                "mode=soft_delete",
                                seal::diag::kv("index", index)}));
    refreshModel();
    setStatus("Account deleted");

    // If nothing visible remains, notify QML to render the empty state.
    bool anyVisible = false;
    for (const auto& rec : m_Workspace.records())
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

void AppViewModel::requestEditSelected()
{
    const int index = m_Model->recordIndexForRow(m_SelectedIndex);
    if (index < 0 || index >= (int)m_Workspace.records().size())
    {
        return;
    }

    qCDebug(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=credential.edit_metadata.request", seal::diag::kv("index", index)}));
    emit editAccountRequested(index,
                              QString::fromUtf8(m_Workspace.records()[index].platform.c_str()));
}

void AppViewModel::requestDeleteSelected()
{
    const int index = m_Model->recordIndexForRow(m_SelectedIndex);
    if (index < 0 || index >= (int)m_Workspace.records().size())
    {
        return;
    }

    emit confirmDeleteRequested(index,
                                QString::fromUtf8(m_Workspace.records()[index].platform.c_str()));
}

void AppViewModel::encryptDirectory()
{
    if (!ensurePassword([this]() { encryptDirectory(); }))
    {
        return;
    }

    QString dirPath = seal::OpenFolderDialog("Select Directory to Encrypt");
    if (dirPath.isEmpty())
        return;

    const std::string opId = seal::diag::nextOpId("dir_encrypt");
    const auto started = std::chrono::steady_clock::now();
    int count = 0;
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
            emit errorOccurred(QStringLiteral("Vault error"),
                               QStringLiteral("Could not access the master key."));
            return;
        }
        count = seal::encryptDirectory(std::filesystem::path{dirPath.toStdWString()},
                                       access.password());
    }
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

void AppViewModel::decryptDirectory()
{
    if (!ensurePassword([this]() { decryptDirectory(); }))
    {
        return;
    }

    QString dirPath = seal::OpenFolderDialog("Select Directory to Decrypt");
    if (dirPath.isEmpty())
        return;

    const std::string opId = seal::diag::nextOpId("dir_decrypt");
    const auto started = std::chrono::steady_clock::now();
    int count = 0;
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
            emit errorOccurred(QStringLiteral("Vault error"),
                               QStringLiteral("Could not access the master key."));
            return;
        }
        count = seal::decryptDirectory(std::filesystem::path{dirPath.toStdWString()},
                                       access.password());
    }
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

void AppViewModel::autoLoadVault()
{
    if (!m_CurrentVaultPath.isEmpty())
        return;

    // Search for a .seal file: exe dir, then cwd, then home (priority order).
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
    if (!ensurePassword([this, foundVaultPath]() { loadVaultFromPath(foundVaultPath, true); }))
    {
        return;
    }

    loadVaultFromPath(foundVaultPath, true);
}

void AppViewModel::armFillForRow(int row)
{
    const int index = m_Model->recordIndexForRow(row);
    if (index < 0)
    {
        return;
    }
    setSelectedIndex(row);
    // armFor() self-gates on the master password; no ensurePassword here.
    if (m_Fill)
    {
        m_Fill->armFor(index);
    }
}

void AppViewModel::armFillForSelection()
{
    const int index = m_Model->recordIndexForRow(m_SelectedIndex);
    if (index < 0)
    {
        return;
    }
    // armFor() self-gates on the master password; no ensurePassword here.
    if (m_Fill)
    {
        m_Fill->armFor(index);
    }
}

void AppViewModel::onAutoArmed(int recordIndex, const QString& platform)
{
    // Display only: select the auto-armed record's row so the user sees which
    // credential is staged, and show a non-secret hint. StagingController owns
    // the actual arming; AppViewModel never touches the fill engine here.
    const int row = m_Model->rowForRecordIndex(recordIndex);
    if (row >= 0)
    {
        setSelectedIndex(row);
    }
    setStatus(QStringLiteral("Auto-armed for %1 - click the login field to fill").arg(platform));
}

void AppViewModel::cleanup()
{
    // Cooperatively cancel any in-flight QR capture first so its token-polling
    // cv loop aborts promptly, rather than waiting for ~AsyncRunner to
    // cancel-all after exec() returns. Safe no-op if no QR ever ran (null flag).
    m_QrHandle.cancel();

    const auto started = std::chrono::steady_clock::now();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.cleanup.begin", "result=start"}));

    if (m_Fill)
    {
        m_Fill->cancelIfArmed();
    }

    // Auto-encrypt the configured directory before wiping the password.
    if (!m_AutoEncryptDirectory.isEmpty() && m_Workspace.isPasswordSet())
    {
        try
        {
            auto access = m_Workspace.session().unlock();
            if (!access.ok())
            {
                throw std::runtime_error("Could not access the master key.");
            }
            int count = seal::encryptDirectory(
                std::filesystem::path{m_AutoEncryptDirectory.toStdWString()}, access.password());
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

    // Wipe the master password from locked memory before exit.
    if (m_Workspace.isPasswordSet())
    {
        m_Workspace.clearPassword();
        emit passwordSetChanged();
    }

    seal::Cryptography::trimWorkingSet();
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.cleanup.finish",
                                "result=ok",
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
}

void AppViewModel::lockVault()
{
    if (!m_Workspace.isPasswordSet())
        return;

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.lock", "result=ok"}));
    cancelFillIfArmed();
    m_Workspace.clearPassword();
    emit passwordSetChanged();
    setStatus("Vault locked - password required for next action");
}

void AppViewModel::rekeyVault(QString currentPassword, QString newPassword)
{
    if (m_CurrentVaultPath.isEmpty() || m_Busy)
    {
        // Scrub the plaintext parameters before the early return - the normal
        // path wipes them below, and the busy/empty branch must not be an
        // avoidable exception to that hygiene.
        currentPassword.fill(QChar(0));
        newPassword.fill(QChar(0));
        emit rekeyFinished(false, QStringLiteral("No vault loaded or operation in progress."));
        return;
    }

    auto currentWide = qstringToSecureWide(currentPassword);
    auto newWide = qstringToSecureWide(newPassword);
    currentPassword.fill(QChar(0));
    newPassword.fill(QChar(0));

    // FillController borrows records + password; both are about to change.
    // cancelFillIfArmed() drops the borrow; the post-rekey reload bumps the
    // workspace generation via replaceRecords(), so no manual pre-bump is needed.
    cancelFillIfArmed();

    m_Busy = true;
    emit busyChanged();
    setStatus(QStringLiteral("Re-encrypting vault..."));
    setLoading(true, QStringLiteral("Re-encrypting vault..."));

    const std::filesystem::path vaultPath{m_CurrentVaultPath.toStdWString()};
    const std::string opId = seal::diag::nextOpId("gui_rekey");
    qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
        {"event=vault.rekey.begin", "result=start", "surface=gui", seal::diag::kv("op", opId)}));

    struct RekeyOutcome
    {
        size_t count = 0;
        bool ok = false;
        QString message;
    };

    // shared_ptr clones so the work body is copyable (QtConcurrent::run
    // decay-copies the callable); secret bytes stay in the locked buffers.
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;
    auto current = std::make_shared<SecureWide>(std::move(currentWide));
    auto fresh = std::make_shared<SecureWide>(std::move(newWide));
    // GUI-thread clone of the new password, captured only by onDone: adopted on
    // success / cleansed on failure (the worker copy is cleansed inside work).
    auto adopt = std::make_shared<SecureWide>();
    adopt->assign(fresh->begin(), fresh->end());

    m_Async.run(
        this,
        [current, fresh, vaultPath]() -> RekeyOutcome
        {
            RekeyOutcome r;
            try
            {
                r.count = seal::rekeyVault(vaultPath, *current, *fresh);
                r.ok = true;
                r.message = QStringLiteral("Master password changed (%1 records re-encrypted).")
                                .arg(r.count);
            }
            catch (const std::exception& e)
            {
                r.message = QString::fromUtf8(e.what());
            }
            seal::Cryptography::cleanseString(*current);  // wipe the locked clones
            seal::Cryptography::cleanseString(*fresh);
            return r;
        },
        [this, opId, adopt](RekeyOutcome r)
        {
            if (r.ok && isPasswordSet())
            {
                // Session still active: adopt the new password (submitPassword's
                // exact dance) and reload from disk so the workspace holds
                // new-password packets. The reload owns the loading cover,
                // switching its caption to "Decrypting vault..." then clearing it.
                m_Workspace.adoptPassword(std::move(*adopt));
                emit passwordSetChanged();
                loadVaultFromPath(m_CurrentVaultPath, false);
            }
            else if (r.ok)
            {
                // Auto-lock fired mid-rekey (session cleared); the disk already
                // holds the new password. Respect the lock instead of silently
                // re-unlocking - the next unlock uses the NEW password.
                seal::Cryptography::cleanseString(*adopt);
                setLoading(false);
                emit infoMessage(QStringLiteral("Master password changed"),
                                 QStringLiteral("Unlock with your new password to continue."));
            }
            else
            {
                seal::Cryptography::cleanseString(*adopt);
                setLoading(false);
            }
            m_Busy = false;
            emit busyChanged();
            qCInfo(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=vault.rekey.finish",
                                        r.ok ? "result=ok" : "result=fail",
                                        "surface=gui",
                                        seal::diag::kv("op", opId)}));
            setStatus(r.ok ? QStringLiteral("Master password changed")
                           : QStringLiteral("Rekey failed"));
            emit rekeyFinished(r.ok, r.message);
        });
}

void AppViewModel::setCliPanel(seal::CliPanelViewModel* cli)
{
    m_Cli = cli;
}

}  // namespace seal

#endif  // USE_QT_UI
