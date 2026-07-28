#ifdef USE_QT_UI

#include "AppViewModel.hpp"

#include "AsyncRunner.hpp"
#include "AutoLockController.hpp"
#include "AutoStagePolicy.hpp"
#include "CliModes.hpp"
#include "CliPanelViewModel.hpp"
#include "Console.hpp"
#include "Diagnostics.hpp"
#include "FileOperations.hpp"
#include "Logging.hpp"
#include "NativeDialogs.hpp"
#include "QrCapture.hpp"
#include "VaultModel.hpp"

#include <QtCore/QCoreApplication>
#include <QtCore/QCryptographicHash>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QSaveFile>
#include <QtCore/QSettings>
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
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{

struct ProtectedFolderOutcome
{
    seal::DirectoryProcessResult process;
    std::size_t scanFailures = 0;
};

struct PasswordVerificationOutcome
{
    bool ok = false;
    bool wrongPassword = false;
    QString message;
};

struct FolderProfileOperationOutcome
{
    bool ok = false;
    bool wrongPassword = false;
    QString message;
};

struct ProtectedFolderPreview
{
    QStringList encryptFiles;
    QStringList skippedFiles;
    qulonglong totalBytes = 0;
};

QString displayRelativePath(const std::filesystem::path& path)
{
    return QString::fromStdWString(path.generic_wstring());
}

QString normalizedAbsolutePath(const QString& path)
{
    return QDir::cleanPath(QFileInfo(path).absoluteFilePath());
}

bool sameWindowsPath(const QString& lhs, const QString& rhs)
{
    if (lhs.isEmpty() || rhs.isEmpty())
    {
        return false;
    }
    return normalizedAbsolutePath(lhs).compare(normalizedAbsolutePath(rhs), Qt::CaseInsensitive) ==
           0;
}

bool secureWideEqual(const seal::ProtectedFolderPassword& lhs,
                     const seal::ProtectedFolderPassword& rhs)
{
    return lhs.size() == rhs.size() &&
           seal::Cryptography::ctEqualRaw(reinterpret_cast<const unsigned char*>(lhs.data()),
                                          reinterpret_cast<const unsigned char*>(rhs.data()),
                                          lhs.size() * sizeof(wchar_t));
}

ProtectedFolderOutcome runProtectedFolderPlan(
    const std::filesystem::path& root,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
    bool encrypt)
{
    ProtectedFolderOutcome outcome;
    seal::ProtectedFolderScan scan = seal::scanProtectedFolder(root);
    outcome.scanFailures = scan.failures;

    const seal::protected_folder::PolicyContext context;
    const seal::protected_folder::FolderPlan plan =
        encrypt ? seal::protected_folder::planEncrypt(scan.entries, context)
                : seal::protected_folder::planDecrypt(scan.entries, context);
    outcome.process = seal::processFolderPlan(root, plan, password, encrypt);
    return outcome;
}

ProtectedFolderPreview makeProtectedFolderPreview(
    std::span<const seal::protected_folder::Entry> entries,
    const seal::protected_folder::PolicyContext& context)
{
    const seal::protected_folder::FolderPlan plan =
        seal::protected_folder::planEncrypt(entries, context);
    ProtectedFolderPreview preview;
    for (const seal::protected_folder::Entry& entry : plan.act)
    {
        preview.encryptFiles.push_back(displayRelativePath(entry.relativePath));
    }
    for (const auto& [entry, reason] : plan.skipped)
    {
        const std::string_view token = seal::protected_folder::skipReasonToken(reason);
        preview.skippedFiles.push_back(QStringLiteral("%1 - %2").arg(
            displayRelativePath(entry.relativePath),
            QString::fromLatin1(token.data(), static_cast<qsizetype>(token.size()))));
    }
    preview.totalBytes = static_cast<qulonglong>(plan.totalBytes());
    return preview;
}

}  // namespace

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

    m_ProtectedFolderRoot = QDir::cleanPath(QCoreApplication::applicationDirPath());
    m_ProtectFolderSettingKey = protectFolderSettingKey(m_ProtectedFolderRoot);
    const QSettings settings;
    m_ProtectFolderEnabled = settings.value(m_ProtectFolderSettingKey, false).toBool();
    m_AutoEncryptDirectory = m_ProtectFolderEnabled ? m_ProtectedFolderRoot : QString();
    m_UncleanProtectedSession =
        m_ProtectFolderEnabled && QFileInfo::exists(protectedFolderMarkerPath());
    if (m_UncleanProtectedSession)
    {
        m_StatusText = QStringLiteral(
            "Folder protection armed - previous session ended uncleanly; files may be plaintext");
    }
    else if (m_ProtectFolderEnabled)
    {
        m_StatusText = QStringLiteral("Folder protection armed");
    }

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
    // QML's held-close flow runs the asynchronous re-protection while the event
    // loop is alive. Destruction starts no worker and shows no prompt: an
    // abnormal teardown is represented by the plaintext marker on the next start.
    m_Destroying = true;
    m_QrHandle.cancel();
    if (m_Fill)
    {
        m_Fill->cancelIfArmed();
    }
    if (m_Workspace.isPasswordSet())
    {
        m_Workspace.clearPassword();
    }
    seal::Cryptography::trimWorkingSet();
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

bool AppViewModel::protectFolderEnabled() const
{
    return m_ProtectFolderEnabled;
}

QString AppViewModel::protectFolderPath() const
{
    return m_ProtectFolderPreflightPath;
}

QStringList AppViewModel::protectFolderEncryptFiles() const
{
    return m_ProtectFolderEncryptFiles;
}

QStringList AppViewModel::protectFolderSkippedFiles() const
{
    return m_ProtectFolderSkippedFiles;
}

qulonglong AppViewModel::protectFolderTotalBytes() const
{
    return m_ProtectFolderTotalBytes;
}

int AppViewModel::protectFolderPasswordMode() const
{
    return m_ProtectFolderPasswordMode;
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

void AppViewModel::adoptPasswordAndDrain(
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&& wide, const char* source)
{
    // CredentialSession takes ownership and keeps the buffer DPAPI-protected
    // between Access windows, so a process dump cannot read it.
    m_Workspace.adoptPassword(std::move(wide));
    m_VerifiedVaultPath.clear();
    m_ProtectedPasswordVerified = false;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=auth.password.set",
                                "result=ok",
                                seal::diag::kv("source", source),
                                seal::diag::kv("pending_depth", pendingActionDepth())}));
    setStatus("Password set");
    emit passwordSetChanged();

    // Drain the actions deferred while waiting for the password, front to back.
    // The queued vault load is what verifies it: a wrong password fails the GCM
    // tag check and reopens the prompt.
    drainPendingActions();
}

void AppViewModel::submitPassword(QString password)
{
    auto wide = qstringToSecureWide(password);
    // Wipe the input QString to reduce plaintext residency in pageable memory.
    password.fill(QChar(0));
    adoptPasswordAndDrain(std::move(wide), "manual_entry");
}

void AppViewModel::requestSecureDesktopUnlock()
{
    try
    {
        // Blocks until the user submits or cancels. The secure desktop owns the
        // screen while it is up, so blocking the GUI thread is invisible. The
        // secure desktop is best-effort: policy or an RDP session can fall back
        // to the normal desktop, which the API does not report.
        auto wide = readPasswordSecureDesktop(
            L"seal - Master Password", L"Enter your master password.", /*secureDesktop=*/true);

        // A blank submission is treated as a cancel: leave the prompt open.
        if (wide.empty())
        {
            return;
        }

        adoptPasswordAndDrain(std::move(wide), "secure_desktop");
    }
    catch (const std::exception& e)
    {
        const std::string msg = e.what();
        const bool canceled = (msg == "User canceled");
        qCWarning(logBackend).noquote() << QString::fromStdString(
            seal::diag::joinFields({"event=auth.secure_desktop.finish",
                                    canceled ? "result=cancel" : "result=fail",
                                    seal::diag::kv("reason", seal::diag::reasonFromMessage(msg))}));
        // Cancel is a normal outcome; only surface genuine failures.
        if (!canceled)
        {
            emit secureCaptureFinished(false);
        }
    }
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
            // Pre-fill the password dialog with the QR text; nothing reaches
            // the session until the user confirms. QrOutcome carries a QString
            // because handleQrResult does the TTL clipboard copy, the cleanse
            // and the masked append.
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

            // Wipe the local copy so the QR text does not linger in the heap
            // after QML receives its own.
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
            reportMasterKeyUnavailable();
            setStatus("Failed to load vault");
            if (isAutoLoad && m_ProtectFolderEnabled && m_ProtectedDecryptPending &&
                m_ProtectedPasswordVerified)
            {
                m_ProtectedDecryptPending = false;
                startProtectedFolderDecrypt(
                    [this]()
                    {
                        setLoading(false);
                        emit protectedFolderBootFinished();
                    });
            }
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
                                seal::diag::errorFields(e.what()),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                    setLoading(false);
                    emit errorOccurred("Error", QString("Failed to load vault: %1").arg(e.what()));
                    setStatus("Failed to load vault");
                    if (isAutoLoad && m_ProtectFolderEnabled && m_ProtectedDecryptPending &&
                        m_ProtectedPasswordVerified)
                    {
                        m_ProtectedDecryptPending = false;
                        startProtectedFolderDecrypt(
                            [this]()
                            {
                                setLoading(false);
                                emit protectedFolderBootFinished();
                            });
                    }
                    return;
                }
                m_CurrentVaultPath = filePath;
                m_VerifiedVaultPath = normalizedAbsolutePath(filePath);
                const size_t recordCount = m_Workspace.records().size();
                qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=vault.load.finish",
                     "result=ok",
                     seal::diag::kv("op", opId),
                     seal::diag::kv("record_count", recordCount),
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                refreshModel();
                if (isAutoLoad && m_ProtectedDecryptPending && m_ProtectFolderEnabled)
                {
                    m_ProtectedDecryptPending = false;
                    startProtectedFolderDecrypt(
                        [this, filePath, isAutoLoad, recordCount]()
                        {
                            finishVaultLoad(filePath, isAutoLoad, recordCount);
                            emit protectedFolderBootFinished();
                        });
                }
                else
                {
                    finishVaultLoad(filePath, isAutoLoad, recordCount);
                }
                return;
            }
            if (r.wrongPassword)
            {
                if (isAutoLoad && m_ProtectFolderEnabled && m_ProtectedDecryptPending &&
                    m_ProtectedPasswordVerified)
                {
                    // The folder profile already authenticated the session. A
                    // newly added vault with a different password is optional:
                    // replacing the folder key would strand the exit
                    // encryption. Continue folder-only and report the skip.
                    m_ProtectedDecryptPending = false;
                    setLoading(false);
                    startProtectedFolderDecrypt(
                        [this]()
                        {
                            setLoading(false);
                            emit errorOccurred(
                                QStringLiteral("Credential vault not loaded"),
                                QStringLiteral(
                                    "The SVH2 vault beside seal.exe uses a different password "
                                    "from .seal-folder-profile. Folder protection continued, "
                                    "but the vault was not loaded."));
                            emit protectedFolderBootFinished();
                        });
                    return;
                }

                // Wrong-password retry: wipe the bad password, clear
                // passwordSet, push a lambda that redoes this load to the front
                // of the queue so it runs before older intents, and signal QML
                // to re-show the dialog with an error hint.
                qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                    {"event=vault.load.finish",
                     "result=retry",
                     seal::diag::kv("op", opId),
                     "reason=wrong_password",
                     seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));
                m_Workspace.clearPassword();
                m_VerifiedVaultPath.clear();
                m_ProtectedPasswordVerified = false;
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
                 seal::diag::errorFields(detail),
                 seal::diag::kv("duration_ms", seal::diag::elapsedMs(started))}));

            if (isAutoLoad && m_ProtectFolderEnabled && m_ProtectedDecryptPending &&
                m_ProtectedPasswordVerified)
            {
                m_ProtectedDecryptPending = false;
                setLoading(false);
                const QString vaultError = r.message;
                startProtectedFolderDecrypt(
                    [this, vaultError]()
                    {
                        setLoading(false);
                        emit errorOccurred(
                            QStringLiteral("Credential vault not loaded"),
                            QStringLiteral(
                                "The optional SVH2 vault could not be loaded (%1). Folder "
                                "protection continued using .seal-folder-profile.")
                                .arg(vaultError));
                        emit protectedFolderBootFinished();
                    });
                return;
            }

            setLoading(false);
            emit errorOccurred("Error", QString("Failed to load vault: %1").arg(r.message));
            setStatus("Failed to load vault");
        });
}

void AppViewModel::finishVaultLoad(const QString& filePath, bool isAutoLoad, size_t recordCount)
{
    if (isAutoLoad)
    {
        setStatus(QString("Auto-loaded %1 account(s) from %2")
                      .arg(recordCount)
                      .arg(QFileInfo(filePath).fileName()));
    }
    else
    {
        setStatus(QString("Loaded %1 account(s) from vault").arg(recordCount));
    }
    setLoading(false);
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
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
        m_VerifiedVaultPath = normalizedAbsolutePath(fileName);

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
    // workspace records does not dangle once the records are cleared.
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
                        logAddAccountFailure(e.what(), true);
                        return;
                    }
                    seal::Cryptography::cleanseString(*secUser, *secPass);
                    finishAddAccount(service, true);
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
        logAddAccountFailure(e.what(), false);
        return;
    }

    seal::Cryptography::cleanseString(secUsername, secPassword);
    finishAddAccount(service, false);
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
        qCWarning(logBackend).noquote()
            << QString::fromStdString(seal::diag::joinFields({"event=vault.record.edit",
                                                              "result=fail",
                                                              seal::diag::kv("index", index),
                                                              seal::diag::errorFields(e.what())}));
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

QVariantMap AppViewModel::previewSiteBinding(const QString& service) const
{
    return previewSiteBinding(service, -1);
}

QVariantMap AppViewModel::previewSiteBinding(const QString& service, int excludedRecordIndex) const
{
    const QByteArray serviceUtf8 = service.trimmed().toUtf8();
    const std::string_view platform(serviceUtf8.constData(),
                                    static_cast<std::size_t>(serviceUtf8.size()));
    const auto preview = seal::previewSiteBinding(
        std::span<const seal::VaultRecord>(m_Workspace.records()), platform, excludedRecordIndex);

    const std::string extractedHost = seal::url::extractHost(platform);
    const bool publicSuffix =
        extractedHost.contains('.') && seal::url::isPublicSuffix(extractedHost);

    QVariantMap result;
    result.insert(QStringLiteral("bindable"), preview.m_Bindable);
    result.insert(QStringLiteral("host"), QString::fromStdString(preview.m_Host));
    result.insert(QStringLiteral("duplicateCount"),
                  QVariant::fromValue<qulonglong>(preview.m_DuplicateCount));
    result.insert(QStringLiteral("publicSuffix"), publicSuffix);

    QString suggestion;
    if (!preview.m_Bindable)
    {
        const std::string key = seal::url::extractKey(platform);
        if (!key.empty())
        {
            suggestion = QString::fromStdString(key + ".com");
        }
    }
    result.insert(QStringLiteral("suggestion"), suggestion);
    return result;
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

    // If nothing visible remains, re-emit the vault signals so the dependent
    // QML bindings re-evaluate and the empty-vault state renders. vaultLoaded()
    // itself stays true: the soft-deleted records are still in the workspace.
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

void AppViewModel::logAddAccountFailure(const char* what, bool deferred)
{
    qCWarning(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.add",
                                "result=fail",
                                deferred ? "deferred=true" : "deferred=false",
                                seal::diag::errorFields(what)}));
    emit errorOccurred("Error", QString("Failed to add account: %1").arg(what));
}

void AppViewModel::finishAddAccount(const QString& service, bool deferred)
{
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.record.add",
                                "result=ok",
                                deferred ? "deferred=true" : "deferred=false",
                                seal::diag::kv("total_records", m_Workspace.records().size()),
                                seal::diag::kv("service_len", service.size())}));
    refreshModel();
    setStatus("Account added");
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
}

void AppViewModel::reportMasterKeyUnavailable()
{
    qCWarning(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=auth.unlock", "result=fail", "reason=dpapi_unprotect"}));
    emit errorOccurred(QStringLiteral("Vault error"),
                       QStringLiteral("Could not access the master key."));
}

void AppViewModel::runDirectoryCrypto(
    const QString& dialogTitle,
    const char* opScope,
    int (*op)(const std::filesystem::path&,
              const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&),
    const char* eventName,
    const QString& verbPast)
{
    QString dirPath = seal::OpenFolderDialog(dialogTitle);
    if (dirPath.isEmpty())
        return;

    const std::string opId = seal::diag::nextOpId(opScope);
    const auto started = std::chrono::steady_clock::now();
    int count = 0;
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            reportMasterKeyUnavailable();
            return;
        }
        count = op(std::filesystem::path{dirPath.toStdWString()}, access.password());
    }
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({std::string("event=") + eventName,
                                "result=ok",
                                seal::diag::kv("op", opId),
                                seal::diag::kv("count", count),
                                seal::diag::kv("duration_ms", seal::diag::elapsedMs(started)),
                                seal::diag::pathSummary(dirPath.toUtf8().toStdString())}));
    setStatus(QString("%1 %2 file(s)").arg(verbPast).arg(count));
    emit infoMessage("Success", QString("%1 %2 file(s) in directory").arg(verbPast).arg(count));
}

void AppViewModel::encryptDirectory()
{
    if (!ensurePassword([this]() { encryptDirectory(); }))
    {
        return;
    }
    runDirectoryCrypto("Select Directory to Encrypt",
                       "dir_encrypt",
                       &seal::encryptDirectory,
                       "directory.encrypt.finish",
                       "Encrypted");
}

void AppViewModel::decryptDirectory()
{
    if (!ensurePassword([this]() { decryptDirectory(); }))
    {
        return;
    }
    runDirectoryCrypto("Select Directory to Decrypt",
                       "dir_decrypt",
                       &seal::decryptDirectory,
                       "directory.decrypt.finish",
                       "Decrypted");
}

QString AppViewModel::protectFolderSettingKey(const QString& executableDirectory)
{
    const QString normalized =
        QDir::toNativeSeparators(QDir::cleanPath(executableDirectory)).toLower();
    const QByteArray digest =
        QCryptographicHash::hash(normalized.toUtf8(), QCryptographicHash::Sha256).toHex();
    return QStringLiteral("security/protectFolder/%1").arg(QString::fromLatin1(digest));
}

QString AppViewModel::protectedFolderMarkerPath() const
{
    const protected_folder::PolicyContext context;
    return QDir(m_ProtectedFolderRoot)
        .filePath(QString::fromStdWString(context.markerRelativePath.wstring()));
}

QString AppViewModel::protectedFolderProfilePath() const
{
    return QDir(m_ProtectedFolderRoot)
        .filePath(QString::fromStdWString(std::wstring{kProtectedFolderProfileFileName}));
}

bool AppViewModel::writeProtectedFolderMarker() const
{
    QSaveFile marker(protectedFolderMarkerPath());
    if (!marker.open(QIODevice::WriteOnly | QIODevice::Text))
    {
        return false;
    }
    static constexpr char kMarkerContents[] =
        "seal protected-folder plaintext session; remove only after re-protection\n";
    if (marker.write(kMarkerContents, static_cast<qint64>(sizeof(kMarkerContents) - 1)) < 0)
    {
        marker.cancelWriting();
        return false;
    }
    return marker.commit();
}

bool AppViewModel::removeProtectedFolderMarker() const
{
    const QString marker = protectedFolderMarkerPath();
    return !QFileInfo::exists(marker) || QFile::remove(marker);
}

void AppViewModel::requestProtectFolderEnabled(bool enabled)
{
    if (m_CleanupStarted || enabled == m_ProtectFolderEnabled)
    {
        return;
    }
    if (m_Busy || m_LoadWorkerActive)
    {
        emit errorOccurred(QStringLiteral("Folder protection"),
                           QStringLiteral("Wait for the current operation to finish first."));
        return;
    }

    if (!enabled)
    {
        const ProtectedFolderScan scan =
            scanProtectedFolder(std::filesystem::path{m_ProtectedFolderRoot.toStdWString()});
        const protected_folder::FolderPlan encryptedPayloads =
            protected_folder::planDecrypt(scan.entries, protected_folder::PolicyContext{});
        if (scan.failures != 0 || !encryptedPayloads.act.empty())
        {
            emit errorOccurred(
                QStringLiteral("Cannot turn off folder protection"),
                scan.failures != 0
                    ? QStringLiteral(
                          "seal could not verify every folder entry. Protection remains armed.")
                    : QStringLiteral(
                          "%1 protected payload file(s) are still encrypted. Relaunch and "
                          "unlock the folder successfully before turning protection off.")
                          .arg(encryptedPayloads.act.size()));
            return;
        }

        QSettings settings;
        settings.setValue(m_ProtectFolderSettingKey, false);
        settings.sync();
        if (settings.status() != QSettings::NoError)
        {
            emit errorOccurred(QStringLiteral("Folder protection"),
                               QStringLiteral("Could not persist the disabled setting."));
            return;
        }

        m_ProtectFolderEnabled = false;
        m_ProtectedDecryptPending = false;
        m_AutoEncryptDirectory.clear();
        m_ProtectFolderPreflightPath.clear();
        if (!removeProtectedFolderMarker())
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=folder_protection.marker.remove", "result=fail", "reason=remove_failed"}));
        }
        setStatus(QStringLiteral(
            "Folder protection off - files will remain decrypted; folder profile retained"));
        emit protectFolderEnabledChanged();
        return;
    }

    const std::filesystem::path root{m_ProtectedFolderRoot.toStdWString()};
    const ProtectedFolderScan scan = scanProtectedFolder(root);
    if (scan.failures != 0)
    {
        emit errorOccurred(
            QStringLiteral("Cannot arm folder protection"),
            QStringLiteral("The deployment preflight could not inspect %1 folder entr%2.")
                .arg(scan.failures)
                .arg(scan.failures == 1 ? QStringLiteral("y") : QStringLiteral("ies")));
        return;
    }

    const protected_folder::PolicyContext context;
    if (!protected_folder::deploymentPreflightPasses(scan.entries, context))
    {
        emit errorOccurred(
            QStringLiteral("Cannot arm folder protection"),
            QStringLiteral(
                "Qt6Core.dll is beside seal.exe, so this is a dynamic Qt deployment whose "
                "runtime is interleaved with your files. Use a --static portable build before "
                "arming this folder."));
        return;
    }

    const std::vector<protected_folder::OutputConflict> conflicts =
        protected_folder::findEncryptOutputConflicts(scan.entries, context);
    if (!conflicts.empty())
    {
        QStringList examples;
        constexpr std::size_t kMaximumExamples = 5;
        for (std::size_t i = 0; i < std::min(conflicts.size(), kMaximumExamples); ++i)
        {
            examples.push_back(QStringLiteral("%1 -> %2")
                                   .arg(displayRelativePath(conflicts[i].source.relativePath),
                                        displayRelativePath(conflicts[i].occupied.relativePath)));
        }
        if (conflicts.size() > kMaximumExamples)
        {
            examples.push_back(
                QStringLiteral("...and %1 more").arg(conflicts.size() - kMaximumExamples));
        }
        emit errorOccurred(
            QStringLiteral("Cannot arm folder protection"),
            QStringLiteral(
                "%1 planned encrypted output or staging path(s) already exist. Rename or "
                "remove the conflicting sibling before arming:\n\n%2")
                .arg(conflicts.size())
                .arg(examples.join(QLatin1Char('\n'))));
        return;
    }

    const std::filesystem::path profilePath{protectedFolderProfilePath().toStdWString()};
    const ProtectedFolderProfileInspection profile = inspectProtectedFolderProfile(profilePath);
    if (profile.state == ProtectedFolderProfileState::Invalid)
    {
        emit errorOccurred(QStringLiteral("Cannot arm folder protection"),
                           QStringLiteral("The existing .seal-folder-profile is invalid: %1")
                               .arg(QString::fromUtf8(profile.message)));
        return;
    }

    const protected_folder::FolderPlan encryptedPayloads =
        protected_folder::planDecrypt(scan.entries, context);
    if (profile.state == ProtectedFolderProfileState::Missing && !encryptedPayloads.act.empty())
    {
        emit errorOccurred(
            QStringLiteral("Cannot arm folder protection"),
            QStringLiteral(
                "%1 encrypted payload file(s) were found, but .seal-folder-profile is "
                "missing. Those files are a recovery hint, not enough to establish the "
                "password safely. Restore the profile or manually decrypt the files first.")
                .arg(encryptedPayloads.act.size()));
        return;
    }

    const ProtectedFolderPreview preview = makeProtectedFolderPreview(scan.entries, context);
    m_ProtectFolderPreflightPath = m_ProtectedFolderRoot;
    m_ProtectFolderPreflightProfileExists = profile.state == ProtectedFolderProfileState::Valid;
    if (m_ProtectFolderPreflightProfileExists)
    {
        m_ProtectFolderPasswordMode =
            m_Workspace.isPasswordSet() && m_ProtectedPasswordVerified ? 0 : 2;
    }
    else
    {
        // A non-empty loaded vault authenticated the current session key. An
        // empty vault has no encrypted record and therefore cannot detect a
        // typo, so fresh folder-only setup still requires confirmation.
        const bool authenticatedVaultPassword = m_Workspace.isPasswordSet() &&
                                                !m_VerifiedVaultPath.isEmpty() &&
                                                !m_Workspace.records().empty();
        m_ProtectFolderPasswordMode = authenticatedVaultPassword ? 0 : 1;
    }
    m_ProtectFolderEncryptFiles = preview.encryptFiles;
    m_ProtectFolderSkippedFiles = preview.skippedFiles;
    m_ProtectFolderTotalBytes = preview.totalBytes;
    emit protectFolderPreflightChanged();
    emit protectFolderPreflightReady();
}

void AppViewModel::confirmProtectFolderEnabled(QString password, QString confirmation)
{
    auto wipeInputs = [&password, &confirmation]()
    {
        password.fill(QChar(0));
        confirmation.fill(QChar(0));
    };

    if (m_ProtectFolderEnabled ||
        !sameWindowsPath(m_ProtectFolderPreflightPath, m_ProtectedFolderRoot))
    {
        wipeInputs();
        return;
    }
    if (m_Busy || m_LoadWorkerActive)
    {
        wipeInputs();
        emit errorOccurred(QStringLiteral("Cannot arm folder protection"),
                           QStringLiteral("Wait for the current operation to finish, then run "
                                          "the preflight again."));
        return;
    }

    const std::filesystem::path root{m_ProtectedFolderRoot.toStdWString()};
    const std::filesystem::path profilePath{protectedFolderProfilePath().toStdWString()};
    const ProtectedFolderScan scan = scanProtectedFolder(root);
    const protected_folder::PolicyContext context;
    const ProtectedFolderProfileInspection profile = inspectProtectedFolderProfile(profilePath);
    if (scan.failures != 0 || !protected_folder::deploymentPreflightPasses(scan.entries, context) ||
        !protected_folder::findEncryptOutputConflicts(scan.entries, context).empty() ||
        profile.state == ProtectedFolderProfileState::Invalid ||
        (profile.state == ProtectedFolderProfileState::Valid) !=
            m_ProtectFolderPreflightProfileExists)
    {
        wipeInputs();
        emit errorOccurred(
            QStringLiteral("Cannot arm folder protection"),
            QStringLiteral("The deployment changed after the preview. Run the preflight again."));
        return;
    }

    const ProtectedFolderPreview preview = makeProtectedFolderPreview(scan.entries, context);
    if (preview.encryptFiles != m_ProtectFolderEncryptFiles ||
        preview.skippedFiles != m_ProtectFolderSkippedFiles ||
        preview.totalBytes != m_ProtectFolderTotalBytes)
    {
        wipeInputs();
        emit errorOccurred(
            QStringLiteral("Cannot arm folder protection"),
            QStringLiteral("The folder contents changed after the preview. Run it again."));
        return;
    }

    ProtectedFolderPassword candidate;
    bool adoptCandidate = false;
    if (m_ProtectFolderPasswordMode == 0)
    {
        wipeInputs();
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            emit errorOccurred(QStringLiteral("Cannot arm folder protection"),
                               QStringLiteral("The current master password is unavailable. Run "
                                              "the preflight again."));
            return;
        }
        candidate.assign(access.password().begin(), access.password().end());
    }
    else
    {
        candidate = qstringToSecureWide(password);
        ProtectedFolderPassword confirmed;
        if (m_ProtectFolderPasswordMode == 1)
        {
            confirmed = qstringToSecureWide(confirmation);
        }
        wipeInputs();

        if (candidate.empty())
        {
            Cryptography::cleanseString(confirmed);
            emit errorOccurred(QStringLiteral("Cannot arm folder protection"),
                               QStringLiteral("Enter a non-empty folder password."));
            return;
        }
        if (m_ProtectFolderPasswordMode == 1 && !secureWideEqual(candidate, confirmed))
        {
            Cryptography::cleanseString(candidate, confirmed);
            emit errorOccurred(QStringLiteral("Cannot arm folder protection"),
                               QStringLiteral("The folder passwords do not match."));
            return;
        }
        Cryptography::cleanseString(confirmed);
        adoptCandidate = true;
    }

    const bool profileExisted = m_ProtectFolderPreflightProfileExists;
    auto workerPassword = std::make_shared<ProtectedFolderPassword>(std::move(candidate));
    auto adoptedPassword = std::make_shared<ProtectedFolderPassword>();
    if (adoptCandidate)
    {
        adoptedPassword->assign(workerPassword->begin(), workerPassword->end());
    }

    setBusy(true);
    setLoading(true,
               profileExisted ? QStringLiteral("Verifying folder password...")
                              : QStringLiteral("Creating folder password profile..."));

    m_Async.run(
        this,
        [profilePath, profileExisted, workerPassword]() -> FolderProfileOperationOutcome
        {
            FolderProfileOperationOutcome outcome;
            if (profileExisted)
            {
                const ProtectedFolderProfileVerifyResult verified =
                    verifyProtectedFolderProfile(profilePath, *workerPassword);
                outcome.ok = verified.result == ProtectedFolderProfileVerification::Verified;
                outcome.wrongPassword =
                    verified.result == ProtectedFolderProfileVerification::WrongPassword;
                outcome.message = QString::fromStdString(verified.message);
            }
            else
            {
                std::string error;
                outcome.ok = createProtectedFolderProfile(profilePath, *workerPassword, &error);
                outcome.message = QString::fromStdString(error);
            }
            Cryptography::cleanseString(*workerPassword);
            return outcome;
        },
        [this, profileExisted, adoptCandidate, adoptedPassword](
            FolderProfileOperationOutcome outcome)
        {
            setBusy(false);
            setLoading(false);

            if (!outcome.ok)
            {
                Cryptography::cleanseString(*adoptedPassword);
                emit errorOccurred(
                    QStringLiteral("Cannot arm folder protection"),
                    outcome.wrongPassword
                        ? QStringLiteral("Wrong folder password. Run the preflight and try again.")
                        : QStringLiteral("Could not prepare .seal-folder-profile: %1")
                              .arg(outcome.message));
                return;
            }

            const std::filesystem::path root{m_ProtectedFolderRoot.toStdWString()};
            const ProtectedFolderScan latestScan = scanProtectedFolder(root);
            const protected_folder::PolicyContext context;
            const ProtectedFolderPreview latest =
                makeProtectedFolderPreview(latestScan.entries, context);
            QStringList comparableSkipped = latest.skippedFiles;
            if (!profileExisted)
            {
                const QString profilePrefix =
                    QString::fromStdWString(std::wstring{kProtectedFolderProfileFileName}) +
                    QStringLiteral(" - ");
                comparableSkipped.removeIf(
                    [&profilePrefix](const QString& value)
                    { return value.startsWith(profilePrefix, Qt::CaseInsensitive); });
            }

            const bool deploymentStillSafe =
                latestScan.failures == 0 &&
                protected_folder::deploymentPreflightPasses(latestScan.entries, context) &&
                protected_folder::findEncryptOutputConflicts(latestScan.entries, context).empty();
            const bool contentsStillMatch = latest.encryptFiles == m_ProtectFolderEncryptFiles &&
                                            comparableSkipped == m_ProtectFolderSkippedFiles &&
                                            latest.totalBytes == m_ProtectFolderTotalBytes;
            if (!deploymentStillSafe || !contentsStillMatch)
            {
                if (!profileExisted)
                {
                    (void)QFile::remove(protectedFolderProfilePath());
                }
                Cryptography::cleanseString(*adoptedPassword);
                emit errorOccurred(
                    QStringLiteral("Cannot arm folder protection"),
                    QStringLiteral(
                        "The folder changed while its password profile was being prepared. "
                        "Run the preflight again."));
                return;
            }

            const bool markerAlreadyExisted = QFileInfo::exists(protectedFolderMarkerPath());
            if (!writeProtectedFolderMarker())
            {
                if (!profileExisted)
                {
                    (void)QFile::remove(protectedFolderProfilePath());
                }
                Cryptography::cleanseString(*adoptedPassword);
                emit errorOccurred(
                    QStringLiteral("Cannot arm folder protection"),
                    QStringLiteral("Could not create the plaintext-session safety marker."));
                return;
            }

            QSettings settings;
            settings.setValue(m_ProtectFolderSettingKey, true);
            settings.sync();
            if (settings.status() != QSettings::NoError)
            {
                if (!markerAlreadyExisted)
                {
                    (void)removeProtectedFolderMarker();
                }
                if (!profileExisted)
                {
                    (void)QFile::remove(protectedFolderProfilePath());
                }
                Cryptography::cleanseString(*adoptedPassword);
                emit errorOccurred(QStringLiteral("Cannot arm folder protection"),
                                   QStringLiteral("Could not persist the per-folder setting."));
                return;
            }

            if (adoptCandidate)
            {
                cancelFillIfArmed();
                m_Workspace.adoptPassword(std::move(*adoptedPassword));
                m_VerifiedVaultPath.clear();
                emit passwordSetChanged();
            }
            else
            {
                Cryptography::cleanseString(*adoptedPassword);
            }

            m_ProtectedPasswordVerified = true;
            m_ProtectFolderEnabled = true;
            m_AutoEncryptDirectory = m_ProtectedFolderRoot;
            setStatus(
                QStringLiteral("Folder protection armed - files will be re-protected on exit"));
            emit protectFolderEnabledChanged();

            const protected_folder::FolderPlan encryptedPayloads =
                protected_folder::planDecrypt(latestScan.entries, context);
            if (!encryptedPayloads.act.empty())
            {
                startProtectedFolderDecrypt([this]() { setLoading(false); });
            }
        });
}

void AppViewModel::autoLoadVault()
{
    if (!m_CurrentVaultPath.isEmpty())
        return;

    // An armed folder is self-contained. Its profile is the folder-password
    // authority; a credential vault beside seal.exe is optional and is only
    // auto-loaded after that profile succeeds. Unarmed startup uses the
    // exe-dir -> cwd -> home priority.
    QStringList searchPaths;
    if (m_ProtectFolderEnabled)
    {
        if (QFileInfo::exists(QDir(m_ProtectedFolderRoot).filePath(QStringLiteral("Qt6Core.dll"))))
        {
            setStatus(QStringLiteral(
                "Folder protection blocked - dynamic Qt runtime detected beside seal.exe"));
            emit errorOccurred(
                QStringLiteral("Folder protection blocked"),
                QStringLiteral(
                    "Qt6Core.dll is now beside seal.exe. Automatic folder decryption was "
                    "stopped because this is no longer a static portable deployment."));
            return;
        }

        const ProtectedFolderProfileInspection profile = inspectProtectedFolderProfile(
            std::filesystem::path{protectedFolderProfilePath().toStdWString()});
        if (profile.state == ProtectedFolderProfileState::Invalid)
        {
            setStatus(QStringLiteral("Folder protection blocked - folder profile is invalid"));
            emit errorOccurred(QStringLiteral("Folder protection blocked"),
                               QStringLiteral(".seal-folder-profile is invalid: %1")
                                   .arg(QString::fromStdString(profile.message)));
            return;
        }
        searchPaths << m_ProtectedFolderRoot;
    }
    else
    {
        searchPaths << QCoreApplication::applicationDirPath() << QDir::currentPath()
                    << QDir::homePath();
    }

    QString foundVaultPath;
    std::size_t protectedVaultCount = 0;

    for (const QString& searchPath : searchPaths)
    {
        QDir dir(searchPath);
        const QFileInfoList files =
            dir.entryInfoList(QStringList() << QStringLiteral("*.seal") << QStringLiteral(".seal"),
                              QDir::Files,
                              QDir::Name | QDir::IgnoreCase);
        std::vector<VaultCandidate> candidates;
        candidates.reserve(static_cast<std::size_t>(files.size()));
        for (const QFileInfo& file : files)
        {
            const QString absolutePath = file.absoluteFilePath();
            const std::filesystem::path candidatePath{absolutePath.toStdWString()};
            candidates.push_back(
                {candidatePath, !file.isSymLink() && looksLikeVault(candidatePath)});
        }

        if (m_ProtectFolderEnabled)
        {
            protectedVaultCount = static_cast<std::size_t>(std::ranges::count_if(
                candidates, [](const VaultCandidate& candidate) { return candidate.vault; }));
            if (protectedVaultCount > 1)
            {
                // Folder protection itself is unambiguous because the profile
                // owns its password. Avoid guessing which credential vault to
                // show; startup continues in folder-only mode.
                candidates.clear();
            }
        }

        const std::filesystem::path selected = selectVaultCandidate(candidates);
        if (!selected.empty())
        {
            foundVaultPath = QString::fromStdWString(selected.wstring());
        }
        if (!foundVaultPath.isEmpty())
            break;
    }

    if (m_ProtectFolderEnabled)
    {
        const ProtectedFolderProfileInspection profile = inspectProtectedFolderProfile(
            std::filesystem::path{protectedFolderProfilePath().toStdWString()});
        if (profile.state == ProtectedFolderProfileState::Missing && foundVaultPath.isEmpty())
        {
            setStatus(QStringLiteral("Folder protection blocked - folder profile is missing"));
            emit errorOccurred(
                QStringLiteral("Folder protection blocked"),
                QStringLiteral(
                    ".seal-folder-profile is missing. Encrypted files alone cannot safely "
                    "identify the folder password. Restore the profile, or restore the former "
                    "SVH2 vault once so seal can migrate this legacy armed folder."));
            return;
        }

        if (protectedVaultCount > 1)
        {
            qCWarning(logBackend).noquote() << QString::fromStdString(
                seal::diag::joinFields({"event=vault.autoload.scan",
                                        "result=ambiguous",
                                        seal::diag::kv("vault_count", protectedVaultCount),
                                        "folder_profile_authority=true"}));
        }

        m_ProtectedDecryptPending = !foundVaultPath.isEmpty();
        if (!ensurePassword([this, foundVaultPath]()
                            { startProtectedFolderUnlock(foundVaultPath); }))
        {
            return;
        }
        startProtectedFolderUnlock(foundVaultPath);
        return;
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

void AppViewModel::startProtectedFolderUnlock(const QString& optionalVaultPath)
{
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

    if (!ensurePassword([this, optionalVaultPath]()
                        { startProtectedFolderUnlock(optionalVaultPath); }))
    {
        return;
    }

    auto workerPassword = std::make_shared<SecureWide>();
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            reportMasterKeyUnavailable();
            emit protectedFolderBootFinished();
            return;
        }
        workerPassword->assign(access.password().begin(), access.password().end());
    }

    const std::filesystem::path profilePath{protectedFolderProfilePath().toStdWString()};
    const std::filesystem::path legacyVaultPath{optionalVaultPath.toStdWString()};
    setBusy(true);
    setLoading(true, QStringLiteral("Verifying folder password..."));

    m_Async.run(
        this,
        [profilePath, legacyVaultPath, workerPassword]() -> FolderProfileOperationOutcome
        {
            FolderProfileOperationOutcome outcome;
            const ProtectedFolderProfileInspection profile =
                inspectProtectedFolderProfile(profilePath);
            if (profile.state == ProtectedFolderProfileState::Valid)
            {
                const ProtectedFolderProfileVerifyResult verified =
                    verifyProtectedFolderProfile(profilePath, *workerPassword);
                outcome.ok = verified.result == ProtectedFolderProfileVerification::Verified;
                outcome.wrongPassword =
                    verified.result == ProtectedFolderProfileVerification::WrongPassword;
                outcome.message = QString::fromStdString(verified.message);
            }
            else if (profile.state == ProtectedFolderProfileState::Missing &&
                     !legacyVaultPath.empty())
            {
                // Migration path for an armed folder that still has no
                // profile: the vault beside seal.exe authenticates the entered
                // key, and the new profile becomes the authority before any
                // file is decrypted.
                try
                {
                    const std::vector<VaultRecord> legacyRecords =
                        loadVaultIndex(legacyVaultPath, *workerPassword);
                    if (legacyRecords.empty())
                    {
                        outcome.message = QStringLiteral(
                            "The legacy vault is empty, so it cannot authenticate a password. "
                            "Disarm and arm again to create a confirmed folder password.");
                        Cryptography::cleanseString(*workerPassword);
                        return outcome;
                    }
                    std::string error;
                    outcome.ok = createProtectedFolderProfile(profilePath, *workerPassword, &error);
                    outcome.message = QString::fromStdString(error);
                }
                catch (const std::exception& error)
                {
                    outcome.wrongPassword = std::string_view{error.what()} == "Wrong password";
                    outcome.message = QString::fromUtf8(error.what());
                }
            }
            else
            {
                outcome.message =
                    QStringLiteral("The protected-folder profile is missing or invalid.");
            }
            Cryptography::cleanseString(*workerPassword);
            return outcome;
        },
        [this, optionalVaultPath](FolderProfileOperationOutcome outcome)
        {
            setBusy(false);
            if (!outcome.ok)
            {
                setLoading(false);
                m_ProtectedPasswordVerified = false;
                if (outcome.wrongPassword)
                {
                    m_Workspace.clearPassword();
                    m_VerifiedVaultPath.clear();
                    emit passwordSetChanged();
                    m_PendingActions.push_front([this, optionalVaultPath]()
                                                { startProtectedFolderUnlock(optionalVaultPath); });
                    setStatus(QStringLiteral("Wrong password - protected folder remains sealed"));
                    emit passwordRetryRequired(
                        QStringLiteral("Wrong folder password - try again."));
                    return;
                }

                setStatus(
                    QStringLiteral("Folder protection blocked - profile verification failed"));
                emit errorOccurred(QStringLiteral("Folder protection blocked"),
                                   QStringLiteral("Could not verify .seal-folder-profile: %1")
                                       .arg(outcome.message));
                emit protectedFolderBootFinished();
                return;
            }

            m_ProtectedPasswordVerified = true;
            if (!optionalVaultPath.isEmpty())
            {
                m_ProtectedDecryptPending = true;
                loadVaultFromPath(optionalVaultPath, true);
                return;
            }

            m_ProtectedDecryptPending = false;
            startProtectedFolderDecrypt(
                [this]()
                {
                    setLoading(false);
                    emit protectedFolderBootFinished();
                });
        });
}

void AppViewModel::startProtectedFolderDecrypt(std::function<void()> done)
{
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

    if (!ensurePassword([this, done]() mutable { startProtectedFolderDecrypt(std::move(done)); }))
    {
        return;
    }

    auto workerPassword = std::make_shared<SecureWide>();
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            m_ProtectedBootDecryptFailures = 1;
            writeProtectedFolderMarker();
            reportMasterKeyUnavailable();
            done();
            setStatus(QStringLiteral(
                "Folder protection armed - automatic decrypt could not access the master key"));
            return;
        }
        workerPassword->assign(access.password().begin(), access.password().end());
    }

    const std::filesystem::path root{m_AutoEncryptDirectory.toStdWString()};
    // Write before the first plaintext commit, not after the worker: this also
    // covers a process death midway through a multi-file decrypt.
    if (!writeProtectedFolderMarker())
    {
        seal::Cryptography::cleanseString(*workerPassword);
        m_ProtectedBootDecryptFailures = 1;
        done();
        setStatus(QStringLiteral(
            "Folder protection armed - automatic decrypt blocked (marker unavailable)"));
        emit errorOccurred(
            QStringLiteral("Folder protection warning"),
            QStringLiteral(
                "seal could not create the plaintext-session safety marker, so automatic "
                "folder decryption was stopped."));
        return;
    }

    setBusy(true);
    setLoading(true, QStringLiteral("Decrypting protected files..."));

    m_Async.run(
        this,
        [root, workerPassword]() -> ProtectedFolderOutcome
        {
            ProtectedFolderOutcome outcome =
                runProtectedFolderPlan(root, *workerPassword, /*encrypt=*/false);
            seal::Cryptography::cleanseString(*workerPassword);
            return outcome;
        },
        [this, done = std::move(done)](ProtectedFolderOutcome outcome)
        {
            m_ProtectedBootDecryptFailures = outcome.process.failed + outcome.scanFailures;
            setBusy(false);

            const std::size_t decrypted = outcome.process.succeeded;
            const std::size_t failures = m_ProtectedBootDecryptFailures;
            done();

            if (m_UncleanProtectedSession)
            {
                setStatus(
                    failures == 0
                        ? QStringLiteral(
                              "Folder protection armed - previous session ended uncleanly; "
                              "files may have been plaintext")
                        : QStringLiteral(
                              "Folder protection armed - unclean prior exit; %1 file(s) could "
                              "not be decrypted")
                              .arg(failures));
            }
            else if (failures != 0)
            {
                setStatus(
                    QStringLiteral("Folder protection armed - %1 file(s) could not be decrypted")
                        .arg(failures));
            }
            else
            {
                setStatus(QStringLiteral("Folder protection armed - decrypted %1 file(s)")
                              .arg(decrypted));
            }

            qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=folder_protection.boot_decrypt.finish",
                 failures == 0 ? "result=ok" : "result=partial",
                 seal::diag::kv("count", decrypted),
                 seal::diag::kv("failed", failures),
                 seal::diag::kv("unclean_previous_session", m_UncleanProtectedSession)}));
        });
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
    if (m_Destroying)
    {
        return;
    }
    if (m_CleanupCompleted)
    {
        emit cleanupFinished();
        return;
    }
    if (m_CleanupStarted)
    {
        return;
    }
    if (m_ProtectFolderEnabled && (m_LoadWorkerActive || m_Busy))
    {
        emit errorOccurred(QStringLiteral("Folder protection"),
                           QStringLiteral("Wait for the current operation to finish, then close "
                                          "seal again so the folder can be re-protected."));
        return;
    }

    m_CleanupStarted = true;

    // Cancel any in-flight QR capture first so its token-polling OpenCV frame
    // loop aborts promptly, instead of waiting for ~AsyncRunner to cancel
    // everything after exec() returns. A no-op when no QR capture ever ran.
    m_QrHandle.cancel();

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.cleanup.begin", "result=start"}));

    if (m_Fill)
    {
        m_Fill->cancelIfArmed();
    }

    if (!m_ProtectFolderEnabled || m_AutoEncryptDirectory.isEmpty())
    {
        finishCleanup();
        return;
    }

    continueExitProtection();
}

void AppViewModel::continueExitProtection()
{
    if (!m_Workspace.isPasswordSet())
    {
        if (!ensurePassword([this]() { continueExitProtection(); }))
        {
            setStatus(QStringLiteral("Unlock to re-protect the folder before exit"));
            return;
        }
    }

    if (m_ProtectedPasswordVerified)
    {
        startExitEncryption();
    }
    else
    {
        verifyExitPassword();
    }
}

void AppViewModel::verifyExitPassword()
{
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

    auto workerPassword = std::make_shared<SecureWide>();
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            failCleanup(QStringLiteral("Could not access the master key."));
            return;
        }
        workerPassword->assign(access.password().begin(), access.password().end());
    }

    const std::filesystem::path profilePath{protectedFolderProfilePath().toStdWString()};
    setBusy(true);
    setLoading(true, QStringLiteral("Verifying folder password..."));

    m_Async.run(
        this,
        [profilePath, workerPassword]() -> PasswordVerificationOutcome
        {
            PasswordVerificationOutcome outcome;
            const ProtectedFolderProfileVerifyResult verified =
                verifyProtectedFolderProfile(profilePath, *workerPassword);
            outcome.ok = verified.result == ProtectedFolderProfileVerification::Verified;
            outcome.wrongPassword =
                verified.result == ProtectedFolderProfileVerification::WrongPassword;
            outcome.message = QString::fromStdString(verified.message);
            seal::Cryptography::cleanseString(*workerPassword);
            return outcome;
        },
        [this](PasswordVerificationOutcome outcome)
        {
            if (outcome.ok)
            {
                m_ProtectedPasswordVerified = true;
                startExitEncryption();
                return;
            }

            setBusy(false);
            setLoading(false);
            if (outcome.wrongPassword)
            {
                m_Workspace.clearPassword();
                m_VerifiedVaultPath.clear();
                m_ProtectedPasswordVerified = false;
                emit passwordSetChanged();
                m_PendingActions.push_front([this]() { continueExitProtection(); });
                setStatus(QStringLiteral("Wrong password - unlock to re-protect before exit"));
                emit passwordRetryRequired(
                    QStringLiteral("Wrong password - required to re-protect files before exit."));
                return;
            }

            failCleanup(
                QStringLiteral("Could not verify .seal-folder-profile: %1").arg(outcome.message));
        });
}

void AppViewModel::startExitEncryption()
{
    using SecureWide = seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>;

    const ProtectedFolderProfileInspection profile = inspectProtectedFolderProfile(
        std::filesystem::path{protectedFolderProfilePath().toStdWString()});
    if (profile.state != ProtectedFolderProfileState::Valid)
    {
        failCleanup(QStringLiteral(
            ".seal-folder-profile is missing or invalid. Restore it before closing so "
            "encrypted files are not orphaned."));
        return;
    }

    auto workerPassword = std::make_shared<SecureWide>();
    {
        auto access = m_Workspace.session().unlock();
        if (!access.ok())
        {
            failCleanup(QStringLiteral("Could not access the master key."));
            return;
        }
        workerPassword->assign(access.password().begin(), access.password().end());
    }

    const std::filesystem::path root{m_AutoEncryptDirectory.toStdWString()};
    setBusy(true);
    setLoading(true, QStringLiteral("Re-protecting files..."));
    setStatus(QStringLiteral("Re-protecting files before exit..."));

    m_Async.run(
        this,
        [root, workerPassword]() -> ProtectedFolderOutcome
        {
            ProtectedFolderOutcome outcome =
                runProtectedFolderPlan(root, *workerPassword, /*encrypt=*/true);
            seal::Cryptography::cleanseString(*workerPassword);
            return outcome;
        },
        [this](ProtectedFolderOutcome outcome)
        {
            const std::size_t failures = outcome.process.failed + outcome.scanFailures;
            if (failures != 0)
            {
                qCWarning(logBackend).noquote() << QString::fromStdString(
                    seal::diag::joinFields({"event=app.cleanup.auto_encrypt.finish",
                                            "result=partial",
                                            seal::diag::kv("count", outcome.process.succeeded),
                                            seal::diag::kv("failed", failures)}));
                failCleanup(
                    QStringLiteral(
                        "Re-protection was incomplete: %1 file(s) failed. The plaintext marker "
                        "was retained and the window will stay open. Resolve the file error and "
                        "close again to retry.")
                        .arg(failures));
                return;
            }

            const bool markerRemoved = removeProtectedFolderMarker();
            qCInfo(logBackend).noquote() << QString::fromStdString(seal::diag::joinFields(
                {"event=app.cleanup.auto_encrypt.finish",
                 "result=ok",
                 seal::diag::kv("count", outcome.process.succeeded),
                 seal::diag::kv("marker_removed", markerRemoved),
                 seal::diag::pathSummary(m_AutoEncryptDirectory.toUtf8().toStdString())}));
            setStatus(QStringLiteral("Re-protected %1 file(s)").arg(outcome.process.succeeded));
            finishCleanup();
        });
}

void AppViewModel::failCleanup(const QString& message)
{
    setBusy(false);
    setLoading(false);
    m_CleanupStarted = false;
    setStatus(QStringLiteral("Re-protection incomplete - close blocked"));
    emit errorOccurred(QStringLiteral("Folder protection incomplete"), message);
}

void AppViewModel::finishCleanup()
{
    // Wipe the master password from locked memory only after folder
    // re-protection is complete (or immediately when protection is off).
    if (m_Workspace.isPasswordSet())
    {
        m_Workspace.clearPassword();
        m_VerifiedVaultPath.clear();
        m_ProtectedPasswordVerified = false;
        emit passwordSetChanged();
    }
    m_PendingActions.clear();
    setBusy(false);
    setLoading(false);
    seal::Cryptography::trimWorkingSet();
    m_CleanupCompleted = true;
    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=app.cleanup.finish", "result=ok"}));
    emit cleanupFinished();
}

void AppViewModel::lockVault()
{
    if (!m_Workspace.isPasswordSet())
        return;

    qCInfo(logBackend).noquote() << QString::fromStdString(
        seal::diag::joinFields({"event=vault.lock", "result=ok"}));
    cancelFillIfArmed();
    m_Workspace.clearPassword();
    m_VerifiedVaultPath.clear();
    m_ProtectedPasswordVerified = false;
    emit passwordSetChanged();
    setStatus("Vault locked - password required for next action");
}

void AppViewModel::rekeyVault(QString currentPassword, QString newPassword)
{
    const bool rekeyFolderOnly = m_ProtectFolderEnabled && m_CurrentVaultPath.isEmpty();
    if ((!rekeyFolderOnly && m_CurrentVaultPath.isEmpty()) || m_Busy)
    {
        // Scrub the plaintext parameters before the early return: every path
        // out of this method wipes them, including this one.
        currentPassword.fill(QChar(0));
        newPassword.fill(QChar(0));
        emit rekeyFinished(
            false,
            QStringLiteral("No vault or armed folder profile is available, or an operation is "
                           "already in progress."));
        return;
    }
    if (m_ProtectFolderEnabled && m_ProtectedBootDecryptFailures != 0)
    {
        currentPassword.fill(QChar(0));
        newPassword.fill(QChar(0));
        emit rekeyFinished(
            false,
            QStringLiteral(
                "Rekey is blocked while folder protection is armed because %1 file(s) failed "
                "to decrypt at boot. Re-protect/recover those files before changing the master "
                "password.")
                .arg(m_ProtectedBootDecryptFailures));
        return;
    }
    if (m_ProtectFolderEnabled)
    {
        const ProtectedFolderProfileInspection profile = inspectProtectedFolderProfile(
            std::filesystem::path{protectedFolderProfilePath().toStdWString()});
        if (profile.state != ProtectedFolderProfileState::Valid)
        {
            currentPassword.fill(QChar(0));
            newPassword.fill(QChar(0));
            emit rekeyFinished(
                false,
                QStringLiteral(
                    "Rekey is blocked because .seal-folder-profile is missing or invalid."));
            return;
        }

        const ProtectedFolderScan scan =
            scanProtectedFolder(std::filesystem::path{m_AutoEncryptDirectory.toStdWString()});
        const protected_folder::FolderPlan decryptPlan =
            protected_folder::planDecrypt(scan.entries, protected_folder::PolicyContext{});
        if (scan.failures != 0 || !decryptPlan.act.empty())
        {
            currentPassword.fill(QChar(0));
            newPassword.fill(QChar(0));
            emit rekeyFinished(
                false,
                scan.failures != 0
                    ? QStringLiteral(
                          "Rekey is blocked while folder protection is armed because seal could "
                          "not verify every protected-folder entry.")
                    : QStringLiteral("Rekey is blocked while folder protection is armed because %1 "
                                     "protected file(s) are still encrypted on disk.")
                          .arg(decryptPlan.act.size()));
            return;
        }
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
    const bool rekeyVaultFile = !vaultPath.empty();
    const std::filesystem::path folderProfilePath{protectedFolderProfilePath().toStdWString()};
    const bool updateFolderProfile = m_ProtectFolderEnabled;
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
        [current, fresh, vaultPath, rekeyVaultFile, folderProfilePath, updateFolderProfile]()
            -> RekeyOutcome
        {
            RekeyOutcome r;
            try
            {
                if (updateFolderProfile)
                {
                    const ProtectedFolderProfileVerifyResult verified =
                        verifyProtectedFolderProfile(folderProfilePath, *current);
                    if (verified.result != ProtectedFolderProfileVerification::Verified)
                    {
                        throw std::runtime_error(
                            verified.result == ProtectedFolderProfileVerification::WrongPassword
                                ? "Current password does not match .seal-folder-profile"
                                : "Could not verify .seal-folder-profile before rekey");
                    }
                }

                if (rekeyVaultFile)
                {
                    r.count = seal::rekeyVault(vaultPath, *current, *fresh);
                }

                if (updateFolderProfile)
                {
                    std::string profileError;
                    if (!replaceProtectedFolderProfile(folderProfilePath, *fresh, &profileError))
                    {
                        // Keep the two authorities aligned. A profile commit
                        // failure occurs after the vault's atomic swap, so
                        // immediately rotate the vault back before reporting
                        // failure. The old profile remained live throughout.
                        if (rekeyVaultFile)
                        {
                            try
                            {
                                (void)seal::rekeyVault(vaultPath, *fresh, *current);
                            }
                            catch (const std::exception& rollbackError)
                            {
                                throw std::runtime_error(
                                    "Folder profile update failed and vault rollback also "
                                    "failed: " +
                                    std::string(rollbackError.what()));
                            }
                            throw std::runtime_error(
                                "Folder profile update failed; vault was rolled back: " +
                                profileError);
                        }
                        throw std::runtime_error("Folder profile update failed: " + profileError);
                    }
                }

                r.ok = true;
                r.message =
                    rekeyVaultFile
                        ? QStringLiteral("Master password changed (%1 records re-encrypted).")
                              .arg(r.count)
                        : QStringLiteral(
                              "Folder password changed. Plaintext files will be encrypted "
                              "with it on exit.");
            }
            catch (const std::exception& e)
            {
                r.message = QString::fromUtf8(e.what());
            }
            seal::Cryptography::cleanseString(*current);  // wipe the locked clones
            seal::Cryptography::cleanseString(*fresh);
            return r;
        },
        [this, opId, adopt, updateFolderProfile, rekeyVaultFile](RekeyOutcome r)
        {
            if (r.ok && isPasswordSet())
            {
                // Session still active: adopt the new password and reload from
                // disk so the workspace holds new-password packets. Unlike
                // submitPassword, nothing is drained here: the rekey dialog is
                // modal, so no action was deferred while it ran. The reload owns
                // the loading cover: it switches the caption to "Decrypting
                // vault...", then clears it.
                m_Workspace.adoptPassword(std::move(*adopt));
                m_VerifiedVaultPath.clear();
                m_ProtectedPasswordVerified = updateFolderProfile;
                emit passwordSetChanged();
                if (rekeyVaultFile)
                {
                    loadVaultFromPath(m_CurrentVaultPath, false);
                }
                else
                {
                    setLoading(false);
                }
            }
            else if (r.ok)
            {
                // Auto-lock fired mid-rekey and cleared the session; the disk
                // already holds the new password. Respect the lock instead of
                // silently re-unlocking: the next unlock needs the new one.
                seal::Cryptography::cleanseString(*adopt);
                m_ProtectedPasswordVerified = false;
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
