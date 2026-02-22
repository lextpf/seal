#ifdef USE_QT_UI

#include "Backend.h"
#include "Clipboard.h"
#include "FillController.h"
#include "Logging.h"
#include "VaultModel.h"

#include <QtCore/QString>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QCoreApplication>
#include <QtCore/QTimer>
#include <QtCore/QThread>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <windows.h>
#include <commdlg.h>
#include <shlobj.h>
#include <dwmapi.h>

#include <functional>
#include <memory>
#include <string>

#include "tess_ocr_api.h"

namespace sage {

basic_secure_string<wchar_t, locked_allocator<wchar_t>>
Backend::qstringToSecureWide(const QString& qstr)
{
    sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>> result;
    if (qstr.isEmpty())
        return result;

    // Intermediate std::wstring is unavoidable; Qt has no direct-to-locked-page API.
    std::wstring wstr = qstr.toStdWString();
    result.s.assign(wstr.begin(), wstr.end());
    SecureZeroMemory(wstr.data(), wstr.size() * sizeof(wchar_t));
    return result;
}

Backend::Backend(QObject* parent)
    : QObject(parent)
    , m_Model(std::make_unique<VaultListModel>(this).release())
    , m_FillController(std::make_unique<FillController>(this).release())
{
    m_Model->setRecords(&m_Records);

    // Relay FillController state to QML so the UI can react to fill progress.
    connect(m_FillController, &FillController::armedChanged,
            this, &Backend::fillArmedChanged);
    connect(m_FillController, &FillController::fillStatusTextChanged,
            this, &Backend::fillStatusTextChanged);
    connect(m_FillController, &FillController::countdownSecondsChanged,
            this, &Backend::fillCountdownSecondsChanged);

    // On fill complete/error/cancel, restore the sage window so the user
    // can see the result without alt-tabbing back.
    connect(m_FillController, &FillController::fillCompleted,
            this, [this](const QString& msg)
    {
        m_DPAPIGuard.reprotect();
        setStatus(msg);
        for (QWindow* w : QGuiApplication::topLevelWindows())
        {
            w->showNormal();
            w->raise();
            w->requestActivate();
        }
    });
    connect(m_FillController, &FillController::fillError,
            this, [this](const QString& msg)
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
    connect(m_FillController, &FillController::fillCancelled,
            this, [this]()
    {
        m_DPAPIGuard.reprotect();
        setStatus("Fill cancelled");
        for (QWindow* w : QGuiApplication::topLevelWindows())
        {
            w->showNormal();
            w->raise();
            w->requestActivate();
        }
    });
}

Backend::~Backend()
{
    try { cleanup(); } catch (...) {}
}

VaultListModel* Backend::vaultModel() const { return m_Model; }

bool Backend::vaultLoaded() const { return !m_CurrentVaultPath.isEmpty() || !m_Records.empty(); }

QString Backend::vaultFileName() const {
    if (m_CurrentVaultPath.isEmpty()) return {};
    return QFileInfo(m_CurrentVaultPath).fileName();
}

bool Backend::hasSelection() const { return m_SelectedIndex >= 0; }

int Backend::selectedIndex() const { return m_SelectedIndex; }

void Backend::setSelectedIndex(int index)
{
    if (m_SelectedIndex == index)
        return;
    m_SelectedIndex = index;
    emit selectionChanged();
}

QString Backend::statusText() const { return m_StatusText; }

bool Backend::isPasswordSet() const { return m_PasswordSet; }

QString Backend::searchFilter() const { return m_SearchFilter; }

void Backend::setSearchFilter(const QString& filter)
{
    if (m_SearchFilter == filter)
        return;
    m_SearchFilter = filter;
    m_Model->setFilter(filter);
    emit searchFilterChanged();
}

QString Backend::countdownText() const { return m_CountdownText; }

bool Backend::isBusy() const { return m_Busy; }

// Fill state is delegated entirely to the controller.
bool Backend::isFillArmed() const { return m_FillController->isArmed(); }
QString Backend::fillStatusText() const { return m_FillController->fillStatusText(); }
int Backend::fillCountdownSeconds() const { return m_FillController->countdownSeconds(); }

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

void Backend::submitPassword(const QString& password)
{
    auto wide = qstringToSecureWide(password);
    m_Password = std::move(wide);
    m_DPAPIGuard = sage::DPAPIGuard<sage::basic_secure_string<wchar_t>>(&m_Password);
    m_PasswordSet = true;
    qCInfo(logBackend) << "password set via manual entry";
    setStatus("Password set");
    emit passwordSetChanged();

    // Resume the action that was waiting for a password (e.g. loadVault, addAccount).
    if (m_PendingAction)
    {
        auto action = std::move(m_PendingAction);
        m_PendingAction = nullptr;
        action();
    }
}

void Backend::requestOcrCapture()
{
    // Configure tess_ocr for GPU-accelerated capture with multiple workers.
    _putenv_s("TESS_OCR_BACKEND", "cuda");
    _putenv_s("TESS_OCR_WORKERS", "1");
    _putenv_s("TESS_OCR_PRELOAD_WORKERS", "1");
    _putenv_s("TESS_OCR_TORCH_THREADS", "8");
    _putenv_s("TESS_OCR_CV_THREADS", "4");
    _putenv_s("TESS_OCR_PRIORITY_LEVEL", "2");
    _putenv_s("TESS_CAMERA_WARMUP_MS", "250");
    _putenv_s("TESS_ENTER_CAPTURE_FRAMES", "3");

    // Let the OCR window come to the foreground over our window.
    AllowSetForegroundWindow(ASFW_ANY);

    qCInfo(logBackend) << "starting webcam OCR capture";
    char buf[512] = {};
    int rc = tess_ocr_capture_from_webcam(nullptr, 0, buf, sizeof(buf));
    qCInfo(logBackend) << "webcam OCR returned rc=" << rc
                       << "len=" << strnlen(buf, sizeof(buf));

    if (rc != TESS_OCR_OK || buf[0] == '\0')
    {
        SecureZeroMemory(buf, sizeof(buf));
        qCWarning(logBackend) << "password NOT set (OCR failed or empty)";
        setStatus("OCR capture failed or cancelled");
        emit ocrCaptureFinished(false);
        return;
    }

    // Convert the UTF-8 OCR result to a QString for pre-filling the
    // password dialog. Don't set m_Password yet - let the user confirm.
    QString captured = QString::fromUtf8(buf, (int)strnlen(buf, sizeof(buf)));
    SecureZeroMemory(buf, sizeof(buf));

    qCInfo(logBackend) << "OCR captured" << captured.size() << "chars, awaiting confirmation";
    setStatus("OCR captured - confirm password");
    emit ocrCaptureFinished(true);

    // Signal the QML layer to re-open the password dialog with the
    // captured text pre-filled. The user can review and press OK to confirm,
    // which flows through the normal submitPassword() path.
    emit ocrTextReady(captured);

    // Wipe the local QString copy.
    captured.fill(QChar(0));
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

QString Backend::openFileDialog(const QString& title, const QString& filter)
{
    wchar_t fileName[MAX_PATH] = {};
    std::wstring wTitle = title.toStdWString();
    std::wstring wFilter = filter.toStdWString();

    // OPENFILENAME expects a double-null-terminated filter string with
    // pairs separated by NUL, e.g. "Description\0*.ext\0\0".
    // The caller passes pipe-separated pairs, so we replace '|' -> '\0'.
    for (auto& c : wFilter)
    {
        if (c == L'|')
            c = L'\0';
    }

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = nullptr;
    ofn.lpstrFilter = wFilter.c_str();
    ofn.lpstrFile   = fileName;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = wTitle.c_str();
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn))
        return QString::fromWCharArray(fileName);
    return {};
}

QString Backend::saveFileDialog(const QString& title, const QString& filter)
{
    wchar_t fileName[MAX_PATH] = L".sage";
    std::wstring wTitle = title.toStdWString();
    std::wstring wFilter = filter.toStdWString();
    for (auto& c : wFilter)
    {
        if (c == L'|')
            c = L'\0';
    }

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = nullptr;
    ofn.lpstrFilter = wFilter.c_str();
    ofn.lpstrFile   = fileName;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = wTitle.c_str();
    ofn.lpstrDefExt = L"sage";
    ofn.Flags       = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

    if (GetSaveFileNameW(&ofn))
        return QString::fromWCharArray(fileName);
    return {};
}

QString Backend::openFolderDialog(const QString& title)
{
    std::wstring wTitle = title.toStdWString();

    BROWSEINFOW bi = {};
    bi.hwndOwner = nullptr;
    bi.lpszTitle = wTitle.c_str();
    bi.ulFlags   = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

    LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
    if (pidl)
    {
        wchar_t path[MAX_PATH];
        if (SHGetPathFromIDListW(pidl, path))
        {
            CoTaskMemFree(pidl);
            return QString::fromWCharArray(path);
        }
        CoTaskMemFree(pidl);
    }
    return {};
}

void Backend::loadVaultFromPath(const QString& filePath, bool isAutoLoad)
{
    qCInfo(logBackend) << "loadVaultFromPath:" << QFileInfo(filePath).fileName()
                       << "autoLoad=" << isAutoLoad;
    try
    {
        m_DPAPIGuard.unprotect();
        m_Records = sage::loadVaultIndex(filePath, m_Password);
        m_DPAPIGuard.reprotect();
        m_CurrentVaultPath = filePath;
        qCInfo(logBackend) << "vault loaded:" << m_Records.size() << "record(s)";
        refreshModel();
        if (isAutoLoad)
            setStatus(QString("Auto-loaded %1 account(s) from %2")
                .arg(m_Records.size()).arg(QFileInfo(filePath).fileName()));
        else
            setStatus(QString("Loaded %1 account(s) from vault").arg(m_Records.size()));
        emit vaultLoadedChanged();
        emit vaultFileNameChanged();
    }
    catch (const std::runtime_error& e)
    {
        m_DPAPIGuard.reprotect();
        if (std::string(e.what()) == "Wrong password")
        {
            qCWarning(logBackend) << "wrong password for vault";
            m_DPAPIGuard = {};
            sage::Cryptography::cleanseString(m_Password);
            m_PasswordSet = false;
            emit passwordSetChanged();
            m_PendingAction = [this, filePath, isAutoLoad]()
            {
                loadVaultFromPath(filePath, isAutoLoad);
            };
            emit passwordRetryRequired("Wrong password - try again.");
            return;
        }
        qCWarning(logBackend) << "vault load error:" << e.what();
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

    QString fileName = openFileDialog(
        "Load Vault File",
        "sage Vault (*.sage)|*.sage|All Files (*)|*.*|");
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
        fileName = saveFileDialog(
            "Save Vault File",
            "sage Vault (*.sage)|*.sage|All Files (*)|*.*|");
    }
    if (fileName.isEmpty())
        return;

    if (!fileName.endsWith(".sage", Qt::CaseInsensitive))
        fileName += ".sage";

    qCInfo(logBackend) << "saveVault:" << QFileInfo(fileName).fileName()
                       << "records=" << m_Records.size();
    m_DPAPIGuard.unprotect();
    bool saveOk = sage::saveVaultV2(fileName, m_Records, m_Password);
    m_DPAPIGuard.reprotect();
    if (saveOk)
    {
        m_CurrentVaultPath = fileName;

        // Clear dirty flags and purge soft-deleted records now that
        // they've been committed to disk.
        for (auto& rec : m_Records)
            rec.m_Dirty = false;
        std::erase_if(m_Records, [](const sage::VaultRecord& r) { return r.m_Deleted; });

        refreshModel();
        qCInfo(logBackend) << "vault saved:" << m_Records.size() << "record(s)";
        setStatus(QString("Saved %1 account(s) to vault").arg(m_Records.size()));
        emit vaultLoadedChanged();
        emit vaultFileNameChanged();
    }
    else
    {
        qCWarning(logBackend) << "vault save failed";
        emit errorOccurred("Error", "Failed to save vault file");
        setStatus("Failed to save vault");
    }
}

void Backend::unloadVault()
{
    qCInfo(logBackend) << "unloadVault: clearing" << m_Records.size() << "record(s)";
    m_Records.clear();
    m_CurrentVaultPath.clear();
    refreshModel();
    setStatus("Vault unloaded");
    emit vaultLoadedChanged();
    emit vaultFileNameChanged();
}

void Backend::addAccount(const QString& service,
                              const QString& username,
                              const QString& password)
{
    if (service.isEmpty() || username.isEmpty() || password.isEmpty())
    {
        emit errorOccurred("Warning", "All fields are required");
        return;
    }

    if (!m_PasswordSet)
    {
        m_PendingAction = [this, service, username, password]()
        {
            addAccount(service, username, password);
        };
        ensurePassword();
        return;
    }

    // Convert to locked-page wide strings so plaintext doesn't sit in
    // pageable memory any longer than necessary.
    auto secUsername = qstringToSecureWide(username);
    auto secPassword = qstringToSecureWide(password);

    m_DPAPIGuard.unprotect();
    sage::VaultRecord newRecord = sage::encryptCredential(
        service.toUtf8().toStdString(), secUsername, secPassword, m_Password);
    m_DPAPIGuard.reprotect();

    sage::Cryptography::cleanseString(secUsername, secPassword);

    m_Records.push_back(std::move(newRecord));
    qCInfo(logBackend) << "addAccount: service=" << service
                       << "total=" << m_Records.size();
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

    auto secUsername = qstringToSecureWide(username);
    auto secPassword = qstringToSecureWide(password);

    // Replace the record entirely - re-encrypt with a fresh salt/IV.
    m_DPAPIGuard.unprotect();
    m_Records[index] = sage::encryptCredential(
        service.toUtf8().toStdString(), secUsername, secPassword, m_Password);
    m_DPAPIGuard.reprotect();

    sage::Cryptography::cleanseString(secUsername, secPassword);

    qCInfo(logBackend) << "editAccount: index=" << index << "service=" << service;
    refreshModel();
    setStatus("Account updated");
}

void Backend::deleteAccount(int index)
{
    if (index < 0 || index >= (int)m_Records.size())
        return;

    // Soft-delete: flag the record so it's excluded from the model
    // immediately, but keep it around until saveVault() commits to disk.
    m_Records[index].m_Deleted = true;
    m_Records[index].m_Dirty = true;
    qCInfo(logBackend) << "deleteAccount: index=" << index << "(soft-delete)";
    refreshModel();
    setStatus("Account deleted");

    // If every record is now deleted, notify QML so it can show the
    // empty-vault state.
    bool anyVisible = false;
    for (const auto& rec : m_Records)
    {
        if (!rec.m_Deleted)
        {
            anyVisible = true;
            break;
        }
    }
    if (!anyVisible) {
        emit vaultLoadedChanged();
        emit vaultFileNameChanged();
    }
}

QVariantMap Backend::decryptAccountForEdit(int index)
{
    qCDebug(logBackend) << "decryptAccountForEdit: index=" << index;
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
                m_DPAPIGuard.unprotect();
                sage::DecryptedCredential cred =
                    sage::decryptCredentialOnDemand(m_Records[index], m_Password);
                m_DPAPIGuard.reprotect();
                data["service"] = QString::fromUtf8(m_Records[index].m_Platform.c_str());
                data["username"] = QString::fromWCharArray(
                    cred.m_Username.data(), (int)cred.m_Username.size());
                data["password"] = QString::fromWCharArray(
                    cred.m_Password.data(), (int)cred.m_Password.size());
                data["editIndex"] = index;
                cred.cleanse();
                emit editAccountReady(data);
            }
            catch (const std::exception& e)
            {
                m_DPAPIGuard.reprotect();
                qCWarning(logBackend) << "decryptAccountForEdit (deferred): decrypt failed:" << e.what();
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
        m_DPAPIGuard.unprotect();
        sage::DecryptedCredential cred =
            sage::decryptCredentialOnDemand(m_Records[index], m_Password);
        m_DPAPIGuard.reprotect();

        result["service"] = QString::fromUtf8(m_Records[index].m_Platform.c_str());
        result["username"] = QString::fromWCharArray(
            cred.m_Username.data(), (int)cred.m_Username.size());
        result["password"] = QString::fromWCharArray(
            cred.m_Password.data(), (int)cred.m_Password.size());

        // Wipe the plaintext as soon as we've copied it into QVariants.
        cred.cleanse();
    }
    catch (const std::exception& e)
    {
        m_DPAPIGuard.reprotect();
        qCWarning(logBackend) << "decryptAccountForEdit: decrypt failed:" << e.what();
        emit errorOccurred("Error",
            QString("Failed to decrypt credential: %1").arg(e.what()));
    }
    return result;
}

// Types username + Tab + password into the currently focused window.
// The 200ms pause between username and Tab gives the target app time to
// process the input before we advance to the next field.
static void doTypeLogin(Backend* backend,
                        const std::vector<sage::VaultRecord>& records,
                        int index,
                        const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& masterPw)
{
    sage::DecryptedCredential cred;
    try
    {
        cred = sage::decryptCredentialOnDemand(records[index], masterPw);
    }
    catch (...)
    {
        return;
    }

    bool success1 = sage::typeSecret(
        cred.m_Username.data(), (int)cred.m_Username.size(), 0);

    if (!success1)
    {
        cred.cleanse();
        return;
    }

    // Brief pause so the target field registers the username keystrokes
    // before we send Tab to advance to the password field.
    QThread::msleep(200);

    // Synthesize a Tab keypress to move focus to the password field.
    INPUT tabInput[2] = {};
    tabInput[0].type     = INPUT_KEYBOARD;
    tabInput[0].ki.wVk   = VK_TAB;
    tabInput[1].type     = INPUT_KEYBOARD;
    tabInput[1].ki.wVk   = VK_TAB;
    tabInput[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, tabInput, sizeof(INPUT));
    QThread::msleep(100);

    sage::typeSecret(cred.m_Password.data(), (int)cred.m_Password.size(), 0);
    cred.cleanse();
}

// Types only the password into the currently focused window.
static void doTypePassword(const std::vector<sage::VaultRecord>& records,
                           int index,
                           const sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>& masterPw)
{
    sage::DecryptedCredential cred;
    try
    {
        cred = sage::decryptCredentialOnDemand(records[index], masterPw);
    }
    catch (...)
    {
        return;
    }

    sage::typeSecret(cred.m_Password.data(), (int)cred.m_Password.size(), 0);
    cred.cleanse();
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

    m_Busy = true;
    emit busyChanged();

    // 3-second countdown gives the user time to focus the target field
    // in the external application before keystrokes start arriving.
    int remaining = 3;
    m_CountdownText = QString("Typing in %1...").arg(remaining);
    emit countdownTextChanged();

    auto* timer = std::make_unique<QTimer>(this).release();
    timer->setInterval(1000);

    connect(timer, &QTimer::timeout, this, [this, timer, index, remaining]() mutable
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

            m_CountdownText = "Typing...";
            emit countdownTextChanged();

            QString service = QString::fromUtf8(m_Records[index].m_Platform.c_str());

            m_DPAPIGuard.unprotect();
            doTypeLogin(this, m_Records, index, m_Password);
            m_DPAPIGuard.reprotect();

            m_CountdownText.clear();
            emit countdownTextChanged();
            m_Busy = false;
            emit busyChanged();
            setStatus(QString("Login typed for '%1'").arg(service));
        }
    });

    timer->start();
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

    m_Busy = true;
    emit busyChanged();

    int remaining = 3;
    m_CountdownText = QString("Typing in %1...").arg(remaining);
    emit countdownTextChanged();

    auto* timer = std::make_unique<QTimer>(this).release();
    timer->setInterval(1000);

    connect(timer, &QTimer::timeout, this, [this, timer, index, remaining]() mutable
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

            m_CountdownText = "Typing...";
            emit countdownTextChanged();

            QString service = QString::fromUtf8(m_Records[index].m_Platform.c_str());

            m_DPAPIGuard.unprotect();
            doTypePassword(m_Records, index, m_Password);
            m_DPAPIGuard.reprotect();

            m_CountdownText.clear();
            emit countdownTextChanged();
            m_Busy = false;
            emit busyChanged();
            setStatus(QString("Password typed for '%1'").arg(service));
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

    QString dirPath = openFolderDialog("Select Directory to Encrypt");
    if (dirPath.isEmpty())
        return;

    m_DPAPIGuard.unprotect();
    int count = sage::encryptDirectory(dirPath, m_Password);
    m_DPAPIGuard.reprotect();
    qCInfo(logBackend) << "encryptDirectory: encrypted" << count << "file(s)";
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

    QString dirPath = openFolderDialog("Select Directory to Decrypt");
    if (dirPath.isEmpty())
        return;

    m_DPAPIGuard.unprotect();
    int count = sage::decryptDirectory(dirPath, m_Password);
    m_DPAPIGuard.reprotect();
    qCInfo(logBackend) << "decryptDirectory: decrypted" << count << "file(s)";
    setStatus(QString("Decrypted %1 file(s)").arg(count));
    emit infoMessage("Success", QString("Decrypted %1 file(s) in directory").arg(count));
}

void Backend::autoLoadVault()
{
    if (!m_CurrentVaultPath.isEmpty())
        return;

    // Search for a .sage vault file in well-known locations, in priority order:
    // 1. Next to the executable   2. Current working directory   3. Home directory
    QStringList searchPaths;
    searchPaths << QCoreApplication::applicationDirPath()
                << QDir::currentPath()
                << QDir::homePath();

    QString foundVaultPath;

    for (const QString& searchPath : searchPaths)
    {
        QDir dir(searchPath);
        QFileInfoList files = dir.entryInfoList(
            QStringList() << "*.sage", QDir::Files);

        if (!files.isEmpty())
            foundVaultPath = files.first().absoluteFilePath();
        if (!foundVaultPath.isEmpty())
            break;
    }

    if (foundVaultPath.isEmpty())
    {
        qCInfo(logBackend) << "autoLoadVault: no vault found";
        return;
    }

    qCInfo(logBackend) << "autoLoadVault: found" << QFileInfo(foundVaultPath).fileName();
    if (!m_PasswordSet)
    {
        // Capture the discovered path so the deferred action can load it
        // after the user supplies the master password.
        m_PendingAction = [this, foundVaultPath]()
        {
            loadVaultFromPath(foundVaultPath, true);
        };
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

    qCInfo(logBackend) << "armFill: index=" << index;
    m_DPAPIGuard.unprotect();
    m_FillController->arm(index, m_Records, m_Password);
    setStatus("Fill armed - Ctrl+Click target field");

    // Minimize so the user can see and click the target application.
    // The window is restored automatically by the fill-complete/error/cancel handlers.
    for (QWindow* w : QGuiApplication::topLevelWindows())
    {
        if (w->isVisible())
            w->showMinimized();
    }
}

void Backend::cancelFill()
{
    qCInfo(logBackend) << "cancelFill";
    m_FillController->cancel();
}

void Backend::cleanup()
{
    qCInfo(logBackend) << "cleanup: starting";
    m_FillController->cancel();

    // If the user configured an auto-encrypt directory, encrypt it now
    // before we wipe the master password.
    if (!m_AutoEncryptDirectory.isEmpty() && m_PasswordSet)
    {
        try
        {
            m_DPAPIGuard.unprotect();
            int count = sage::encryptDirectory(m_AutoEncryptDirectory, m_Password);
            m_DPAPIGuard.reprotect();
            qCInfo(logBackend) << "cleanup: auto-encrypted" << count << "file(s)";
            setStatus(QString("Auto-encrypted %1 file(s) in directory").arg(count));
        }
        catch (const std::exception& e)
        {
            m_DPAPIGuard.reprotect();
            qCWarning(logBackend) << "cleanup: auto-encrypt failed:" << e.what();
        }
    }

    // Wipe the master password from locked memory so it doesn't persist
    // after the application exits.
    if (m_PasswordSet)
    {
        m_DPAPIGuard = {};
        sage::Cryptography::cleanseString(m_Password);
        m_PasswordSet = false;
        emit passwordSetChanged();
    }

    sage::Cryptography::trimWorkingSet();
}

void Backend::updateWindowTheme(bool dark)
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
        return;

    HWND hwnd = (HWND)windows.first()->winId();
    if (!hwnd)
        return;

    // Remove window icon from title bar
    static bool iconRemoved = false;
    if (!iconRemoved) {
        // Clear class-level icons (Qt default fallback)
        SetClassLongPtr(hwnd, GCLP_HICON, 0);
        SetClassLongPtr(hwnd, GCLP_HICONSM, 0);
        // Clear instance-level icons
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, 0);
        SendMessage(hwnd, WM_SETICON, ICON_BIG, 0);
        // Add dialog frame style to suppress icon area
        LONG_PTR exStyle = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
        SetWindowLongPtr(hwnd, GWL_EXSTYLE, exStyle | WS_EX_DLGMODALFRAME);
        SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
        iconRemoved = true;
    }

    BOOL darkMode = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, 20, &darkMode, sizeof(darkMode));

    COLORREF captionColor = dark ? RGB(18, 24, 38) : RGB(245, 239, 230);
    DwmSetWindowAttribute(hwnd, 34, &captionColor, sizeof(captionColor));
    DwmSetWindowAttribute(hwnd, 35, &captionColor, sizeof(captionColor));

    COLORREF textColor = dark ? RGB(240, 242, 248) : RGB(44, 24, 16);
    DwmSetWindowAttribute(hwnd, 36, &textColor, sizeof(textColor));
}

} // namespace sage

#endif // USE_QT_UI
