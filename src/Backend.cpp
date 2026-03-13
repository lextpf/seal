#ifdef USE_QT_UI

#include "Backend.h"
#include "Clipboard.h"
#include "FillController.h"
#include "Logging.h"
#include "QrCapture.h"
#include "ScopedDpapiUnprotect.h"
#include "VaultModel.h"

#include <QtCore/QAbstractNativeEventFilter>
#include <QtCore/QCoreApplication>
#include <QtCore/QDir>
#include <QtCore/QFileInfo>
#include <QtCore/QString>
#include <QtCore/QThread>
#include <QtCore/QTimer>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>

#include <commdlg.h>
#include <dwmapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <windows.h>
#include <windowsx.h>

#include <functional>
#include <memory>
#include <string>

// Concrete alias used throughout this file.
using ScopedDpapiUnprotect =
    seal::ScopedDpapiUnprotect<seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>>;

namespace
{

// Native event filter that extends the client area into the title bar,
// keeps the DWM caption buttons (close/min/max), and handles resize edges.
//
// This filter intercepts Win32 messages before Qt sees them, allowing us to
// implement a fully custom title bar (drawn in QML) while still supporting
// native window chrome behaviors like resizing, snapping, and DWM shadows.
class TitleBarFilter : public QAbstractNativeEventFilter
{
public:
    HWND m_hwnd = nullptr;

    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override
    {
        if (eventType != "windows_generic_MSG")
            return false;
        auto* msg = static_cast<MSG*>(message);
        if (!m_hwnd || msg->hwnd != m_hwnd)
            return false;

        switch (msg->message)
        {
            case WM_NCCALCSIZE:
            {
                if (msg->wParam == TRUE)
                {
                    // Returning 0 makes the entire window the client area,
                    // removing the native title bar. For maximized windows,
                    // constrain to the monitor work area so the taskbar stays visible.
                    if (IsZoomed(msg->hwnd))
                    {
                        auto* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(msg->lParam);
                        HMONITOR mon = MonitorFromWindow(msg->hwnd, MONITOR_DEFAULTTONEAREST);
                        MONITORINFO mi{};
                        mi.cbSize = sizeof(mi);
                        if (GetMonitorInfoW(mon, &mi))
                            params->rgrc[0] = mi.rcWork;
                    }
                    *result = 0;
                    return true;
                }
                break;
            }
            case WM_NCPAINT:
            {
                // Suppress all non-client painting to eliminate the 1px
                // DWM border. The client area covers the full window so
                // there is nothing legitimate to paint in the NC region.
                *result = 0;
                return true;
            }
            case WM_NCHITTEST:
            {
                // Custom title bar: all caption buttons are QML-driven,
                // so we only handle resize borders here.
                POINT pt;
                pt.x = GET_X_LPARAM(msg->lParam);
                pt.y = GET_Y_LPARAM(msg->lParam);
                RECT rc;
                GetWindowRect(msg->hwnd, &rc);

                // Resize borders (only when not maximized).
                if (!IsZoomed(msg->hwnd))
                {
                    // SM_CXPADDEDBORDERWIDTH (index 92) adds the extra padding
                    // Windows uses around resizable frames. We use the raw
                    // integer 92 because some older SDK headers don't define the
                    // SM_CXPADDEDBORDERWIDTH constant.
                    int frame = GetSystemMetrics(SM_CXSIZEFRAME) + GetSystemMetrics(92);
                    // Walk the edges: check top strip first (corners have
                    // priority), then bottom strip, then left/right. The
                    // returned HT* codes tell Windows which resize cursor to
                    // show and which edge the user is dragging.
                    if (pt.y < rc.top + frame)
                    {
                        if (pt.x < rc.left + frame)
                        {
                            *result = HTTOPLEFT;
                            return true;
                        }
                        if (pt.x >= rc.right - frame)
                        {
                            *result = HTTOPRIGHT;
                            return true;
                        }
                        *result = HTTOP;
                        return true;
                    }
                    if (pt.y >= rc.bottom - frame)
                    {
                        if (pt.x < rc.left + frame)
                        {
                            *result = HTBOTTOMLEFT;
                            return true;
                        }
                        if (pt.x >= rc.right - frame)
                        {
                            *result = HTBOTTOMRIGHT;
                            return true;
                        }
                        *result = HTBOTTOM;
                        return true;
                    }
                    if (pt.x < rc.left + frame)
                    {
                        *result = HTLEFT;
                        return true;
                    }
                    if (pt.x >= rc.right - frame)
                    {
                        *result = HTRIGHT;
                        return true;
                    }
                }

                // Everything else is client area; QML handles window dragging
                // via startSystemMove() from the header bar.
                *result = HTCLIENT;
                return true;
            }
        }
        return false;
    }
};

}  // anonymous namespace

namespace seal
{

basic_secure_string<wchar_t, locked_allocator<wchar_t>> Backend::qstringToSecureWide(
    const QString& qstr)
{
    seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> result;
    if (qstr.isEmpty())
        return result;

    // Intermediate std::wstring is unavoidable; Qt has no direct-to-locked-page API.
    // toStdWString() allocates a normal-heap wstring that we can't control,
    // so we copy it into locked (non-pageable) memory immediately, then
    // scrub the heap copy to minimize the window where plaintext sits in
    // swappable RAM.
    std::wstring wstr = qstr.toStdWString();
    result.s.assign(wstr.begin(), wstr.end());
    SecureZeroMemory(wstr.data(), wstr.size() * sizeof(wchar_t));
    return result;
}

Backend::Backend(QObject* parent)
    : QObject(parent),
      m_Model(new VaultListModel(this)),
      m_FillController(new FillController(this))
{
    m_Model->setRecords(&m_Records);

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
    // the app the user just filled credentials into. Only restore on error
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
    // memory is dumped. unprotect()/reprotect() bracket every use.
    m_DPAPIGuard = seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>(&m_Password);
    m_PasswordSet = true;
    qCInfo(logBackend) << "password set via manual entry";
    setStatus("Password set");
    emit passwordSetChanged();

    // Resume the action that was waiting for a password (e.g. loadVault, addAccount).
    // The pending-action pattern: callers stash a lambda in m_PendingAction
    // before triggering the password dialog. Once the user submits, we
    // move-and-clear the lambda to avoid re-entrancy if the action itself
    // queues another pending action.
    if (m_PendingAction)
    {
        auto action = std::move(m_PendingAction);
        m_PendingAction = nullptr;
        action();
    }
}

void Backend::requestQrCapture()
{
    _putenv_s("TESS_CAMERA_WARMUP_MS", "250");
    _putenv_s("TESS_ENTER_CAPTURE_FRAMES", "3");

    // AllowSetForegroundWindow(ASFW_ANY) grants any process permission to
    // steal foreground focus. Without this, the QR scanner's OpenCV window
    // would open behind our window because Windows blocks background
    // processes from taking the foreground.
    AllowSetForegroundWindow(ASFW_ANY);

    qCInfo(logBackend) << "starting webcam QR capture (worker thread)";

    // Run the blocking OpenCV capture on a worker thread so the Qt event
    // loop stays responsive. captureQrFromWebcam() can block for up to
    // 60 seconds (capture timeout); doing that on the GUI thread would
    // freeze the entire UI.
    auto* thread = QThread::create(
        [this]()
        {
            seal::secure_string<> qrResult = seal::captureQrFromWebcam();

            // Deliver the result back to the GUI thread via a queued invocation
            // so all signal emissions happen on the correct thread.
            QMetaObject::invokeMethod(
                this,
                [this, result = std::move(qrResult)]() mutable
                {
                    qCInfo(logBackend) << "webcam QR returned len=" << result.size();

                    if (result.empty())
                    {
                        qCWarning(logBackend) << "password NOT set (QR capture failed or empty)";
                        setStatus("QR capture failed or cancelled");
                        emit qrCaptureFinished(false);
                        return;
                    }

                    // Convert the UTF-8 QR result to a QString for pre-filling the
                    // password dialog. Don't set m_Password yet - let the user confirm.
                    QString captured = QString::fromUtf8(result.data(), (int)result.size());
                    // result auto-wipes on scope exit

                    qCInfo(logBackend)
                        << "QR captured" << captured.size() << "chars, awaiting confirmation";
                    setStatus("QR captured - confirm password");
                    emit qrCaptureFinished(true);

                    // Signal the QML layer to re-open the password dialog with the
                    // captured text pre-filled. The user can review and press OK to
                    // confirm, which flows through the normal submitPassword() path.
                    emit qrTextReady(captured);

                    // Wipe the local QString copy so the raw QR text doesn't linger
                    // on the heap after the signal delivers it to QML.
                    captured.fill(QChar(0));
                },
                Qt::QueuedConnection);
        });

    // Clean up the thread object after it finishes.
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
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
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = wFilter.c_str();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = wTitle.c_str();
    // OFN_NOCHANGEDIR prevents the dialog from changing the process CWD,
    // which would break relative-path vault auto-discovery.
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn))
        return QString::fromWCharArray(fileName);
    return {};
}

QString Backend::saveFileDialog(const QString& title, const QString& filter)
{
    wchar_t fileName[MAX_PATH] = L".seal";
    std::wstring wTitle = title.toStdWString();
    std::wstring wFilter = filter.toStdWString();
    for (auto& c : wFilter)
    {
        if (c == L'|')
            c = L'\0';
    }

    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = wFilter.c_str();
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = wTitle.c_str();
    ofn.lpstrDefExt = L"seal";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;

    if (GetSaveFileNameW(&ofn))
        return QString::fromWCharArray(fileName);
    return {};
}

QString Backend::openFolderDialog(const QString& title)
{
    IFileDialog* pfd = nullptr;
    HRESULT hr =
        CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pfd));
    if (FAILED(hr))
        return {};

    DWORD opts = 0;
    pfd->GetOptions(&opts);
    pfd->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_NOCHANGEDIR);
    pfd->SetTitle(title.toStdWString().c_str());

    QString result;
    if (SUCCEEDED(pfd->Show(nullptr)))
    {
        IShellItem* psi = nullptr;
        if (SUCCEEDED(pfd->GetResult(&psi)))
        {
            PWSTR path = nullptr;
            if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &path)))
            {
                result = QString::fromWCharArray(path);
                CoTaskMemFree(path);
            }
            psi->Release();
        }
    }
    pfd->Release();
    return result;
}

void Backend::loadVaultFromPath(const QString& filePath, bool isAutoLoad)
{
    qCInfo(logBackend) << "loadVaultFromPath:" << QFileInfo(filePath).fileName()
                       << "autoLoad=" << isAutoLoad;
    try
    {
        ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
        m_Records = seal::loadVaultIndex(filePath, m_Password);
        m_CurrentVaultPath = filePath;
        qCInfo(logBackend) << "vault loaded:" << m_Records.size() << "record(s)";
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
            qCWarning(logBackend) << "wrong password for vault";
            m_DPAPIGuard = {};
            seal::Cryptography::cleanseString(m_Password);
            m_PasswordSet = false;
            emit passwordSetChanged();
            m_PendingAction = [this, filePath, isAutoLoad]()
            { loadVaultFromPath(filePath, isAutoLoad); };
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

    QString fileName =
        openFileDialog("Load Vault File", "seal Vault (*.seal)|*.seal|All Files (*)|*.*|");
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
        fileName =
            saveFileDialog("Save Vault File", "seal Vault (*.seal)|*.seal|All Files (*)|*.*|");
    }
    if (fileName.isEmpty())
        return;

    if (!fileName.endsWith(".seal", Qt::CaseInsensitive))
        fileName += ".seal";

    qCInfo(logBackend) << "saveVault:" << QFileInfo(fileName).fileName()
                       << "records=" << m_Records.size();
    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    bool saveOk = seal::saveVaultV2(fileName, m_Records, m_Password);
    if (saveOk)
    {
        m_CurrentVaultPath = fileName;

        // Clear dirty flags and purge soft-deleted records now that
        // they've been committed to disk.
        for (auto& rec : m_Records)
            rec.dirty = false;
        std::erase_if(m_Records, [](const seal::VaultRecord& r) { return r.deleted; });

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

void Backend::addAccount(const QString& service, const QString& username, const QString& password)
{
    if (service.isEmpty() || username.isEmpty() || password.isEmpty())
    {
        emit errorOccurred("Warning", "All fields are required");
        return;
    }

    if (!m_PasswordSet)
    {
        m_PendingAction = [this, service, username, password]()
        { addAccount(service, username, password); };
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

    m_Records.push_back(std::move(newRecord));
    qCInfo(logBackend) << "addAccount: service=" << service << "total=" << m_Records.size();
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
        m_PendingAction = [this, index, service, username, password]()
        { editAccount(index, service, username, password); };
        ensurePassword();
        return;
    }

    auto secUsername = qstringToSecureWide(username);
    auto secPassword = qstringToSecureWide(password);

    // Replace the record entirely - re-encrypt with a fresh salt/IV.
    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    m_Records[index] = seal::encryptCredential(
        service.toUtf8().toStdString(), secUsername, secPassword, m_Password);

    seal::Cryptography::cleanseString(secUsername, secPassword);

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
    m_Records[index].deleted = true;
    m_Records[index].dirty = true;
    qCInfo(logBackend) << "deleteAccount: index=" << index << "(soft-delete)";
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
                if (index < 0 || index >= static_cast<int>(m_Records.size()))
                {
                    qCWarning(logBackend)
                        << "decryptAccountForEdit (deferred): record no longer exists";
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
            }
            catch (const std::exception& e)
            {
                qCWarning(logBackend)
                    << "decryptAccountForEdit (deferred): decrypt failed:" << e.what();
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

        // Wipe the plaintext as soon as we've copied it into QVariants.
        cred.cleanse();
    }
    catch (const std::exception& e)
    {
        qCWarning(logBackend) << "decryptAccountForEdit: decrypt failed:" << e.what();
        emit errorOccurred("Error", QString("Failed to decrypt credential: %1").arg(e.what()));
    }
    return result;
}

// Types username + Tab + password into the currently focused window.
// The 200ms pause between username and Tab gives the target app time to
// process the input before we advance to the next field.
static void doTypeLogin(
    const std::vector<seal::VaultRecord>& records,
    int index,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    if (index < 0 || index >= static_cast<int>(records.size()))
    {
        return;
    }

    seal::DecryptedCredential cred;
    try
    {
        cred = seal::decryptCredentialOnDemand(records[index], masterPw);
    }
    catch (...)
    {
        return;
    }

    bool success1 = seal::typeSecret(cred.username.data(), (int)cred.username.size(), 0);

    if (!success1)
    {
        cred.cleanse();
        return;
    }

    // Brief pause so the target field registers the username keystrokes
    // before we send Tab to advance to the password field.
    QThread::msleep(200);

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
    QThread::msleep(100);

    seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);
    cred.cleanse();
}

// Types only the password into the currently focused window.
static void doTypePassword(
    const std::vector<seal::VaultRecord>& records,
    int index,
    const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& masterPw)
{
    if (index < 0 || index >= static_cast<int>(records.size()))
    {
        return;
    }

    seal::DecryptedCredential cred;
    try
    {
        cred = seal::decryptCredentialOnDemand(records[index], masterPw);
    }
    catch (...)
    {
        return;
    }

    seal::typeSecret(cred.password.data(), (int)cred.password.size(), 0);
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

    scheduleTypingAction(
        index, [this, index]() { doTypeLogin(m_Records, index, m_Password); }, "Login");
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

    scheduleTypingAction(
        index, [this, index]() { doTypePassword(m_Records, index, m_Password); }, "Password");
}

void Backend::scheduleTypingAction(int index, std::function<void()> action, const QString& label)
{
    m_Busy = true;
    emit busyChanged();

    // 3-second countdown gives the user time to focus the target field
    // in the external application before keystrokes start arriving.
    int remaining = 3;
    m_CountdownText = QString("Typing in %1...").arg(remaining);
    emit countdownTextChanged();

    auto* timer = new QTimer(this);
    timer->setInterval(1000);

    connect(timer,
            &QTimer::timeout,
            this,
            [this, timer, index, action = std::move(action), label, remaining]() mutable
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
                        m_CountdownText.clear();
                        emit countdownTextChanged();
                        m_Busy = false;
                        emit busyChanged();
                        return;
                    }

                    m_CountdownText = "Typing...";
                    emit countdownTextChanged();

                    QString service = QString::fromUtf8(m_Records[index].platform.c_str());

                    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
                    action();

                    m_CountdownText.clear();
                    emit countdownTextChanged();
                    m_Busy = false;
                    emit busyChanged();
                    setStatus(QString("%1 typed for '%2'").arg(label, service));
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

    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    int count = seal::encryptDirectory(dirPath, m_Password);
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

    ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
    int count = seal::decryptDirectory(dirPath, m_Password);
    qCInfo(logBackend) << "decryptDirectory: decrypted" << count << "file(s)";
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
        qCInfo(logBackend) << "autoLoadVault: no vault found";
        return;
    }

    qCInfo(logBackend) << "autoLoadVault: found" << QFileInfo(foundVaultPath).fileName();
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

    qCInfo(logBackend) << "armFill: index=" << index;
    m_DPAPIGuard.unprotect();
    const bool armed = m_FillController->arm(index, m_Records, m_Password);
    if (!armed)
    {
        // If hook install failed, don't apply "armed" UI state/minimize behavior.
        // fillError may already have reprotected, but this is harmless if unchanged.
        m_DPAPIGuard.reprotect();
        return;
    }
    setStatus("Fill armed - Ctrl+Click target field");

    // Minimize so the user can see and click the target application.
    // Stays minimized after fill completes or is cancelled; only restored on error.
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
            ScopedDpapiUnprotect dpapiScope(m_DPAPIGuard);
            int count = seal::encryptDirectory(m_AutoEncryptDirectory, m_Password);
            qCInfo(logBackend) << "cleanup: auto-encrypted" << count << "file(s)";
            setStatus(QString("Auto-encrypted %1 file(s) in directory").arg(count));
        }
        catch (const std::exception& e)
        {
            qCWarning(logBackend) << "cleanup: auto-encrypt failed:" << e.what();
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
}

void Backend::updateWindowTheme(bool dark)
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
        return;

    HWND hwnd = (HWND)windows.first()->winId();
    if (!hwnd)
        return;

    // One-time setup: install the native event filter that extends the client
    // area into the title bar and handles resize-border hit testing.
    static bool frameInstalled = false;
    if (!frameInstalled)
    {
        // Remove window icon from title bar
        SetClassLongPtr(hwnd, GCLP_HICON, 0);
        SetClassLongPtr(hwnd, GCLP_HICONSM, 0);
        SendMessage(hwnd, WM_SETICON, ICON_SMALL, 0);
        SendMessage(hwnd, WM_SETICON, ICON_BIG, 0);

        // Install native event filter for custom title bar
        auto* filter = new TitleBarFilter();
        filter->m_hwnd = hwnd;
        QCoreApplication::instance()->installNativeEventFilter(filter);

        // Extend the DWM frame into the client area so the system draws its
        // shadow and caption buttons over our content.
        // {-1,-1,-1,-1} means "extend to the entire window" - DWM will
        // render its glass/shadow over the full client surface.
        MARGINS margins{-1, -1, -1, -1};
        DwmExtendFrameIntoClientArea(hwnd, &margins);

        // Request rounded window corners from the DWM compositor.
        static constexpr DWORD DWMWA_WINDOW_CORNER_PREFERENCE = 33;
        DWORD cornerPref = 2;  // DWMWCP_ROUND
        DwmSetWindowAttribute(
            hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &cornerPref, sizeof(cornerPref));

        // Force a frame recalculation so WM_NCCALCSIZE runs with our handler.
        SetWindowPos(
            hwnd, nullptr, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);

        frameInstalled = true;
    }

    // These DWM attribute IDs were introduced in Windows 10/11 but aren't
    // always in the SDK headers. Defining them as constants lets us build
    // with older SDKs while still using the newer personalization APIs.
    static constexpr DWORD DWMWA_USE_IMMERSIVE_DARK_MODE = 20;  // Win10 1903+
    static constexpr DWORD DWMWA_CAPTION_COLOR = 34;            // Win11 22000+
    static constexpr DWORD DWMWA_BORDER_COLOR = 35;             // Win11 22000+
    static constexpr DWORD DWMWA_TEXT_COLOR = 36;               // Win11 22000+

    BOOL darkMode = dark ? TRUE : FALSE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &darkMode, sizeof(darkMode));

    // Match border color to bgDeep so the 1px DWM frame blends invisibly.
    COLORREF captionColor = dark ? RGB(18, 24, 38) : RGB(245, 239, 230);
    DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &captionColor, sizeof(captionColor));
    DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &captionColor, sizeof(captionColor));

    COLORREF textColor = dark ? RGB(240, 242, 248) : RGB(44, 24, 16);
    DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &textColor, sizeof(textColor));
}

void Backend::startWindowDrag()
{
    auto windows = QGuiApplication::topLevelWindows();
    if (!windows.isEmpty())
        windows.first()->startSystemMove();
}

bool Backend::isAlwaysOnTop() const
{
    return m_AlwaysOnTop;
}

void Backend::toggleAlwaysOnTop()
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
        return;

    HWND hwnd = (HWND)windows.first()->winId();
    m_AlwaysOnTop = !m_AlwaysOnTop;
    SetWindowPos(
        hwnd, m_AlwaysOnTop ? HWND_TOPMOST : HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    qCInfo(logBackend) << "alwaysOnTop:" << m_AlwaysOnTop;
    emit alwaysOnTopChanged();
}

void Backend::lockVault()
{
    if (!m_PasswordSet)
        return;

    qCInfo(logBackend) << "lockVault: wiping master password";
    m_FillController->cancel();
    m_DPAPIGuard = {};
    seal::Cryptography::cleanseString(m_Password);
    m_PasswordSet = false;
    emit passwordSetChanged();
    setStatus("Vault locked - password required for next action");
}

bool Backend::isCompact() const
{
    return m_Compact;
}

void Backend::toggleCompact()
{
    auto windows = QGuiApplication::topLevelWindows();
    if (windows.isEmpty())
        return;

    QWindow* win = windows.first();
    m_Compact = !m_Compact;

    if (m_Compact)
    {
        // Save the current dimensions so we can restore them when leaving
        // compact mode, preserving whatever size the user had chosen.
        m_NormalWidth = win->width();
        m_NormalHeight = win->height();
        win->setMinimumHeight(272);
        win->resize(win->width(), 272);
    }
    else
    {
        // Restore saved dimensions, falling back to default size if none
        // were captured (e.g. app launched directly into compact mode).
        win->setMinimumHeight(540);
        win->resize(m_NormalWidth > 0 ? m_NormalWidth : 1420,
                    m_NormalHeight > 0 ? m_NormalHeight : 690);
    }

    qCInfo(logBackend) << "compactMode:" << m_Compact;
    emit compactChanged();
}

}  // namespace seal

#endif  // USE_QT_UI
