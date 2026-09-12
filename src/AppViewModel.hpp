#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>
#include <QStringList>
#include <QTimer>
#include <QVariantMap>

#include <deque>
#include <functional>
#include <optional>
#include <vector>

#include "AsyncRunner.hpp"
#include "CredentialSession.hpp"
#include "CredentialWorkspace.hpp"
#include "Cryptography.hpp"
#include "IFillControl.hpp"
#include "IPasswordGate.hpp"
#include "IUiFeedback.hpp"
#include "ProtectedFolderProfile.hpp"
#include "Vault.hpp"
#include "VaultModel.hpp"

namespace seal
{

class AutoLockController;
class CliPanelViewModel;

/**
 * @class AppViewModel
 * @brief Coordinate vault commands and non-secret QML state.
 * @author Alex (<https://github.com/lextpf>)
 * @ingroup ViewModel
 *
 * Commands may accept secrets; properties and model roles must not expose them.
 * Call commands on the owning GUI thread; worker results return to that thread.
 * `IUiFeedback` and `IPasswordGate` give controllers access to private UI setters
 * and the password queue. `RunQMLMode` owns the context-property wiring.
 *
 * ### :material-lock: Vault lifecycle
 *
 * `lockVault()` and `cleanup()` clear the key but keep records. `unloadVault()`
 * clears records but keeps the key. Password adoption does not verify the key.
 * `deleteAccount()` needs no key; `rekeyVault()` receives one as an argument.
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * stateDiagram-v2
 *     [*] --> Locked
 *     Locked --> Locked : ensurePassword()-gated command [queued, passwordRequired()]
 *     Locked --> Unlocked : submitPassword() / requestSecureDesktopUnlock()
 *     Locked --> Unlocked : confirmProtectFolderEnabled() (modes 1 and 2, no drain)
 *     Unlocked --> Unlocked : loadVault() / saveVault() / addAccount() / editAccount()
 *     Unlocked --> Locked : lockVault() / cleanup() / wrong password on load
 * ```
 *
 * ### :material-key: Pending actions
 *
 * Commands use `ensurePassword()` before accessing the key. It checks only whether
 * a password is present; the resumed operation must authenticate its own data.
 * Wrong-password retries go to the front of the queue.
 * `confirmProtectFolderEnabled()` adopts a password without draining the queue.
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * sequenceDiagram
 *     participant C as Caller (e.g. loadVault)
 *     participant B as AppViewModel
 *     participant Q as QML UI
 *
 *     C->>B: loadVault()
 *     B->>B: ensurePassword([loadVault lambda])
 *     B->>Q: passwordRequired()
 *     Q->>B: submitPassword(pw)
 *     B->>B: store pw in locked memory
 *     B->>B: drainPendingActions()
 *     B->>C: (loadVault resumes)
 * ```
 *
 * @verbatim
 *   m_PendingActions : std::deque<std::function<void()>>   (FIFO)
 *
 *   ensurePassword(a) --push_back-->   front [ a | b | c ] back
 *   ensurePassword(b) --push_back-->               ^ enqueued in call order
 *   ensurePassword(c) --push_back-->
 *   wrong-password retry --push_front--> front [ retry | a | b | c ] back
 *
 *   submitPassword(pw) --> drainPendingActions(): pop_front until empty
 * @endverbatim
 *
 * Cancel armed fills before workspace mutations. QR results reach the session
 * only after the user confirms them.
 *
 * @see IUiFeedback, IPasswordGate, IFillControl
 */
class AppViewModel : public QObject, public IUiFeedback, public IPasswordGate
{
    Q_OBJECT

    Q_PROPERTY(VaultListModel* vaultModel READ vaultModel CONSTANT)
    Q_PROPERTY(bool vaultLoaded READ vaultLoaded NOTIFY vaultLoadedChanged)
    Q_PROPERTY(QString vaultFileName READ vaultFileName NOTIFY vaultFileNameChanged)
    Q_PROPERTY(bool hasSelection READ hasSelection NOTIFY selectionChanged)
    Q_PROPERTY(int selectedIndex READ selectedIndex WRITE setSelectedIndex NOTIFY selectionChanged)
    Q_PROPERTY(QString statusText READ statusText NOTIFY statusTextChanged)
    Q_PROPERTY(bool passwordSet READ isPasswordSet NOTIFY passwordSetChanged)
    Q_PROPERTY(
        QString searchFilter READ searchFilter WRITE setSearchFilter NOTIFY searchFilterChanged)
    Q_PROPERTY(int sortMode READ sortMode WRITE setSortMode NOTIFY sortModeChanged)
    Q_PROPERTY(QString countdownText READ countdownText NOTIFY countdownTextChanged)
    Q_PROPERTY(bool isBusy READ isBusy NOTIFY busyChanged)
    Q_PROPERTY(bool isLoading READ isLoading NOTIFY loadingChanged)
    Q_PROPERTY(QString loadingCaption READ loadingCaption NOTIFY loadingChanged)
    Q_PROPERTY(
        bool protectFolderEnabled READ protectFolderEnabled NOTIFY protectFolderEnabledChanged)
    Q_PROPERTY(
        QString protectFolderPath READ protectFolderPath NOTIFY protectFolderPreflightChanged)
    Q_PROPERTY(QStringList protectFolderEncryptFiles READ protectFolderEncryptFiles NOTIFY
                   protectFolderPreflightChanged)
    Q_PROPERTY(QStringList protectFolderSkippedFiles READ protectFolderSkippedFiles NOTIFY
                   protectFolderPreflightChanged)
    Q_PROPERTY(qulonglong protectFolderTotalBytes READ protectFolderTotalBytes NOTIFY
                   protectFolderPreflightChanged)
    Q_PROPERTY(int protectFolderPasswordMode READ protectFolderPasswordMode NOTIFY
                   protectFolderPreflightChanged)

public:
    /**
     * @fn AppViewModel(seal::CredentialWorkspace& workspace, seal::AsyncRunner& asyncRunner,
     *     QObject* parent = nullptr)
     * @brief Read folder-protection settings and create the UI collaborators.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The workspace supplies the initial records and password state.
     *
     * @pre `workspace` and `asyncRunner` outlive this object.
     */
    explicit AppViewModel(seal::CredentialWorkspace& workspace,
                          seal::AsyncRunner& asyncRunner,
                          QObject* parent = nullptr);

    /**
     * @fn ~AppViewModel() override
     * @brief Cancel capture and fills, then wipe the password.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Call `cleanup()` while the event loop runs to re-protect an armed folder.
     * Destruction alone leaves its plaintext-session marker on disk.
     */
    ~AppViewModel() override;

    /**
     * @fn VaultListModel* vaultModel() const
     * @brief Borrowed, non-null child; valid until this object is destroyed.
     * @author Alex (<https://github.com/lextpf>)
     */
    VaultListModel* vaultModel() const;

    /**
     * @fn bool vaultLoaded() const
     * @brief True when a vault path or any records, including soft deletes, exist.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool vaultLoaded() const;

    /**
     * @fn QString vaultFileName() const
     * @brief Filename without its directory; empty when no vault path is held.
     * @author Alex (<https://github.com/lextpf>)
     */
    QString vaultFileName() const;

    bool hasSelection() const;

    /**
     * @fn int selectedIndex() const
     * @brief -1 when no row is selected.
     * @author Alex (<https://github.com/lextpf>)
     */
    int selectedIndex() const;

    /**
     * @fn void setSelectedIndex(int index)
     * @brief Select a visible row and notify selection observers.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param index Filtered row, or -1 to clear selection.
     */
    void setSelectedIndex(int index);

    QString statusText() const;

    bool isPasswordSet() const;

    QString searchFilter() const;

    /**
     * @fn void setSearchFilter(const QString& filter)
     * @brief An empty filter shows all records.
     * @author Alex (<https://github.com/lextpf>)
     */
    void setSearchFilter(const QString& filter);

    int sortMode() const;

    /**
     * @fn void setSortMode(int mode)
     * @brief Normalize the requested sort mode and notify observers.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Invalid modes select SortMode::Alphabetical. Emit unless the requested mode
     * already matches the model's current mode.
     */
    void setSortMode(int mode);

    QString countdownText() const;

    /**
     * @fn bool isBusy() const override
     * @brief Covers folder workers, rekey and the typing countdown; excludes vault loads.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool isBusy() const override;

    /**
     * @fn bool isLoading() const
     * @brief Show the cover during vault, rekey and protected-folder crypto.
     * @author Alex (<https://github.com/lextpf>)
     *
     * A vault load sets `m_LoadWorkerActive`, not `m_Busy`; the typing countdown sets
     * `m_Busy` without the cover. Exclusion gates must test both worker flags.
     */
    bool isLoading() const;

    /**
     * @fn QString loadingCaption() const
     * @brief Empty when isLoading() is false.
     * @author Alex (<https://github.com/lextpf>)
     */
    QString loadingCaption() const;

    bool protectFolderEnabled() const;

    /**
     * @fn QString protectFolderPath() const
     * @brief Empty before an arming preview and after protection is disabled.
     * @author Alex (<https://github.com/lextpf>)
     */
    QString protectFolderPath() const;

    /**
     * @fn QStringList protectFolderEncryptFiles() const
     * @brief Paths relative to the executable directory.
     * @author Alex (<https://github.com/lextpf>)
     */
    QStringList protectFolderEncryptFiles() const;

    /**
     * @fn QStringList protectFolderSkippedFiles() const
     * @brief Each entry is a relative path followed by a stable skip-reason token.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Format: `<relative path> - <skip reason token>`.
     *
     * @see seal::protected_folder::skipReasonToken
     */
    QStringList protectFolderSkippedFiles() const;

    /**
     * @fn qulonglong protectFolderTotalBytes() const
     * @brief Plaintext bytes in the arming preview.
     * @author Alex (<https://github.com/lextpf>)
     */
    qulonglong protectFolderTotalBytes() const;

    /**
     * @fn int protectFolderPasswordMode() const
     * @brief Select the password prompt for the arming preview.
     * @author Alex (<https://github.com/lextpf>)
     *
     * | Value | Action                          |
     * |-------|---------------------------------|
     * | 0     | Reuse verified session password |
     * | 1     | Create and confirm a password   |
     * | 2     | Unlock an existing profile      |
     */
    int protectFolderPasswordMode() const;

    /**
     * @fn void loadVault()
     * @brief Choose a vault and decrypt its platform names on a worker.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Prompts for a missing password. Credentials stay sealed. Cancelling the picker
     * does nothing; success emits `vaultLoadedChanged()`.
     */
    Q_INVOKABLE void loadVault();

    /**
     * @fn void saveVault()
     * @brief Save on the GUI thread, prompting for a missing password or first path.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Appends `.seal` when needed. Cancels armed fills before erasing soft deletes,
     * then rebuilds the model because the erase changes indices without a generation bump.
     *
     * Exceptions from key access or platform encryption report the master-key error
     * and `reason=dpapi_unprotect`. I/O and 32-bit field/count overflow report the
     * save error. Either failure leaves records and the vault file unchanged.
     */
    Q_INVOKABLE void saveVault();

    /**
     * @fn void unloadVault()
     * @brief Discard unsaved records and selection; keep the master password.
     * @author Alex (<https://github.com/lextpf>)
     */
    Q_INVOKABLE void unloadVault();

    /**
     * @fn void addAccount(const QString& service, const QString& username, const QString& password)
     * @brief Encrypt a new credential in memory; saveVault() commits it to disk.
     * @author Alex (<https://github.com/lextpf>)
     *
     * All fields must be non-empty. A missing master password defers the operation
     * with secrets in locked memory. Validation and encryption failures emit
     * `errorOccurred()`.
     *
     * @param service Non-secret platform label stored as plaintext.
     */
    Q_INVOKABLE void addAccount(const QString& service,
                                const QString& username,
                                const QString& password);

    /**
     * @fn void editAccount(int index, const QString& service, const QString& username, const
     *     QString& password)
     * @brief Re-encrypt a record in memory; saveVault() commits it to disk.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Rejects an empty service. A missing password defers the operation with secrets
     * in locked memory. Encryption failures emit `errorOccurred()`.
     *
     * @param index Full record index; out-of-range values are ignored.
     * @param username Empty keeps the stored username.
     * @param password Empty keeps the stored password.
     */
    Q_INVOKABLE void editAccount(int index,
                                 const QString& service,
                                 const QString& username,
                                 const QString& password);

    /**
     * @fn QVariantMap previewSiteBinding(const QString& service) const
     * @brief Inspect a trimmed platform label without storing it or accessing secrets.
     * @author Alex (<https://github.com/lextpf>)
     *
     * | Result key       | Meaning                                                         |
     * |------------------|-----------------------------------------------------------------|
     * | `bindable`       | Host has a dot and a registrable domain                         |
     * | `host`           | Normalized full host; empty when unbindable                     |
     * | `duplicateCount` | Live records with the same host; 0 when unbindable              |
     * | `publicSuffix`   | Host is a dotted public suffix, such as `co.uk`; excludes `com` |
     * | `suggestion`     | `<key>.com` for an unbindable brand label; otherwise empty      |
     *
     * Parent and child hosts do not count as duplicates.
     */
    Q_INVOKABLE QVariantMap previewSiteBinding(const QString& service) const;

    /**
     * @fn QVariantMap previewSiteBinding(const QString& service, int excludedRecordIndex) const
     * @brief Preview a site binding while excluding the edited record.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param excludedRecordIndex Full record index to omit from duplicates; -1 omits none.
     * @return The same map as the single-argument overload.
     */
    Q_INVOKABLE QVariantMap previewSiteBinding(const QString& service,
                                               int excludedRecordIndex) const;

    /**
     * @fn void deleteAccount(int index)
     * @brief Hide a record until saveVault() removes it from memory and disk.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cancels armed fills first. Deleting the last visible record still leaves
     * `vaultLoaded()` true until save removes the soft deletes.
     *
     * @param index Full record index; out-of-range values are ignored.
     */
    Q_INVOKABLE void deleteAccount(int index);

    /**
     * @fn void encryptDirectory()
     * @brief Choose a folder and encrypt eligible files recursively.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses the protected-folder skip policy and prompts for a missing password.
     * Blocks the GUI thread; one session access window spans the walk, with one
     * scrypt derivation per file.
     *
     * @warning Successful writes delete each plaintext source.
     * @see seal::protected_folder
     */
    Q_INVOKABLE void encryptDirectory();

    /**
     * @fn void decryptDirectory()
     * @brief Decrypt eligible files using encryptDirectory() policy and blocking.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Credential vaults stay sealed.
     *
     * @warning Successful writes delete each encrypted source.
     */
    Q_INVOKABLE void decryptDirectory();

    /**
     * @fn void autoLoadVault()
     * @brief Find a vault for startup; do nothing if a vault path is already held.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Without folder protection, search the executable directory, working directory,
     * then home directory. In each, use case-insensitive name order and accept the
     * first non-symlink `.seal` file with decoded `SVH2` magic.
     *
     * Armed protection restricts the search to the executable directory. Startup
     * refuses a dynamic Qt deployment, invalid folder profile, or missing profile
     * without a vault. One vault can authenticate creation of a missing profile;
     * multiple candidates select folder-only startup.
     *
     * Loading requires the master password.
     */
    Q_INVOKABLE void autoLoadVault();

    /**
     * @fn void requestProtectFolderEnabled(bool enabled)
     * @brief Preview arming or disable executable-folder protection.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op for an unchanged state or active cleanup; a background operation refuses
     * the request. Enabling checks deployment, output collisions and the profile,
     * then emits `protectFolderPreflightReady()` without arming.
     *
     * Disabling is immediate, keeps the profile, and encrypts nothing. Encrypted
     * payloads or unreadable entries prevent disabling.
     */
    Q_INVOKABLE void requestProtectFolderEnabled(bool enabled);

    /**
     * @fn void confirmProtectFolderEnabled(QString password, QString confirmation)
     * @brief Revalidate the preview, prepare the profile on a worker and persist arming.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Any preview mismatch aborts. Both arguments are wiped on every path. Modes 1
     * and 2 adopt the password and clear vault verification without draining actions.
     *
     * @param password Ignored in mode 0, which uses the verified session password.
     * @param confirmation Checked only in mode 1; mismatch aborts.
     */
    Q_INVOKABLE void confirmProtectFolderEnabled(QString password, QString confirmation);

    /**
     * @fn void cleanup()
     * @brief Hold window close until an armed folder is re-protected.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cancels capture and fills, then protects files on a worker, prompting for a
     * verified folder password if needed. Completion wipes the key, drops queued
     * actions and trims the working set; encrypted records remain until destruction.
     *
     * An active cleanup or destructor makes this a no-op. After completion, it only
     * re-emits `cleanupFinished()`. A busy worker or protection failure emits
     * `errorOccurred()` and keeps the window open; closing again retries.
     */
    Q_INVOKABLE void cleanup();

    /**
     * @fn void submitPassword(QString password)
     * @brief Adopt an unverified password in locked memory and drain queued actions.
     * @author Alex (<https://github.com/lextpf>)
     *
     * `passwordSet` becomes true before verification. A queued load detects a wrong
     * password and emits `passwordRetryRequired()`.
     *
     * @post The input QString is filled with null characters.
     */
    Q_INVOKABLE void submitPassword(QString password);

    /**
     * @fn void requestQrCapture()
     * @brief Capture QR text on a worker; ignore overlapping requests.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cleanup and destruction request cancellation. CLI mode sends the result to its
     * panel; otherwise `qrCaptureFinished()` and `qrTextReady()` drive the dialog.
     *
     * @see captureQrFromWebcam
     */
    Q_INVOKABLE void requestQrCapture();

    /**
     * @fn void requestSecureDesktopUnlock()
     * @brief Request an unverified password through the Windows credential prompt.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Blocks the GUI thread. Plaintext moves directly into locked memory and never
     * becomes a QString or reaches QML. Adoption follows `submitPassword()` semantics.
     *
     * Cancel, blank input and other credential-dialog failures stay silent. Only
     * pack/unpack failures emit `secureCaptureFinished(false)`.
     *
     * @note Windows may require Ctrl+Alt+Delete to enter the secure desktop. Policy
     *       or a remote session can cause a normal-desktop fallback without an API
     *       indication; success does not prove which desktop displayed the prompt.
     */
    Q_INVOKABLE void requestSecureDesktopUnlock();

    /**
     * @fn void armFillForRow(int row)
     * @brief Select a filtered row and arm its record through IFillControl.
     * @author Alex (<https://github.com/lextpf>)
     *
     * An invalid row does nothing. Without a fill collaborator, selection still
     * changes. The collaborator owns password gating.
     */
    Q_INVOKABLE void armFillForRow(int row);

    /**
     * @fn void armFillForSelection()
     * @brief No-op without a selection or fill collaborator.
     * @author Alex (<https://github.com/lextpf>)
     */
    Q_INVOKABLE void armFillForSelection();

    /**
     * @fn void onAutoArmed(int recordIndex, const QString& platform)
     * @brief Highlight an already staged record without changing the fill engine.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param recordIndex Full record index.
     * @param platform Non-secret label for the status hint.
     */
    void onAutoArmed(int recordIndex, const QString& platform);

    /**
     * @fn void requestEditSelected()
     * @brief Request editing with non-secret metadata only.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Stored credentials stay in C++; blank edit fields keep them. No-op without a
     * visible selection.
     */
    Q_INVOKABLE void requestEditSelected();

    /**
     * @fn void requestDeleteSelected()
     * @brief Request confirmation with the full record index and non-secret platform label.
     * @author Alex (<https://github.com/lextpf>)
     *
     * No-op without a visible selection.
     */
    Q_INVOKABLE void requestDeleteSelected();

    /**
     * @fn void lockVault()
     * @brief Cancel armed fills and clear the key and verification state; keep records.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Touches no file. No-op without a password; the next gated command prompts.
     */
    Q_INVOKABLE void lockVault();

    /**
     * @fn void rekeyVault(QString currentPassword, QString newPassword)
     * @brief Rotate the vault password, folder password, or both on a worker.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Always reports `rekeyFinished()`. Verifies the folder profile before writing,
     * atomically swaps the vault, then replaces the profile. A failed profile write
     * attempts to rotate the vault back. Folder-only rotation changes the profile;
     * plaintext files use the new password on exit.
     *
     * Success reloads vault packets and adopts the password unless auto-lock cleared
     * the session during work. Queued actions remain pending.
     *
     * Refuses a busy worker, no vault or armed folder, invalid/missing folder profile,
     * or armed folder with encrypted payloads or unreadable entries.
     *
     * @param currentPassword Wiped after capture.
     * @param newPassword Wiped after capture.
     */
    Q_INVOKABLE void rekeyVault(QString currentPassword, QString newPassword);

    /**
     * @fn void setFillControl(IFillControl* fill)
     * @brief Borrowed fill collaborator; nullptr detaches.
     * @author Alex (<https://github.com/lextpf>)
     */
    void setFillControl(IFillControl* fill);

    /**
     * @fn void setCliPanel(seal::CliPanelViewModel* cli)
     * @brief Borrowed CLI panel; nullptr detaches QR-result routing.
     * @author Alex (<https://github.com/lextpf>)
     */
    void setCliPanel(seal::CliPanelViewModel* cli);

signals:
    void vaultLoadedChanged();
    void vaultFileNameChanged();
    void selectionChanged();
    void statusTextChanged();
    void passwordSetChanged();
    void searchFilterChanged();
    void sortModeChanged();
    void countdownTextChanged();
    void busyChanged();
    void loadingChanged();
    void protectFolderEnabledChanged();
    void protectFolderPreflightChanged();
    void protectFolderPreflightReady();  ///< A safe arming preview is ready to display.
    void protectedFolderBootFinished();  ///< Armed-folder startup done; boot cover may close.
    void cleanupFinished();

    void errorOccurred(const QString& title, const QString& message);

    /**
     * @fn void confirmDeleteRequested(int index, const QString& platform)
     * @brief Request confirmation before a record is marked for deletion.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param index Full record index to pass to deleteAccount().
     */
    void confirmDeleteRequested(int index, const QString& platform);

    /**
     * @fn void editAccountRequested(int index, const QString& service)
     * @brief Request editing with non-secret record metadata.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param index Full record index to pass to editAccount().
     * @param service Non-secret platform label.
     */
    void editAccountRequested(int index, const QString& service);

    void infoMessage(const QString& title, const QString& message);

    void passwordRequired();

    /**
     * @fn void qrCaptureFinished(bool success)
     * @brief CLI mode routes the result to the panel instead of emitting this signal.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param success False on error or cancellation.
     */
    void qrCaptureFinished(bool success);

    /**
     * @fn void qrTextReady(const QString& text)
     * @brief Propose unverified QR text after qrCaptureFinished(true).
     * @author Alex (<https://github.com/lextpf>)
     *
     * The sender wipes its copy immediately after emitting; the receiver owns
     * the remaining plaintext.
     */
    void qrTextReady(const QString& text);

    void passwordRetryRequired(const QString& message);

    /**
     * @fn void rekeyFinished(bool success, const QString& message)
     * @brief Report completion of vault or folder password rotation.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param success True when the vault, folder profile, or both use the new password.
     */
    void rekeyFinished(bool success, const QString& message);

    /**
     * @fn void secureCaptureFinished(bool ok)
     * @brief Emitted with false for pack/unpack failures; cancellation is silent.
     * @author Alex (<https://github.com/lextpf>)
     */
    void secureCaptureFinished(bool ok);

private:
    /**
     * @fn bool ensurePassword(std::function<void()> action) override
     * @brief Queue an action and request a password when the key is absent.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param action Copyable retry; hold captured secrets in shared locked buffers.
     * @return True when the caller may proceed inline; false when queued.
     */
    bool ensurePassword(std::function<void()> action) override;

    /**
     * @fn void drainPendingActions()
     * @brief Drain actions in FIFO order, re-reading the queue after each call.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Does not wait for workers. Another queued load is rejected while one is active;
     * records added by a later action can be replaced when that load completes.
     */
    void drainPendingActions();

    size_t pendingActionDepth() const;

    /**
     * @fn void cancelFillIfArmed()
     * @brief Cancel fills before records or the key change, releasing borrowed workspace pointers.
     * @author Alex (<https://github.com/lextpf>)
     */
    void cancelFillIfArmed();

    /**
     * @fn void editAccountWithSecureFields( int index, const QString& service,
     *     seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username, bool
     *     hasUsername, seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&
     *     password, bool hasPassword)
     * @brief Reuse omitted fields inside C++ and re-encrypt the record.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Rewriting the service makes a soft-deleted record visible. Invalid index or
     * absent password leaves input buffers intact; an attempted edit cleanses both.
     *
     * @param hasUsername False keeps the stored username.
     * @param hasPassword False keeps the stored password.
     */
    void editAccountWithSecureFields(
        int index,
        const QString& service,
        seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
        bool hasUsername,
        seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
        bool hasPassword);

    /**
     * @fn void loadVaultFromPath(const QString& filePath, bool isAutoLoad = false)
     * @brief Clone the key in a short access window and load the vault on a worker.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Ignore overlapping loads. A wrong password clears the key, prepends a retry,
     * and emits `passwordRetryRequired()`. During folder startup with an already
     * verified profile, skip the optional vault instead.
     *
     * @param filePath Absolute vault path.
     * @param isAutoLoad Enables startup wording and folder-only fallbacks.
     */
    void loadVaultFromPath(const QString& filePath, bool isAutoLoad = false);

    void finishVaultLoad(const QString& filePath, bool isAutoLoad, size_t recordCount);

    /**
     * @fn void startProtectedFolderDecrypt(std::function<void()> done)
     * @brief Mark the folder plaintext before decrypting it on a worker.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The marker detects interrupted decryption at next startup. Missing key or
     * unwritable marker reports failure without starting a worker.
     *
     * @param done Runs once on the GUI thread, including early failures. A missing
     *             password defers the whole call.
     */
    void startProtectedFolderDecrypt(std::function<void()> done);

    /**
     * @fn void startProtectedFolderUnlock(const QString& optionalVaultPath)
     * @brief Authenticate the folder before optional vault load and boot decryption.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Verification runs on a worker. A missing profile requires a non-empty vault to
     * authenticate the key, then a profile write before any file decrypts.
     *
     * A wrong password clears the key, prepends a retry and re-prompts. Other errors
     * end startup with `protectedFolderBootFinished()` and leave the folder sealed.
     *
     * @param optionalVaultPath Empty selects folder-only startup.
     */
    void startProtectedFolderUnlock(const QString& optionalVaultPath);

    void continueExitProtection();

    void verifyExitPassword();

    void startExitEncryption();

    void finishCleanup();

    /**
     * @fn void failCleanup(const QString& message)
     * @brief Report the failure and clear cleanup state so another close retries.
     * @author Alex (<https://github.com/lextpf>)
     */
    void failCleanup(const QString& message);

    /**
     * @fn QString protectFolderSettingKey(const QString& executableDirectory)
     * @brief Scope the setting by SHA-256 of the normalized executable directory.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Uses native separators and lowercase before hashing.
     *
     * @return `security/protectFolder/<hex SHA-256>`.
     */
    static QString protectFolderSettingKey(const QString& executableDirectory);

    /**
     * @fn QString protectedFolderMarkerPath() const
     * @brief Path to .seal-folder-unprotected in the armed folder.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Decryption creates it; successful cleanup removes it. Its presence at startup
     * means files may remain plaintext.
     */
    QString protectedFolderMarkerPath() const;

    QString protectedFolderProfilePath() const;

    /**
     * @fn bool writeProtectedFolderMarker() const
     * @brief False when the marker write fails.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool writeProtectedFolderMarker() const;

    /**
     * @fn bool removeProtectedFolderMarker() const
     * @brief True when the marker is already absent.
     * @author Alex (<https://github.com/lextpf>)
     */
    bool removeProtectedFolderMarker() const;

    void setStatus(const QString& text) override;

    /**
     * @fn void setLoading(bool on, const QString& caption = {}) override
     * @brief Update cover state and emit once if either value changes.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @param caption Discarded when `on` is false.
     */
    void setLoading(bool on, const QString& caption = {}) override;

    void setBusy(bool busy) override;

    void setCountdown(const QString& text) override;

    /**
     * @fn void refreshModel()
     * @brief Re-filter the model and clear selection because row indices can change.
     * @author Alex (<https://github.com/lextpf>)
     */
    void refreshModel();

    /**
     * @fn void runDirectoryCrypto( const QString& dialogTitle, const char* opScope, int (*op)(const
     *     std::filesystem::path&, const seal::basic_secure_string<wchar_t,
     *     seal::locked_allocator<wchar_t>>&), const char* eventName, const QString& verbPast)
     * @brief Choose a directory and run its operation in one session access window.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Cancel returns silently; unlock failure reports the master-key error. The
     * operation blocks the GUI thread.
     *
     * @pre The caller has passed `ensurePassword()`.
     * @param opScope Diagnostic operation scope, such as `dir_encrypt`.
     * @param eventName Completion event, such as `directory.encrypt.finish`.
     * @param verbPast Past-tense status verb, such as `Encrypted`.
     */
    void runDirectoryCrypto(
        const QString& dialogTitle,
        const char* opScope,
        int (*op)(const std::filesystem::path&,
                  const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&),
        const char* eventName,
        const QString& verbPast);

    /**
     * @fn void reportMasterKeyUnavailable()
     * @brief Report the master-key access error; the caller must still close its access window.
     * @author Alex (<https://github.com/lextpf>)
     */
    void reportMasterKeyUnavailable();

    /**
     * @fn void logAddAccountFailure(const char* what, bool deferred)
     * @brief Report account creation failure after secret cleanup.
     * @author Alex (<https://github.com/lextpf>)
     *
     * @pre The caller has cleansed the secure fields.
     */
    void logAddAccountFailure(const char* what, bool deferred);

    void finishAddAccount(const QString& service, bool deferred);

    /**
     * @fn seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> qstringToSecureWide(
     *     const QString& qstr)
     * @brief Copy directly into locked memory without an intermediate pageable wide string.
     * @author Alex (<https://github.com/lextpf>)
     *
     * The caller must wipe the source QString.
     */
    static seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> qstringToSecureWide(
        const QString& qstr);

    /**
     * @fn void adoptPasswordAndDrain( seal::basic_secure_string<wchar_t,
     *     seal::locked_allocator<wchar_t>>&& wide, const char* source)
     * @brief Adopt an unverified password and drain actions that can verify it.
     * @author Alex (<https://github.com/lextpf>)
     *
     * Clears vault and folder verification. Ownership moves into the session, which
     * DPAPI-protects the password between access windows.
     *
     * @param source Diagnostic origin, such as `manual_entry` or `secure_desktop`.
     */
    void adoptPasswordAndDrain(
        seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&& wide,
        const char* source);

    std::deque<std::function<void()>> m_PendingActions;  ///< FIFO of deferred actions.

    VaultListModel* m_Model = nullptr;
    IFillControl* m_Fill = nullptr;  ///< IFillControl seam (arm/cancel delegate).

    AutoLockController* m_AutoLock = nullptr;

    seal::CredentialWorkspace& m_Workspace;
    seal::AsyncRunner& m_Async;

    QString m_CurrentVaultPath;
    QString m_AutoEncryptDirectory;  ///< Armed executable directory; empty when disabled.
    QString m_ProtectedFolderRoot;   ///< Executable directory keyed by the persisted setting.
    QString m_VerifiedVaultPath;     ///< Vault against which the current session key was verified.
    QString m_ProtectFolderSettingKey;  ///< Security/protectFolder/<directory hash>.
    QString m_ProtectFolderPreflightPath;
    QStringList m_ProtectFolderEncryptFiles;
    QStringList m_ProtectFolderSkippedFiles;
    qulonglong m_ProtectFolderTotalBytes = 0;
    int m_ProtectFolderPasswordMode = 1;  ///< 0=current, 1=create, 2=existing profile.
    bool m_ProtectFolderPreflightProfileExists = false;

    int m_SelectedIndex = -1;  ///< Currently selected row (-1 = none).
    QString m_StatusText = QStringLiteral("Ready");
    QString m_SearchFilter;
    QString m_CountdownText;
    bool m_Busy = false;
    bool m_Loading = false;
    QString m_LoadingCaption;
    bool m_LoadWorkerActive = false;  ///< A vault-load worker thread is in flight.
    bool m_ProtectFolderEnabled = false;
    bool m_ProtectedDecryptPending = false;     ///< Optional vault load precedes folder decryption.
    bool m_ProtectedPasswordVerified = false;   ///< Session key verified by the folder profile.
    bool m_UncleanProtectedSession = false;     ///< Marker was already present at process start.
    size_t m_ProtectedBootDecryptFailures = 0;  ///< Partial boot decrypt count; blocks rekey.
    bool m_CleanupStarted = false;
    bool m_CleanupCompleted = false;  ///< QML may accept the next close after this becomes true.
    bool m_Destroying = false;        ///< Destructor path must not launch asynchronous work.
    seal::AsyncHandle m_QrHandle;
    bool m_QrActive = false;

    CliPanelViewModel* m_Cli = nullptr;  ///< Borrowed CLI panel for QR-into-CLI routing.
};

}  // namespace seal

#endif  // USE_QT_UI
