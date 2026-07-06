#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>
#include <QTimer>

#include <deque>
#include <functional>
#include <vector>

#include "AsyncRunner.hpp"
#include "CredentialSession.hpp"
#include "CredentialWorkspace.hpp"
#include "Cryptography.hpp"
#include "IFillControl.hpp"
#include "IPasswordGate.hpp"
#include "IUiFeedback.hpp"
#include "Vault.hpp"
#include "VaultModel.hpp"

namespace seal
{

class AutoLockController;
class CliPanelViewModel;

/**
 * @class AppViewModel
 * @brief QML-facing application ViewModel exposing non-secret UI state and
 *        command methods for vault, credential, and auto-fill workflows.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Coordinates the seal crypto core and service/controller collaborators for
 * the QML view layer. Secret values are accepted through command-style
 * methods where needed, but are not exposed as Q_PROPERTY values or model
 * roles.
 *
 * @par The five QML context properties (registered in RunQMLMode)
 * | QML name       | C++ type          | Role                                      |
 * |----------------|-------------------|-------------------------------------------|
 * | `AppViewModel` | AppViewModel      | The hub (this type): vault/credential UI  |
 * | `Cli`          | CliPanelViewModel | Embedded terminal panel                   |
 * | `Fill`         | TypeController    | Auto-fill surface; drives FillController  |
 * | `Bridge`       | BridgeViewModel   | Browser-companion enable/diagnose/install |
 * | `WindowVM`     | WindowController  | Win32 window chrome                       |
 *
 * `WindowVM` is spelled that way (not `Window`) to avoid colliding with
 * QtQuick's built-in `Window` type; `UiScale` (a bare `qreal` DPI factor) is a
 * sixth context property but not a ViewModel.
 *
 * ## :material-lock: Vault Lifecycle
 *
 * ```mermaid
 * ---
 * config:
 *   theme: dark
 *   look: handDrawn
 * ---
 * stateDiagram-v2
 *     [*] --> NoVault
 *     NoVault --> PasswordSet : submitPassword()
 *     PasswordSet --> VaultLoaded : loadVault()
 *     VaultLoaded --> VaultLoaded : addAccount() / editAccount() / deleteAccount()
 *     VaultLoaded --> VaultSaved : saveVault()
 *     VaultSaved --> VaultLoaded : (continue editing)
 *     VaultLoaded --> NoVault : unloadVault() [password retained]
 *     VaultSaved --> NoVault : unloadVault() [password retained]
 *     PasswordSet --> NoVault : cleanup()
 *     VaultLoaded --> NoVault : cleanup()
 *     VaultSaved --> NoVault : cleanup()
 * ```
 *
 * 1. User supplies a master password via submitPassword().
 * 2. loadVault() opens a `.seal` file and populates the workspace records.
 * 3. Credentials are displayed through the VaultListModel (vaultModel property).
 * 4. saveVault() encrypts and writes records back to disk.
 * 5. unloadVault() clears records but retains the master password;
 *    call cleanup() to wipe the password and release all resources.
 *
 * ## :material-key: Pending-Action Pattern
 *
 * Many operations (loadVault, addAccount, saveVault, ...) require the master
 * password. When the password is not yet set, the caller passes a lambda to
 * `ensurePassword(action)` which enqueues it in `m_PendingActions` (FIFO)
 * and emits `passwordRequired()`. Once the user enters the password via
 * `submitPassword()`, `drainPendingActions()` runs all queued actions in
 * order.
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
 * The queue itself is an ordered FIFO: intents pile up at the back while the
 * password is missing, then drain from the front once it arrives.
 *
 * @verbatim
 *   m_PendingActions : std::deque<std::function<void()>>   (FIFO)
 *
 *   ensurePassword(a) --push_back-->   front [ a | b | c ] back
 *   ensurePassword(b) --push_back-->               ^ enqueued in call order
 *   ensurePassword(c) --push_back-->
 *
 *   submitPassword(pw) --> drainPendingActions(): pop_front a, then b, then c
 * @endverbatim
 *
 * ## :material-keyboard: Auto-Fill
 *
 * armFillForRow() / armFillForSelection() arm a global mouse/keyboard hook
 * via the IFillControl seam (TypeController, which drives the FillController
 * engine). While armed, each Ctrl+Click in an external application types
 * whichever field the probe pipeline auto-detects under the cursor (username
 * or password, in either order) until both are filled; Ctrl+Shift+Click and
 * Ctrl+Alt+Click force password/username respectively. cancelFillIfArmed()
 * disarms the hook before any vault mutation.
 *
 * ## :material-camera: QR Capture
 *
 * requestQrCapture() launches OpenCV's `cv::QRCodeDetector` to scan a
 * QR code from a phone screen held up to the webcam. On success the captured
 * text is proposed via qrTextReady() to pre-fill the password dialog;
 * the password is not committed until the user confirms.
 *
 * @see FillController, VaultListModel, Cryptography
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

public:
    /**
     * @brief Construct the AppViewModel, creating the vault model.
     * @param workspace    Injected Qt-free core that owns records, session, and vault path.
     * @param asyncRunner  Async runner for off-thread vault load, rekey, and QR capture.
     * @param parent       Optional QObject parent.
     */
    explicit AppViewModel(seal::CredentialWorkspace& workspace,
                          seal::AsyncRunner& asyncRunner,
                          QObject* parent = nullptr);

    /// @brief Destructor. Wipes sensitive data and removes hooks.
    ~AppViewModel() override;

    /// @brief Get the vault list model for QML binding.
    VaultListModel* vaultModel() const;

    /// @brief Check whether a vault file is currently loaded.
    bool vaultLoaded() const;

    /// @brief Return the filename (without path) of the loaded vault, or empty.
    QString vaultFileName() const;

    /// @brief Check whether a row is currently selected.
    bool hasSelection() const;

    /// @brief Get the currently selected row index (-1 if none).
    int selectedIndex() const;

    /**
     * @brief Set the selected row index.
     * @param index Row index, or -1 to clear selection.
     */
    void setSelectedIndex(int index);

    /// @brief Get the current status bar text.
    QString statusText() const;

    /// @brief Check whether the master password has been entered.
    bool isPasswordSet() const;

    /// @brief Get the current search filter string.
    QString searchFilter() const;

    /**
     * @brief Set the search filter and update the model.
     * @param filter New filter text (empty to show all).
     */
    void setSearchFilter(const QString& filter);

    /// @brief Get the chip-grid ordering mode (VaultListModel::SortMode value).
    int sortMode() const;

    /**
     * @brief Set the chip-grid ordering and re-sort the model.
     * @param mode One of the VaultListModel::SortMode enum values.
     */
    void setSortMode(int mode);

    /// @brief Get the countdown display text for timed operations.
    QString countdownText() const;

    /// @brief Check whether a background operation is in progress.
    bool isBusy() const override;

    /**
     * @brief Whether a full-window loading cover should be shown (vault
     * decrypt or rekey in progress). Distinct from isBusy(), which also
     * covers the auto-fill countdown that must not be covered.
     */
    bool isLoading() const;

    /**
     * @brief Caption shown beneath the loading spinner (e.g. "Decrypting
     * vault...").
     */
    QString loadingCaption() const;

    /**
     * @brief Open a vault file via file dialog and load its index.
     *
     * Prompts for master password if not already set. Decrypts platform
     * names (index only - credentials stay encrypted until needed).
     * Emits vaultLoadedChanged on success.
     */
    Q_INVOKABLE void loadVault();

    /**
     * @brief Save the current vault records to disk.
     *
     * Writes all records (including any pending adds/edits/deletes)
     * via seal::saveVault(). Prompts for file path on first save.
     */
    Q_INVOKABLE void saveVault();

    /**
     * @brief Unload the vault, clearing all records and the file path.
     *
     * Resets selectedIndex, clears the model, and resets the vault path.
     * The master password is retained so the user can open another vault
     * without re-entering it; use cleanup() to wipe the password.
     */
    Q_INVOKABLE void unloadVault();

    /**
     * @brief Add a new credential to the vault.
     *
     * Encrypts the credential with the master password and appends
     * it to the record list. Does not save to disk automatically.
     *
     * @param service  Platform / service name (plaintext, shown in list)
     * @param username Username or email
     * @param password Password for the account
     * @throw std::runtime_error on encryption failure.
     */
    Q_INVOKABLE void addAccount(const QString& service,
                                const QString& username,
                                const QString& password);

    /**
     * @brief Edit an existing credential in the vault.
     *
     * Re-encrypts the credential with updated values. The record is
     * marked dirty until the vault is saved.
     *
     * @param index    Row index of the record to edit
     * @param service  New platform / service name
     * @param username New username. In edit mode, an empty value keeps the stored username.
     * @param password New password. In edit mode, an empty value keeps the stored password.
     * @throw std::runtime_error on encryption failure.
     */
    Q_INVOKABLE void editAccount(int index,
                                 const QString& service,
                                 const QString& username,
                                 const QString& password);

    /**
     * @brief Mark a credential as deleted.
     *
     * The record is flagged but not removed until the vault is saved.
     *
     * @param index Row index of the record to delete
     */
    Q_INVOKABLE void deleteAccount(int index);

    /**
     * @brief Encrypt all files in a user-selected directory.
     *
     * Opens a folder picker, then encrypts every file in the directory
     * with the master password. Prompts for password if not set.
     */
    Q_INVOKABLE void encryptDirectory();

    /**
     * @brief Decrypt all `.seal` files in a user-selected directory.
     *
     * Opens a folder picker, then decrypts every `.seal` file in the
     * directory with the master password. Prompts for password if not set.
     */
    Q_INVOKABLE void decryptDirectory();

    /**
     * @brief Attempt to auto-load a vault from well-known locations.
     *
     * Searches for a `.seal` vault file in priority order:
     * 1. Next to the executable
     * 2. Current working directory
     * 3. User's home directory
     *
     * Loads the first match automatically (still requires master password).
     */
    Q_INVOKABLE void autoLoadVault();

    /**
     * @brief Clean up resources before application exit.
     *
     * Cancels any active fill operation, wipes the master password,
     * and clears all records from memory.
     */
    Q_INVOKABLE void cleanup();

    /**
     * @brief Accept the master password from the QML password dialog.
     *
     * Stores the password in a secure (locked-page) buffer and
     * re-executes any pending action that was waiting for a password.
     *
     * @param password The master password entered by the user.
     *
     * @post The input QString is wiped (filled with null characters) after
     *       the value has been captured into the secure buffer.
     */
    Q_INVOKABLE void submitPassword(QString password);

    /**
     * @brief Capture text from the webcam by scanning a QR code.
     *
     * Launches a QR capture via OpenCV's `cv::QRCodeDetector`.
     * When the borrowed CLI panel is in CLI mode the result is routed into
     * its transcript; otherwise qrCaptureFinished / qrTextReady are emitted
     * for the password dialog.
     */
    Q_INVOKABLE void requestQrCapture();

    /**
     * @brief Arm auto-fill for a visible row (chip double-click gesture).
     *
     * Resolves the filtered row to its record index, selects the row,
     * and arms the fill hooks. No-op when the row is invalid.
     *
     * @param row Visible (filtered) row index from the chip grid.
     */
    Q_INVOKABLE void armFillForRow(int row);

    /**
     * @brief Arm auto-fill for the currently selected row (Fill button).
     *
     * No-op when nothing is selected.
     */
    Q_INVOKABLE void armFillForSelection();

    /**
     * @brief Highlight a record that StagingController just auto-armed.
     *
     * Selects the record's visible row (so the user sees which credential is
     * staged) and shows a non-secret status hint. Deliberately does NOT touch
     * the fill engine - StagingController already armed it; this is display
     * only, keeping AppViewModel free of any fill-engine reference.
     *
     * @param recordIndex Real record index that was auto-armed.
     * @param platform    Cleartext platform label (non-secret) for the hint.
     */
    void onAutoArmed(int recordIndex, const QString& platform);

    /**
     * @brief Request the edit dialog for the currently selected row.
     *
     * Resolves the selection to a record index and emits
     * editAccountRequested() with the non-secret metadata the dialog
     * needs. Stored username/password values are not exposed to QML;
     * the edit command treats blank fields as "keep current value".
     * No-op when nothing is selected.
     */
    Q_INVOKABLE void requestEditSelected();

    /**
     * @brief Request delete confirmation for the currently selected row.
     *
     * Resolves the selection to a record index and emits
     * confirmDeleteRequested() with the platform name for the dialog
     * message. No-op when nothing is selected.
     */
    Q_INVOKABLE void requestDeleteSelected();

    /// @brief Wipe the master password without unloading the vault.
    Q_INVOKABLE void lockVault();

    /**
     * @brief Change the vault master password (atomic re-key on a worker).
     *
     * Validates the current password by loading the vault, re-encrypts all
     * records with the new password, atomically replaces the
     * file, then adopts the new password and reloads the vault. Runs on a
     * worker thread behind isBusy; emits rekeyFinished() on completion.
     *
     * @param currentPassword Current master password (wiped after capture).
     * @param newPassword     New master password (wiped after capture).
     */
    Q_INVOKABLE void rekeyVault(QString currentPassword, QString newPassword);

    /**
     * @brief Wire up the IFillControl seam used to arm/cancel the auto-fill engine.
     * @param fill Pointer to the IFillControl implementation (may be nullptr to detach).
     */
    void setFillControl(IFillControl* fill);

    /**
     * @brief Wire up the borrowed CLI panel so QR captures route into its transcript.
     * @param cli Pointer to the CliPanelViewModel (may be nullptr to detach).
     */
    void setCliPanel(seal::CliPanelViewModel* cli);

signals:
    void vaultLoadedChanged();    ///< Vault open/close state changed.
    void vaultFileNameChanged();  ///< Vault file name changed.
    void selectionChanged();      ///< Selected row index changed.
    void statusTextChanged();     ///< Status bar text updated.
    void passwordSetChanged();    ///< Master password set or cleared.
    void searchFilterChanged();   ///< Search filter text changed.
    void sortModeChanged();       ///< Chip-grid ordering mode changed.
    void countdownTextChanged();  ///< Countdown display text changed.
    void busyChanged();           ///< Background operation started or finished.
    void loadingChanged();        ///< Loading-cover visibility or caption changed.

    /**
     * @brief An error occurred that should be shown to the user.
     * @param title   Dialog title
     * @param message Error description
     */
    void errorOccurred(const QString& title, const QString& message);

    /**
     * @brief Confirmation needed before deleting a credential.
     * @param index    Row index of the record
     * @param platform Service name for display in the dialog
     */
    void confirmDeleteRequested(int index, const QString& platform);

    /**
     * @brief Edit dialog should open for a record.
     * @param index   Row index of the record to edit
     * @param service Current service name to pre-fill (non-secret)
     */
    void editAccountRequested(int index, const QString& service);

    /**
     * @brief An informational message should be shown to the user.
     * @param title   Dialog title
     * @param message Information text
     */
    void infoMessage(const QString& title, const QString& message);

    /// @brief Master password is required before an action can proceed.
    void passwordRequired();

    /**
     * @brief QR webcam capture has finished.
     * @param success True if text was captured, false on error/cancel.
     */
    void qrCaptureFinished(bool success);

    /**
     * @brief QR captured text ready to pre-fill the password dialog.
     * @param text The captured password text (not yet confirmed).
     */
    void qrTextReady(const QString& text);

    /**
     * @brief Wrong password entered - prompt user to retry.
     * @param message Error message to display in the password dialog.
     */
    void passwordRetryRequired(const QString& message);

    /**
     * @brief Rekey finished. @p success false leaves the old password active.
     * @param message Human-readable status for the dialog / status bar.
     */
    void rekeyFinished(bool success, const QString& message);

private:
    /**
     * @brief Ensure the master password is available, deferring @p action if not.
     *
     * If the password is set, returns true and the caller proceeds inline. If
     * not, @p action is enqueued (FIFO) and passwordRequired() is emitted so
     * the dialog opens; returns false. The queue preserves multiple pending
     * intents instead of the previous single overwrite-able slot.
     * @return true if the password is already available.
     */
    bool ensurePassword(std::function<void()> action) override;

    /**
     * @brief Run all queued pending actions in FIFO order (after the password
     *        is set in submitPassword).
     */
    void drainPendingActions();

    /// @brief Current number of deferred actions (diagnostics).
    size_t pendingActionDepth() const;

    /**
     * @brief Cancel any active fill operation and re-protect DPAPI.
     *
     * Must be called before any operation that mutates the workspace records
     * or the master key, since FillController borrows pointers to both.
     * No-op when the fill controller is not armed.
     */
    void cancelFillIfArmed();

    /**
     * @brief Re-encrypt an edited account from secure fields.
     *
     * If @p hasUsername or @p hasPassword is false, the missing field is
     * decrypted from the existing record inside C++ and reused without
     * crossing the QML boundary.
     */
    void editAccountWithSecureFields(
        int index,
        const QString& service,
        seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& username,
        bool hasUsername,
        seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>& password,
        bool hasPassword);

    /**
     * @brief Attempt to load a vault from the given path.
     *
     * On wrong-password, clears the master key, re-queues itself as
     * the pending action, and emits passwordRetryRequired() so the UI
     * can re-prompt.
     *
     * @param filePath Absolute path to the .seal vault file
     * @param isAutoLoad True when called from autoLoadVault()
     */
    void loadVaultFromPath(const QString& filePath, bool isAutoLoad = false);

    /**
     * @brief Update the status bar text and emit statusTextChanged().
     * @param text New status message
     */
    void setStatus(const QString& text) override;

    /**
     * @brief Toggle the loading cover and set its caption, emitting
     *        loadingChanged() once.
     * @param on      Whether the cover should be visible.
     * @param caption Spinner caption (ignored when @p on is false).
     */
    void setLoading(bool on, const QString& caption = {}) override;

    /**
     * @brief Set busy state and emit busyChanged().
     * @param busy True when a background operation is in progress.
     */
    void setBusy(bool busy) override;

    /**
     * @brief Set the countdown display text and emit countdownTextChanged().
     * @param text New countdown text (empty to clear).
     */
    void setCountdown(const QString& text) override;

    /**
     * @brief Rebuild the VaultListModel from the current record list.
     *
     * Applies the active search filter and updates filtered indices.
     */
    void refreshModel();

    /**
     * @brief Shared body for encryptDirectory()/decryptDirectory().
     *
     * Opens the folder picker, runs @p op under a tight session().unlock()
     * window, and logs the finish line. Reports the standard master-key error
     * and returns if the session cannot be unlocked. Callers gate on
     * ensurePassword() first, so the password is already set here.
     *
     * @param dialogTitle Folder-picker caption.
     * @param opScope     nextOpId() scope token (e.g. "dir_encrypt").
     * @param op          seal::encryptDirectory or seal::decryptDirectory.
     * @param eventName   Finish-event token (e.g. "directory.encrypt.finish").
     * @param verbPast    Past-tense verb for the status/info text ("Encrypted").
     */
    void runDirectoryCrypto(
        const QString& dialogTitle,
        const char* opScope,
        int (*op)(const std::filesystem::path&,
                  const seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&),
        const char* eventName,
        const QString& verbPast);

    /**
     * @brief Emit the canonical "master key unavailable" error.
     *
     * Logs the standard `event=auth.unlock result=fail` line and raises
     * errorOccurred() with the fixed vault-access message. Callers still own the
     * unlock() window and the bail-out that follows.
     */
    void reportMasterKeyUnavailable();

    /**
     * @brief Log an add-account failure and surface it to the UI.
     *
     * Shared by the deferred and immediate add paths. The caller has already
     * cleansed the secure fields before calling this.
     *
     * @param what     Exception text (`std::exception::what()`).
     * @param deferred Whether the add ran from a queued pending action.
     */
    void logAddAccountFailure(const char* what, bool deferred);

    /**
     * @brief Log an add-account success, refresh the model, and emit the
     *        vault-changed signals. Shared by the deferred and immediate paths.
     * @param service  Platform name that was added (for the service_len field).
     * @param deferred Whether the add ran from a queued pending action.
     */
    void finishAddAccount(const QString& service, bool deferred);

    /**
     * @brief Convert a QString to a secure wide-character string.
     *
     * The returned string uses locked memory pages to prevent the
     * password from being swapped to disk.
     *
     * @param qstr Input QString
     * @return Secure wchar_t string backed by a locked allocator
     */
    static seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> qstringToSecureWide(
        const QString& qstr);

    std::deque<std::function<void()>> m_PendingActions;  ///< FIFO of deferred actions.

    VaultListModel* m_Model = nullptr;  ///< Vault list model for QML binding.
    IFillControl* m_Fill = nullptr;     ///< IFillControl seam (arm/cancel delegate).

    AutoLockController* m_AutoLock = nullptr;  ///< Idle/session auto-lock collaborator.

    seal::CredentialWorkspace& m_Workspace;  ///< Qt-free core: records, session, vault path.
    seal::AsyncRunner& m_Async;              ///< Async runner for off-thread load/rekey/QR work.

    QString m_CurrentVaultPath;      ///< Path to the currently loaded vault file.
    QString m_AutoEncryptDirectory;  ///< Directory for auto-encrypt on save.

    int m_SelectedIndex = -1;                        ///< Currently selected row (-1 = none).
    QString m_StatusText = QStringLiteral("Ready");  ///< Status bar text.
    QString m_SearchFilter;                          ///< Active search/filter string.
    QString m_CountdownText;                         ///< Countdown display for timed ops.
    bool m_Busy = false;                             ///< Background operation in progress.
    bool m_Loading = false;           ///< Loading cover (vault decrypt/rekey) visible.
    QString m_LoadingCaption;         ///< Caption shown beneath the loading spinner.
    bool m_LoadWorkerActive = false;  ///< A vault-load worker thread is in flight.
    seal::AsyncHandle m_QrHandle;     ///< Handle to the active QR capture task (for cancel).
    bool m_QrActive = false;          ///< True while a QR capture task is in flight.

    CliPanelViewModel* m_Cli = nullptr;  ///< Borrowed CLI panel for QR-into-CLI routing.
};

}  // namespace seal

#endif  // USE_QT_UI
