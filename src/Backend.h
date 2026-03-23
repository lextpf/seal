#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariantMap>

#include <functional>
#include <vector>

#include "Cryptography.h"
#include "Vault.h"
#include "VaultModel.h"

namespace seal
{

class FillController;
class WindowController;

/**
 * @class Backend
 * @brief QML backend exposing vault operations, credential management,
 *        and auto-fill functionality to the QML UI layer.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Backend
 *
 * Bridges the seal crypto core with the QML front-end. Owns the vault
 * record list, master password, vault model, and the FillController used
 * for auto-typing credentials into external windows.
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
 * 2. loadVault() opens a `.seal` file and populates m_Records.
 * 3. Credentials are displayed through the VaultListModel (vaultModel property).
 * 4. saveVault() encrypts and writes records back to disk.
 * 5. unloadVault() clears records but retains the master password;
 *    call cleanup() to wipe the password and release all resources.
 *
 * ## :material-keyboard: Auto-Fill
 *
 * armFill() arms a global mouse/keyboard hook (via FillController).
 * The user Ctrl+Clicks in an external application to type the username,
 * then Ctrl+Clicks again for the password. cancelFill() disarms early.
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
class Backend : public QObject
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
    Q_PROPERTY(QString countdownText READ countdownText NOTIFY countdownTextChanged)
    Q_PROPERTY(bool isBusy READ isBusy NOTIFY busyChanged)
    Q_PROPERTY(bool isFillArmed READ isFillArmed NOTIFY fillArmedChanged)
    Q_PROPERTY(QString fillStatusText READ fillStatusText NOTIFY fillStatusTextChanged)
    Q_PROPERTY(
        int fillCountdownSeconds READ fillCountdownSeconds NOTIFY fillCountdownSecondsChanged)
    Q_PROPERTY(bool isAlwaysOnTop READ isAlwaysOnTop NOTIFY alwaysOnTopChanged)
    Q_PROPERTY(bool isCompact READ isCompact NOTIFY compactChanged)
    Q_PROPERTY(bool isCliMode READ isCliMode NOTIFY cliModeChanged)

public:
    /// @brief Construct the backend, creating the vault model and fill controller.
    explicit Backend(QObject* parent = nullptr);

    /// @brief Destructor. Wipes sensitive data and removes hooks.
    ~Backend() override;

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

    /// @brief Set the selected row index.
    /// @param index Row index, or -1 to clear selection.
    void setSelectedIndex(int index);

    /// @brief Get the current status bar text.
    QString statusText() const;

    /// @brief Check whether the master password has been entered.
    bool isPasswordSet() const;

    /// @brief Get the current search filter string.
    QString searchFilter() const;

    /// @brief Set the search filter and update the model.
    /// @param filter New filter text (empty to show all).
    void setSearchFilter(const QString& filter);

    /// @brief Get the countdown display text for timed operations.
    QString countdownText() const;

    /// @brief Check whether a background operation is in progress.
    bool isBusy() const;

    /// @brief Check whether the auto-fill hooks are armed.
    bool isFillArmed() const;

    /// @brief Get the current auto-fill status message.
    QString fillStatusText() const;

    /// @brief Get seconds remaining before auto-fill times out.
    int fillCountdownSeconds() const;

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
     * using saveVaultV2 format. Prompts for file path on first save.
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
     * @param username New username
     * @param password New password
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
     * @brief Decrypt a credential for display in the edit dialog.
     *
     * Returns a QVariantMap with "service", "username", and "password"
     * keys. The plaintext is wiped from memory after the QML layer
     * copies the values.
     *
     * @param index Row index of the record to decrypt
     * @return QVariantMap with decrypted fields, or empty map on error.
     * @throw std::runtime_error on decryption/authentication failure.
     */
    Q_INVOKABLE QVariantMap decryptAccountForEdit(int index);

    /**
     * @brief Auto-type the username for a credential into the focused window.
     *
     * Decrypts on demand and sends keystrokes via SendInput.
     *
     * @param index Row index of the record
     */
    Q_INVOKABLE void typeLogin(int index);

    /**
     * @brief Auto-type the password for a credential into the focused window.
     *
     * Decrypts on demand and sends keystrokes via SendInput.
     *
     * @param index Row index of the record
     */
    Q_INVOKABLE void typePassword(int index);

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
     * Emits qrCaptureFinished when complete.
     */
    Q_INVOKABLE void requestQrCapture();

    /**
     * @brief Arm auto-fill hooks for a specific credential.
     *
     * Installs global mouse and keyboard hooks. The user then
     * Ctrl+Clicks in an external window to type the username,
     * and Ctrl+Clicks again for the password. Times out after
     * a configurable number of seconds.
     *
     * @param index Row index of the credential to fill
     */
    Q_INVOKABLE void armFill(int index);

    /**
     * @brief Cancel an active auto-fill operation.
     *
     * Removes global hooks and resets the fill controller to idle.
     */
    Q_INVOKABLE void cancelFill();

    /// @brief Apply DWM dark or light window theme and update the custom title bar.
    /// @param dark `true` for dark theme, `false` for light.
    Q_INVOKABLE void updateWindowTheme(bool dark);

    /// @brief Initiate a native window drag via `startSystemMove()`.
    Q_INVOKABLE void startWindowDrag();

    /// @brief Toggle always-on-top (HWND_TOPMOST / HWND_NOTOPMOST).
    Q_INVOKABLE void toggleAlwaysOnTop();

    /// @brief Wipe the master password without unloading the vault.
    Q_INVOKABLE void lockVault();

    /// @brief Toggle compact mode (shrinks window to a minimal strip).
    Q_INVOKABLE void toggleCompact();

    /// @brief Toggle CLI mode (replaces vault UI with embedded terminal).
    Q_INVOKABLE void toggleCliMode();

    /// @brief Execute a command in the embedded CLI panel.
    /// @param command The command string entered by the user.
    Q_INVOKABLE void executeCliCommand(const QString& command);

    /// @brief Handle QR capture result when in CLI mode.
    /// @param text The captured QR text.
    Q_INVOKABLE void handleQrResultForCli(const QString& text);

    /// @brief Check whether the window is pinned above other windows.
    bool isAlwaysOnTop() const;

    /// @brief Check whether the window is in compact (minimal strip) mode.
    bool isCompact() const;

    /// @brief Check whether the CLI panel is active.
    bool isCliMode() const;

signals:
    void vaultLoadedChanged();    ///< Vault open/close state changed.
    void vaultFileNameChanged();  ///< Vault file name changed.
    void selectionChanged();      ///< Selected row index changed.
    void statusTextChanged();     ///< Status bar text updated.
    void passwordSetChanged();    ///< Master password set or cleared.
    void searchFilterChanged();   ///< Search filter text changed.
    void countdownTextChanged();  ///< Countdown display text changed.
    void busyChanged();           ///< Background operation started or finished.

    /// @brief An error occurred that should be shown to the user.
    /// @param title   Dialog title
    /// @param message Error description
    void errorOccurred(const QString& title, const QString& message);

    /// @brief Confirmation needed before deleting a credential.
    /// @param index    Row index of the record
    /// @param platform Service name for display in the dialog
    void confirmDeleteRequested(int index, const QString& platform);

    /// @brief An informational message should be shown to the user.
    /// @param title   Dialog title
    /// @param message Information text
    void infoMessage(const QString& title, const QString& message);

    /// @brief Master password is required before an action can proceed.
    void passwordRequired();

    /// @brief QR webcam capture has finished.
    /// @param success True if text was captured, false on error/cancel.
    void qrCaptureFinished(bool success);

    /// @brief QR captured text ready to pre-fill the password dialog.
    /// @param text The captured password text (not yet confirmed).
    void qrTextReady(const QString& text);

    /// @brief Decrypted account data is ready for the edit dialog.
    /// @param data QVariantMap with "service", "username", "password" keys.
    void editAccountReady(const QVariantMap& data);

    /// @brief Wrong password entered - prompt user to retry.
    /// @param message Error message to display in the password dialog.
    void passwordRetryRequired(const QString& message);

    /// @brief Re-show the add-account dialog after password was entered.
    /// @param service The service name that was originally submitted.
    void addAccountRetryRequired(const QString& service);

    void fillArmedChanged();             ///< Auto-fill armed state toggled.
    void fillStatusTextChanged();        ///< Auto-fill status message updated.
    void fillCountdownSecondsChanged();  ///< Auto-fill countdown tick.
    void alwaysOnTopChanged();           ///< Always-on-top toggled.
    void compactChanged();               ///< Compact mode toggled.
    void cliModeChanged();               ///< CLI mode toggled.

    /// @brief Output text from CLI command execution.
    /// @param text The output line to display in the CLI panel.
    void cliOutputReady(const QString& text);

    /// @brief CLI panel output should be cleared.
    void cliOutputCleared();

private:
    /**
     * @brief Ensure master password is available, prompting if needed.
     *
     * If the password is not set, emits passwordRequired() and stores the
     * pending action for re-execution after submitPassword() is called.
     *
     * @return true if password is available, false if prompt was shown
     */
    bool ensurePassword();

    /**
     * @brief Cancel any active fill operation and re-protect DPAPI.
     *
     * Must be called before any operation that mutates m_Records or
     * m_Password, since FillController borrows pointers to both.
     * No-op when the fill controller is not armed.
     */
    void cancelFillIfArmed();

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
    void setStatus(const QString& text);

    /// @brief Typing mode for scheduleTypingAction.
    enum class TypingMode
    {
        Login,
        Password
    };

    /**
     * @brief Start a 3-second countdown, then execute a typing action.
     *
     * Shared implementation for typeLogin() and typePassword().
     * Snapshots the target record and master password into the worker
     * thread's captures so the worker never touches shared state.
     *
     * @param index  Record index to type.
     * @param mode   Whether to type login (user+tab+pass) or password only.
     * @param label  Status label (e.g. "Login" or "Password").
     */
    void scheduleTypingAction(int index, TypingMode mode, const QString& label);

    /**
     * @brief Rebuild the VaultListModel from the current record list.
     *
     * Applies the active search filter and updates filtered indices.
     */
    void refreshModel();

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

    std::function<void()> m_PendingAction;  ///< Action deferred until password is entered.

    VaultListModel* m_Model = nullptr;               ///< Vault list model for QML binding.
    FillController* m_FillController = nullptr;      ///< Auto-fill hook controller.
    WindowController* m_WindowController = nullptr;  ///< Window chrome controller.

    seal::basic_secure_string<wchar_t> m_Password;  ///< Master password in locked memory.
    seal::DPAPIGuard<seal::basic_secure_string<wchar_t>>
        m_DPAPIGuard;            ///< DPAPI in-memory encryption for m_Password.
    bool m_PasswordSet = false;  ///< Whether master password has been entered.

    QString m_CurrentVaultPath;                ///< Path to the currently loaded vault file.
    std::vector<seal::VaultRecord> m_Records;  ///< In-memory vault records.
    QString m_AutoEncryptDirectory;            ///< Directory for auto-encrypt on save.

    int m_SelectedIndex = -1;                        ///< Currently selected row (-1 = none).
    QString m_StatusText = QStringLiteral("Ready");  ///< Status bar text.
    QString m_SearchFilter;                          ///< Active search/filter string.
    QString m_CountdownText;                         ///< Countdown display for timed ops.
    bool m_Busy = false;                             ///< Background operation in progress.
    bool m_CliMode = false;                          ///< CLI panel active.
    bool m_CliWelcomeShown = false;                  ///< Welcome banner shown once.
    QThread* m_QrThread = nullptr;                   ///< Active QR capture worker thread.
};

}  // namespace seal

#endif  // USE_QT_UI
