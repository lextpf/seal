#pragma once

#ifdef USE_QT_UI
#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QTimer>

#include <vector>
#include <functional>

#include "Cryptography.h"
#include "Vault.h"
#include "VaultModel.h"

namespace sage {

class FillController;

/**
 * @class Backend
 * @brief QML backend exposing vault operations, credential management,
 *        and auto-fill functionality to the QML UI layer.
 * @author Alex (https://github.com/lextpf)
 * @ingroup Backend
 *
 * Bridges the sage crypto core with the QML front-end. Owns the vault
 * record list, master password, vault model, and the FillController used
 * for auto-typing credentials into external windows.
 *
 * ## :material-lock: Vault Lifecycle
 *
 * 1. User supplies a master password via submitPassword().
 * 2. loadVault() opens a `.sage` file and populates m_Records.
 * 3. Credentials are displayed through the VaultListModel (vaultModel property).
 * 4. saveVault() encrypts and writes records back to disk.
 * 5. unloadVault() clears records and wipes the master password.
 *
 * ## :material-keyboard: Auto-Fill
 *
 * armFill() arms a global mouse/keyboard hook (via FillController).
 * The user Ctrl+Clicks in an external application to type the username,
 * then Ctrl+Clicks again for the password. cancelFill() disarms early.
 *
 * ## :material-camera: QR Capture
 *
 * requestQrCapture() launches the tess_qr library to scan a QR code
 * from a phone screen held up to the webcam. On success the captured
 * text is stored as the master password, skipping manual entry.
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
    Q_PROPERTY(QString searchFilter READ searchFilter WRITE setSearchFilter NOTIFY searchFilterChanged)
    Q_PROPERTY(QString countdownText READ countdownText NOTIFY countdownTextChanged)
    Q_PROPERTY(bool isBusy READ isBusy NOTIFY busyChanged)
    Q_PROPERTY(bool isFillArmed READ isFillArmed NOTIFY fillArmedChanged)
    Q_PROPERTY(QString fillStatusText READ fillStatusText NOTIFY fillStatusTextChanged)
    Q_PROPERTY(int fillCountdownSeconds READ fillCountdownSeconds NOTIFY fillCountdownSecondsChanged)

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
     * @brief Unload the vault, clearing all records and wiping the password.
     *
     * Resets selectedIndex, clears the model, and cleanses the master
     * password from memory.
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
     * @return QVariantMap with decrypted fields, or empty map on error
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
     * @brief Decrypt all `.sage` files in a user-selected directory.
     *
     * Opens a folder picker, then decrypts every `.sage` file in the
     * directory with the master password. Prompts for password if not set.
     */
    Q_INVOKABLE void decryptDirectory();

    /**
     * @brief Attempt to auto-load a vault from a well-known location.
     *
     * Checks for a `.sage` vault file next to the executable. If found,
     * loads it automatically (still requires master password).
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
     * @param password The master password entered by the user
     */
    Q_INVOKABLE void submitPassword(const QString& password);

    /**
     * @brief Capture text from the webcam by scanning a QR code.
     *
     * Launches a QR capture via the tess_qr library.
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

    Q_INVOKABLE void updateWindowTheme(bool dark);

signals:
    void vaultLoadedChanged();          ///< Vault open/close state changed.
    void vaultFileNameChanged();        ///< Vault file name changed.
    void selectionChanged();            ///< Selected row index changed.
    void statusTextChanged();           ///< Status bar text updated.
    void passwordSetChanged();          ///< Master password set or cleared.
    void searchFilterChanged();         ///< Search filter text changed.
    void countdownTextChanged();        ///< Countdown display text changed.
    void busyChanged();                 ///< Background operation started or finished.

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

    void fillArmedChanged();              ///< Auto-fill armed state toggled.
    void fillStatusTextChanged();         ///< Auto-fill status message updated.
    void fillCountdownSecondsChanged();   ///< Auto-fill countdown tick.

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
     * @brief Attempt to load a vault from the given path.
     *
     * On wrong-password, clears the master key, re-queues itself as
     * the pending action, and emits passwordRetryRequired() so the UI
     * can re-prompt.
     *
     * @param filePath Absolute path to the .sage vault file
     * @param isAutoLoad True when called from autoLoadVault()
     */
    void loadVaultFromPath(const QString& filePath, bool isAutoLoad = false);

    /**
     * @brief Update the status bar text and emit statusTextChanged().
     * @param text New status message
     */
    void setStatus(const QString& text);

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
    static sage::basic_secure_string<wchar_t, sage::locked_allocator<wchar_t>>
        qstringToSecureWide(const QString& qstr);

    /**
     * @brief Open a Win32 file-open dialog.
     * @param title  Dialog title
     * @param filter File type filter (e.g. "Vault Files (*.sage)")
     * @return Selected file path, or empty string if cancelled
     */
    QString openFileDialog(const QString& title, const QString& filter);

    /**
     * @brief Open a Win32 file-save dialog.
     * @param title  Dialog title
     * @param filter File type filter (e.g. "Vault Files (*.sage)")
     * @return Selected file path, or empty string if cancelled
     */
    QString saveFileDialog(const QString& title, const QString& filter);

    /**
     * @brief Open a Win32 folder picker dialog.
     * @param title Dialog title
     * @return Selected folder path, or empty string if cancelled
     */
    QString openFolderDialog(const QString& title);

    std::function<void()>               m_PendingAction;             ///< Action deferred until password is entered.

    VaultListModel*                     m_Model          = nullptr;  ///< Vault list model for QML binding.
    FillController*                     m_FillController = nullptr;  ///< Auto-fill hook controller.

    sage::basic_secure_string<wchar_t>  m_Password;                  ///< Master password in locked memory.
    sage::DPAPIGuard<sage::basic_secure_string<wchar_t>> m_DPAPIGuard; ///< DPAPI in-memory encryption for m_Password.
    bool                                m_PasswordSet    = false;    ///< Whether master password has been entered.

    QString                             m_CurrentVaultPath;          ///< Path to the currently loaded vault file.
    std::vector<sage::VaultRecord>      m_Records;                   ///< In-memory vault records.
    QString                             m_AutoEncryptDirectory;      ///< Directory for auto-encrypt on save.

    int                                 m_SelectedIndex  = -1;                       ///< Currently selected row (-1 = none).
    QString                             m_StatusText     = QStringLiteral("Ready");  ///< Status bar text.
    QString                             m_SearchFilter;                              ///< Active search/filter string.
    QString                             m_CountdownText;                             ///< Countdown display for timed ops.
    bool                                m_Busy           = false;                    ///< Background operation in progress.
};

} // namespace sage

#endif // USE_QT_UI
