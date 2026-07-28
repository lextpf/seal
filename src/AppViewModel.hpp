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
 * @brief QML-facing hub ViewModel for the vault, credential and auto-fill
 *        commands, holding only non-secret UI state.
 * @author Alex (https://github.com/lextpf)
 * @ingroup ViewModel
 *
 * Coordinates the crypto core and the controller collaborators for the QML view
 * layer. Command methods accept secrets where needed, but no Q_PROPERTY and no
 * model role ever exposes one.
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
 * `WindowVM` is spelled that way to avoid a collision with QtQuick's built-in
 * `Window` type.
 *
 * AppViewModel is also the only implementation of IUiFeedback (status text,
 * loading cover, busy flag, countdown) and IPasswordGate (ensurePassword).
 * RunQMLMode passes it to TypeController and CliPanelViewModel as both seams,
 * and to StagingController as IUiFeedback. The setters and ensurePassword() are
 * private, so only a seam holder drives them; QML reads the Q_PROPERTY values.
 *
 * ## :material-lock: Vault Lifecycle
 *
 * The master key and the loaded records move independently: lockVault() and
 * cleanup() drop the key and keep the records; unloadVault() drops the records
 * and keeps the key. The diagram tracks the key, because that is what every
 * vault command gates on.
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
 * 1. submitPassword() adopts the password unverified; the queued vault load is
 *    what proves it.
 * 2. loadVault() decrypts only the platform names; each credential stays sealed
 *    until VaultListModel is asked for it.
 * 3. saveVault() rewrites the file and erases the soft-deleted records.
 * 4. cleanup() wipes the key and, when folder protection is armed, re-encrypts
 *    the executable folder before the window may close.
 *
 * Two commands run without the gate. deleteAccount() soft-deletes at once; the
 * delete reaches disk only through the gated saveVault(). rekeyVault() takes the
 * current password as a parameter, so it rotates the key while the session stays
 * locked.
 *
 * ## :material-key: Pending-Action Pattern
 *
 * Commands that need the master password (loadVault, addAccount, saveVault,
 * ...) pass a lambda to `ensurePassword(action)`. With no password set it is
 * queued in `m_PendingActions` and `passwordRequired()` is emitted;
 * `submitPassword()` or `requestSecureDesktopUnlock()` then runs
 * `drainPendingActions()`, which dispatches the queue in order.
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
 * One exception to the tail-append rule: a wrong-password retry
 * (loadVaultFromPath, startProtectedFolderUnlock, verifyExitPassword) pushes
 * itself to the front, so the retried action runs before older intents.
 * confirmProtectFolderEnabled() also adopts a password but does not drain:
 * actions queued before it wait for a later submitPassword().
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
 * ## :material-keyboard: Auto-Fill
 *
 * armFillForRow() and armFillForSelection() arm a global mouse/keyboard hook
 * through the IFillControl seam (TypeController, which drives FillController).
 * While armed, each Ctrl+Click in an external application types whichever field
 * the probe pipeline detects under the cursor, until both are filled.
 * Ctrl+Shift+Click forces the password, Ctrl+Alt+Click the username.
 * cancelFillIfArmed() disarms the hook before any vault mutation.
 *
 * ## :material-camera: QR Capture
 *
 * requestQrCapture() uses OpenCV's `cv::QRCodeDetector` to scan a QR code from
 * a phone screen held up to the webcam. On success the text is proposed through
 * qrTextReady() to pre-fill the password dialog; nothing reaches the session
 * until the user confirms.
 *
 * @see FillController, VaultListModel, Cryptography, IUiFeedback, IPasswordGate,
 *      IFillControl
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
     * @brief Construct the AppViewModel and create the vault model.
     *
     * Reads the per-directory folder-protection opt-in from QSettings, seeds the
     * initial status text from it, and creates the AutoLockController child. No
     * vault is loaded and no password is held afterwards.
     *
     * @param workspace   Qt-free core owning the records, session and vault path.
     * @param asyncRunner Runner for every off-thread task: vault load, rekey, QR
     *                    capture, folder-profile create/verify, folder crypto.
     *
     * @pre @p workspace and @p asyncRunner are borrowed, not owned, and outlive
     *      this object.
     */
    explicit AppViewModel(seal::CredentialWorkspace& workspace,
                          seal::AsyncRunner& asyncRunner,
                          QObject* parent = nullptr);

    /**
     * @brief Destructor. Cancels QR capture and armed fills, then wipes the password.
     *
     * Starts no worker and shows no prompt. Exit re-protection of an armed
     * folder belongs to cleanup(), which runs while the event loop is alive. A
     * teardown that skips cleanup() leaves the plaintext-session marker on
     * disk, which is reported on the next start.
     */
    ~AppViewModel() override;

    /**
     * @brief Get the vault list model for QML binding.
     *
     * The model is a QObject child of this AppViewModel, is never null after
     * construction, and stays the same instance for the whole lifetime of this
     * object; that is why the Q_PROPERTY is CONSTANT. QML binds to the model
     * but never owns it: do not delete it, reparent it, or keep the pointer
     * past this object, which RunQMLMode holds as a stack local.
     */
    VaultListModel* vaultModel() const;

    /**
     * @brief Whether the UI should show vault content instead of the empty state.
     *
     * True when a vault path is held or the workspace holds records, so accounts
     * added before the first saveVault() already count as loaded. Soft-deleted
     * records still count, so deleting every account keeps this true; QML
     * detects the empty grid from the model row count instead.
     */
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
     *
     * The model coerces a value that is not a SortMode enumerator to
     * SortMode::Alphabetical, so sortMode() can differ from @p mode afterwards.
     * sortModeChanged() is emitted either way.
     *
     * @param mode One of the VaultListModel::SortMode enum values.
     */
    void setSortMode(int mode);

    /// @brief Get the countdown display text for timed operations.
    QString countdownText() const;

    /**
     * @brief Check whether a background operation is in progress.
     *
     * Covers the worker-backed folder operations, the rekey and the auto-fill
     * countdown. A vault load is not covered: it raises isLoading() and the
     * separate `m_LoadWorkerActive` flag instead.
     */
    bool isBusy() const override;

    /**
     * @brief Whether the full-window loading cover should be shown.
     *
     * Set for the long crypto steps that own the whole window: vault decrypt,
     * rekey, folder-profile create/verify, and protected-folder crypto.
     * isBusy() is not a superset: a vault decrypt raises isLoading() and
     * `m_LoadWorkerActive` but never isBusy(), and the auto-fill countdown
     * raises isBusy() but must stay visible, so it never raises the cover. A
     * gate that must exclude a running load tests `m_Busy || m_LoadWorkerActive`.
     */
    bool isLoading() const;

    /**
     * @brief Caption shown beneath the loading spinner, such as "Decrypting
     *        vault..." or "Verifying folder password...".
     *
     * Empty whenever isLoading() is false.
     */
    QString loadingCaption() const;

    /// @brief Whether this executable directory is armed for exit protection.
    bool protectFolderEnabled() const;

    /**
     * @brief Executable directory shown by the arming preflight.
     *
     * Empty until requestProtectFolderEnabled(true) produces a preview, and
     * cleared again when protection is turned off.
     */
    QString protectFolderPath() const;

    /// @brief Relative files that the current arming preview would encrypt.
    QStringList protectFolderEncryptFiles() const;

    /**
     * @brief Entries the arming preview would leave alone, with their reason.
     *
     * Each string is `<relative path> - <skip reason token>`, where the token is
     * the stable telemetry spelling from
     * seal::protected_folder::skipReasonToken (`app_runtime`, `qt_deploy_dir`,
     * `credential_vault`, `already_encrypted`, ...).
     */
    QStringList protectFolderSkippedFiles() const;

    /// @brief Total plaintext bytes covered by the current arming preview.
    qulonglong protectFolderTotalBytes() const;

    /**
     * @brief Password UI mode for the current arming preview.
     *
     * 0 reuses a currently verified password, 1 creates and confirms a new
     * folder password, and 2 unlocks an existing copied folder profile.
     */
    int protectFolderPasswordMode() const;

    /**
     * @brief Open a vault file via file dialog and load its index.
     *
     * Prompts for the master password when it is not set. Decrypts the platform
     * names only, on a worker behind the loading cover; the credentials stay
     * encrypted until needed. Cancelling the file dialog is a silent no-op.
     * Emits vaultLoadedChanged() on success.
     */
    Q_INVOKABLE void loadVault();

    /**
     * @brief Save the current vault records to disk.
     *
     * Prompts for the master password when it is not set, then reuses the loaded
     * vault path or asks for one on first save, appending `.seal` when the
     * chosen name has no such suffix. Runs on the GUI thread.
     *
     * @par Soft deletes
     * Soft-deleted records are committed here: the file omits them and they are
     * erased from memory. That erase renumbers the records without bumping the
     * workspace generation, so the model is rebuilt afterwards, and an armed
     * fill is cancelled first because it borrows the same record list.
     *
     * @par Failure
     * Any exception from the workspace save - a failed Access window on the
     * master key, or a failed re-encryption of a dirty platform name - reports
     * errorOccurred("Vault error", "Could not access the master key.") and logs
     * `reason=dpapi_unprotect`; the vault file is left untouched. An I/O error,
     * or a field or record count that overflows the 32-bit on-disk fields,
     * reports errorOccurred("Error", "Failed to save vault file") instead. No
     * record is modified on either path.
     */
    Q_INVOKABLE void saveVault();

    /**
     * @brief Unload the vault, clearing all records and the file path.
     *
     * Resets selectedIndex, clears the model, and resets the vault path. Nothing
     * is written to disk, so unsaved edits are discarded. The master password is
     * kept so the user can open another vault without re-entering it; use
     * lockVault() or cleanup() to wipe it.
     */
    Q_INVOKABLE void unloadVault();

    /**
     * @brief Add a new record to the vault.
     *
     * Encrypts the credential with the master password and appends it to the
     * record list. Nothing is written to disk; call saveVault().
     *
     * All three fields are required: an empty one reports
     * errorOccurred("Warning", ...) and adds no record. When the master password
     * is not set, both secrets move into locked memory and the add is deferred
     * until submitPassword() drains it. Encryption failure does not propagate:
     * it is logged and reported through errorOccurred().
     *
     * @param service  Platform label; stored in plaintext and shown in the list.
     *                 The account dialog labels this field Service.
     * @param username Username or email for the account.
     * @param password Password for the account.
     */
    Q_INVOKABLE void addAccount(const QString& service,
                                const QString& username,
                                const QString& password);

    /**
     * @brief Edit an existing record in the vault.
     *
     * Re-encrypts the record in place and marks it dirty until the vault is
     * saved. An empty @p service is rejected with errorOccurred("Warning", ...).
     * When the master password is not set, the supplied fields are held in
     * locked memory and the edit is deferred until the password arrives.
     * Encryption failure does not propagate: it is logged and reported through
     * errorOccurred().
     *
     * @param index    Record index (position in the full record list, not the
     *                 filtered row); out-of-range values are ignored.
     * @param service  New platform label.
     * @param username New username. An empty value keeps the stored username.
     * @param password New password. An empty value keeps the stored password.
     */
    Q_INVOKABLE void editAccount(int index,
                                 const QString& service,
                                 const QString& username,
                                 const QString& password);

    /**
     * @brief Preview the strict browser site binding for a platform label.
     *
     * Read-only: nothing is stored and no secret is touched. @p service is
     * trimmed, then reduced to a host by seal::url::extractHost.
     *
     * @param service Proposed platform label.
     * @return Map with five keys:
     *         - `bindable` (bool) - host contains a dot and has a registrable
     *           domain.
     *         - `host` (QString) - normalised full host; empty when not bindable.
     *         - `duplicateCount` (qulonglong) - live records with an equal host;
     *           a parent/child pair does not count. 0 when not bindable.
     *         - `publicSuffix` (bool) - the host is a public suffix with a dot,
     *           such as `co.uk`; a single-label host such as `com` is false.
     *         - `suggestion` (QString) - `<key>.com` when the label is not
     *           bindable and seal::url::extractKey finds a brand; else empty.
     */
    Q_INVOKABLE QVariantMap previewSiteBinding(const QString& service) const;

    /**
     * @brief Editing overload that excludes the current record from duplicates.
     * @param service Proposed platform label.
     * @param excludedRecordIndex Record index to skip while counting
     *                            duplicates, or -1 when adding.
     * @return Same map as the single-argument overload.
     */
    Q_INVOKABLE QVariantMap previewSiteBinding(const QString& service,
                                               int excludedRecordIndex) const;

    /**
     * @brief Mark a record as deleted.
     *
     * Soft delete: the record is hidden from the model at once but stays in
     * memory until saveVault() writes the file without it. An armed fill is
     * cancelled first. When no visible record remains, vaultLoadedChanged() and
     * vaultFileNameChanged() are emitted so the dependent QML bindings
     * re-evaluate; vaultLoaded() itself stays true, because the soft-deleted
     * records are still in the workspace.
     *
     * @param index Record index (position in the full record list, not the
     *              filtered row); out-of-range values are ignored.
     */
    Q_INVOKABLE void deleteAccount(int index);

    /**
     * @brief Encrypt the eligible files of a user-selected directory.
     *
     * Prompts for the master password when it is not set, opens a folder picker,
     * then walks the directory recursively under the protected-folder policy.
     * That policy skips executables and other runtime files, Qt deployment
     * directories, native-messaging manifests, credential vaults, existing
     * `.seal` files, lock files, and symlinks. The walk runs on the GUI thread
     * and blocks the UI until it ends.
     *
     * @warning Every successfully encrypted source file is deleted; only its
     *          `.seal` output remains. One CredentialSession::Access window
     *          covers the whole walk, so the master key stays unprotected in
     *          memory until the walk ends, much longer than the per-record
     *          decrypt window. Each file costs one scrypt derivation (64 MiB),
     *          so the UI freeze grows with the number of files.
     */
    Q_INVOKABLE void encryptDirectory();

    /**
     * @brief Decrypt the eligible `.seal` files of a user-selected directory.
     *
     * Mirror of encryptDirectory(): same password prompt, same folder picker,
     * same recursive walk and skip policy, same GUI-thread blocking, same
     * single Access window over the whole walk, and the same scrypt cost per
     * file. Credential vaults stay sealed.
     *
     * @warning Every successfully decrypted `.seal` file is deleted; only the
     *          plaintext output remains.
     */
    Q_INVOKABLE void decryptDirectory();

    /**
     * @brief Attempt to auto-load a vault from well-known locations.
     *
     * No-op when a vault path is already held. Loading still requires the master
     * password.
     *
     * @par Search order without folder protection
     * 1. Next to the executable
     * 2. Current working directory
     * 3. User's home directory
     *
     * Within one directory the `*.seal` and `.seal` matches are visited in
     * case-insensitive name order, and the first file whose decoded frame magic
     * is `SVH2` wins. A symlink, and a `.seal` file without that magic, is never
     * adopted.
     *
     * @par With folder protection armed
     * Only the protected executable directory is searched, and the startup
     * preflight is enforced. Startup is refused with errorOccurred() and no load
     * when Qt6Core.dll sits beside seal.exe, when `.seal-folder-profile` is
     * invalid, or when the profile is missing and no vault was found. A missing
     * profile plus one vault is the migration case handled by
     * startProtectedFolderUnlock(). Two or more candidates are ambiguous, so no
     * vault is adopted and startup continues folder-only.
     */
    Q_INVOKABLE void autoLoadVault();

    /**
     * @brief Request a change to executable-folder protection.
     *
     * No-op when @p enabled already matches the current state or exit cleanup
     * has begun; refused with errorOccurred() while a background operation is in
     * flight.
     *
     * @par Disabling
     * Immediate, and never triggers a final encryption. Refused while any
     * protected payload is still encrypted on disk or any folder entry cannot be
     * inspected. The folder profile is kept on disk.
     *
     * @par Enabling
     * Inventories the folder, enforces the static-deployment preflight, checks
     * for occupied encrypt-output paths, inspects the folder profile, and emits
     * protectFolderPreflightReady() for explicit confirmation. Nothing is armed
     * until confirmProtectFolderEnabled() runs.
     *
     * @param enabled Requested state of protection for this executable folder.
     */
    Q_INVOKABLE void requestProtectFolderEnabled(bool enabled);

    /**
     * @brief Confirm the protected-folder plan shown by the preflight.
     *
     * Revalidates the deployment and re-runs the preview, then creates or
     * verifies the folder profile on a worker and persists the per-directory
     * setting. Any mismatch against the preview aborts the arming. Both QString
     * arguments are wiped on every path, used or not, including each early
     * return.
     *
     * In modes 1 and 2 the accepted password is adopted as the session master
     * password, which clears the verified-vault path. Unlike submitPassword(),
     * adoption does not drain the pending-action queue.
     *
     * @param password     Folder password. Ignored when
     *                     protectFolderPasswordMode() is 0, which reuses the
     *                     verified session password instead.
     * @param confirmation Repeat of @p password. Read only in mode 1 (new
     *                     profile); a mismatch aborts the arming.
     */
    Q_INVOKABLE void confirmProtectFolderEnabled(QString password, QString confirmation);

    /**
     * @brief Clean up resources before application exit.
     *
     * Cancels an in-flight QR capture and any armed fill. With folder protection
     * armed, it then holds the window open and re-protects eligible files
     * asynchronously, prompting for and validating the folder profile password
     * when needed. Finishing wipes the master password, drops queued pending
     * actions, and trims the working set; the encrypted records stay in memory
     * until destruction.
     *
     * @par Idempotence
     * QML drives the held-close handshake, so repeated calls are safe: during a
     * running cleanup, and after the destructor starts, the call does nothing;
     * after cleanup completed it only re-emits cleanupFinished().
     *
     * @par Refusal and retry
     * With protection armed and a vault load or another background operation in
     * flight, the call is refused through errorOccurred() and nothing is torn
     * down; the user closes again once it finishes. A failed re-protection
     * reports errorOccurred(), keeps the window open, and is retried by closing
     * again.
     */
    Q_INVOKABLE void cleanup();

    /**
     * @brief Accept the master password from the QML password dialog.
     *
     * Stores the password in a locked-page buffer and drains every action that
     * was waiting for a password. The password is adopted, not verified:
     * passwordSet turns true immediately, and a wrong password is detected only
     * by the queued vault load, which then re-prompts through
     * passwordRetryRequired().
     *
     * @param password The master password entered by the user.
     *
     * @post The input QString is filled with null characters once the value has
     *       been captured into the secure buffer.
     */
    Q_INVOKABLE void submitPassword(QString password);

    /**
     * @brief Capture text from the webcam by scanning a QR code.
     *
     * Runs the OpenCV `cv::QRCodeDetector` loop on the async pool, because it
     * blocks until a code is found or its timeout expires (60 s by default,
     * `SEAL_CAPTURE_TIMEOUT_SEC`). A second call while a capture is in flight is
     * logged and ignored. cleanup() and the destructor cancel the task
     * cooperatively.
     *
     * When the borrowed CLI panel is in CLI mode the result goes into its
     * transcript; otherwise qrCaptureFinished() and qrTextReady() are emitted
     * for the password dialog.
     */
    Q_INVOKABLE void requestQrCapture();

    /**
     * @brief Capture the master password on Windows' secure desktop.
     *
     * Opens `CredUIPromptForWindowsCredentialsW` with `CREDUIWIN_SECURE_PROMPT`
     * (a dimmed, keylogger-isolated screen), copies the typed password into
     * locked memory, and routes it through the same adopt-then-verify path as
     * manual entry. The secret never becomes a QString and never reaches QML.
     * Runs synchronously on the GUI thread; the secure desktop owns the screen
     * meanwhile.
     *
     * A cancel, or a blank submission which counts as one, leaves the QML
     * password dialog open and fires no signal. Only a credential pack or
     * unpack failure emits `secureCaptureFinished(false)`.
     * readPasswordSecureDesktop() reports every other non-success result of the
     * credential dialog as `"User canceled"`, so those outcomes stay silent and
     * appear only in the `event=auth.secure_desktop.finish` log line, with
     * `result=cancel`.
     *
     * @note On Windows 11 the secure prompt is reached only through the
     *       Ctrl+Alt+Delete secure attention sequence: Windows first shows an
     *       uneditable "authentic Windows sign-in screen" message that a plain
     *       click does not advance. Windows controls that, so the
     *       PasswordDialog "Secure" button carries a priming tooltip. Custom
     *       secure desktops (CreateDesktop/SwitchDesktop) are deprecated on
     *       Windows 11, leaving this CredUI path as the only supported option.
     */
    Q_INVOKABLE void requestSecureDesktopUnlock();

    /**
     * @brief Arm auto-fill for a visible row (chip double-click gesture).
     *
     * Resolves the filtered row to its record index, selects the row, and arms
     * the fill hooks through the IFillControl seam. A row that maps to no record
     * is a complete no-op. With no seam attached the row is still selected and
     * nothing is armed. The seam runs its own password gate, so this method
     * never calls ensurePassword().
     *
     * @param row Visible (filtered) row index from the chip grid.
     */
    Q_INVOKABLE void armFillForRow(int row);

    /**
     * @brief Arm auto-fill for the currently selected row (Fill button).
     *
     * No-op when nothing is selected or no IFillControl seam is attached.
     */
    Q_INVOKABLE void armFillForSelection();

    /**
     * @brief Highlight a record that StagingController just auto-armed.
     *
     * Selects the record's visible row, so the user sees which credential is
     * staged, and shows a non-secret status hint. Display only: StagingController
     * has already armed the fill engine, and AppViewModel holds no reference to
     * it.
     *
     * @param recordIndex Real record index that was auto-armed.
     * @param platform    Cleartext platform label (non-secret) for the hint.
     */
    void onAutoArmed(int recordIndex, const QString& platform);

    /**
     * @brief Request the edit dialog for the currently selected row.
     *
     * Resolves the selection to a record index and emits editAccountRequested()
     * with the non-secret metadata the dialog needs. The stored username and
     * password stay in C++; the edit command treats a blank field as "keep the
     * current value". No-op when nothing is selected or the selected row is
     * filtered out.
     */
    Q_INVOKABLE void requestEditSelected();

    /**
     * @brief Request delete confirmation for the currently selected row.
     *
     * Resolves the selection to a record index and emits
     * confirmDeleteRequested() with the platform name for the dialog message.
     * No-op when nothing is selected or the selected row is filtered out.
     */
    Q_INVOKABLE void requestDeleteSelected();

    /**
     * @brief Wipe the master password without unloading the vault.
     *
     * Cancels an armed fill, clears the session key, and clears the verified-vault
     * path and the verified-folder flag; no file is touched. The next action that
     * needs the key re-prompts. No-op when no password is held. This is also the
     * target of the AutoLockController idle and session-lock triggers.
     */
    Q_INVOKABLE void lockVault();

    /**
     * @brief Change the master password of the vault, the armed folder, or both.
     *
     * Runs on a worker behind isBusy and the loading cover, and always ends in
     * rekeyFinished().
     *
     * @par What is rewritten
     * A loaded vault file is re-encrypted record by record and swapped
     * atomically. An armed folder also verifies @p currentPassword against
     * `.seal-folder-profile` before any write, then replaces that profile. If
     * the profile write fails after the vault swap, the vault is rotated back,
     * so the two authorities never disagree. With an armed folder and no vault,
     * only the profile changes; the plaintext files take the new password on
     * exit.
     *
     * @par After success
     * The new password is adopted, and a re-keyed vault is reloaded so the
     * workspace holds new-password packets. If auto-lock cleared the session
     * mid-rekey, the password is not adopted: the disk already holds it, so the
     * next unlock needs it. Queued pending actions are not drained.
     *
     * @par Refused before any work (rekeyFinished(false, ...))
     * - no loaded vault and no armed folder, or a background operation is busy
     * - folder armed and boot decryption left files encrypted
     * - folder armed and `.seal-folder-profile` is missing or invalid
     * - folder armed and the folder still holds encrypted payloads or
     *   unreadable entries
     *
     * @param currentPassword Current master password; wiped after capture.
     * @param newPassword     New master password; wiped after capture.
     */
    Q_INVOKABLE void rekeyVault(QString currentPassword, QString newPassword);

    /**
     * @brief Wire up the IFillControl seam used to arm and cancel the auto-fill engine.
     * @param fill IFillControl implementation, or nullptr to detach.
     */
    void setFillControl(IFillControl* fill);

    /**
     * @brief Wire up the borrowed CLI panel so QR captures route into its transcript.
     * @param cli Borrowed CliPanelViewModel, or nullptr to detach.
     */
    void setCliPanel(seal::CliPanelViewModel* cli);

signals:
    void vaultLoadedChanged();             ///< Vault open/close state changed.
    void vaultFileNameChanged();           ///< Vault file name changed.
    void selectionChanged();               ///< Selected row index changed.
    void statusTextChanged();              ///< Status bar text updated.
    void passwordSetChanged();             ///< Master password set or cleared.
    void searchFilterChanged();            ///< Search filter text changed.
    void sortModeChanged();                ///< Chip-grid ordering mode changed.
    void countdownTextChanged();           ///< Countdown display text changed.
    void busyChanged();                    ///< Background operation started or finished.
    void loadingChanged();                 ///< Loading-cover visibility or caption changed.
    void protectFolderEnabledChanged();    ///< Per-directory protection setting changed.
    void protectFolderPreflightChanged();  ///< Arming preview content changed.
    void protectFolderPreflightReady();    ///< A safe arming preview is ready to display.
    void protectedFolderBootFinished();    ///< Armed-folder startup done; boot cover may close.
    void cleanupFinished();                ///< Exit cleanup/re-protection completed.

    /// @brief An error dialog should open with this title and message.
    void errorOccurred(const QString& title, const QString& message);

    /**
     * @brief Confirmation needed before deleting a credential.
     * @param index    Record index to pass back to deleteAccount().
     * @param platform Service name shown in the dialog.
     */
    void confirmDeleteRequested(int index, const QString& platform);

    /**
     * @brief Edit dialog should open for a record.
     * @param index   Record index to pass back to editAccount().
     * @param service Current service name to pre-fill; non-secret.
     */
    void editAccountRequested(int index, const QString& service);

    /// @brief An informational dialog should open with this title and message.
    void infoMessage(const QString& title, const QString& message);

    /// @brief Master password is required before an action can proceed.
    void passwordRequired();

    /**
     * @brief QR webcam capture has finished.
     *
     * Not emitted when the borrowed CLI panel is in CLI mode; that result goes
     * to the panel transcript instead.
     *
     * @param success True when text was captured; false on error or cancel.
     */
    void qrCaptureFinished(bool success);

    /**
     * @brief QR captured text ready to pre-fill the password dialog.
     *
     * Follows qrCaptureFinished(true). The ViewModel wipes its own copy right
     * after emitting, so the receiver holds the only remaining plaintext.
     *
     * @param text The captured text, not yet confirmed as a password.
     */
    void qrTextReady(const QString& text);

    /// @brief Wrong password entered; @p message is shown in the password dialog.
    void passwordRetryRequired(const QString& message);

    /**
     * @brief Rekey finished.
     *
     * On failure nothing on disk changed and the old password stays active.
     *
     * @param success True when the vault file, the folder profile, or both
     *                now use the new password.
     * @param message Human-readable status for the dialog and status bar.
     */
    void rekeyFinished(bool success, const QString& message);

    /**
     * @brief Secure-desktop capture failed.
     *
     * A user cancel is a normal outcome and is silent, so this signal is only
     * ever emitted with false.
     *
     * @param ok Always false; the parameter exists for QML symmetry with the
     *           other finished signals.
     */
    void secureCaptureFinished(bool ok);

private:
    /**
     * @brief Ensure the master password is available, deferring @p action if not.
     *
     * With the password set, returns true and the caller proceeds inline.
     * Otherwise @p action is appended to the tail of the queue,
     * passwordRequired() is emitted so the dialog opens, and the call returns
     * false. The queue holds every pending intent, not just the newest.
     *
     * @param action Callable re-run once the password arrives. A caller that
     *               holds secrets keeps them in locked memory behind a
     *               shared_ptr, because the callable is copied into the queue.
     * @return true when the password is already available.
     */
    bool ensurePassword(std::function<void()> action) override;

    /**
     * @brief Run queued pending actions front to back until the queue is empty.
     *
     * Runs after a password is adopted. An action may enqueue further work (a
     * wrong-password retry pushes itself to the front), so the loop re-reads the
     * queue after every call instead of iterating a snapshot.
     *
     * The loop waits for nothing. An action that starts a worker returns as soon
     * as the task is queued, so the remaining actions run beside it. A second
     * queued vault load is then dropped by the in-flight guard in
     * loadVaultFromPath(), and a record added by a later action is lost when
     * that load completes and calls replaceRecords().
     */
    void drainPendingActions();

    /// @brief Current number of deferred actions (diagnostics).
    size_t pendingActionDepth() const;

    /**
     * @brief Cancel an armed or in-progress fill through the IFillControl seam.
     *
     * Cancelling drops the fill engine's borrowed pointers to the records and
     * the session, so this runs before any operation that mutates the workspace
     * records or the master key. No-op when no seam is attached or the engine is
     * idle.
     */
    void cancelFillIfArmed();

    /**
     * @brief Re-encrypt an edited account from secure fields.
     *
     * When @p hasUsername or @p hasPassword is false, the missing field is
     * decrypted from the existing record inside C++ and reused without crossing
     * the QML boundary. The service name is always rewritten, so a soft-deleted
     * record edited this way becomes visible again.
     *
     * @par Buffer ownership
     * An out-of-range @p index, or no master password held, returns silently and
     * leaves both buffers intact for the caller. Once the edit is attempted,
     * both are cleansed here, on success and on failure alike.
     *
     * @param index       Record index to replace.
     * @param service     New platform name; converted to UTF-8 for the record.
     * @param username    New username buffer.
     * @param hasUsername False keeps the stored username.
     * @param password    New password buffer.
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
     * @brief Attempt to load a vault from the given path.
     *
     * Clones the master password inside a short GUI-thread unlock window, then
     * runs the scrypt KDF and the index decrypt on a worker behind the loading
     * cover. A re-entrant dispatch is dropped while a load worker is in flight.
     *
     * @par Wrong password
     * Clears the master key, re-queues this call at the front of the
     * pending-action queue, and emits passwordRetryRequired() so the UI
     * re-prompts. The one exception is an armed folder whose profile already
     * authenticated the session: there the optional vault is reported as skipped
     * and folder-only startup continues.
     *
     * @param filePath   Absolute path to the .seal vault file.
     * @param isAutoLoad True when called from the startup path; selects the
     *                   auto-load status wording and enables the folder-only
     *                   fallbacks above.
     */
    void loadVaultFromPath(const QString& filePath, bool isAutoLoad = false);

    /**
     * @brief Finish the GUI-visible tail of a successful vault load.
     * @param filePath    Loaded vault path; only its file name is shown.
     * @param isAutoLoad  Selects the auto-load wording of the status line.
     * @param recordCount Number of records reported in the status line.
     */
    void finishVaultLoad(const QString& filePath, bool isAutoLoad, size_t recordCount);

    /**
     * @brief Decrypt the armed executable folder on a worker, then invoke @p done.
     *
     * Writes the plaintext-session marker before the first commit so a process
     * death mid-decrypt is still detected on the next start. @p done runs
     * exactly once on the GUI thread, including on the early failure paths
     * (master key unavailable, marker not writable), which report the failure
     * and skip the worker.
     *
     * @param done Continuation invoked after the decrypt attempt. It is
     *             deferred with the whole call when the password is missing.
     */
    void startProtectedFolderDecrypt(std::function<void()> done);

    /**
     * @brief Verify the folder profile before optional vault load and boot decryption.
     *
     * The profile is the folder-password authority. Verification runs on a
     * worker behind the loading cover. When the profile is missing but a vault
     * path is supplied, that vault authenticates the entered password once and a
     * fresh profile is written before any file is decrypted; an empty vault
     * authenticates nothing and is refused.
     *
     * A wrong password clears the master key, re-queues this call at the front
     * of the pending-action queue, and emits passwordRetryRequired(). Any other
     * verification failure reports errorOccurred() and ends the boot sequence
     * with protectedFolderBootFinished(), leaving the folder sealed.
     *
     * @param optionalVaultPath Credential vault to load after a successful
     *                          verification, or empty for folder-only startup.
     */
    void startProtectedFolderUnlock(const QString& optionalVaultPath);

    /// @brief Start/continue the held-close re-protection flow.
    void continueExitProtection();

    /// @brief Verify a newly entered exit password against the folder profile.
    void verifyExitPassword();

    /// @brief Encrypt the armed executable folder on a worker.
    void startExitEncryption();

    /// @brief Complete cleanup after successful protection or an unarmed close.
    void finishCleanup();

    /**
     * @brief Surface an exit-protection failure while leaving the window open.
     *
     * Clears the cleanup-in-progress flag so closing again retries the flow.
     *
     * @param message Detail shown in the folder-protection error dialog.
     */
    void failCleanup(const QString& message);

    /**
     * @brief Persisted setting key, scoped by a SHA-256 of the executable directory.
     * @param executableDirectory Directory to scope the setting to; cleaned,
     *                            converted to native separators, lower-cased.
     * @return `security/protectFolder/<hex SHA-256>` QSettings key.
     */
    static QString protectFolderSettingKey(const QString& executableDirectory);

    /**
     * @brief Absolute path of the plaintext-session marker.
     *
     * The marker is the `.seal-folder-unprotected` file in the armed folder.
     * The decrypt path writes it and cleanup() removes it, so a marker present
     * at start means the previous session left the files in plaintext.
     */
    QString protectedFolderMarkerPath() const;

    /// @brief Absolute path of the password-verifier profile.
    QString protectedFolderProfilePath() const;

    /// @brief Create the plaintext-session marker; false when the write fails.
    bool writeProtectedFolderMarker() const;

    /// @brief Remove the plaintext-session marker; true when it is already absent.
    bool removeProtectedFolderMarker() const;

    /**
     * @brief Update the status bar text and emit statusTextChanged().
     * @param text New status message
     */
    void setStatus(const QString& text) override;

    /**
     * @brief Toggle the loading cover and set its caption.
     *
     * Emits loadingChanged() at most once, and emits nothing when both the flag
     * and the caption already hold the requested values.
     *
     * @param on      Whether the cover should be visible.
     * @param caption Spinner caption. Discarded when @p on is false, which
     *                always clears the stored caption.
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
     * Applies the active search filter, updates the filtered indices, and
     * clears the selection, because row numbers do not survive a re-filter.
     */
    void refreshModel();

    /**
     * @brief Shared body for encryptDirectory()/decryptDirectory().
     *
     * Opens the folder picker, runs @p op under a tight session().unlock()
     * window, and logs the finish line. A cancelled picker returns silently. A
     * session that cannot be unlocked reports the standard master-key error and
     * returns. @p op runs on the GUI thread and blocks the UI.
     *
     * @pre The caller gated on ensurePassword(), so the password is set.
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
     * errorOccurred() with the fixed vault-access message. The caller still owns
     * the unlock() window and the bail-out that follows.
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
     * The result lives on locked pages, so the password is never swapped to
     * disk. The copy is element-wise, so no intermediate pageable std::wstring
     * exists. An empty input yields an empty result. The caller still owns the
     * source QString and should wipe it.
     *
     * @return Secure wchar_t string backed by a locked allocator.
     */
    static seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>> qstringToSecureWide(
        const QString& qstr);

    /**
     * @brief Adopt a candidate master password and drain queued actions.
     *
     * The shared tail of submitPassword() and requestSecureDesktopUnlock().
     * Adoption is unverified, so the verified-vault path and the verified-folder
     * flag are cleared; the drained actions are what prove the password.
     *
     * @param wide   Candidate password; ownership moves to the session, which
     *               keeps it DPAPI-protected between Access windows.
     * @param source Diagnostic origin token (e.g. "manual_entry", "secure_desktop").
     */
    void adoptPasswordAndDrain(
        seal::basic_secure_string<wchar_t, seal::locked_allocator<wchar_t>>&& wide,
        const char* source);

    std::deque<std::function<void()>> m_PendingActions;  ///< FIFO of deferred actions.

    VaultListModel* m_Model = nullptr;  ///< Vault list model for QML binding.
    IFillControl* m_Fill = nullptr;     ///< IFillControl seam (arm/cancel delegate).

    AutoLockController* m_AutoLock = nullptr;  ///< Idle/session auto-lock collaborator.

    seal::CredentialWorkspace& m_Workspace;  ///< Qt-free core: records, session, vault path.
    seal::AsyncRunner& m_Async;              ///< Async runner for off-thread load/rekey/QR work.

    QString m_CurrentVaultPath;      ///< Path to the currently loaded vault file.
    QString m_AutoEncryptDirectory;  ///< Armed executable directory; empty when disabled.
    QString m_ProtectedFolderRoot;   ///< Executable directory keyed by the persisted setting.
    QString m_VerifiedVaultPath;     ///< Vault against which the current session key was verified.
    QString m_ProtectFolderSettingKey;         ///< security/protectFolder/<directory hash>.
    QString m_ProtectFolderPreflightPath;      ///< Root shown by the current arming preview.
    QStringList m_ProtectFolderEncryptFiles;   ///< Exact preview action list.
    QStringList m_ProtectFolderSkippedFiles;   ///< Protected entries + stable reasons.
    qulonglong m_ProtectFolderTotalBytes = 0;  ///< Sum of preview action sizes.
    int m_ProtectFolderPasswordMode = 1;       ///< 0=current, 1=create, 2=existing profile.
    bool m_ProtectFolderPreflightProfileExists = false;  ///< Profile state shown in preview.

    int m_SelectedIndex = -1;                        ///< Currently selected row (-1 = none).
    QString m_StatusText = QStringLiteral("Ready");  ///< Status bar text.
    QString m_SearchFilter;                          ///< Active search/filter string.
    QString m_CountdownText;                         ///< Countdown display for timed ops.
    bool m_Busy = false;                             ///< Background operation in progress.
    bool m_Loading = false;                  ///< Loading cover (vault decrypt/rekey) visible.
    QString m_LoadingCaption;                ///< Caption shown beneath the loading spinner.
    bool m_LoadWorkerActive = false;         ///< A vault-load worker thread is in flight.
    bool m_ProtectFolderEnabled = false;     ///< Persisted opt-in state for this executable folder.
    bool m_ProtectedDecryptPending = false;  ///< Optional vault load precedes folder decryption.
    bool m_ProtectedPasswordVerified = false;   ///< Session key verified by the folder profile.
    bool m_UncleanProtectedSession = false;     ///< Marker was already present at process start.
    size_t m_ProtectedBootDecryptFailures = 0;  ///< Partial boot decrypt count; blocks rekey.
    bool m_CleanupStarted = false;    ///< Close has been intercepted and cleanup is in progress.
    bool m_CleanupCompleted = false;  ///< QML may accept the next close after this becomes true.
    bool m_Destroying = false;        ///< Destructor path must not launch asynchronous work.
    seal::AsyncHandle m_QrHandle;     ///< Handle to the active QR capture task (for cancel).
    bool m_QrActive = false;          ///< True while a QR capture task is in flight.

    CliPanelViewModel* m_Cli = nullptr;  ///< Borrowed CLI panel for QR-into-CLI routing.
};

}  // namespace seal

#endif  // USE_QT_UI
