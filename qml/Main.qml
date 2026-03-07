import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Root application window.
//
// Responsibilities:
//   - Owns the top-level layout (header, search, table, actions, footer)
//   - Wires every Backend signal to the appropriate dialog (password, error, info, edit, delete)
//   - Manages dialog instances (created once, shown/hidden via open()/close() to avoid
//     repeated QML object creation and to preserve state across re-shows)
//   - Drives startup (autoLoadVault) and shutdown (cleanup) lifecycle hooks
//
// Data flow:
//   Backend (C++) --signals--> Connections block here --sets props/opens--> Dialog instances
//   Dialog instances --signals (accepted/confirmed)--> Backend Q_INVOKABLE slots
//
// No credential plaintext ever reaches QML. The VaultListModel exposes only
// masked strings; real values are decrypted on-demand in C++ and sent via
// SendInput keystrokes or returned through QVariantMap for the edit dialog.

ApplicationWindow {
    id: window
    visible: true
    width: 1420
    height: 690
    minimumWidth: 1100
    minimumHeight: 540
    title: "seal"
    color: Theme.bgDeep
    // Smooth cross-fade when the user toggles dark/light mode, so the
    // background doesn't snap harshly.
    Behavior on color { ColorAnimation { duration: 350; easing.type: Easing.InOutQuad } }

    // Qt's frameless title bar doesn't follow system dark/light mode, so we
    // push the current theme to the Win32 DWM layer (caption color, text color)
    // every time the user toggles. Without this, the title bar stays white in
    // dark mode or vice-versa.
    Connections {
        target: Theme
        function onDarkChanged() { Backend.updateWindowTheme(Theme.dark) }
    }

    // Central signal router. Backend emits signals from C++ when it needs the
    // UI to react (show a dialog, fill a field, report an error). Each handler
    // here configures the target dialog's properties and opens it. This keeps
    // all Backend-to-UI wiring in one place rather than scattered across
    // individual components.
    Connections {
        target: Backend

        function onErrorOccurred(title, message) {
            errorDialog.title = title;
            errorDialog.message = message;
            errorDialog.open();
        }

        // Resolves record index to platform name for the confirmation message.
        function onConfirmDeleteRequested(index, platform) {
            confirmDlg.deleteIndex = index;
            confirmDlg.message = "Are you sure you want to delete the account for '" + platform + "'?";
            confirmDlg.open();
        }

        function onInfoMessage(title, message) {
            infoDialog.title = title;
            infoDialog.message = message;
            infoDialog.open();
        }

        // First password prompt, no error message.
        function onPasswordRequired() {
            passwordDlg.errorMessage = "";
            passwordDlg.open();
        }

        // Re-prompt after a failed decryption attempt (wrong password / GCM auth failure).
        function onPasswordRetryRequired(message) {
            passwordDlg.errorMessage = message;
            passwordDlg.open();
        }

        // Show error in the already-open dialog on QR failure.
        function onQrCaptureFinished(success) {
            if (!success) {
                passwordDlg.errorMessage = "QR capture failed or cancelled.";
            }
        }

        // QR captured text - fill the password field (dialog is still open).
        function onQrTextReady(text) {
            passwordDlg.errorMessage = "";
            passwordDlg.fillPassword(text);
        }

        // Deferred edit path: if no password was set when the user clicked Edit,
        // the Backend queued the decrypt and emits this signal once the password
        // dialog completes and decryption succeeds. The data map carries the
        // plaintext fields for one-time display in the edit dialog.
        function onEditAccountReady(data) {
            accountDlg.dialogTitle = "Edit Account";
            accountDlg.editIndex = data.editIndex;
            accountDlg.initialService = data.service;
            accountDlg.initialUsername = data.username;
            accountDlg.initialPassword = data.password;
            accountDlg.open();
        }
    }

    Component.onCompleted: {
        Backend.updateWindowTheme(Theme.dark);
        // Try loading the last-used vault automatically on startup.
        Backend.autoLoadVault();
    }

    // Cleanup runs synchronously before the window closes. Backend::cleanup()
    // cancels any armed fill hooks, auto-encrypts the configured directory
    // (if any), wipes the master password, and trims the working set so
    // sensitive data doesn't linger in physical RAM after exit.
    onClosing: function(close) {
        Backend.cleanup();
        close.accepted = true;
    }

    // Eight decorative background blobs at z:-1 create subtle depth and visual
    // warmth behind the main UI. Percentage-based x/y positions scale with the
    // window so they redistribute naturally on resize. Three alternating colors
    // at 3-5% alpha keep them unobtrusive; the semi-transparent bgCard lets
    // them bleed through the main content area for a layered glass effect.
    // Each blob animates its color on theme toggle for a smooth transition.
    Rectangle {
        width: 260; height: 260; radius: 130
        color: Theme.blobColor1
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.04; y: window.height * -0.05
        z: -1
    }
    Rectangle {
        width: 200; height: 200; radius: 100
        color: Theme.blobColor2
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.82; y: window.height * 0.06
        z: -1
    }
    Rectangle {
        width: 320; height: 320; radius: 160
        color: Theme.blobColor3
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.42; y: window.height * 0.12
        z: -1
    }
    Rectangle {
        width: 240; height: 240; radius: 120
        color: Theme.blobColor1
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.72; y: window.height * 0.38
        z: -1
    }
    Rectangle {
        width: 280; height: 280; radius: 140
        color: Theme.blobColor2
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.08; y: window.height * 0.45
        z: -1
    }
    Rectangle {
        width: 180; height: 180; radius: 90
        color: Theme.blobColor3
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.52; y: window.height * 0.55
        z: -1
    }
    Rectangle {
        width: 220; height: 220; radius: 110
        color: Theme.blobColor1
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.30; y: window.height * 0.72
        z: -1
    }
    Rectangle {
        width: 160; height: 160; radius: 80
        color: Theme.blobColor2
        Behavior on color { ColorAnimation { duration: 350 } }
        x: window.width * 0.88; y: window.height * 0.68
        z: -1
    }

    // Two-tier ColumnLayout: the outer one fills the window edge-to-edge (so the
    // status footer can span the full width with no side margins), while the inner
    // one adds generous content margins around header/search/table/actions.
    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: Theme.spacingXL
            Layout.topMargin: 30
            Layout.bottomMargin: 24
            spacing: Theme.spacingLarge

            // Header
            HeaderBar {
                Layout.fillWidth: true
                vaultLoaded: Backend.vaultLoaded

                onLoadClicked: Backend.loadVault()
                onSaveClicked: Backend.saveVault()
                onUnloadClicked: Backend.unloadVault()
            }

            // Header separator
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: Theme.divider
            }

            // Two-way binding: typing here sets Backend.searchFilter, which
            // calls VaultModel::setFilter() in C++ to re-filter the proxy list.
            // The model emits dataChanged and the ListView updates instantly.
            SearchBar {
                Layout.fillWidth: true
                onTextChanged: Backend.searchFilter = text
            }

            // Toggle-select: clicking the same row deselects it.
            AccountsTable {
                Layout.fillWidth: true
                Layout.fillHeight: true
                model: Backend.vaultModel
                selectedRow: Backend.selectedIndex
                searchActive: Backend.searchFilter.length > 0
                vaultLoaded: Backend.vaultLoaded

                onRowClicked: function(row) {
                    Backend.selectedIndex = (Backend.selectedIndex === row) ? -1 : row;
                }
            }

            // CRUD + Fill action buttons. When a search filter is active, the
            // visible row indices don't match the underlying record vector, so
            // each handler calls vaultModel.recordIndexForRow() to resolve the
            // visual index to the real record position before calling Backend.
            ActionBar {
                Layout.fillWidth: true
                hasSelection: Backend.hasSelection
                isFillArmed: Backend.isFillArmed
                fillCountdownSeconds: Backend.fillCountdownSeconds

                onAddClicked: {
                    accountDlg.dialogTitle = "Add Account";
                    accountDlg.editIndex = -1;
                    accountDlg.initialService = "";
                    accountDlg.initialUsername = "";
                    accountDlg.initialPassword = "";
                    accountDlg.open();
                }

                // Synchronous path: if the password is already set, decryptAccountForEdit()
                // returns a QVariantMap with plaintext fields immediately. If not, it
                // returns an empty map and the deferred path (onEditAccountReady) handles it.
                onEditClicked: {
                    if (!Backend.hasSelection) return;
                    var realIdx = Backend.vaultModel.recordIndexForRow(Backend.selectedIndex);
                    var data = Backend.decryptAccountForEdit(realIdx);
                    if (!data.service) return;
                    accountDlg.dialogTitle = "Edit Account";
                    accountDlg.editIndex = realIdx;
                    accountDlg.initialService = data.service;
                    accountDlg.initialUsername = data.username;
                    accountDlg.initialPassword = data.password;
                    accountDlg.open();
                }

                onDeleteClicked: {
                    if (!Backend.hasSelection) return;
                    var realIdx = Backend.vaultModel.recordIndexForRow(Backend.selectedIndex);
                    confirmDlg.deleteIndex = realIdx;
                    confirmDlg.message = "Are you sure you want to delete this account?";
                    confirmDlg.open();
                }

                // Arms global mouse/keyboard hooks via FillController. The seal
                // window minimizes so the user can Ctrl+Click in any external app
                // to type the username, then Ctrl+Click again for the password.
                // The hooks are removed automatically on completion, timeout, or cancel.
                onFillClicked: {
                    if (!Backend.hasSelection) return;
                    var realIdx = Backend.vaultModel.recordIndexForRow(Backend.selectedIndex);
                    Backend.armFill(realIdx);
                }

                onCancelFillClicked: {
                    Backend.cancelFill();
                }
            }

            // Directory buttons
            DirectoryBar {
                Layout.fillWidth: true
                onEncryptDirClicked: Backend.encryptDirectory()
                onDecryptDirClicked: Backend.decryptDirectory()
            }
        }

        // Status footer
        StatusFooter {
            Layout.fillWidth: true
            statusText: Backend.statusText
            fillArmed: Backend.isFillArmed
            vaultFileName: Backend.vaultFileName
            accountCount: Backend.vaultModel.count
        }
    }

    // -- Dialogs --
    // All dialogs are instantiated once at startup and reused via open()/close().
    // This avoids repeated QML object construction (expensive for styled popups)
    // and keeps dialog state (e.g. error messages) stable across re-shows.

    // Master password entry. Blocks all interaction until submitted. The Backend
    // stores a pending action lambda that re-executes once the password is set,
    // so the user never has to re-click the original action after entering it.
    PasswordDialog {
        id: passwordDlg
        onAccepted: function(password) {
            Backend.submitPassword(password);
        }
        onQrRequested: {
            Backend.requestQrCapture();
        }
    }

    // Add/edit dialog. editIdx == -1 means add; >= 0 means edit.
    AccountDialog {
        id: accountDlg
        onAccepted: function(service, username, password, editIdx) {
            if (editIdx >= 0)
                Backend.editAccount(editIdx, service, username, password);
            else
                Backend.addAccount(service, username, password);
        }
    }

    // Soft-delete: marks record as deleted in memory, removed on next save.
    ConfirmDialog {
        id: confirmDlg
        title: "Confirm Delete"
        property int deleteIndex: -1

        onConfirmed: {
            if (deleteIndex >= 0)
                Backend.deleteAccount(deleteIndex);
            deleteIndex = -1;
        }
    }

    // Error dialog. Reuses ConfirmDialog's popup shell but replaces the
    // contentItem entirely: shows an exclamation icon + message + single OK
    // button (no Yes/No). This avoids creating a separate Popup component
    // just for a different button layout.
    ConfirmDialog {
        id: errorDialog
        contentItem: ColumnLayout {
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                spacing: 8

                SvgIcon {
                    source: Theme.iconTriangleExclamation
                    width: Theme.px(18)
                    height: Theme.px(18)
                    color: Theme.textError
                    Layout.alignment: Qt.AlignVCenter
                }

                Text {
                    Layout.fillWidth: true
                    text: errorDialog.title
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.px(16)
                    font.bold: true
                    color: Theme.textPrimary
                }
            }

            Text {
                Layout.fillWidth: true
                Layout.topMargin: 12
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                text: errorDialog.message
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.bottomMargin: 20
                Layout.rightMargin: 24
                spacing: Theme.spacingSmall

                Item { Layout.fillWidth: true }

                Button {
                    id: errorOkButton
                    text: "OK"
                    onClicked: errorDialog.close()

                    HoverHandler { id: errorOkHover; cursorShape: Qt.PointingHandCursor }

                    scale: pressed ? 0.97 : 1.0
                    Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                    contentItem: Text {
                        text: "OK"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeMedium
                        font.weight: Font.DemiBold
                        color: Theme.textOnAccent
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        implicitWidth: 110
                        implicitHeight: 34
                        radius: Theme.radiusMedium
                        gradient: Gradient {
                            GradientStop { position: 0; color: errorOkButton.pressed ? Theme.btnPressTop : errorOkButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                            GradientStop { position: 1; color: errorOkButton.pressed ? Theme.btnPressBot : errorOkButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        }
                        border.width: 1
                        border.color: errorOkButton.hovered ? Theme.borderBright : Theme.borderBtn
                        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                        RippleEffect { id: errorOkRipple; baseColor: Qt.rgba(Theme.btnGradTop.r, Theme.btnGradTop.g, Theme.btnGradTop.b, 0.35) }
                    }
                    onPressed: errorOkRipple.trigger(errorOkHover.point.position.x, errorOkHover.point.position.y)
                }
            }
        }
    }

    // Success/info messages (e.g. "Vault saved", "Directory encrypted").
    ConfirmDialog {
        id: infoDialog

        contentItem: ColumnLayout {
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                spacing: 8

                SvgIcon {
                    source: Theme.iconCircleCheck
                    width: Theme.px(18)
                    height: Theme.px(18)
                    color: Theme.accent
                    Layout.alignment: Qt.AlignVCenter
                }

                Text {
                    Layout.fillWidth: true
                    text: infoDialog.title
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.px(16)
                    font.bold: true
                    color: Theme.textPrimary
                }
            }

            Text {
                Layout.fillWidth: true
                Layout.topMargin: 12
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                text: infoDialog.message
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.bottomMargin: 20
                Layout.rightMargin: 24
                spacing: Theme.spacingSmall

                Item { Layout.fillWidth: true }

                Button {
                    id: infoOkButton
                    text: "OK"
                    onClicked: infoDialog.close()

                    HoverHandler { id: infoOkHover; cursorShape: Qt.PointingHandCursor }

                    scale: pressed ? 0.97 : 1.0
                    Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                    contentItem: Text {
                        text: "OK"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeMedium
                        font.weight: Font.DemiBold
                        color: Theme.textOnAccent
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        implicitWidth: 110
                        implicitHeight: 34
                        radius: Theme.radiusMedium
                        gradient: Gradient {
                            GradientStop { position: 0; color: infoOkButton.pressed ? Theme.btnPressTop : infoOkButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                            GradientStop { position: 1; color: infoOkButton.pressed ? Theme.btnPressBot : infoOkButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        }
                        border.width: 1
                        border.color: infoOkButton.hovered ? Theme.borderBright : Theme.borderBtn
                        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                        RippleEffect { id: infoOkRipple; baseColor: Qt.rgba(Theme.btnGradTop.r, Theme.btnGradTop.g, Theme.btnGradTop.b, 0.35) }
                    }
                    onPressed: infoOkRipple.trigger(infoOkHover.point.position.x, infoOkHover.point.position.y)
                }
            }
        }
    }
}
