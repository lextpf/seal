import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Root window. Owns layout, dialogs, and all Backend signal wiring.

ApplicationWindow {
    id: window
    visible: true
    width: 1420
    height: 690
    minimumWidth: 1100
    minimumHeight: 540
    title: "sage"
    color: Theme.bgDeep
    // Cross-fade on theme switch.
    Behavior on color { ColorAnimation { duration: 350; easing.type: Easing.InOutQuad } }

    // Sync Windows title bar color via DwmSetWindowAttribute on theme change.
    Connections {
        target: Theme
        function onDarkChanged() { Backend.updateWindowTheme(Theme.dark) }
    }

    // Backend signal routing: map each signal to the appropriate dialog.
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

        // Credentials are encrypted at rest; Backend decrypts and sends data for editing.
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

    // Auto-encrypt and hook cleanup before exit.
    onClosing: function(close) {
        Backend.cleanup();
        close.accepted = true;
    }

    // Eight decorative blobs at z:-1. Percentage-based positions scale with window.
    // Varied sizes (160-320px), three alternating colors, very low alpha.
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

    // Outer layout fills window; inner layout adds content margins. Footer spans full width.
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

            // Drives VaultModel::setFilter() for live filtering.
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

            // Resolves visible row to real record index (model may be filtered).
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

                // Synchronous decrypt; returns empty strings on failure.
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

                // Next Ctrl+Click (even outside sage) will type decrypted credentials.
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

    // -- Dialogs (instantiated once, reused via open/close) --
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

    // Overrides ConfirmDialog contentItem to show a single OK button.
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
