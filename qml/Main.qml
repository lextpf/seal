import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

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
    visible: false
    width: 1420
    height: 568
    minimumWidth: 1100
    minimumHeight: 570
    title: "seal"
    flags: Qt.Window | Qt.FramelessWindowHint
    topPadding: 0
    leftPadding: 0
    rightPadding: 0
    bottomPadding: 0
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

        // Show error on QR failure - route to CLI panel or password dialog.
        function onQrCaptureFinished(success) {
            if (!success) {
                if (Backend.isCliMode)
                    Backend.handleQrResultForCli("(QR capture failed or cancelled)");
                else
                    passwordDlg.errorMessage = "QR capture failed or cancelled.";
            }
        }

        // QR captured text - fill the password field, or route to CLI panel.
        function onQrTextReady(text) {
            if (Backend.isCliMode) {
                Backend.handleQrResultForCli(text);
            } else {
                passwordDlg.errorMessage = "";
                passwordDlg.fillPassword(text);
            }
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

    function openAddAccountDialog() {
        accountDlg.dialogTitle = "Add Account";
        accountDlg.editIndex = -1;
        accountDlg.initialService = "";
        accountDlg.initialUsername = "";
        accountDlg.initialPassword = "";
        accountDlg.open();
    }

    Component.onCompleted: {
        Backend.updateWindowTheme(Theme.dark);
        visible = true;
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

    // Inline component for window chrome buttons. All share the same 46x36
    // size, background hover behavior, and centered icon pattern. Optional
    // bleed lets a hover fill cover the last compositor/frame pixel at the edge.
    component ChromeButton: Item {
        id: chromeButton
        property alias iconSource: _icon.source
        property color iconColor: _area.containsMouse ? Theme.textPrimary : Theme.textMuted
        property alias iconRotation: _icon.rotation
        readonly property bool hovered: _area.containsMouse
        readonly property bool pressed: _area.pressed
        property color hoverColor: _area.pressed ? Theme.bgInputFocus : Theme.bgHover
        property color idleColor: "transparent"
        property int backgroundLeftBleed: 0
        property int backgroundTopBleed: 0
        property int backgroundRightBleed: 0
        property int backgroundBottomBleed: 0
        signal clicked()

        width: 46; height: 36

        Rectangle {
            id: _background
            anchors.fill: parent
            color: _area.containsMouse ? chromeButton.hoverColor : chromeButton.idleColor
            Behavior on color { ColorAnimation { duration: 100 } }
        }

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.top
            height: chromeButton.backgroundTopBleed
            visible: _area.containsMouse && chromeButton.backgroundTopBleed > 0
            color: chromeButton.hoverColor
        }

        Rectangle {
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.right: parent.left
            width: chromeButton.backgroundLeftBleed
            visible: _area.containsMouse && chromeButton.backgroundLeftBleed > 0
            color: chromeButton.hoverColor
        }

        Rectangle {
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.right
            width: chromeButton.backgroundRightBleed
            visible: _area.containsMouse && chromeButton.backgroundRightBleed > 0
            color: chromeButton.hoverColor
        }

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.bottom
            height: chromeButton.backgroundBottomBleed
            visible: _area.containsMouse && chromeButton.backgroundBottomBleed > 0
            color: chromeButton.hoverColor
        }

        SvgIcon {
            id: _icon
            width: Theme.px(12); height: Theme.px(12)
            anchors.centerIn: parent
            color: parent.iconColor
            Behavior on color { ColorAnimation { duration: 100 } }
            Behavior on rotation { NumberAnimation { duration: 200; easing.type: Easing.OutBack } }
        }
        MouseArea {
            id: _area
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: parent.clicked()
        }
    }

    // Drag area for the title bar strip above content. Covers the full width
    // except the window-button zone on the right so those stay clickable.
    MouseArea {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: windowButtons.left
        height: 36
        z: 9
        acceptedButtons: Qt.LeftButton
        onPressed: function(mouse) { Backend.startWindowDrag() }
        onDoubleClicked: function(mouse) {
            if (window.visibility === Window.Maximized)
                window.showNormal()
            else
                window.showMaximized()
        }
    }

    // Custom window control buttons pinned to the top-right corner.
    Row {
        id: windowButtons
        anchors.top: parent.top
        anchors.right: parent.right
        z: 10
        spacing: 0

        ChromeButton {
            iconSource: Theme.iconThumbtack
            idleColor: Backend.isAlwaysOnTop ? Theme.accentSoft : "transparent"
            iconColor: Backend.isAlwaysOnTop ? Theme.accent
                     : hovered ? Theme.textPrimary : Theme.textMuted
            iconRotation: Backend.isAlwaysOnTop ? 0 : 30
            onClicked: Backend.toggleAlwaysOnTop()
        }
        ChromeButton {
            iconSource: Backend.passwordSet ? Theme.iconLockOpen : Theme.iconLock
            iconColor: hovered && Backend.passwordSet ? Theme.textWarning : Theme.textMuted
            opacity: Backend.passwordSet ? 1.0 : 0.4
            onClicked: if (Backend.passwordSet) Backend.lockVault()
        }
        ChromeButton {
            iconSource: Theme.iconTerminal
            idleColor: Backend.isCliMode ? Theme.accentSoft : "transparent"
            iconColor: Backend.isCliMode ? Theme.accent
                     : hovered ? Theme.textPrimary : Theme.textMuted
            onClicked: Backend.toggleCliMode()
        }
        ChromeButton {
            iconSource: Backend.isCompact ? Theme.iconExpand : Theme.iconCompress
            onClicked: Backend.toggleCompact()
        }
        ChromeButton {
            iconSource: Theme.iconChevronDown
            onClicked: window.showMinimized()
        }
        ChromeButton {
            id: closeButton
            iconSource: Theme.iconPowerOff
            hoverColor: pressed ? Theme.windowClosePressed : Theme.windowCloseHover
            iconColor: hovered ? Theme.textOnAccent : Theme.textMuted
            onClicked: window.close()
        }
    }

    // Paint directly on the window edge when the close button is hovered so
    // any remaining scene-gap pixel at the top/right disappears with the same
    // red fill as the button itself.
    Rectangle {
        anchors.top: parent.top
        anchors.right: parent.right
        width: closeButton.width
        height: 1
        z: 11
        visible: closeButton.hovered
        color: closeButton.pressed ? Theme.windowClosePressed : Theme.windowCloseHover
    }

    Rectangle {
        anchors.top: parent.top
        anchors.right: parent.right
        width: 1
        height: closeButton.height
        z: 11
        visible: closeButton.hovered
        color: closeButton.pressed ? Theme.windowClosePressed : Theme.windowCloseHover
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
            Layout.topMargin: 36
            Layout.bottomMargin: 24
            spacing: Theme.spacingLarge

            // Header (hidden in compact mode)
            HeaderBar {
                Layout.fillWidth: true
                visible: !Backend.isCompact
                vaultLoaded: Backend.vaultLoaded

                onLoadClicked: Backend.loadVault()
                onSaveClicked: Backend.saveVault()
                onUnloadClicked: Backend.unloadVault()
            }

            // Header separator (hidden in compact/CLI mode)
            Rectangle {
                Layout.fillWidth: true
                visible: !Backend.isCompact && !Backend.isCliMode
                implicitHeight: 1
                color: Theme.divider
            }

            // Two-way binding: typing here sets Backend.searchFilter, which
            // calls VaultModel::setFilter() in C++ to re-filter the proxy list.
            // The model emits dataChanged and the ListView updates instantly.
            SearchBar {
                id: searchBar
                Layout.fillWidth: true
                visible: !Backend.isCliMode
                vaultLoaded: Backend.vaultLoaded
                resultCount: Backend.vaultModel.count
                onSearchRequested: function(text) { Backend.searchFilter = text }
            }

            // Toggle-select: clicking the same row deselects it.
            AccountsTable {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: !Backend.isCliMode
                Layout.maximumHeight: Backend.isCompact ? 102 : (1 + 44 + 4 * 48 + 1)
                model: Backend.vaultModel
                selectedRow: Backend.selectedIndex
                searchActive: Backend.searchFilter.length > 0
                isCompact: Backend.isCompact
                vaultLoaded: Backend.vaultLoaded

                onRowClicked: function(row) {
                    Backend.selectedIndex = (Backend.selectedIndex === row) ? -1 : row;
                }

                onAddAccountRequested: window.openAddAccountDialog()
                onClearSearchRequested: {
                    searchBar.text = "";
                    Backend.searchFilter = "";
                }
            }

            // CRUD + Fill action buttons. When a search filter is active, the
            // visible row indices don't match the underlying record vector, so
            // each handler calls vaultModel.recordIndexForRow() to resolve the
            // visual index to the real record position before calling Backend.
            ActionBar {
                Layout.fillWidth: true
                visible: !Backend.isCliMode
                hasSelection: Backend.hasSelection
                isFillArmed: Backend.isFillArmed
                fillCountdownSeconds: Backend.fillCountdownSeconds
                isCompact: Backend.isCompact
                isBusy: Backend.isBusy

                onAddClicked: {
                    window.openAddAccountDialog();
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

            // CLI panel (shown only in CLI mode)
            CliPanel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: Backend.isCliMode
            }
        }

        // Status footer (hidden in compact mode)
        StatusFooter {
            Layout.fillWidth: true
            visible: !Backend.isCompact
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
        tone: Theme.textError
        contentItem: ColumnLayout {
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                spacing: 8

                Item {
                    Layout.alignment: Qt.AlignVCenter
                    Layout.preferredWidth: Theme.px(28)
                    Layout.preferredHeight: Theme.px(28)

                    SvgIcon {
                        source: Theme.iconTriangleExclamation
                        width: Theme.px(14)
                        height: Theme.px(14)
                        color: Theme.textError
                        anchors.centerIn: parent
                    }
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
                        clip: true
                        gradient: Gradient {
                            GradientStop { position: 0; color: errorOkButton.pressed ? Theme.btnPressTop : errorOkButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                            GradientStop { position: 1; color: errorOkButton.pressed ? Theme.btnPressBot : errorOkButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        }
                        border.width: 1
                        border.color: errorOkButton.hovered ? Theme.borderBright : Theme.borderBtn
                        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                        RippleEffect {
                            id: errorOkRipple
                            baseColor: Qt.rgba(Theme.textOnAccent.r, Theme.textOnAccent.g, Theme.textOnAccent.b, 0.30)
                            cornerRadius: parent.radius
                        }
                    }
                    onPressed: errorOkRipple.trigger(errorOkHover.point.position.x, errorOkHover.point.position.y)
                }
            }
        }
    }

    // Success/info messages (e.g. "Vault saved", "Directory encrypted").
    ConfirmDialog {
        id: infoDialog
        tone: Theme.accent

        contentItem: ColumnLayout {
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                spacing: 8

                Item {
                    Layout.alignment: Qt.AlignVCenter
                    Layout.preferredWidth: Theme.px(28)
                    Layout.preferredHeight: Theme.px(28)

                    SvgIcon {
                        source: Theme.iconCircleCheck
                        width: Theme.px(14)
                        height: Theme.px(14)
                        color: Theme.accent
                        anchors.centerIn: parent
                    }
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
                        clip: true
                        gradient: Gradient {
                            GradientStop { position: 0; color: infoOkButton.pressed ? Theme.btnPressTop : infoOkButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                            GradientStop { position: 1; color: infoOkButton.pressed ? Theme.btnPressBot : infoOkButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        }
                        border.width: 1
                        border.color: infoOkButton.hovered ? Theme.borderBright : Theme.borderBtn
                        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                        RippleEffect {
                            id: infoOkRipple
                            baseColor: Qt.rgba(Theme.textOnAccent.r, Theme.textOnAccent.g, Theme.textOnAccent.b, 0.30)
                            cornerRadius: parent.radius
                        }
                    }
                    onPressed: infoOkRipple.trigger(infoOkHover.point.position.x, infoOkHover.point.position.y)
                }
            }
        }
    }
}
