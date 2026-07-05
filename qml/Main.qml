import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

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
    Behavior on color { ColorAnimation { duration: 350; easing.type: Easing.InOutQuad } }

    Connections {
        target: Theme
        function onDarkChanged() { WindowVM.updateWindowTheme(Theme.dark) }
    }

    Binding {
        target: AppViewModel
        property: "sortMode"
        value: Theme.sortMode
    }

    Connections {
        target: AppViewModel

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

        function onEditAccountRequested(index, service) {
            accountDlg.dialogTitle = "Edit Account";
            accountDlg.editIndex = index;
            accountDlg.initialService = service;
            accountDlg.open();
        }

        function onInfoMessage(title, message) {
            infoDialog.title = title;
            infoDialog.message = message;
            infoDialog.open();
        }

        // Rekey result - surface via the info/error dialogs.
        function onRekeyFinished(success, message) {
            if (success) {
                infoDialog.title = "Master password changed";
                infoDialog.message = message;
                infoDialog.open();
            } else {
                errorDialog.title = "Rekey failed";
                errorDialog.message = message;
                errorDialog.open();
            }
        }

        // First password prompt, no error message.
        function onPasswordRequired() {
            passwordDlg.errorMessage = "";
            passwordDlg.open();
        }

        function onPasswordRetryRequired(message) {
            passwordDlg.errorMessage = message;
            loadingOverlay.breakSeal();
            retryReopen.restart();
        }

        function onVaultLoadedChanged() {
            if (AppViewModel.vaultLoaded)
                loadingOverlay.sealSuccess();
        }

        function onQrCaptureFinished(success) {
            if (!success)
                passwordDlg.errorMessage = "QR capture failed or cancelled.";
        }

        // QR captured text - pre-fill the password dialog.
        function onQrTextReady(text) {
            passwordDlg.errorMessage = "";
            passwordDlg.fillPassword(text);
        }
    }

    Connections {
        target: Bridge

        function onInfoMessage(title, message) {
            infoDialog.title = title;
            infoDialog.message = message;
            infoDialog.open();
        }

        function onErrorOccurred(title, message) {
            errorDialog.title = title;
            errorDialog.message = message;
            errorDialog.open();
        }

        function onBridgeDiagnoseReady(summary) {
            infoDialog.title = "Bridge diagnose";
            infoDialog.message = summary;
            infoDialog.open();
        }

        function onBridgeDiagnoseCancelled() {}
    }

    function openAddAccountDialog() {
        accountDlg.dialogTitle = "Add Account";
        accountDlg.editIndex = -1;
        accountDlg.initialService = "";
        accountDlg.open();
    }

    Component.onCompleted: {
        WindowVM.updateWindowTheme(Theme.dark);
        visible = true;
        // Try loading the last-used vault automatically on startup.
        AppViewModel.autoLoadVault();
    }

    onClosing: function(close) {
        AppViewModel.cleanup();
        close.accepted = true;
    }

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

    MouseArea {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: windowButtons.left
        height: 36
        z: 9
        acceptedButtons: Qt.LeftButton
        onPressed: function(mouse) { WindowVM.startWindowDrag() }
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
            idleColor: WindowVM.isAlwaysOnTop ? Theme.accentSoft : "transparent"
            iconColor: WindowVM.isAlwaysOnTop ? Theme.accent
                     : hovered ? Theme.textPrimary : Theme.textMuted
            iconRotation: WindowVM.isAlwaysOnTop ? 0 : 30
            onClicked: WindowVM.toggleAlwaysOnTop()
        }
        ChromeButton {
            iconSource: AppViewModel.passwordSet ? Theme.iconLockOpen : Theme.iconLock
            iconColor: hovered && AppViewModel.passwordSet ? Theme.textWarning : Theme.textMuted
            opacity: AppViewModel.passwordSet ? 1.0 : 0.4
            onClicked: if (AppViewModel.passwordSet) AppViewModel.lockVault()
        }
        ChromeButton {
            iconSource: Theme.iconTerminal
            idleColor: Cli.isCliMode ? Theme.accentSoft : "transparent"
            iconColor: Cli.isCliMode ? Theme.accent
                     : hovered ? Theme.textPrimary : Theme.textMuted
            onClicked: Cli.toggleCliMode()
        }
        ChromeButton {
            iconSource: WindowVM.isCompact ? Theme.iconExpand : Theme.iconCompress
            onClicked: WindowVM.toggleCompact()
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

    Binding {
        target: Ambient
        property: "awake"
        value: window.visible && window.visibility !== Window.Minimized
               && loadingOverlay.opacity < 0.999
    }

    component Blob: Rectangle {
        id: blob
        property real phase: 0                 // shared clock, injected per instance
        property real baseX: 0                 // responsive anchor (percentage of window)
        property real baseY: 0
        property real swayAmp: Theme.px(12)    // horizontal drift (the smaller axis)
        property real bobAmp: Theme.px(18)     // vertical bob (the dominant swell)
        property real breatheAmp: 0.05         // scale swell, +/-5%
        property int freqX: 1                  // integer multipliers keep the loop seamless
        property int freqY: 1
        property int freqS: 1
        property real phaseX: 0                // phase offsets spread the field out of sync
        property real phaseY: 0
        property real phaseS: 0

        radius: width / 2
        z: -1
        antialiasing: true
        transformOrigin: Item.Center
        x: baseX + swayAmp * 5.0 * Math.sin(phase * freqX + phaseX)
        y: baseY + bobAmp * 5.0 * Math.sin(phase * freqY + phaseY)
        scale: 1.0 + breatheAmp * 4.0 * Math.sin(phase * freqS + phaseS)
        opacity: 0.55 + 0.45 * (0.5 + 0.5 * Math.sin(phase * freqS + phaseS + 1.0))
        Behavior on color { ColorAnimation { duration: 350 } }
    }

    component Mote: Rectangle {
        id: mote
        property real baseX: 0
        property real baseY: 0
        property int seed: 0
        width: Theme.px(3 + (seed % 3)); height: width
        radius: width / 2
        color: Theme.moteColor
        antialiasing: true
        z: -1
        x: baseX + Theme.px(11) * Math.sin(Ambient.tidePhase + seed)
        y: baseY + Theme.px(11) * Math.cos(Ambient.driftPhase + seed)
        opacity: 0.30 + 0.45 * (0.5 + 0.5 * Math.sin(Ambient.tidePhase * 2 + seed))
    }

    Blob {
        width: 260; height: 260
        color: Theme.blobColor1
        baseX: window.width * 0.04; baseY: window.height * -0.05
        phase: Ambient.tidePhase
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 0.0; phaseY: 0.6; phaseS: 0.0
        bobAmp: Theme.px(18); swayAmp: Theme.px(12); breatheAmp: 0.05
    }
    Blob {
        width: 200; height: 200
        color: Theme.blobColor2
        baseX: window.width * 0.82; baseY: window.height * 0.06
        phase: Ambient.tidePhase
        freqX: 2; freqY: 1; freqS: 2
        phaseX: 1.8; phaseY: 2.2; phaseS: 1.0
        bobAmp: Theme.px(16); swayAmp: Theme.px(11); breatheAmp: 0.06
    }
    Blob {
        width: 320; height: 320
        color: Theme.blobColor3
        baseX: window.width * 0.42; baseY: window.height * 0.12
        phase: Ambient.tidePhase
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 0.9; phaseY: 4.0; phaseS: 2.4
        bobAmp: Theme.px(20); swayAmp: Theme.px(14); breatheAmp: 0.045
    }
    Blob {
        width: 240; height: 240
        color: Theme.blobColor1
        baseX: window.width * 0.72; baseY: window.height * 0.38
        phase: Ambient.tidePhase
        freqX: 2; freqY: 1; freqS: 1
        phaseX: 3.3; phaseY: 1.4; phaseS: 4.0
        bobAmp: Theme.px(17); swayAmp: Theme.px(12); breatheAmp: 0.055
    }
    Blob {
        width: 280; height: 280
        color: Theme.blobColor2
        baseX: window.width * 0.08; baseY: window.height * 0.45
        phase: Ambient.tidePhase
        freqX: 1; freqY: 2; freqS: 1
        phaseX: 4.6; phaseY: 3.0; phaseS: 5.2
        bobAmp: Theme.px(15); swayAmp: Theme.px(13); breatheAmp: 0.05
    }
    Blob {
        width: 180; height: 180
        color: Theme.blobColor3
        baseX: window.width * 0.52; baseY: window.height * 0.55
        phase: Ambient.tidePhase
        freqX: 2; freqY: 1; freqS: 2
        phaseX: 0.4; phaseY: 5.0; phaseS: 0.8
        bobAmp: Theme.px(16); swayAmp: Theme.px(11); breatheAmp: 0.06
    }
    Blob {
        width: 220; height: 220
        color: Theme.blobColor1
        baseX: window.width * 0.30; baseY: window.height * 0.72
        phase: Ambient.tidePhase
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 5.4; phaseY: 2.6; phaseS: 3.0
        bobAmp: Theme.px(18); swayAmp: Theme.px(12); breatheAmp: 0.05
    }
    Blob {
        width: 160; height: 160
        color: Theme.blobColor2
        baseX: window.width * 0.88; baseY: window.height * 0.68
        phase: Ambient.tidePhase
        freqX: 2; freqY: 2; freqS: 1
        phaseX: 2.5; phaseY: 0.2; phaseS: 4.6
        bobAmp: Theme.px(13); swayAmp: Theme.px(10); breatheAmp: 0.065
    }

    Repeater {
        model: 10
        Mote {
            seed: index
            baseX: window.width * (((index * 0.17) + 0.05) % 1.0)
            baseY: window.height * (((index * 0.29) + 0.08) % 1.0)
        }
    }

    property real ripplePhase: 0
    NumberAnimation on ripplePhase {
        running: Ambient.awake
        from: 0; to: 1; duration: 12000
        loops: Animation.Infinite
    }
    Repeater {
        model: 3
        Rectangle {
            id: ripple
            readonly property real ph: (window.ripplePhase + index / 3.0) % 1.0
            property real lastPh: 0
            property real cx: (index * 0.31 + 0.2) % 1.0   // initial spread; re-randomized on wrap
            property real cy: (index * 0.47 + 0.15) % 1.0
            property var blobHues: [Theme.blobColor1, Theme.blobColor2, Theme.blobColor3]
            property color hue: Qt.rgba(blobHues[index % 3].r, blobHues[index % 3].g, blobHues[index % 3].b, 1.0)
            readonly property real maxD: Math.hypot(window.width, window.height) * 1.2

            onPhChanged: {
                if (ph < lastPh) {              // wrapped -> new cycle: re-seed while invisible
                    cx = Math.random();
                    cy = Math.random();
                    var c = blobHues[Math.floor(Math.random() * 3)];
                    hue = Qt.rgba(c.r, c.g, c.b, 1.0);
                }
                lastPh = ph;
            }

            width: maxD * (0.04 + 0.96 * ph)
            height: width
            radius: width / 2
            x: window.width * cx - width / 2
            y: window.height * cy - height / 2
            color: "transparent"
            border.width: Math.max(Theme.px(1), Theme.px(8) * Math.exp(-7.0 * ph))
            border.color: ripple.hue
            opacity: Math.min(1.0, ph / 0.12) * Math.pow(1.0 - ph, 1.4) * (Theme.dark ? 0.08 : 0.14)
            z: -1
            antialiasing: true
        }
    }

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
                visible: !WindowVM.isCompact
                vaultLoaded: AppViewModel.vaultLoaded

                onLoadClicked: AppViewModel.loadVault()
                onSaveClicked: AppViewModel.saveVault()
                onUnloadClicked: AppViewModel.unloadVault()
                onRekeyClicked: rekeyDlg.open()
            }

            // Header separator (hidden in compact/CLI mode)
            Rectangle {
                Layout.fillWidth: true
                visible: !WindowVM.isCompact && !Cli.isCliMode
                implicitHeight: 1
                color: Theme.divider
            }

            SearchBar {
                id: searchBar
                Layout.fillWidth: true
                visible: !Cli.isCliMode
                vaultLoaded: AppViewModel.vaultLoaded
                resultCount: AppViewModel.vaultModel.count
                onSearchRequested: function(text) { AppViewModel.searchFilter = text }
            }

            AccountsGrid {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: !Cli.isCliMode
                Layout.maximumHeight: WindowVM.isCompact
                                      ? (1 + 32 + 14 + 38 + 14 + 1)
                                      : (1 + 32 + 4 * 44 + 14 + 14 + 1)
                model: AppViewModel.vaultModel
                selectedRow: AppViewModel.selectedIndex
                searchActive: AppViewModel.searchFilter.length > 0
                isCompact: WindowVM.isCompact
                vaultLoaded: AppViewModel.vaultLoaded

                onRowClicked: function(row) {
                    AppViewModel.selectedIndex = (AppViewModel.selectedIndex === row) ? -1 : row;
                }

                onRowDoubleClicked: function(row) {
                    AppViewModel.armFillForRow(row);
                }

                onAddAccountRequested: window.openAddAccountDialog()
                onClearSearchRequested: {
                    searchBar.text = "";
                    AppViewModel.searchFilter = "";
                }
            }

            ActionBar {
                Layout.fillWidth: true
                visible: !Cli.isCliMode
                hasSelection: AppViewModel.hasSelection
                isFillArmed: Fill.isFillArmed
                fillCountdownSeconds: Fill.fillCountdownSeconds
                isCompact: WindowVM.isCompact
                isBusy: AppViewModel.isBusy

                onAddClicked: {
                    window.openAddAccountDialog();
                }

                onEditClicked: AppViewModel.requestEditSelected()

                onDeleteClicked: AppViewModel.requestDeleteSelected()

                onFillClicked: AppViewModel.armFillForSelection()

                onCancelFillClicked: {
                    Fill.cancelFill();
                }
            }

            // CLI panel (shown only in CLI mode)
            CliPanel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: Cli.isCliMode
            }
        }

        // Status footer (hidden in compact mode)
        StatusFooter {
            Layout.fillWidth: true
            visible: !WindowVM.isCompact
            statusText: AppViewModel.statusText
            fillArmed: Fill.isFillArmed
            vaultFileName: AppViewModel.vaultFileName
            accountCount: AppViewModel.vaultModel.count
        }
    }

    LoadingOverlay {
        id: loadingOverlay
        anchors.fill: parent
        z: 100
        listening: passwordDlg.visible && !AppViewModel.isLoading
        sounding: AppViewModel.isLoading
        caption: AppViewModel.isLoading ? AppViewModel.loadingCaption : ""
    }

    RekeyDialog {
        id: rekeyDlg
        parent: Overlay.overlay
    }

    PasswordDialog {
        id: passwordDlg
        onAccepted: function(password) {
            AppViewModel.submitPassword(password);
        }
        onQrRequested: {
            AppViewModel.requestQrCapture();
        }
    }

    Timer {
        id: retryReopen
        interval: 340
        onTriggered: passwordDlg.open()
    }

    // Add/edit dialog. editIdx == -1 means add; >= 0 means edit.
    AccountDialog {
        id: accountDlg
        onAccepted: function(service, username, password, editIdx) {
            if (editIdx >= 0)
                AppViewModel.editAccount(editIdx, service, username, password);
            else
                AppViewModel.addAccount(service, username, password);
        }
    }

    // Soft-delete: marks record as deleted in memory, removed on next save.
    ConfirmDialog {
        id: confirmDlg
        title: "Confirm Delete"
        property int deleteIndex: -1

        onConfirmed: {
            if (deleteIndex >= 0)
                AppViewModel.deleteAccount(deleteIndex);
            deleteIndex = -1;
        }
    }

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
