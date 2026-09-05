/*  ============================================================================================  *
 *                                                            ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
 *                                                            ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
 *           ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
 *          :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
 *          +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
 *          +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
 *                 +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇
 *          #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
 *           ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
 *                                                            ⠀⠀⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 *
 *                                  << P A S S   M A N A G E R >>
 *
 *  ============================================================================================  *
 *
 *      A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *      providing on-demand credential management, directory encryption,
 *      webcam QR authentication, and global auto-fill.
 *
 *    ----------------------------------------------------------------------
 *
 *      Repository:   https://github.com/lextpf/seal
 *      License:      GPL
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

// The application shell: one frameless window that owns the drag strip and window
// buttons, the ambient backdrop, the content column and every top-level dialog.
// Four of the five C++ context properties are driven from here: AppViewModel (vault
// state and commands), Fill (TypeController, auto-fill arming), Cli (embedded
// terminal) and WindowVM (Win32 window chrome). Bridge is only listened to here, for
// its info and error dialogs; its commands live in HeaderBar and BridgeSettings.
ApplicationWindow {
    id: window
    visible: false
    width: 1600
    height: 568
    minimumWidth: 800
    minimumHeight: WindowVM.isCompact ? 272 : 480
    title: "seal"
    flags: Qt.Window | Qt.FramelessWindowHint
    topPadding: 0
    leftPadding: 0
    rightPadding: 0
    bottomPadding: 0
    color: Theme.bgDeep
    Behavior on color { ColorAnimation { duration: 350; easing.type: Easing.InOutQuad } }

    // Desktop-only breakpoints. Qt reports these dimensions in logical pixels,
    // so they remain stable across Windows DPI settings and mixed-DPI monitors.
    readonly property bool narrowDesktop: width < 1200
    readonly property bool compactDesktop: width < 960
    readonly property bool shortDesktop: !WindowVM.isCompact && height < 540
    readonly property int contentSideMargin: WindowVM.isCompact ? 16
                                                   : compactDesktop ? 20
                                                   : narrowDesktop ? 28
                                                   : Theme.spacingXL
    // The window-control row owns the first 36 logical pixels in every mode, so
    // content starts below it. Anything opaque drawn over that strip also removes
    // window dragging there - see the drag MouseArea below.
    readonly property int contentTopMargin: 36
    readonly property int contentBottomMargin: WindowVM.isCompact ? 14
                                                     : shortDesktop ? 16
                                                     : 24
    readonly property int contentSpacing: WindowVM.isCompact ? 10
                                                : shortDesktop ? 12
                                                : narrowDesktop ? 16
                                                : Theme.spacingLarge

    function fitInitialWindowToScreen() {
        var availableWidth = Screen.desktopAvailableWidth;
        var availableHeight = Screen.desktopAvailableHeight;
        if (availableWidth <= 0 || availableHeight <= 0)
            return;

        var screenInset = 64;
        width = Math.max(minimumWidth, Math.min(width, availableWidth - screenInset));
        height = Math.max(minimumHeight, Math.min(height, availableHeight - screenInset));
    }

    Connections {
        target: Theme
        function onDarkChanged() { WindowVM.updateWindowTheme(Theme.dark) }
    }

    // Theme.sortMode is the persisted user choice. Pushing it into the view model
    // here keeps the ordering decision out of the views that display it.
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

        // AppViewModel resolves the row and passes the platform name, so the view
        // never reads the model to build the question.
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

        // Rekey runs off-thread; this signal is its only completion report.
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

        // First unlock prompt. Marks the boot cover as owned by the prompt so
        // Component.onCompleted holds the cover instead of dropping it.
        function onPasswordRequired() {
            window.bootPasswordPending = true;
            passwordDlg.errorMessage = "";
            passwordDlg.open();
        }

        function onPasswordRetryRequired(message) {
            passwordDlg.errorMessage = message;
            loadingOverlay.breakSeal();
            retryReopen.restart();
        }

        function onVaultLoadedChanged() {
            if (AppViewModel.vaultLoaded) {
                passwordDlg.close();
                loadingOverlay.sealSuccess();
            }
        }

        function onQrCaptureFinished(success) {
            if (!success)
                passwordDlg.errorMessage = "QR capture failed or cancelled.";
        }

        function onSecureCaptureFinished(ok) {
            if (!ok)
                passwordDlg.errorMessage = "Secure screen unavailable.";
        }

        // The QR path is the only one that pre-fills the field. The secure-desktop
        // path hands its result straight to the view model instead.
        function onQrTextReady(text) {
            passwordDlg.errorMessage = "";
            passwordDlg.fillPassword(text);
        }

        function onProtectFolderPreflightReady() {
            protectFolderDialog.open();
        }

        function onProtectedFolderBootFinished() {
            window.bootPasswordPending = false;
            passwordDlg.close();
            loadingOverlay.sealSuccess();
        }

        function onCleanupFinished() {
            window.closeReady = true;
            Qt.callLater(function() { window.close(); });
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

    // Set true whenever an unlock prompt is raised. Read once at startup, during the
    // synchronous autoLoadVault call, to tell "vault present, awaiting unlock" from
    // "no vault" so the boot cover is held or dropped correctly.
    property bool bootPasswordPending: false
    // The first close is always intercepted. AppViewModel emits cleanupFinished
    // only after asynchronous folder re-protection (when armed) has completed.
    property bool closeReady: false

    Component.onCompleted: {
        fitInitialWindowToScreen();
        WindowVM.updateWindowTheme(Theme.dark);
        visible = true;
        // The cover starts opaque (LoadingOverlay.booting) so the app is never seen
        // before it. autoLoadVault raises the unlock prompt synchronously when a vault
        // exists; the cover then stays up until the prompt takes over. With no vault,
        // drop the cover at once (snap still true) so the empty app appears with no
        // reverse-flash.
        AppViewModel.autoLoadVault();
        if (!window.bootPasswordPending)
            loadingOverlay.booting = false;
        loadingOverlay.snap = false;
    }

    onClosing: function(close) {
        if (window.closeReady) {
            close.accepted = true;
            return;
        }
        close.accepted = false;
        AppViewModel.cleanup();
    }

    // Flat window-chrome button, fixed at 46x36 to match the drag strip height. The
    // bleed properties extend the hover fill past one edge, for a button that has to
    // reach into a window corner; every instance below leaves them at zero.
    component ChromeButton: Item {
        id: chromeButton
        property alias iconSource: _icon.source
        property color iconColor: _area.containsMouse
                                  ? Theme.chromeIconHover
                                  : Theme.chromeIcon
        property alias iconRotation: _icon.rotation
        readonly property bool hovered: _area.containsMouse
        readonly property bool pressed: _area.pressed
        property color hoverColor: _area.pressed ? Theme.chromePressed : Theme.chromeHover
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
            radius: 0
            border.width: 0
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
            width: Theme.px(14); height: Theme.px(14)
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

    // Window drag strip. A frameless window has no system title bar, so dragging
    // exists only because this MouseArea calls WindowVM.startWindowDrag(). It spans
    // the top 36 px up to the window buttons; a new opaque item over that strip takes
    // the press and dragging stops working there.
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

    // Author mark inside the drag strip. It stacks above the drag handler but has no
    // input handler of its own, so presses still reach the drag MouseArea.
    Text {
        anchors.left: parent.left
        anchors.leftMargin: 10
        anchors.top: parent.top
        height: 36
        z: 10
        text: "@lextpf"
        color: "#000000"
        opacity: 0.58
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontSizeSmall
        font.weight: Font.Medium
        verticalAlignment: Text.AlignVCenter
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
                     : hovered ? Theme.chromeIconHover : Theme.chromeIcon
            iconRotation: WindowVM.isAlwaysOnTop ? 0 : 30
            onClicked: WindowVM.toggleAlwaysOnTop()
        }
        ChromeButton {
            iconSource: AppViewModel.passwordSet ? Theme.iconLockOpen : Theme.iconLock
            iconColor: AppViewModel.passwordSet
                       ? (hovered ? Theme.textWarning : Theme.chromeIcon)
                       : Theme.chromeIconDisabled
            onClicked: if (AppViewModel.passwordSet) AppViewModel.lockVault()
        }
        ChromeButton {
            iconSource: Theme.iconTerminal
            idleColor: Cli.isCliMode ? Theme.accentSoft : "transparent"
            iconColor: Cli.isCliMode ? Theme.accent
                     : hovered ? Theme.chromeIconHover : Theme.chromeIcon
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
            iconColor: hovered ? Theme.textOnAccent : Theme.chromeIcon
            onClicked: window.close()
        }
    }

    Rectangle {
        anchors.top: parent.top
        anchors.right: parent.right
        width: closeButton.width
        height: Theme.strokeRegular
        z: 11
        visible: closeButton.hovered
        color: closeButton.pressed ? Theme.windowClosePressed : Theme.windowCloseHover
    }

    Rectangle {
        anchors.top: parent.top
        anchors.right: parent.right
        width: Theme.strokeRegular
        height: closeButton.height
        z: 11
        visible: closeButton.hovered
        color: closeButton.pressed ? Theme.windowClosePressed : Theme.windowCloseHover
    }

    // Escape hatch during the master-password prompt: the window-control row (z:10)
    // is buried under the loading cover (z:100), so surface a close button above it
    // (z:101). The prompt otherwise offers no way to quit the app.
    ChromeButton {
        anchors.top: parent.top
        anchors.right: parent.right
        z: 101
        visible: passwordDlg.visible
        iconSource: Theme.iconPowerOff
        hoverColor: pressed ? Theme.windowClosePressed : Theme.windowCloseHover
        iconColor: hovered ? Theme.textOnAccent : Theme.chromeIcon
        onClicked: window.close()
    }

    // Stop the shared animation clock whenever nothing of the ambient field is
    // visible, so a hidden, minimised or fully covered window costs nothing per frame.
    Binding {
        target: Ambient
        property: "awake"
        value: window.visible && window.visibility !== Window.Minimized
               && loadingOverlay.opacity < 0.999
    }

    // Keep the ambient field proportionate without allowing decorative blobs
    // to dominate a small desktop window or disappear on a large one.
    readonly property real ambientSizeScale:
        Math.max(0.82, Math.min(1.30, Math.min(width / 1600, height / 568)))

    component Blob: Rectangle {
        id: blob
        property real phase: 0                 // shared clock, injected per instance
        property real baseX: 0                 // responsive anchor (percentage of window)
        property real baseY: 0
        property real swayAmp: Theme.px(12)    // horizontal drift base (the smaller axis)
        property real bobAmp: Theme.px(18)     // vertical bob base (the dominant swell)
        property real breatheAmp: 0.05         // scale swell base; x4 in the binding is +/-20%
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
        // The amplitude properties above are bases; these bindings scale them:
        // x5 for sway and bob, x4 for the scale swell.
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
        width: 260 * window.ambientSizeScale; height: width
        color: Theme.blobColor1
        baseX: window.width * 0.04; baseY: window.height * -0.05
        phase: Ambient.tidePhase
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 0.0; phaseY: 0.6; phaseS: 0.0
        bobAmp: Theme.px(18); swayAmp: Theme.px(12); breatheAmp: 0.05
    }
    Blob {
        width: 200 * window.ambientSizeScale; height: width
        color: Theme.blobColor2
        baseX: window.width * 0.82; baseY: window.height * 0.06
        phase: Ambient.tidePhase
        freqX: 2; freqY: 1; freqS: 2
        phaseX: 1.8; phaseY: 2.2; phaseS: 1.0
        bobAmp: Theme.px(16); swayAmp: Theme.px(11); breatheAmp: 0.06
    }
    Blob {
        width: 320 * window.ambientSizeScale; height: width
        color: Theme.blobColor3
        baseX: window.width * 0.42; baseY: window.height * 0.12
        phase: Ambient.tidePhase
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 0.9; phaseY: 4.0; phaseS: 2.4
        bobAmp: Theme.px(20); swayAmp: Theme.px(14); breatheAmp: 0.045
    }
    Blob {
        width: 240 * window.ambientSizeScale; height: width
        color: Theme.blobColor1
        baseX: window.width * 0.72; baseY: window.height * 0.38
        phase: Ambient.tidePhase
        freqX: 2; freqY: 1; freqS: 1
        phaseX: 3.3; phaseY: 1.4; phaseS: 4.0
        bobAmp: Theme.px(17); swayAmp: Theme.px(12); breatheAmp: 0.055
    }
    Blob {
        width: 280 * window.ambientSizeScale; height: width
        color: Theme.blobColor2
        baseX: window.width * 0.08; baseY: window.height * 0.45
        phase: Ambient.tidePhase
        freqX: 1; freqY: 2; freqS: 1
        phaseX: 4.6; phaseY: 3.0; phaseS: 5.2
        bobAmp: Theme.px(15); swayAmp: Theme.px(13); breatheAmp: 0.05
    }
    Blob {
        width: 180 * window.ambientSizeScale; height: width
        color: Theme.blobColor3
        baseX: window.width * 0.52; baseY: window.height * 0.55
        phase: Ambient.tidePhase
        freqX: 2; freqY: 1; freqS: 2
        phaseX: 0.4; phaseY: 5.0; phaseS: 0.8
        bobAmp: Theme.px(16); swayAmp: Theme.px(11); breatheAmp: 0.06
    }
    Blob {
        width: 220 * window.ambientSizeScale; height: width
        color: Theme.blobColor1
        baseX: window.width * 0.30; baseY: window.height * 0.72
        phase: Ambient.tidePhase
        freqX: 1; freqY: 1; freqS: 1
        phaseX: 5.4; phaseY: 2.6; phaseS: 3.0
        bobAmp: Theme.px(18); swayAmp: Theme.px(12); breatheAmp: 0.05
    }
    Blob {
        width: 160 * window.ambientSizeScale; height: width
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
            Layout.leftMargin: window.contentSideMargin
            Layout.rightMargin: window.contentSideMargin
            Layout.topMargin: window.contentTopMargin
            Layout.bottomMargin: window.contentBottomMargin
            spacing: window.contentSpacing

            // Vault commands leave the header as signals and are routed into
            // AppViewModel here, so the header holds no vault state.
            HeaderBar {
                Layout.fillWidth: true
                visible: !WindowVM.isCompact
                vaultLoaded: AppViewModel.vaultLoaded
                protectFolderEnabled: AppViewModel.protectFolderEnabled

                onLoadClicked: AppViewModel.loadVault()
                onSaveClicked: AppViewModel.saveVault()
                onUnloadClicked: AppViewModel.unloadVault()
                onRekeyClicked: rekeyDlg.open()
                onProtectFolderToggled: function(enabled) {
                    AppViewModel.requestProtectFolderEnabled(enabled);
                }
            }

            // Cli.isCliMode swaps the vault views for the terminal panel. Both stay
            // instantiated; only visibility changes.
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
                // Compact strip height, summed from metrics owned by three other files:
                // 1 (AccountsGrid top margin) + 32 (AccountsToolbar.implicitHeight)
                // + 14 (ScrollView topPadding 10 + Flow y 4) + 38 (AccountChip.implicitHeight,
                // 36 + 2 hover headroom) + 14 (Flow bottom 4 + ScrollView bottomPadding 10)
                // + 1 (AccountsGrid bottom margin). Update the sum if any of those change.
                Layout.maximumHeight: WindowVM.isCompact
                                      ? (1 + 32 + 14 + 38 + 14 + 1)
                                      : window.height
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

            CliPanel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: Cli.isCliMode
            }
        }

        StatusFooter {
            Layout.fillWidth: true
            visible: !WindowVM.isCompact
            statusText: AppViewModel.statusText
            fillArmed: Fill.isFillArmed
            vaultFileName: AppViewModel.vaultFileName
            accountCount: AppViewModel.vaultModel.count
            protectFolderEnabled: AppViewModel.protectFolderEnabled
        }
    }

    // Boot cover and scrypt-grind indicator. At z:100 it covers the whole window,
    // including the window-control row.
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

    ProtectFolderDialog {
        id: protectFolderDialog
        parent: Overlay.overlay
        folderPath: AppViewModel.protectFolderPath
        encryptFiles: AppViewModel.protectFolderEncryptFiles
        skippedFiles: AppViewModel.protectFolderSkippedFiles
        totalBytes: AppViewModel.protectFolderTotalBytes
        passwordMode: AppViewModel.protectFolderPasswordMode
        onConfirmed: function(password, confirmation) {
            AppViewModel.confirmProtectFolderEnabled(password, confirmation);
        }
    }

    PasswordDialog {
        id: passwordDlg
        onAccepted: function(password) {
            AppViewModel.submitPassword(password);
        }
        onQrRequested: {
            AppViewModel.requestQrCapture();
        }
        onSecureScreenRequested: {
            AppViewModel.requestSecureDesktopUnlock();
        }
    }

    // A wrong password fractures the cover; reopen the prompt after that animation
    // rather than on top of it.
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
                        border.width: Theme.strokeRegular
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
                        border.width: Theme.strokeRegular
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
