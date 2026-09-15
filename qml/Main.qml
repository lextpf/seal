/*/-============================================================================================-\*\

                                                             ⠀⣠⡤⠀⢀⣀⣀⡀⠀⠀⠀⠀⣦⡀⠀⠀⠀⠀⠀⠀
                                                             ⠀⠘⠃⠈⢿⡏⠉⠉⠀⢀⣀⣰⣿⣿⡄⠀⠀⠀⠀⢀
            ::::::::  ::::::::::     :::     :::             ⠀⠀⠀⠀⠀⢹⠀⠀⠀⣸⣿⡿⠉⠿⣿⡆⠀⠰⠿⣿
           :+:    :+: :+:          :+: :+:   :+:             ⠀⠀⠀⠀⠀⢀⣠⠾⠿⠿⠿⠀⢰⣄⠘⢿⠀⠀⠀⠞
           +:+        +:+         +:+   +:+  +:+             ⢲⣶⣶⡂⠐⢉⣀⣤⣶⣶⡦⠀⠈⣿⣦⠈⠀⣾⡆⠀
           +#++:++#++ +#++:++#   +#++:++#++: +#+             ⠀⠀⠿⣿⡇⠀⠀⠀⠙⢿⣧⠀⠳⣿⣿⡀⠸⣿⣿⠀
                  +#+ +#+        +#+     +#+ +#+             ⠀⠀⠐⡟⠁⠀⠀⢀⣴⣿⠛⠓⠀⣉⣿⣿⢠⡈⢻⡇          
           #+#    #+# #+#        #+#     #+# #+#             ⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣆⠀⢹⣿⣿⣷⡀⠁⢸⡇
            ########  ########## ###     ### ##########      ⠀⠀⠀⠀⠀⠀⠘⠛⠛⠉⠀⠀⠈⠙⠛⠿⢿⣶⣼⠃
                                                              ⠀ ⠀⢰⣧⣤⠤⠖⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 
                                    << P A S S   M A N A G E R >>
  
\*\-============================================================================================-/*/
/*
 *               A Windows AES-256-GCM encryption utility with Qt6/QML GUI and CLI
 *               providing on-demand credential management, directory encryption,
 *               webcam QR authentication, and global auto-fill.
 *
 *             +--------------------------------------------------------------------+
 *
 *               Repository:   https://github.com/lextpf/seal
 *               License:      GPL
 */
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

/*!
 * \qmltype Main
 * \inqmlmodule seal
 * \brief Compose the application window and connect UI actions to C++ controllers.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Create this window after QmlMain installs the context objects. They must remain
 * alive until the QML engine is destroyed. QML presents state and routes gestures;
 * C++ owns vault records, command validation, and credential access.
 *
 * \section1 Context objects
 *
 * \table
 * \header
 *     \li Object
 *     \li Responsibility
 * \row
 *     \li \c AppViewModel
 *     \li Vault commands, account selection, and password requests.
 * \row
 *     \li \c Fill
 *     \li Armed-fill state, countdown, and cancellation.
 * \row
 *     \li \c Bridge
 *     \li Browser companion state, installation, and diagnostics.
 * \row
 *     \li \c WindowVM
 *     \li Native window operations and system motion preference.
 * \row
 *     \li \c Cli
 *     \li CLI mode, command submission, and sanitized transcript output.
 * \endtable
 *
 * Startup retains the cover during password entry and loading. If startup returns
 * without a password request, release the initial cover hold. Closing waits for the
 * cleanup completion signal because folder protection can finish asynchronously.
 *
 * Stored credentials do not enter edit fields. Typed passwords and QR results can
 * enter QML temporarily; secure-desktop password capture remains in C++.
 *
 * \section1 Window geometry
 *
 * All dimensions use logical pixels. The compact minimum height is 272 pixels and
 * must match WindowController. The fixed content uses 266 pixels: 92 for the header,
 * 20 for two gaps, 100 for the account strip, 40 for actions, and 14 for the bottom
 * margin. The content column receives the remaining 6 pixels.
 */
ApplicationWindow {
    id: window
    visible: false
    width: 1600
    height: 568
    minimumWidth: 800
    // Keep the compact minimum synchronized with WindowController.
    minimumHeight: WindowVM.isCompact ? 272 : 480
    title: "seal"
    flags: Qt.Window | Qt.FramelessWindowHint
    topPadding: 0
    leftPadding: 0
    rightPadding: 0
    bottomPadding: 0
    // Alpha exposes the desktop beneath the window.
    color: Theme.windowBase
    Behavior on color { ColorAnimation { duration: 350; easing.type: Easing.InOutQuad } }

    /*!
     * Use tighter horizontal spacing below 1200 logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool narrowDesktop: width < 1200
    /*!
     * Use the narrowest horizontal spacing below 960 logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool compactDesktop: width < 960
    /*!
     * Reduce vertical spacing below 540 logical pixels outside compact mode.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property bool shortDesktop: !WindowVM.isCompact && height < 540
    /*!
     * Left and right content inset, in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int contentSideMargin: WindowVM.isCompact ? 16
                                                   : compactDesktop ? 20
                                                   : narrowDesktop ? 28
                                                   : Theme.spacingXL
    /*!
     * Content inset above the footer, in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int contentBottomMargin: WindowVM.isCompact ? 14
                                                     : shortDesktop ? 16
                                                     : 24
    /*!
     * Gap between the header and content and between content rows, in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int contentSpacing: WindowVM.isCompact ? 10
                                                : shortDesktop ? 12
                                                : narrowDesktop ? 16
                                                : Theme.spacingLarge

    /*!
     * \brief Limit the initial window size to the available screen area.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Reserve 64 logical pixels on each screen dimension, subject to the window's
     * minimum size. Leave geometry unchanged if either available dimension is
     * non-positive. This method does not reposition the window.
     */
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

    // Apply the persisted sort choice to the model.
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

        // AppViewModel supplies the resolved, non-secret platform label.
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

        // Rekey reports validation failures and worker completion through this signal.
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

        // Mark the unlock prompt as owner of the startup cover.
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

        // Only QR results enter this field; secure-desktop input stays in C++.
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

    /*!
     * \brief Open the account dialog in add mode.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Clear the initial service and reset the edit index. Opening the dialog resets
     * its text fields; this method does not create a vault record.
     */
    function openAddAccountDialog() {
        accountDlg.dialogTitle = "Add Account";
        accountDlg.editIndex = -1;
        accountDlg.initialService = "";
        accountDlg.open();
    }

    /*!
     * Record that a password request claimed the initial cover during startup.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The startup call checks this flag before releasing the cover hold. The flag does
     * not track whether a password request is currently pending.
     */
    property bool bootPasswordPending: false
    /*!
     * Allow window closure after asynchronous cleanup reports completion.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool closeReady: false

    Component.onCompleted: {
        fitInitialWindowToScreen();
        WindowVM.updateWindowTheme(Theme.dark);
        visible = true;
        // autoLoadVault synchronously transfers the boot cover to the unlock prompt.
        // Without a vault, release it before the first fade to avoid a flash.
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

    // Positive bleed extends the hover background beyond the button hit area.
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

        width: 46; height: Theme.chromeHeight

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

    // Keep this drag strip uncovered up to the window buttons. Items that consume
    // presses here must call WindowVM.startWindowDrag() themselves.
    MouseArea {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: windowButtons.left
        height: Theme.chromeHeight
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

    // No input handler, so presses reach the drag MouseArea.
    Text {
        anchors.left: parent.left
        anchors.leftMargin: 10
        anchors.top: parent.top
        height: Theme.chromeHeight
        z: 10
        text: "@lextpf"
        color: Theme.chromeIcon
        opacity: 0.58 * window.shellReveal
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontSizeSmall
        font.weight: Font.Medium
        verticalAlignment: Text.AlignVCenter
    }

    Row {
        id: windowButtons
        anchors.top: parent.top
        anchors.right: parent.right
        z: 10
        spacing: 0
        opacity: window.shellReveal
        visible: opacity > 0.001

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

    // Keep a close button above the cover while the normal window controls are hidden.
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

    /*!
     * Shell opacity, from 0 through 1, complementary to the cover opacity.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The ambient background remains visible while the password prompt covers the shell.
     */
    readonly property real shellReveal: 1.0 - loadingOverlay.opacity

    // Stop the shared clock when the window is hidden or minimized.
    Binding {
        target: Ambient
        property: "awake"
        value: window.visible && window.visibility !== Window.Minimized
    }

    /*!
     * Decorative size multiplier, clamped to 0.82 through 1.30.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property real ambientSizeScale:
        Math.max(0.82, Math.min(1.30, Math.min(width / 1600, height / 568)))

    component Blob: Rectangle {
        id: blob
        // Shared phase in radians, supplied by each instance.
        property real phase: 0
        property real baseX: 0                 // Horizontal anchor in logical pixels.
        property real baseY: 0
        // Horizontal amplitude in logical pixels, multiplied by 5.
        property real swayAmp: Theme.px(12)
        // Vertical amplitude in logical pixels, multiplied by 5.
        property real bobAmp: Theme.px(18)
        property real breatheAmp: 0.05         // Scale amplitude, multiplied by 4.
        property int freqX: 1                  // Integer frequencies keep the loop continuous.
        property int freqY: 1
        property int freqS: 1
        property real phaseX: 0                // Phase offset in radians.
        property real phaseY: 0
        property real phaseS: 0

        radius: width / 2
        z: -1
        antialiasing: true
        transformOrigin: Item.Center
        // Scale base amplitudes by 5 for sway/bob and 4 for swell.
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
            // Initial horizontal position as a fraction of window width; randomized at wrap.
            property real cx: (index * 0.31 + 0.2) % 1.0
            property real cy: (index * 0.47 + 0.15) % 1.0
            property var blobHues: [Theme.blobColor1, Theme.blobColor2, Theme.blobColor3]
            property color hue: Qt.rgba(blobHues[index % 3].r, blobHues[index % 3].g, blobHues[index % 3].b, 1.0)
            readonly property real maxD: Math.hypot(window.width, window.height) * 1.2

            onPhChanged: {
                // Choose the next center and hue at wrap, while the ripple is invisible.
                if (ph < lastPh) {
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
        opacity: window.shellReveal
        visible: opacity > 0.001

        // Compact mode leaves 6 px beyond fixed child heights; the content column takes
        // that slack so the header keeps its height and starts at y = 0.
        HeaderBar {
            id: headerBar
            Layout.fillWidth: true
            isCompact: WindowVM.isCompact
            isCliMode: Cli.isCliMode
            sideMargin: window.contentSideMargin
            vaultLoaded: AppViewModel.vaultLoaded
            protectFolderEnabled: AppViewModel.protectFolderEnabled
            resultCount: AppViewModel.vaultModel.count

            onLoadClicked: AppViewModel.loadVault()
            onSaveClicked: AppViewModel.saveVault()
            onUnloadClicked: AppViewModel.unloadVault()
            onRekeyClicked: rekeyDlg.open()
            onProtectFolderToggled: function(enabled) {
                AppViewModel.requestProtectFolderEnabled(enabled);
            }
            onSearchRequested: function(text) { AppViewModel.searchFilter = text }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            // Assign slack to this cell; AlignTop keeps content against the header.
            Layout.verticalStretchFactor: 1
            Layout.alignment: Qt.AlignTop
            Layout.leftMargin: window.contentSideMargin
            Layout.rightMargin: window.contentSideMargin
            Layout.topMargin: window.contentSpacing
            Layout.bottomMargin: window.contentBottomMargin
            spacing: window.contentSpacing

            // Both views remain instantiated across mode changes.
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
                    headerBar.searchText = "";
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

    // At z:100 the cover owns window input; shellReveal fades the underlying content.
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

    // Reopen after the fracture animation finishes.
    Timer {
        id: retryReopen
        interval: 340
        onTriggered: passwordDlg.open()
    }

    // A negative editIdx adds a record; a non-negative value edits a record.
    AccountDialog {
        id: accountDlg
        onAccepted: function(service, username, password, editIdx) {
            if (editIdx >= 0)
                AppViewModel.editAccount(editIdx, service, username, password);
            else
                AppViewModel.addAccount(service, username, password);
        }
    }

    // Soft deletes commit on the next save.
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
