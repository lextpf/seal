import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Master-password prompt: the only view that collects the master password to
// unlock, by typing, a QR scan, or the Windows secure screen. RekeyDialog also
// takes the current password, to change it.
// Each route emits a signal; Main.qml calls AppViewModel, which owns the gate and
// decides when the prompt closes.
Popup {
    id: root

    property string errorMessage: ""  // Non-empty shows a red error line and shakes on open
    readonly property color shellTone: Theme.accent

    signal accepted(string password)
    signal qrRequested()
    signal secureScreenRequested()

    // QR path only: Main.qml pushes the decoded text here for the user to confirm.
    // The secure-screen result never comes back through the field.
    function fillPassword(text) {
        if (text.length > 0) {
            passwordField.text = text;
            passwordField.forceActiveFocus();
        }
    }

    modal: false
    focus: true
    anchors.centerIn: parent
    width: 420
    padding: 0
    // Esc and click-outside do nothing: Main.qml closes this on unlock or on the
    // protected-folder boot path, so the prompt cannot be walked away from.
    closePolicy: Popup.NoAutoClose

    enter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 175; easing.type: Easing.OutCubic }
            NumberAnimation {
                property: "scale"; from: 0.94; to: 1; duration: 190
                easing.type: root.errorMessage === "" ? Easing.OutBack : Easing.OutCubic
                easing.overshoot: 1.15
            }
        }
    }
    exit: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 130; easing.type: Easing.InCubic }
            NumberAnimation { property: "scale"; from: 1; to: 0.95; duration: 130; easing.type: Easing.InCubic }
        }
    }

    background: Item {}

    // Clear stale password on open.
    onAboutToShow: {
        passwordField.text = "";
        passwordField.forceActiveFocus();
    }

    onClosed: passwordField.text = ""

    // Wrong-password shake, skipped when reduce-motion is on.
    SequentialAnimation {
        id: shakeAnim
        NumberAnimation { target: shakeOffset; property: "x"; to: -Theme.px(8); duration: 70; easing.type: Easing.OutQuad }
        NumberAnimation { target: shakeOffset; property: "x"; to: Theme.px(6); duration: 70; easing.type: Easing.InOutQuad }
        NumberAnimation { target: shakeOffset; property: "x"; to: -Theme.px(3); duration: 70; easing.type: Easing.InOutQuad }
        NumberAnimation { target: shakeOffset; property: "x"; to: Theme.px(1); duration: 70; easing.type: Easing.InOutQuad }
        NumberAnimation { target: shakeOffset; property: "x"; to: 0; duration: 60; easing.type: Easing.OutQuad }
    }
    onOpened: if (errorMessage !== "" && !WindowVM.reduceMotion) shakeAnim.restart()

    contentItem: ColumnLayout {
        spacing: 0
        transform: Translate { id: shakeOffset; x: 0 }

        RowLayout {
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: 24
            spacing: Theme.px(6)

            SvgIcon {
                source: Theme.iconLock
                color: root.shellTone
                Layout.preferredWidth: Theme.px(14)
                Layout.preferredHeight: Theme.px(14)
                Layout.alignment: Qt.AlignVCenter
            }

            Text {
                text: "Enter Master Password"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.px(16)
                font.bold: true
                color: Theme.textPrimary
            }
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: 8
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            text: "Type your password, scan a QR code, or use the secure screen."
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            color: Theme.textSecondary
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: 6
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            opacity: root.errorMessage !== "" ? 1.0 : 0.0
            text: root.errorMessage === "" ? " " : root.errorMessage
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            font.weight: Font.Medium
            color: Theme.textError
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        // Hover-to-reveal eye icon. Enter submits if non-empty.
        TextField {
            id: passwordField
            Layout.fillWidth: true
            Layout.topMargin: 16
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            echoMode: showPassword ? TextInput.Normal : TextInput.Password
            passwordCharacter: "\u2981"
            placeholderText: "Password"
            placeholderTextColor: Theme.textMuted
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeLarge
            color: Theme.textPrimary
            leftPadding: 12
            rightPadding: 36

            property bool showPassword: eyeArea.containsMouse

            background: Rectangle {
                implicitHeight: 38
                radius: Theme.radiusSmall
                color: passwordField.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                border.width: Theme.strokeRegular
                border.color: passwordField.activeFocus ? Theme.borderFocus : Theme.borderSubtle
            }

            SvgIcon {
                anchors.right: parent.right
                anchors.rightMargin: 8
                anchors.verticalCenter: parent.verticalCenter
                source: passwordField.showPassword ? Theme.iconEye : Theme.iconEyeSlash
                color: eyeArea.containsMouse ? Theme.accent : Theme.textMuted
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium

                MouseArea {
                    id: eyeArea
                    anchors.fill: parent
                    anchors.margins: -4
                    cursorShape: Qt.PointingHandCursor
                    hoverEnabled: true
                    acceptedButtons: Qt.NoButton
                }
            }

            Keys.onReturnPressed: {
                if (passwordField.text.length > 0) {
                    var pw = passwordField.text;
                    passwordField.text = ""; // Best-effort scrub before close animation runs.
                    root.close();
                    root.accepted(pw);
                }
            }
            Keys.onEnterPressed: {
                if (passwordField.text.length > 0) {
                    var pw = passwordField.text;
                    passwordField.text = ""; // Best-effort scrub before close animation runs.
                    root.close();
                    root.accepted(pw);
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.bottomMargin: 20
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: Theme.spacingSmall

            // The three actions share the row equally, so the group spans the same
            // width as the password field above.
            Button {
                id: secureButton
                Layout.fillWidth: true
                Layout.preferredWidth: 100
                onClicked: {
                    root.secureScreenRequested();
                }

                // The secure desktop is reached with the Ctrl+Alt+Delete secure
                // attention sequence. Warn first, so the Windows sign-in prompt
                // that appears is not mistaken for phishing.
                ToolTip.visible: secureButton.hovered
                ToolTip.delay: 600
                ToolTip.text: "Enter your password on the Windows secure screen (press Ctrl+Alt+Delete when prompted)."

                HoverHandler { id: secureHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Item {
                    Row {
                        anchors.centerIn: parent
                        spacing: 6
                        SvgIcon {
                            source: Theme.iconLock
                            color: secureButton.hovered ? Theme.textPrimary : Theme.textGhost
                            width: Theme.iconSizeSmall
                            height: Theme.iconSizeSmall
                            anchors.verticalCenter: parent.verticalCenter
                            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                        }
                        Text {
                            text: "Secure"
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSizeMedium
                            font.weight: Font.Medium
                            color: secureButton.hovered ? Theme.textPrimary : Theme.textGhost
                            anchors.verticalCenter: parent.verticalCenter
                            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                        }
                    }
                }
                background: Rectangle {
                    implicitWidth: 104
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    clip: true
                    gradient: Gradient {
                        GradientStop { position: 0; color: secureButton.pressed ? Theme.ghostBtnPressed : secureButton.hovered ? Theme.ghostBtnHoverTop : Theme.ghostBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: secureButton.pressed ? Theme.ghostBtnPressed : secureButton.hovered ? Theme.ghostBtnHoverEnd : Theme.ghostBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: Theme.strokeRegular
                    border.color: secureButton.pressed ? Theme.borderPressed
                                : secureButton.hovered ? Theme.borderFocusHover
                                : Theme.borderSubtle
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: secureRipple
                        baseColor: Qt.rgba(Theme.textPrimary.r, Theme.textPrimary.g, Theme.textPrimary.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: secureRipple.trigger(secureHover.point.position.x, secureHover.point.position.y)
            }

            Button {
                id: qrButton
                Layout.fillWidth: true
                Layout.preferredWidth: 100
                onClicked: {
                    root.qrRequested();
                }

                HoverHandler { id: qrHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Item {
                    Row {
                        anchors.centerIn: parent
                        spacing: 6
                        SvgIcon {
                            source: Theme.iconQrCode
                            color: qrButton.hovered ? Theme.textPrimary : Theme.textGhost
                            width: Theme.iconSizeSmall
                            height: Theme.iconSizeSmall
                            anchors.verticalCenter: parent.verticalCenter
                            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                        }
                        Text {
                            text: "QR Scan"
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSizeMedium
                            font.weight: Font.Medium
                            color: qrButton.hovered ? Theme.textPrimary : Theme.textGhost
                            anchors.verticalCenter: parent.verticalCenter
                            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                        }
                    }
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    clip: true
                    gradient: Gradient {
                        GradientStop { position: 0; color: qrButton.pressed ? Theme.ghostBtnPressed : qrButton.hovered ? Theme.ghostBtnHoverTop : Theme.ghostBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: qrButton.pressed ? Theme.ghostBtnPressed : qrButton.hovered ? Theme.ghostBtnHoverEnd : Theme.ghostBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: Theme.strokeRegular
                    border.color: qrButton.pressed ? Theme.borderPressed
                                : qrButton.hovered ? Theme.borderFocusHover
                                : Theme.borderSubtle
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: qrRipple
                        baseColor: Qt.rgba(Theme.textPrimary.r, Theme.textPrimary.g, Theme.textPrimary.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: qrRipple.trigger(qrHover.point.position.x, qrHover.point.position.y)
            }

            Button {
                id: okButton
                text: "Unlock"
                enabled: passwordField.text.length > 0
                Layout.fillWidth: true
                Layout.preferredWidth: 100
                onClicked: {
                    var pw = passwordField.text;
                    passwordField.text = ""; // Best-effort scrub before close animation runs.
                    root.close();
                    root.accepted(pw);
                }

                HoverHandler { id: pwOkHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Item {
                    Row {
                        anchors.centerIn: parent
                        spacing: 6
                        SvgIcon {
                            source: Theme.iconLockOpen
                            color: okButton.enabled ? Theme.textOnAccent : Theme.textDisabled
                            width: Theme.iconSizeSmall
                            height: Theme.iconSizeSmall
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        Text {
                            text: okButton.text
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSizeMedium
                            font.weight: Font.DemiBold
                            color: okButton.enabled ? Theme.textOnAccent : Theme.textDisabled
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    clip: true
                    gradient: Gradient {
                        GradientStop { position: 0; color: okButton.enabled ? (okButton.pressed ? Theme.btnPressTop : okButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop) : Theme.btnDisabledTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: okButton.enabled ? (okButton.pressed ? Theme.btnPressBot : okButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot) : Theme.btnDisabledBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: Theme.strokeRegular
                    border.color: !okButton.enabled ? Theme.borderSubtle : okButton.hovered ? Theme.borderBright : Theme.borderBtn
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: pwOkRipple
                        baseColor: Qt.rgba(Theme.textOnAccent.r, Theme.textOnAccent.g, Theme.textOnAccent.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: pwOkRipple.trigger(pwOkHover.point.position.x, pwOkHover.point.position.y)
            }
        }
    }
}
