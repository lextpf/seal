import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Master password entry. Escape-only close (no click-outside) to prevent
// accidental dismissal. Re-shown with error on wrong password.

Popup {
    id: root

    property string errorMessage: ""

    signal accepted(string password)
    signal qrRequested()

    /// Set the password field text (e.g. from QR scan) without closing the dialog.
    function fillPassword(text) {
        passwordField.text = text;
        passwordField.forceActiveFocus();
    }

    modal: true
    anchors.centerIn: parent
    width: 420
    padding: 0
    closePolicy: Popup.NoAutoClose

    enter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 150; easing.type: Easing.OutCubic }
            NumberAnimation { property: "scale"; from: 0.92; to: 1; duration: 150; easing.type: Easing.OutCubic }
        }
    }
    exit: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 120; easing.type: Easing.InCubic }
            NumberAnimation { property: "scale"; from: 1; to: 0.92; duration: 120; easing.type: Easing.InCubic }
        }
    }

    background: Rectangle {
        color: Theme.bgDialog
        radius: Theme.radiusLarge
        border.width: 1
        border.color: Theme.borderMedium
    }

    Overlay.modal: Rectangle {
        color: Theme.bgOverlay
    }

    // Clear stale password on open.
    onAboutToShow: {
        passwordField.text = "";
        passwordField.forceActiveFocus();
    }

    contentItem: ColumnLayout {
        spacing: 0

        // Title row
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: 10

            SvgIcon {
                source: Theme.iconLock
                color: Theme.accent
                width: Theme.iconSizeMedium
                height: Theme.iconSizeMedium
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
            text: "Type your password or scan a QR code."
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            color: Theme.textSecondary
            wrapMode: Text.WordWrap
        }

        // Error feedback after failed attempt.
        Text {
            Layout.fillWidth: true
            Layout.topMargin: 6
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            visible: root.errorMessage !== ""
            text: root.errorMessage
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
                border.width: 1
                border.color: passwordField.activeFocus ? Theme.borderFocus : Theme.borderSubtle
            }

            SvgIcon {
                anchors.right: parent.right
                anchors.rightMargin: 8
                anchors.verticalCenter: parent.verticalCenter
                source: passwordField.showPassword ? Theme.iconEyeSlash : Theme.iconEye
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

            // Close before accepted() so dialog is gone during scrypt derivation.
            Keys.onReturnPressed: {
                if (passwordField.text.length > 0) {
                    var pw = passwordField.text;
                    root.close();
                    root.accepted(pw);
                }
            }
            Keys.onEnterPressed: {
                if (passwordField.text.length > 0) {
                    var pw = passwordField.text;
                    root.close();
                    root.accepted(pw);
                }
            }
        }

        // Buttons
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.bottomMargin: 20
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: Theme.spacingSmall

            Item { Layout.fillWidth: true }

            // QR button. Dialog stays open; field is filled when capture completes.
            Button {
                id: qrButton
                onClicked: {
                    root.qrRequested();
                }

                HoverHandler { id: qrHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Item {
                    SvgIcon {
                        source: Theme.iconQrCode
                        color: qrButton.hovered ? Theme.textPrimary : Theme.textGhost
                        width: Theme.iconSizeSmall
                        height: Theme.iconSizeSmall
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.left: parent.left
                        anchors.leftMargin: 4
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                    Text {
                        text: "QR"
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeMedium
                        font.weight: Font.Medium
                        color: qrButton.hovered ? Theme.textPrimary : Theme.textGhost
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.horizontalCenter: parent.horizontalCenter
                        anchors.horizontalCenterOffset: 4
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    gradient: Gradient {
                        GradientStop { position: 0; color: qrButton.pressed ? Theme.ghostBtnPressed : qrButton.hovered ? Theme.ghostBtnHoverTop : Theme.ghostBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: qrButton.pressed ? Theme.ghostBtnPressed : qrButton.hovered ? Theme.ghostBtnHoverEnd : Theme.ghostBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: 1
                    border.color: qrButton.pressed ? Theme.borderPressed
                                : qrButton.hovered ? Theme.borderFocusHover
                                : Theme.borderSubtle
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect { id: qrRipple; baseColor: Qt.rgba(Theme.ghostBtnHoverTop.r, Theme.ghostBtnHoverTop.g, Theme.ghostBtnHoverTop.b, 0.35) }
                }
                onPressed: qrRipple.trigger(qrHover.point.position.x, qrHover.point.position.y)
            }

            // OK button. Disabled until non-empty to prevent empty scrypt call.
            Button {
                id: okButton
                text: "OK"
                enabled: passwordField.text.length > 0
                onClicked: {
                    var pw = passwordField.text;
                    root.close();
                    root.accepted(pw);
                }

                HoverHandler { id: pwOkHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Text {
                    text: parent.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.DemiBold
                    color: okButton.enabled ? Theme.textOnAccent : Theme.textDisabled
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    gradient: Gradient {
                        GradientStop { position: 0; color: okButton.enabled ? (okButton.pressed ? Theme.btnPressTop : okButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop) : Theme.btnDisabledTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: okButton.enabled ? (okButton.pressed ? Theme.btnPressBot : okButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot) : Theme.btnDisabledBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: 1
                    border.color: !okButton.enabled ? Theme.borderSubtle : okButton.hovered ? Theme.borderBright : Theme.borderBtn
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect { id: pwOkRipple; baseColor: Qt.rgba(Theme.btnGradTop.r, Theme.btnGradTop.g, Theme.btnGradTop.b, 0.35) }
                }
                onPressed: pwOkRipple.trigger(pwOkHover.point.position.x, pwOkHover.point.position.y)
            }
        }
    }
}
