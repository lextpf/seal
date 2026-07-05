import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts

Popup {
    id: root

    property string errorMessage: ""
    readonly property color shellTone: Theme.accent

    function clearFields() {
        currentField.text = "";
        newField.text = "";
        confirmField.text = "";
        errorMessage = "";
    }

    function submit() {
        if (currentField.text.length === 0) {
            errorMessage = "Current password must not be empty.";
            return;
        }
        if (newField.text.length === 0) {
            errorMessage = "New password must not be empty.";
            return;
        }
        if (newField.text !== confirmField.text) {
            errorMessage = "New passwords do not match.";
            return;
        }
        AppViewModel.rekeyVault(currentField.text, newField.text);
        clearFields();
        root.close();
    }

    modal: true
    anchors.centerIn: parent
    width: 420
    padding: 0
    closePolicy: Popup.CloseOnEscape

    onAboutToShow: {
        clearFields();
        currentField.forceActiveFocus();
    }
    onClosed: clearFields()

    enter: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 175; easing.type: Easing.OutCubic }
            NumberAnimation { property: "scale"; from: 0.94; to: 1; duration: 190; easing.type: Easing.OutBack; easing.overshoot: 1.15 }
        }
    }
    exit: Transition {
        ParallelAnimation {
            NumberAnimation { property: "opacity"; from: 1; to: 0; duration: 130; easing.type: Easing.InCubic }
            NumberAnimation { property: "scale"; from: 1; to: 0.95; duration: 130; easing.type: Easing.InCubic }
        }
    }

    background: Rectangle {
        id: dialogBg
        color: Theme.bgDialog
        radius: Theme.radiusLarge
        border.width: 1
        border.color: Theme.borderMedium

        Item {
            anchors.fill: parent
            layer.enabled: true
            layer.smooth: true
            layer.effect: MultiEffect {
                maskEnabled: true
                maskSource: dialogShellMask
                autoPaddingEnabled: false
            }

            DialogBlobs { }

            Rectangle {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                height: 54
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.rgba(root.shellTone.r, root.shellTone.g, root.shellTone.b, 0.04) }
                    GradientStop { position: 1.0; color: Qt.rgba(root.shellTone.r, root.shellTone.g, root.shellTone.b, 0.0) }
                }
            }

            Rectangle {
                anchors.top: parent.top
                anchors.left: parent.left
                anchors.right: parent.right
                height: 1
                color: Theme.dialogEdgeLight
                opacity: 0.20
            }

            Rectangle {
                width: 180
                height: 128
                radius: 90
                x: -30
                y: -52
                color: Qt.rgba(root.shellTone.r, root.shellTone.g, root.shellTone.b, 0.05)
            }
        }

        Rectangle {
            id: dialogShellMask
            anchors.fill: parent
            radius: parent.radius
            visible: false
            layer.enabled: true
            layer.smooth: true
            antialiasing: true
        }
    }

    Overlay.modal: Rectangle {
        color: Theme.bgOverlay
    }

    component RekeyField: TextField {
        id: field
        Layout.fillWidth: true
        Layout.leftMargin: 24
        Layout.rightMargin: 24
        echoMode: field.showPassword ? TextInput.Normal : TextInput.Password
        passwordCharacter: "*"
        placeholderTextColor: Theme.textMuted
        font.family: Theme.fontFamily
        font.pixelSize: Theme.fontSizeLarge
        color: Theme.textPrimary
        leftPadding: 12
        rightPadding: 36

        property bool showPassword: rekeyEyeArea.containsMouse

        background: Rectangle {
            implicitHeight: 38
            radius: Theme.radiusSmall
            color: field.activeFocus ? Theme.bgInputFocus : Theme.bgInput
            border.width: 1
            border.color: field.activeFocus ? Theme.borderFocus : Theme.borderSubtle
        }

        SvgIcon {
            anchors.right: parent.right
            anchors.rightMargin: 8
            anchors.verticalCenter: parent.verticalCenter
            source: field.showPassword ? Theme.iconEye : Theme.iconEyeSlash
            color: rekeyEyeArea.containsMouse ? Theme.accent : Theme.textMuted
            width: Theme.iconSizeMedium
            height: Theme.iconSizeMedium

            MouseArea {
                id: rekeyEyeArea
                anchors.fill: parent
                anchors.margins: -4
                cursorShape: Qt.PointingHandCursor
                hoverEnabled: true
                acceptedButtons: Qt.NoButton
            }
        }
    }

    contentItem: ColumnLayout {
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: 10

            Item {
                Layout.preferredWidth: Theme.px(30)
                Layout.preferredHeight: Theme.px(30)

                SvgIcon {
                    source: Theme.iconKey
                    color: root.shellTone
                    width: Theme.px(14)
                    height: Theme.px(14)
                    anchors.centerIn: parent
                }
            }

            Text {
                text: "Change Master Password"
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
            text: "Every record is re-encrypted and the vault file is replaced atomically."
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            color: Theme.textSecondary
            wrapMode: Text.WordWrap
        }

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

        RekeyField {
            id: currentField
            Layout.topMargin: 16
            placeholderText: "Current password"
            onAccepted: newField.forceActiveFocus()
        }

        RekeyField {
            id: newField
            Layout.topMargin: 10
            placeholderText: "New password"
            onAccepted: confirmField.forceActiveFocus()
        }

        RekeyField {
            id: confirmField
            Layout.topMargin: 10
            placeholderText: "Confirm new password"
            onAccepted: root.submit()
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.bottomMargin: 20
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: Theme.spacingSmall

            Item { Layout.fillWidth: true }

            Button {
                id: rekeyCancelButton
                text: "Cancel"
                onClicked: root.close()

                HoverHandler { id: rekeyCancelHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Text {
                    text: parent.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.Medium
                    color: rekeyCancelButton.hovered ? Theme.textPrimary : Theme.textGhost
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    clip: true
                    gradient: Gradient {
                        GradientStop { position: 0; color: rekeyCancelButton.pressed ? Theme.ghostBtnPressed : rekeyCancelButton.hovered ? Theme.ghostBtnHoverTop : Theme.ghostBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: rekeyCancelButton.pressed ? Theme.ghostBtnPressed : rekeyCancelButton.hovered ? Theme.ghostBtnHoverEnd : Theme.ghostBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: 1
                    border.color: rekeyCancelButton.pressed ? Theme.borderPressed
                                : rekeyCancelButton.hovered ? Theme.borderFocusHover
                                : Theme.borderSubtle
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: rekeyCancelRipple
                        baseColor: Qt.rgba(Theme.textPrimary.r, Theme.textPrimary.g, Theme.textPrimary.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: rekeyCancelRipple.trigger(rekeyCancelHover.point.position.x, rekeyCancelHover.point.position.y)
            }

            Button {
                id: rekeyOkButton
                text: "Change"
                enabled: currentField.text.length > 0
                      && newField.text.length > 0
                      && confirmField.text.length > 0
                onClicked: root.submit()

                HoverHandler { id: rekeyOkHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Text {
                    text: parent.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.DemiBold
                    color: rekeyOkButton.enabled ? Theme.textOnAccent : Theme.textDisabled
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 90
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    clip: true
                    gradient: Gradient {
                        GradientStop { position: 0; color: rekeyOkButton.enabled ? (rekeyOkButton.pressed ? Theme.btnPressTop : rekeyOkButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop) : Theme.btnDisabledTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: rekeyOkButton.enabled ? (rekeyOkButton.pressed ? Theme.btnPressBot : rekeyOkButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot) : Theme.btnDisabledBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: 1
                    border.color: !rekeyOkButton.enabled ? Theme.borderSubtle : rekeyOkButton.hovered ? Theme.borderBright : Theme.borderBtn
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: rekeyOkRipple
                        baseColor: Qt.rgba(Theme.textOnAccent.r, Theme.textOnAccent.g, Theme.textOnAccent.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: rekeyOkRipple.trigger(rekeyOkHover.point.position.x, rekeyOkHover.point.position.y)
            }
        }
    }
}
