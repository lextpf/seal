import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts

Popup {
    id: root

    property string dialogTitle: "Add Account"
    property string initialService: ""
    property int editIndex: -1  // -1 = add mode, >= 0 = record index to edit
    property bool _showValidation: false
    readonly property bool _requiresSecretFields: root.editIndex < 0
    readonly property color shellTone: root.editIndex >= 0 ? Theme.accent3 : Theme.accent2
    readonly property string shellIcon: root.editIndex >= 0 ? Theme.iconPen : Theme.iconPlus
    readonly property string shellSubtitle: root.editIndex >= 0
                                         ? "Change service or enter replacement login details."
                                         : "Add a credential to your vault."

    signal accepted(string service, string username, string password, int editIdx)

    modal: true
    anchors.centerIn: parent
    width: 440
    padding: 0
    // Click-outside to dismiss; no data lost until OK is clicked.
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    // Slightly weightier scale+fade entrance to match the richer dialog shell.
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

    // Overlay dimming
    Overlay.modal: Rectangle {
        color: Theme.bgOverlay
    }

    contentItem: ColumnLayout {
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 24
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            Layout.bottomMargin: 18
            spacing: 10

            Item {
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: Theme.px(30)
                Layout.preferredHeight: Theme.px(30)

                SvgIcon {
                    source: root.shellIcon
                    width: Theme.px(14)
                    height: Theme.px(14)
                    color: root.shellTone
                    anchors.centerIn: parent
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2

                Text {
                    text: root.dialogTitle
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.px(16)
                    font.bold: true
                    color: Theme.textPrimary
                }

                Text {
                    Layout.fillWidth: true
                    text: root.shellSubtitle
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textMuted
                    wrapMode: Text.WordWrap
                }
            }
        }

        GridLayout {
            Layout.fillWidth: true
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            columns: 2
            columnSpacing: 12
            rowSpacing: 12

            Row {
                spacing: 6
                SvgIcon {
                    source: Theme.iconService
                    width: Theme.iconSizeMedium
                    height: Theme.iconSizeMedium
                    color: Theme.accent
                    anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                    text: "Service:"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    color: Theme.accent
                }
            }
            TextField {
                id: serviceField
                Layout.fillWidth: true
                text: root.initialService
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textPrimary
                placeholderText: "e.g. GitHub"
                placeholderTextColor: Theme.textPlaceholder
                selectByMouse: true

                background: Rectangle {
                    implicitHeight: 38
                    radius: Theme.radiusSmall
                    color: serviceField.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                    border.width: 1
                    border.color: root._showValidation && serviceField.text.trim() === "" ? Theme.textError
                                 : serviceField.activeFocus ? Theme.borderFocus : Theme.borderInput
                }

                Keys.onReturnPressed: root.submitForm()
                Keys.onEnterPressed: root.submitForm()
            }

            Row {
                spacing: 6
                SvgIcon {
                    source: Theme.iconUsername
                    width: Theme.iconSizeMedium
                    height: Theme.iconSizeMedium
                    color: Theme.accent2
                    anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                    text: "Username:"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    color: Theme.accent2
                }
            }
            TextField {
                id: usernameField
                Layout.fillWidth: true
                text: ""
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textPrimary
                placeholderText: root._requiresSecretFields ? "" : "Leave blank to keep current"
                placeholderTextColor: Theme.textPlaceholder
                selectByMouse: true

                background: Rectangle {
                    implicitHeight: 38
                    radius: Theme.radiusSmall
                    color: usernameField.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                    border.width: 1
                    border.color: root._showValidation && root._requiresSecretFields
                                                   && usernameField.text.trim() === "" ? Theme.textError
                                 : usernameField.activeFocus ? Theme.borderFocus : Theme.borderInput
                }

                Keys.onReturnPressed: root.submitForm()
                Keys.onEnterPressed: root.submitForm()
            }

            Row {
                spacing: 6
                SvgIcon {
                    source: Theme.iconPassword
                    width: Theme.iconSizeMedium
                    height: Theme.iconSizeMedium
                    color: Theme.accent3
                    anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                    text: "Password:"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    color: Theme.accent3
                }
            }
            TextField {
                id: passwordField
                Layout.fillWidth: true
                text: ""
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textPrimary
                placeholderText: root._requiresSecretFields ? "" : "Leave blank to keep current"
                placeholderTextColor: Theme.textPlaceholder
                echoMode: showPassword ? TextInput.Normal : TextInput.Password
                passwordCharacter: "\u2981"
                selectByMouse: true
                rightPadding: 36

                Keys.onReturnPressed: root.submitForm()
                Keys.onEnterPressed: root.submitForm()

                property bool showPassword: eyeArea.containsMouse

                background: Rectangle {
                    implicitHeight: 38
                    radius: Theme.radiusSmall
                    color: passwordField.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                    border.width: 1
                    border.color: root._showValidation && root._requiresSecretFields
                                                   && passwordField.text === "" ? Theme.textError
                                 : passwordField.activeFocus ? Theme.borderFocus : Theme.borderInput
                }

                SvgIcon {
                    anchors.right: parent.right
                    anchors.rightMargin: 8
                    anchors.verticalCenter: parent.verticalCenter
                    source: passwordField.showPassword ? Theme.iconEye : Theme.iconEyeSlash
                    color: eyeArea.containsMouse ? Theme.accent3 : Theme.textMuted
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
            }
        }

        // Client-side validation hint shown after a failed submit attempt.
        Text {
            Layout.fillWidth: true
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            Layout.topMargin: 4
            visible: root._showValidation
            text: root._requiresSecretFields ? "All fields are required." : "Service is required."
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.textError
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
                id: cancelButton
                text: "Cancel"
                onClicked: root.close()

                HoverHandler { id: acctCancelHover; cursorShape: Qt.PointingHandCursor }

                scale: pressed ? 0.97 : 1.0
                Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

                contentItem: Text {
                    text: parent.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.Medium
                    color: cancelButton.hovered ? Theme.textPrimary : Theme.textGhost
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
                        GradientStop { position: 0; color: cancelButton.pressed ? Theme.ghostBtnPressed : cancelButton.hovered ? Theme.ghostBtnHoverTop : Theme.ghostBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: cancelButton.pressed ? Theme.ghostBtnPressed : cancelButton.hovered ? Theme.ghostBtnHoverEnd : Theme.ghostBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: 1
                    border.color: cancelButton.pressed ? Theme.borderPressed
                                : cancelButton.hovered ? Theme.borderFocusHover
                                : Theme.borderSubtle
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: acctCancelRipple
                        baseColor: Qt.rgba(Theme.textPrimary.r, Theme.textPrimary.g, Theme.textPrimary.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: acctCancelRipple.trigger(acctCancelHover.point.position.x, acctCancelHover.point.position.y)
            }

            Button {
                id: okButton
                text: "OK"
                enabled: serviceField.text.trim().length > 0
                      && (!root._requiresSecretFields
                          || (usernameField.text.trim().length > 0
                              && passwordField.text.length > 0))
                onClicked: root.submitForm()

                HoverHandler { id: acctOkHover; cursorShape: Qt.PointingHandCursor }

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
                    clip: true
                    gradient: Gradient {
                        GradientStop { position: 0; color: okButton.enabled ? (okButton.pressed ? Theme.btnPressTop : okButton.hovered ? Theme.btnHoverTop : Theme.btnGradTop) : Theme.btnDisabledTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                        GradientStop { position: 1; color: okButton.enabled ? (okButton.pressed ? Theme.btnPressBot : okButton.hovered ? Theme.btnHoverBot : Theme.btnGradBot) : Theme.btnDisabledBot; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                    }
                    border.width: 1
                    border.color: !okButton.enabled ? Theme.borderSubtle : okButton.hovered ? Theme.borderBright : Theme.borderBtn
                    Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                    RippleEffect {
                        id: acctOkRipple
                        baseColor: Qt.rgba(Theme.textOnAccent.r, Theme.textOnAccent.g, Theme.textOnAccent.b, 0.30)
                        cornerRadius: parent.radius
                    }
                }
                onPressed: acctOkRipple.trigger(acctOkHover.point.position.x, acctOkHover.point.position.y)
            }
        }
    }

    // Focus the first field on open so the user can start typing immediately.
    onOpened: serviceField.forceActiveFocus()

    function submitForm() {
        var svc = serviceField.text.trim()
        var usr = usernameField.text.trim()
        var pwd = passwordField.text
        if (svc === "" || (root._requiresSecretFields && (usr === "" || pwd === ""))) {
            _showValidation = true
            return
        }
        root.accepted(svc, usr, pwd, root.editIndex)
        root.close()
    }

    // Reset fields on open. Edit mode intentionally leaves secrets blank.
    function resetFields() {
        serviceField.text = initialService;
        usernameField.text = "";
        passwordField.text = "";
    }

    onAboutToShow: { _showValidation = false; resetFields() }

    onClosed: {
        initialService = ""
        serviceField.text = ""
        usernameField.text = ""
        passwordField.text = ""
    }
}
