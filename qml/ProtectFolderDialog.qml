import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Two-step dialog that arms folder protection. Step one shows the preflight plan
// that AppViewModel computed; step two collects the folder password. The dialog
// decides nothing: it emits confirmed(), and AppViewModel re-runs the preflight
// and aborts the arming if the plan changed in the meantime.
Popup {
    id: root

    property string folderPath: ""
    property var encryptFiles: []   // Preflight plan: plaintext files to be encrypted on exit
    property var skippedFiles: []   // Files the plan leaves untouched
    property double totalBytes: 0   // Combined size of encryptFiles, shown in the header
    // 0 = reuse the verified session password and skip step two,
    // 1 = create a profile, which needs the password twice,
    // 2 = unlock the .seal-folder-profile already in the folder.
    property int passwordMode: 1
    property bool passwordStep: false  // false = plan page, true = password page

    signal confirmed(string password, string confirmation)

    // Runs on open, on close, on Back, and on confirm once the text is copied into
    // locals, so a typed folder password never outlives the step that collected it.
    function clearPasswordFields() {
        folderPassword.text = "";
        folderPasswordConfirm.text = "";
    }

    function formatBytes(bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return (bytes / 1024).toFixed(1) + " KiB";
        if (bytes < 1024 * 1024 * 1024)
            return (bytes / (1024 * 1024)).toFixed(1) + " MiB";
        return (bytes / (1024 * 1024 * 1024)).toFixed(2) + " GiB";
    }

    modal: true
    focus: true
    anchors.centerIn: parent
    width: Math.min(720, parent ? parent.width - 32 : 720)
    height: Math.min(610, parent ? parent.height - 24 : 610)
    padding: 0
    closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside

    onAboutToShow: {
        passwordStep = false;
        clearPasswordFields();
    }
    onClosed: clearPasswordFields()

    enter: Transition {
        ParallelAnimation {
            NumberAnimation {
                property: "opacity"
                from: 0
                to: 1
                duration: 175
                easing.type: Easing.OutCubic
            }
            NumberAnimation {
                property: "scale"
                from: 0.96
                to: 1
                duration: 190
                easing.type: Easing.OutBack
                easing.overshoot: 1.1
            }
        }
    }

    exit: Transition {
        ParallelAnimation {
            NumberAnimation {
                property: "opacity"
                from: 1
                to: 0
                duration: 130
                easing.type: Easing.InCubic
            }
            NumberAnimation {
                property: "scale"
                from: 1
                to: 0.96
                duration: 130
                easing.type: Easing.InCubic
            }
        }
    }

    background: Rectangle {
        color: Theme.bgDialog
        radius: Theme.radiusLarge
        border.width: Theme.strokeRegular
        border.color: Theme.borderMedium
    }

    Overlay.modal: Rectangle {
        color: Theme.bgOverlay
    }

    contentItem: ColumnLayout {
        spacing: 0

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 22
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: 10

            SvgIcon {
                source: Theme.iconShieldHalved
                Layout.preferredWidth: Theme.px(18)
                Layout.preferredHeight: Theme.px(18)
                color: Theme.accent
            }

            Text {
                Layout.fillWidth: true
                text: root.passwordStep
                      ? (root.passwordMode === 1 ? "Create folder password"
                                                 : "Unlock folder profile")
                      : "Arm folder protection"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.px(17)
                font.bold: true
                color: Theme.textPrimary
            }

            Text {
                visible: !root.passwordStep
                text: root.encryptFiles.length + " file(s) - " + root.formatBytes(root.totalBytes)
                font.family: Theme.fontMono
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.accent
            }
        }

        // ---- Plan page: these items hide once passwordStep turns true ----

        Text {
            Layout.fillWidth: true
            Layout.topMargin: 10
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            text: root.folderPath
            font.family: Theme.fontMono
            font.pixelSize: Theme.fontSizeSmall
            color: Theme.textMuted
            elide: Text.ElideMiddle
            visible: !root.passwordStep
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.topMargin: 14
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            implicitHeight: warningText.implicitHeight + 20
            radius: Theme.radiusMedium
            color: Qt.rgba(Theme.textWarning.r, Theme.textWarning.g, Theme.textWarning.b, 0.08)
            border.width: Theme.strokeRegular
            border.color: Qt.rgba(Theme.textWarning.r, Theme.textWarning.g,
                                  Theme.textWarning.b, 0.32)
            visible: !root.passwordStep

            Text {
                id: warningText
                anchors.fill: parent
                anchors.margins: 10
                text: "Irreversible warning: on exit, each plaintext source is replaced by an encrypted .seal file. If the folder password is lost, the files cannot be recovered. Keep .seal-folder-profile with the folder so automatic unlock can verify it."
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                font.weight: Font.Medium
                color: Theme.textWarning
                wrapMode: Text.WordWrap
            }
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: 14
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            text: "Will be encrypted"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            font.bold: true
            color: Theme.textPrimary
            visible: !root.passwordStep
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 120
            Layout.topMargin: 6
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            color: Theme.bgInput
            radius: Theme.radiusMedium
            border.width: Theme.strokeRegular
            border.color: Theme.borderSubtle
            clip: true
            visible: !root.passwordStep

            ListView {
                id: encryptList
                anchors.fill: parent
                anchors.margins: 8
                model: root.encryptFiles
                spacing: 3
                clip: true

                delegate: Text {
                    required property string modelData
                    width: encryptList.width
                    text: modelData
                    font.family: Theme.fontMono
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textSecondary
                    elide: Text.ElideMiddle
                }

                ScrollBar.vertical: ScrollBar {}
            }

            Text {
                anchors.centerIn: parent
                visible: root.encryptFiles.length === 0
                text: "No plaintext payload files currently present"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.textMuted
            }
        }

        Text {
            Layout.fillWidth: true
            Layout.topMargin: 12
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            text: "Protected from the plan - stable reason token"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            font.bold: true
            color: Theme.textPrimary
            visible: !root.passwordStep
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: 6
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            color: Theme.bgInput
            radius: Theme.radiusMedium
            border.width: Theme.strokeRegular
            border.color: Theme.borderSubtle
            clip: true
            visible: !root.passwordStep

            ListView {
                id: skippedList
                anchors.fill: parent
                anchors.margins: 8
                model: root.skippedFiles
                spacing: 3
                clip: true

                delegate: Text {
                    required property string modelData
                    width: skippedList.width
                    text: modelData
                    font.family: Theme.fontMono
                    font.pixelSize: Theme.fontSizeSmall
                    color: Theme.textMuted
                    elide: Text.ElideMiddle
                }

                ScrollBar.vertical: ScrollBar {}
            }
        }

        // ---- Password page: reached from the plan page when passwordMode is 1 or 2 ----

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: 28
            Layout.leftMargin: 54
            Layout.rightMargin: 54
            spacing: 14
            visible: root.passwordStep

            Text {
                Layout.fillWidth: true
                text: root.passwordMode === 1
                      ? "Choose the password that will encrypt this folder. seal stores only an authenticated verifier in .seal-folder-profile-never the password itself."
                      : "This folder already has .seal-folder-profile. Enter its password to adopt the folder without creating a credential vault."
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeMedium
                color: Theme.textSecondary
                wrapMode: Text.WordWrap
                horizontalAlignment: Text.AlignHCenter
            }

            TextField {
                id: folderPassword
                Layout.fillWidth: true
                Layout.topMargin: 12
                echoMode: showPassword ? TextInput.Normal : TextInput.Password
                passwordCharacter: "\u2981"
                placeholderText: "Folder password"
                placeholderTextColor: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeLarge
                color: Theme.textPrimary
                leftPadding: 12
                rightPadding: 36
                property bool showPassword: folderPasswordEye.containsMouse

                background: Rectangle {
                    implicitHeight: 40
                    radius: Theme.radiusSmall
                    color: folderPassword.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                    border.width: Theme.strokeRegular
                    border.color: folderPassword.activeFocus ? Theme.borderFocus
                                                             : Theme.borderSubtle
                }

                SvgIcon {
                    anchors.right: parent.right
                    anchors.rightMargin: 8
                    anchors.verticalCenter: parent.verticalCenter
                    source: folderPassword.showPassword ? Theme.iconEye : Theme.iconEyeSlash
                    color: folderPasswordEye.containsMouse ? Theme.accent : Theme.textMuted
                    width: Theme.iconSizeMedium
                    height: Theme.iconSizeMedium

                    MouseArea {
                        id: folderPasswordEye
                        anchors.fill: parent
                        anchors.margins: -4
                        hoverEnabled: true
                        acceptedButtons: Qt.NoButton
                    }
                }
            }

            TextField {
                id: folderPasswordConfirm
                Layout.fillWidth: true
                visible: root.passwordMode === 1
                echoMode: folderPassword.showPassword ? TextInput.Normal : TextInput.Password
                passwordCharacter: "\u2981"
                placeholderText: "Confirm folder password"
                placeholderTextColor: Theme.textMuted
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeLarge
                color: Theme.textPrimary
                leftPadding: 12

                background: Rectangle {
                    implicitHeight: 40
                    radius: Theme.radiusSmall
                    color: folderPasswordConfirm.activeFocus ? Theme.bgInputFocus : Theme.bgInput
                    border.width: Theme.strokeRegular
                    border.color: folderPasswordConfirm.activeFocus ? Theme.borderFocus
                                                                    : Theme.borderSubtle
                }
            }

            Text {
                Layout.fillWidth: true
                text: root.passwordMode === 1 &&
                      folderPassword.text.length > 0 &&
                      folderPasswordConfirm.text.length > 0 &&
                      folderPassword.text !== folderPasswordConfirm.text
                      ? "Passwords do not match."
                      : "The profile remains beside seal.exe and is never included in the encryption plan."
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                color: text.startsWith("Passwords") ? Theme.textError : Theme.textMuted
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
            }

            Item { Layout.fillHeight: true }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 18
            Layout.bottomMargin: 20
            Layout.leftMargin: 24
            Layout.rightMargin: 24
            spacing: Theme.spacingSmall

            Text {
                Layout.fillWidth: true
                text: root.passwordStep
                      ? "The same one-password prompt unlocks the folder on later launches."
                      : root.passwordMode === 2
                        ? "Existing .seal-folder-profile detected; it will be retained."
                        : "A .seal-folder-profile verifier stays outside the encryption plan."
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.textMuted
            }

            // Back on the password page returns to the plan; Cancel closes the dialog.
            Button {
                id: cancelButton
                text: root.passwordStep ? "Back" : "Cancel"
                onClicked: {
                    if (root.passwordStep) {
                        root.clearPasswordFields();
                        root.passwordStep = false;
                    } else {
                        root.close();
                    }
                }

                HoverHandler {
                    cursorShape: Qt.PointingHandCursor
                }

                contentItem: Text {
                    text: cancelButton.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.Medium
                    color: cancelButton.hovered ? Theme.textPrimary : Theme.textGhost
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }

                background: Rectangle {
                    implicitWidth: 94
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    color: cancelButton.pressed ? Theme.ghostBtnPressed
                                                : cancelButton.hovered ? Theme.ghostBtnHoverTop
                                                                       : Theme.ghostBtnTop
                    border.width: Theme.strokeRegular
                    border.color: cancelButton.hovered ? Theme.borderFocusHover
                                                       : Theme.borderSubtle
                }
            }

            // One button, two jobs: on the plan page it advances to the password
            // page, unless passwordMode is 0, which confirms straight away.
            Button {
                id: armButton
                text: root.passwordStep
                      ? (root.passwordMode === 1 ? "Create & arm" : "Unlock & arm")
                      : "Arm protection"
                enabled: !root.passwordStep ||
                         (folderPassword.text.length > 0 &&
                          (root.passwordMode !== 1 ||
                           (folderPasswordConfirm.text.length > 0 &&
                            folderPassword.text === folderPasswordConfirm.text)))
                onClicked: {
                    if (!root.passwordStep && root.passwordMode !== 0) {
                        root.passwordStep = true;
                        folderPassword.forceActiveFocus();
                        return;
                    }

                    var password = folderPassword.text;
                    var confirmation = folderPasswordConfirm.text;
                    root.clearPasswordFields();
                    root.confirmed(password, confirmation);
                    root.close();
                }

                HoverHandler {
                    cursorShape: Qt.PointingHandCursor
                }

                contentItem: Text {
                    text: armButton.text
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeMedium
                    font.weight: Font.DemiBold
                    color: armButton.enabled ? Theme.textOnAccent : Theme.textDisabled
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }

                background: Rectangle {
                    implicitWidth: 130
                    implicitHeight: 34
                    radius: Theme.radiusMedium
                    color: !armButton.enabled ? Theme.btnDisabledTop
                                             : armButton.pressed ? Theme.btnPressTop
                                                                 : armButton.hovered
                                                                   ? Theme.btnHoverTop
                                                                   : Theme.btnGradTop
                    border.width: Theme.strokeRegular
                    border.color: armButton.hovered ? Theme.borderBright : Theme.borderBtn
                }
            }
        }
    }
}
