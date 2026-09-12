import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

/*!
 * \qmltype ProtectFolderDialog
 * \inqmlmodule seal
 * \brief Preview folder protection and collect its password when required.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Main binds the plan to AppViewModel's preflight result. Confirmation requests
 * arming; it does not encrypt files. C++ revalidates the plan and aborts if it changed.
 * Opening shows the plan page and clears both password fields.
 *
 * \section1 Password modes
 *
 * \table
 * \header
 *     \li Mode
 *     \li Password action
 * \row
 *     \li 0
 *     \li Reuse the verified session password; skip password entry.
 * \row
 *     \li 1
 *     \li Create a folder profile; require a non-empty password and matching confirmation.
 * \row
 *     \li 2
 *     \li Unlock an existing folder profile; require a non-empty password.
 * \endtable
 */
Popup {
    id: root

    /*!
     * Root path from the preflight result. Used only for display.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property string folderPath: ""
    /*!
     * Relative plaintext paths planned for encryption on exit. Supply a string list.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property var encryptFiles: []
    /*!
     * Display strings in the form \c {<relative path> - <skip reason token>}.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property var skippedFiles: []
    /*!
     * Total plaintext size in bytes for \c encryptFiles. Must be non-negative.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property double totalBytes: 0
    /*!
     * Preflight password mode, from 0 to 2. See the type's password-mode table.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property int passwordMode: 1
    /*!
     * Show password entry when true, or the plan when false. Reset to false on open.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool passwordStep: false

    /*!
     * \brief Request folder arming with the selected password mode.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The \a password and \a confirmation preserve whitespace. Both are empty in
     * mode 0; \a confirmation is required only in mode 1. Fields are cleared before
     * emission, but the argument strings still contain the submitted text. Handlers
     * run before close. The caller revalidates the plan and applies the password mode.
     */
    signal confirmed(string password, string confirmation)

    /*!
     * \brief Clear both password fields without changing the current page.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * Used on open, close, Back, and submission. This does not guarantee that QML
     * string storage or strings copied for confirmation are overwritten.
     */
    function clearPasswordFields() {
        folderPassword.text = "";
        folderPasswordConfirm.text = "";
    }

    /*!
     * \brief Format a byte count for the plan summary.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The input \a bytes is a non-negative integer byte count. Return a label using
     * the largest applicable unit, up to GiB. Each unit is 1024 times the previous one.
     *
     * \table
     * \header
     *     \li Unit
     *     \li Decimal places
     * \row
     *     \li B
     *     \li 0
     * \row
     *     \li KiB or MiB
     *     \li 1
     * \row
     *     \li GiB
     *     \li 2
     * \endtable
     */
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

            // Mode 0 confirms from the plan; other modes advance to password entry.
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
