import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts

// Master-password change dialog.
//
// Pure view: collects current + new + confirm, validates locally
// (non-empty, match), then calls AppViewModel.rekeyVault(). The actual
// re-encryption runs on a ViewModel worker thread; the result arrives via
// AppViewModel.rekeyFinished and is surfaced by Main.qml's central router.
//
// Fields are cleared on every close so passwords never linger in QML state.

Popup {
    id: root

    property string errorMessage: ""
    readonly property color shellTone: Theme.accent

    // Best-effort scrub: QML strings are immutable and GC-managed, so they cannot be SecureZero'd.
    // We clear the visible fields and drop references; the authoritative secret lifetime is governed
    // C++-side by CredentialSession.
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

        // Decorative overlays masked to the dialog's rounded silhouette, matching
        // the Add/Edit dialog shell: drifting blobs, a top tone gradient, an edge
        // light, and a corner tone blob -- all in this dialog's shellTone.
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

    // Shared styling for the three password fields. Hover-to-reveal eye, mirroring
    // the Add/Edit dialog: masked by default, shown only while the cursor is over
    // the eye, re-hidden the moment it leaves (less shoulder-surfing exposure than
    // a persistent toggle).
    component RekeyField: TextField {
        id: field
        Layout.fillWidth: true
        Layout.leftMargin: 24
        Layout.rightMargin: 24
        echoMode: field.showPassword ? TextInput.Normal : TextInput.Password
        passwordCharacter: "⦁"
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

            // Qt.NoButton: track hover without intercepting clicks (which would
            // steal focus from the field). -4 margin enlarges the hit area.
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

            TintedButton {
                text: "Cancel"
                tintTop:       Theme.iconBtnTop
                tintEnd:       Theme.iconBtnEnd
                tintHoverTop:  Theme.iconBtnHoverTop
                tintHoverEnd:  Theme.iconBtnHoverEnd
                tintPressed:   Theme.iconBtnPressed
                tintText:      Theme.textIcon
                tintTextHover: Theme.textSecondary
                background.implicitWidth: 100
                onClicked: root.close()
            }

            TintedButton {
                text: "Change"
                faIcon: Theme.iconKey
                tintTop:       Theme.iconBtnTop
                tintEnd:       Theme.iconBtnEnd
                tintHoverTop:  Theme.iconBtnHoverTop
                tintHoverEnd:  Theme.iconBtnHoverEnd
                tintPressed:   Theme.iconBtnPressed
                tintText:      Theme.accent
                tintTextHover: Theme.accentBright
                background.implicitWidth: 110
                onClicked: root.submit()
            }
        }
    }
}
