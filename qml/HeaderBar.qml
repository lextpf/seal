import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

// Top header bar. Layout: [fingerprint icon] [title] [theme toggle] ... [Load] [Save] [Unload]
//
// Save and Unload are disabled until a vault is loaded (bound to vaultLoaded).
// Load is always enabled so the user can open a vault from any state.
//
// All three vault buttons use the neutral iconBtn palette (same hue, different
// states) because they're utilities rather than primary actions like Add/Edit/Delete.

RowLayout {
    id: root
    spacing: Theme.spacingMedium

    signal loadClicked()
    signal saveClicked()
    signal unloadClicked()

    property bool vaultLoaded: false

    // App identity icon. Clicking triggers a rainbow color cycle easter egg:
    // the icon transitions through seven hues then returns to the theme accent.
    SvgIcon {
        id: fingerprintIcon
        source: Theme.iconFingerprint
        width: Theme.px(32)
        height: Theme.px(32)
        color: Theme.accent

        property bool cycling: false
        property int colorIndex: 0
        readonly property var rainbow: ["#ff4444", "#ff8800", "#ffcc00", "#44cc44", "#4488ff", "#8844ff", "#ff44cc"]

        ColorAnimation on color {
            id: rainbowAnim
            running: false
            duration: 120
            onFinished: {
                if (fingerprintIcon.cycling) {
                    fingerprintIcon.colorIndex++;
                    if (fingerprintIcon.colorIndex < fingerprintIcon.rainbow.length) {
                        rainbowAnim.to = fingerprintIcon.rainbow[fingerprintIcon.colorIndex];
                        rainbowAnim.restart();
                    } else {
                        // Return to accent
                        rainbowAnim.to = Theme.accent;
                        rainbowAnim.restart();
                        fingerprintIcon.cycling = false;
                    }
                }
            }
        }

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                if (fingerprintIcon.cycling) return;
                fingerprintIcon.cycling = true;
                fingerprintIcon.colorIndex = 0;
                rainbowAnim.to = fingerprintIcon.rainbow[0];
                rainbowAnim.restart();
            }
        }
    }

    // Title block
    ColumnLayout {
        spacing: 2

        Text {
            text: "seal"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeTitle
            font.bold: true
            color: Theme.accent
        }
        Text {
            text: "Password Manager"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSubtitle
            color: Theme.accentDim
        }
    }

    // Theme toggle: sun in dark mode, moon in light mode.
    SvgIcon {
        source: Theme.dark ? Theme.iconSun : Theme.iconMoon
        width: Theme.iconSizeMedium
        height: Theme.iconSizeMedium
        color: themeArea.containsMouse ? Theme.accent : Theme.accentDim
        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

        MouseArea {
            id: themeArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: Theme.toggle()
        }
    }

    // Spacer pushes vault control buttons to the right edge.
    Item { Layout.fillWidth: true }

    // Vault buttons share the iconBtn palette. HoverHandler for cursor shape
    // since MouseArea would interfere with Button's click handling.
    Button {
        id: loadBtn
        text: "Load"
        leftPadding: 12
        rightPadding: 12
        onClicked: root.loadClicked()

        HoverHandler { id: loadHover; cursorShape: Qt.PointingHandCursor }

        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: Theme.iconFolderOpen
                width: Theme.iconSizeSmall
                height: Theme.iconSizeSmall
                color: loadBtn.hovered ? Theme.textSecondary : Theme.textIcon
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
            Text {
                text: "Load"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: loadBtn.hovered ? Theme.textSecondary : Theme.textIcon
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        scale: pressed ? 0.97 : 1.0
        Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

        background: Rectangle {
            implicitWidth: 86
            implicitHeight: 32
            radius: Theme.radiusSmall
            gradient: Gradient {
                GradientStop { position: 0; color: loadBtn.pressed ? Theme.iconBtnPressed : loadBtn.hovered ? Theme.iconBtnHoverTop : Theme.iconBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                GradientStop { position: 1; color: loadBtn.pressed ? Theme.iconBtnPressed : loadBtn.hovered ? Theme.iconBtnHoverEnd : Theme.iconBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            }
            border.width: 1
            border.color: loadBtn.hovered ? Theme.borderHover : Theme.borderSoft
            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            RippleEffect { id: loadRipple; baseColor: Qt.rgba(Theme.iconBtnHoverTop.r, Theme.iconBtnHoverTop.g, Theme.iconBtnHoverTop.b, 0.40) }
        }
        onPressed: loadRipple.trigger(loadHover.point.position.x, loadHover.point.position.y)
    }

    Button {
        id: saveBtn
        text: "Save"
        leftPadding: 12
        rightPadding: 12
        enabled: root.vaultLoaded
        onClicked: root.saveClicked()

        HoverHandler { id: saveHover; cursorShape: Qt.PointingHandCursor }

        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: Theme.iconFloppyDisk
                width: Theme.iconSizeSmall
                height: Theme.iconSizeSmall
                color: !saveBtn.enabled ? Theme.textDisabled : saveBtn.hovered ? Theme.textSecondary : Theme.textIcon
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
            Text {
                text: "Save"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: !saveBtn.enabled ? Theme.textDisabled : saveBtn.hovered ? Theme.textSecondary : Theme.textIcon
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        scale: pressed ? 0.97 : 1.0
        Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

        background: Rectangle {
            implicitWidth: 86
            implicitHeight: 32
            radius: Theme.radiusSmall
            gradient: Gradient {
                GradientStop { position: 0; color: !saveBtn.enabled ? Theme.btnDisabledTop : saveBtn.pressed ? Theme.iconBtnPressed : saveBtn.hovered ? Theme.iconBtnHoverTop : Theme.iconBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                GradientStop { position: 1; color: !saveBtn.enabled ? Theme.btnDisabledBot : saveBtn.pressed ? Theme.iconBtnPressed : saveBtn.hovered ? Theme.iconBtnHoverEnd : Theme.iconBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            }
            border.width: 1
            border.color: !saveBtn.enabled ? Theme.borderDim : saveBtn.hovered ? Theme.borderHover : Theme.borderSoft
            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            RippleEffect { id: saveRipple; baseColor: Qt.rgba(Theme.iconBtnHoverTop.r, Theme.iconBtnHoverTop.g, Theme.iconBtnHoverTop.b, 0.40) }
        }
        onPressed: saveRipple.trigger(saveHover.point.position.x, saveHover.point.position.y)
    }

    Button {
        id: unloadBtn
        text: "Unload"
        leftPadding: 12
        rightPadding: 12
        enabled: root.vaultLoaded
        onClicked: root.unloadClicked()

        HoverHandler { id: unloadHover; cursorShape: Qt.PointingHandCursor }

        contentItem: Row {
            spacing: 6
            anchors.centerIn: parent
            SvgIcon {
                source: Theme.iconEject
                width: Theme.iconSizeSmall
                height: Theme.iconSizeSmall
                color: !unloadBtn.enabled ? Theme.textDisabled : unloadBtn.hovered ? Theme.textSecondary : Theme.textIcon
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
            Text {
                text: "Unload"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: !unloadBtn.enabled ? Theme.textDisabled : unloadBtn.hovered ? Theme.textSecondary : Theme.textIcon
                anchors.verticalCenter: parent.verticalCenter
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }

        scale: pressed ? 0.97 : 1.0
        Behavior on scale { NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 } }

        background: Rectangle {
            implicitWidth: 96
            implicitHeight: 32
            radius: Theme.radiusSmall
            gradient: Gradient {
                GradientStop { position: 0; color: !unloadBtn.enabled ? Theme.btnDisabledTop : unloadBtn.pressed ? Theme.iconBtnPressed : unloadBtn.hovered ? Theme.iconBtnHoverTop : Theme.iconBtnTop; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
                GradientStop { position: 1; color: !unloadBtn.enabled ? Theme.btnDisabledBot : unloadBtn.pressed ? Theme.iconBtnPressed : unloadBtn.hovered ? Theme.iconBtnHoverEnd : Theme.iconBtnEnd; Behavior on color { ColorAnimation { duration: Theme.hoverDuration } } }
            }
            border.width: 1
            border.color: !unloadBtn.enabled ? Theme.borderDim : unloadBtn.hovered ? Theme.borderHover : Theme.borderSoft
            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

            RippleEffect { id: unloadRipple; baseColor: Qt.rgba(Theme.iconBtnHoverTop.r, Theme.iconBtnHoverTop.g, Theme.iconBtnHoverTop.b, 0.40) }
        }
        onPressed: unloadRipple.trigger(unloadHover.point.position.x, unloadHover.point.position.y)
    }
}
