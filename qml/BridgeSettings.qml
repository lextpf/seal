import QtQuick
import QtQuick.Controls

/*!
 * \qmltype BridgeSettings
 * \inqmlmodule seal
 * \brief Display browser connections and provide bridge controls.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * The Bridge context property supplies browser rows and connection state.
 * Left-click starts a diagnostic probe. Right-click toggles the entire bridge,
 * including connections for other browsers. HeaderBar owns installation commands.
 * Disabling the bridge overrides each browser's connected indicator.
 */
Row {
    id: root
    /*!
     * Hide browser and authentication-warning labels; retain icons and status dots.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool compact: false
    spacing: compact ? 6 : 8

    Repeater {
        model: Bridge.browsers

        delegate: Item {
            id: chip

            required property var modelData

            // Disabled overrides a live connection.
            readonly property bool _on: Bridge.bridgeEnabled && modelData.connected

            implicitWidth: chipBg.implicitWidth
            implicitHeight: 22

            Rectangle {
                id: chipBg
                anchors.fill: parent
                radius: height / 2
                readonly property int leftInset: root.compact ? 7 : 8
                readonly property int rightInset: root.compact ? 10 : 13
                implicitWidth: chipRow.implicitWidth + leftInset + rightInset

                gradient: Gradient {
                    GradientStop {
                        position: 0
                        color: chip._on ? Theme.statusChipStrongTop : Theme.statusChipTop
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                    GradientStop {
                        position: 1
                        color: chip._on ? Theme.statusChipStrongEnd : Theme.statusChipEnd
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                }
                border.width: 0

                scale: chipMouse.pressed ? 0.97 : 1.0
                Behavior on scale {
                    NumberAnimation { duration: 160; easing.type: Easing.OutBack; easing.overshoot: 1.5 }
                }

                Rectangle {
                    anchors.fill: parent
                    radius: height / 2
                    color: Theme.surfaceHighlight
                    opacity: chipMouse.containsMouse ? 0.6 : 0.0
                    Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
                }

                Row {
                    id: chipRow
                    anchors.left: parent.left
                    anchors.leftMargin: chipBg.leftInset
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 4

                    Item {
                        id: dotContainer
                        width: 14
                        height: 14
                        anchors.verticalCenter: parent.verticalCenter

                        readonly property color statusColor:
                            chip._on ? Theme.textSuccess : Theme.textError

                        property real pulse: 0.0
                        SequentialAnimation on pulse {
                            running: true
                            loops: Animation.Infinite
                            NumberAnimation {
                                from: 0.0; to: 1.0
                                duration: 700; easing.type: Easing.InOutSine
                            }
                            NumberAnimation {
                                from: 1.0; to: 0.0
                                duration: 700; easing.type: Easing.InOutSine
                            }
                        }

                        Repeater {
                            model: 7
                            Rectangle {
                                readonly property real ringBase: 14.0 - index * 1.0
                                readonly property real ringFade: 0.02 + index * 0.012
                                anchors.centerIn: parent
                                width: ringBase * (1.0 + dotContainer.pulse * 0.45)
                                height: width
                                radius: width / 2
                                color: dotContainer.statusColor
                                opacity: ringFade * (1.0 - dotContainer.pulse * 0.7)
                                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                            }
                        }

                        Rectangle {
                            id: dot
                            anchors.centerIn: parent
                            width: 7
                            height: 7
                            radius: width / 2
                            color: dotContainer.statusColor
                            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                        }
                    }

                    SvgIcon {
                        source: chip.modelData.iconPath
                        width: Theme.px(11)
                        height: Theme.px(11)
                        anchors.verticalCenter: parent.verticalCenter
                        visible: chip.modelData.iconAvailable
                        color: chipMouse.containsMouse
                               ? Theme.textPrimary
                               : (chip._on ? Theme.statusChipStrongText : Theme.statusChipText)
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }

                    Rectangle {
                        width: Theme.px(11)
                        height: Theme.px(11)
                        radius: width / 2
                        anchors.verticalCenter: parent.verticalCenter
                        visible: !chip.modelData.iconAvailable
                        color: chipMouse.containsMouse
                               ? Theme.textPrimary
                               : (chip._on ? Theme.statusChipStrongText : Theme.statusChipText)
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }

                        Text {
                            anchors.centerIn: parent
                            text: chip.modelData.label.charAt(0)
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.px(7)
                            font.bold: true
                            color: Theme.bgDeep
                        }
                    }

                    Text {
                        visible: !root.compact
                        text: chip.modelData.label
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.weight: Font.Medium
                        color: chipMouse.containsMouse
                               ? Theme.textPrimary
                               : (chip._on ? Theme.statusChipStrongText : Theme.statusChipText)
                        anchors.verticalCenter: parent.verticalCenter
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }
                }

                MouseArea {
                    id: chipMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    acceptedButtons: Qt.LeftButton | Qt.RightButton
                    onClicked: (mouse) => {
                        if (mouse.button === Qt.RightButton) {
                            Bridge.setBridgeEnabled(!Bridge.bridgeEnabled);
                        } else {
                            Bridge.runBridgeDiagnose();
                        }
                    }
                }

                ToolTip.visible: chipMouse.containsMouse
                ToolTip.delay: 600
                ToolTip.text: (!Bridge.bridgeEnabled
                               ? "Bridge disabled (M8 panic). Right-click to re-enable."
                               : chip._on
                                   ? (chip.modelData.label + " companion connected.")
                                   : (chip.modelData.label + " not connected. Waiting for the extension.")) +
                              "\nClick: dry-run probe (Ctrl+Click any field to test detection)." +
                              "\nRight-click: toggle bridge enable / M8 panic mode."
            }
        }
    }

    // Warn when peer-signer matching is unavailable. Process pinning and trusted
    // browser ancestry checks still apply to unsigned development builds.
    Item {
        id: authWarn
        visible: !Bridge.bridgePeerAuthEnforced
        implicitWidth: authWarnRow.implicitWidth
        implicitHeight: 22
        anchors.verticalCenter: parent.verticalCenter

        Row {
            id: authWarnRow
            anchors.centerIn: parent
            spacing: 6

            SvgIcon {
                source: Theme.iconTriangleExclamation
                width: Theme.px(12)
                height: Theme.px(12)
                anchors.verticalCenter: parent.verticalCenter
                color: Theme.textWarning
            }

            Text {
                visible: !root.compact
                text: "Unsigned build"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: Theme.textWarning
                anchors.verticalCenter: parent.verticalCenter
            }
        }

        MouseArea {
            id: authWarnMouse
            anchors.fill: parent
            hoverEnabled: true
        }

        ToolTip.visible: authWarnMouse.containsMouse
        ToolTip.delay: 600
        ToolTip.text: "This build is unsigned, so the browser bridge accepts any local" +
                      "\npeer - peer signer authentication (M6) is disabled. Use a signed" +
                      "\nrelease build for full protection."
    }
}
