import QtQuick
import QtQuick.Controls

Row {
    id: root
    spacing: 8

    readonly property var _browsers: [
        {"label": "Chrome", "icon": "chrome.svg", "key": "chrome"},
        {"label": "Brave", "icon": "brave.svg", "key": "brave"}
    ]

    Repeater {
        model: root._browsers

        delegate: Item {
            id: chip

            required property var modelData

            readonly property bool _on: Bridge.bridgeEnabled
                                        && (modelData.key === "chrome"
                                                ? Bridge.bridgeChromeConnected
                                                : Bridge.bridgeBraveConnected)

            implicitWidth: chipBg.implicitWidth
            implicitHeight: 22

            Rectangle {
                id: chipBg
                anchors.fill: parent
                radius: height / 2
                implicitWidth: chipRow.implicitWidth + 18

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
                border.width: 1
                border.color: chipMouse.containsMouse
                              ? Theme.borderHighlight
                              : (chip._on ? Theme.statusChipStrongBorder : Theme.statusChipBorder)
                Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

                scale: chipMouse.pressed ? 0.97 : 1.0
                Behavior on scale {
                    NumberAnimation { duration: 160; easing.type: Easing.OutBack; easing.overshoot: 1.5 }
                }

                Row {
                    id: chipRow
                    anchors.centerIn: parent
                    spacing: 6

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
                        source: "qrc:/qt/qml/seal/assets/brands/" + chip.modelData.icon
                        width: Theme.px(11)
                        height: Theme.px(11)
                        anchors.verticalCenter: parent.verticalCenter
                        color: chip._on ? Theme.statusChipStrongText : Theme.statusChipText
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }

                    Text {
                        text: chip.modelData.label
                        font.family: Theme.fontFamily
                        font.pixelSize: Theme.fontSizeSmall
                        font.weight: Font.Medium
                        color: chip._on ? Theme.statusChipStrongText : Theme.statusChipText
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

    Item {
        id: autoChip
        implicitWidth: autoBg.implicitWidth
        implicitHeight: 22
        anchors.verticalCenter: parent.verticalCenter

        readonly property bool _on: Bridge.autoStageEnabled

        Rectangle {
            id: autoBg
            anchors.fill: parent
            radius: height / 2
            implicitWidth: autoRow.implicitWidth + 18
            gradient: Gradient {
                GradientStop {
                    position: 0
                    color: autoChip._on ? Theme.statusChipStrongTop : Theme.statusChipTop
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
                GradientStop {
                    position: 1
                    color: autoChip._on ? Theme.statusChipStrongEnd : Theme.statusChipEnd
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
            }
            border.width: 1
            border.color: autoMouse.containsMouse
                          ? Theme.borderHighlight
                          : (autoChip._on ? Theme.statusChipStrongBorder : Theme.statusChipBorder)
            Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }
            scale: autoMouse.pressed ? 0.97 : 1.0
            Behavior on scale {
                NumberAnimation { duration: 160; easing.type: Easing.OutBack; easing.overshoot: 1.5 }
            }

            Row {
                id: autoRow
                anchors.centerIn: parent
                spacing: 6

                Rectangle {
                    width: 7
                    height: 7
                    radius: width / 2
                    anchors.verticalCenter: parent.verticalCenter
                    color: autoChip._on ? Theme.textSuccess : Theme.textError
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }

                Text {
                    text: "Auto-fill"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeSmall
                    font.weight: Font.Medium
                    color: autoChip._on ? Theme.statusChipStrongText : Theme.statusChipText
                    anchors.verticalCenter: parent.verticalCenter
                    Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                }
            }

            MouseArea {
                id: autoMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: Bridge.setAutoStageEnabled(!Bridge.autoStageEnabled)
            }

            ToolTip.visible: autoMouse.containsMouse
            ToolTip.delay: 600
            ToolTip.text: (autoChip._on ? "Staged auto-fill ON." : "Staged auto-fill OFF.") +
                          "\nWhen on, seal pre-arms a matching record on navigation;" +
                          "\na plain click into the login field completes the fill." +
                          "\nThe password is never sent to the browser."
        }
    }
}
