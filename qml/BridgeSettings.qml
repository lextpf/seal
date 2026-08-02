import QtQuick
import QtQuick.Controls

// Browser connection chips for the status footer (instantiated by
// StatusFooter.qml): one pulsing chip per entry in Bridge.browsers, plus a
// warning sign on unsigned builds. Left-click runs a dry-run probe,
// right-click toggles the bridge. The chips report link state only; the
// install and uninstall actions live in HeaderBar.
Row {
    id: root
    property bool compact: false   // Narrow window: drop the labels, keep the dots.
    spacing: compact ? 6 : 8

    Repeater {
        model: Bridge.browsers

        delegate: Item {
            id: chip

            required property var modelData

            // Green only when the extension is connected and the bridge is
            // enabled: a disabled bridge reads as down even with a live port.
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
                border.width: Theme.strokeRegular
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

                        // Concentric fading rings make the halo around the dot;
                        // they breathe outward with `pulse`.
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
                        color: chip._on ? Theme.statusChipStrongText : Theme.statusChipText
                        Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
                    }

                    // Fallback for a browser with no bundled icon: a lettered
                    // disc, so an untracked assets/ still gives every chip a mark.
                    Rectangle {
                        width: Theme.px(11)
                        height: Theme.px(11)
                        radius: width / 2
                        anchors.verticalCenter: parent.verticalCenter
                        visible: !chip.modelData.iconAvailable
                        color: chip._on ? Theme.statusChipStrongText : Theme.statusChipText

                        Text {
                            anchors.centerIn: parent
                            text: chip.modelData.label.charAt(0)
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.px(7)
                            font.bold: true
                            color: chip._on ? Theme.statusChipStrongEnd : Theme.statusChipEnd
                        }
                    }

                    Text {
                        visible: !root.compact
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

    // An unsigned build has an empty signer identity, so peer authentication
    // (M6) degrades to accept-all and any local process can talk to the bridge.
    // A bare amber sign rather than a chip, so it reads as a caution instead of
    // another pill. A signed release hides it (Row skips invisible items) and
    // shows no "signed" counterpart.
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
