import QtQuick
import QtQuick.Controls

// Browser-companion bridge status — one chip per supported browser (Chrome and
// Brave). Each chip's dot is green only when that browser's companion host is
// actually connected (bridge enabled AND that browser handshaked), and red when
// disconnected or when the bridge is disabled (M8 panic mode). Because both
// chips reflect the one shared bridge, the interactions are global: left-click
// runs the diagnose dry-run, right-click toggles the bridge (M8). Install /
// uninstall of the native-messaging host happens via the CLI subcommands
// `seal install-browser-extension` / `seal uninstall-browser-extension`, so no
// install controls live in the UI.
//
// Visual model per chip: a neutral pill whose status dot is the sole on/off
// indicator. The brand glyph + label make each target obvious; chip background
// colors do not change between states so the dot pops cleanly.

Row {
    id: root
    spacing: 8

    // Per-browser descriptors. `key` selects which Backend property the chip
    // binds to; the icon must exist at assets/brands/<icon>.
    readonly property var _browsers: [
        {"label": "Google Chrome", "icon": "chrome.svg", "key": "chrome"},
        {"label": "Brave", "icon": "brave.svg", "key": "brave"}
    ]

    Repeater {
        model: root._browsers

        delegate: Item {
            id: chip

            required property var modelData

            // The chip is "live" only when the bridge is enabled AND this
            // browser's companion peer is actually connected. Without the
            // peer-connected half, the chip would light green at app launch
            // even if the extension isn't installed (or hasn't connected yet).
            readonly property bool _on: Backend.bridgeEnabled
                                        && (modelData.key === "chrome"
                                                ? Backend.bridgeChromeConnected
                                                : Backend.bridgeBraveConnected)

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

                    // Sole state indicator. Green when this browser's companion
                    // is connected, red otherwise (or bridge disabled). Colors
                    // come from the theme's textSuccess / textError tokens so
                    // they adapt to dark and light themes.
                    //
                    // Visual: a solid inner dot wrapped in a feathered halo that
                    // pulses size + opacity together. The halo is assembled from
                    // seven concentric translucent rings of decreasing opacity
                    // from inside out, so its outer edge dissolves smoothly into
                    // the chip background instead of presenting as a second
                    // hard-edged circle.
                    Item {
                        id: dotContainer
                        width: 14
                        height: 14
                        anchors.verticalCenter: parent.verticalCenter

                        readonly property color statusColor:
                            chip._on ? Theme.textSuccess : Theme.textError

                        // Single shared pulse driver in [0, 1]. Every ring binds
                        // its size and opacity to this so the whole halo breathes
                        // as one body; 700 ms each direction = a 1.4 s cycle.
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

                        // Feathered halo: seven concentric discs of decreasing
                        // opacity from outside in, so the alpha-composited stack
                        // peaks just outside the central dot and the dot reads as
                        // the focal point. Drawn back-to-front (largest first).
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

                        // Solid central dot. Not part of the pulse, so the chip
                        // keeps a stable focal point even at the halo's dimmest.
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

                    // Brand glyph. The asset must live at
                    // assets/brands/<icon>; rendered in the chip's current text
                    // color so the icon + label read as one unit.
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
                    // Plain click runs the diagnose dry-run (the "test the
                    // bridge" path). M8 panic toggle moves to right-click so a
                    // stray hover-click can't accidentally tear down the
                    // browser-extension connection and force a reconnect
                    // backoff. Both chips drive the one shared bridge, so the
                    // toggle keys off the global enabled state.
                    acceptedButtons: Qt.LeftButton | Qt.RightButton
                    onClicked: (mouse) => {
                        if (mouse.button === Qt.RightButton) {
                            Backend.setBridgeEnabled(!Backend.bridgeEnabled);
                        } else {
                            Backend.runBridgeDiagnose();
                        }
                    }
                }

                ToolTip.visible: chipMouse.containsMouse
                ToolTip.delay: 600
                ToolTip.text: (!Backend.bridgeEnabled
                               ? "Bridge disabled (M8 panic). Right-click to re-enable."
                               : chip._on
                                   ? (chip.modelData.label + " companion connected.")
                                   : (chip.modelData.label + " not connected. Waiting for the extension.")) +
                              "\nClick: dry-run probe (Ctrl+Click any field to test detection)." +
                              "\nRight-click: toggle bridge enable / M8 panic mode."
            }
        }
    }
}
