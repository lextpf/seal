import QtQuick
import QtQuick.Controls

// Browser-companion bridge status chip.
//
// A single clickable pill that lives in the footer alongside the other
// status indicators. Toggles the bridge (M8 panic mode) on click. Install /
// uninstall of the native-messaging host happens via the CLI subcommands
// `seal install-browser-extension` / `seal uninstall-browser-extension`,
// so no install controls live in the UI.
//
// Visual model: a single neutral chip whose status dot is the sole on/off
// indicator — green when accepting extension reports, red when disabled.
// The Chrome brand glyph plus the "Google Chrome" label make the target
// obvious; chip background colors do not change between states so the dot
// pops cleanly. The neutral tone is the standard statusChip palette so
// the chip coordinates with neighboring footer text rather than
// competing with the armed-fill yellow used by the Fill button.

Item {
    id: root

    // The chip is "live" only when the bridge is enabled AND a browser-
    // companion peer is actually connected. Without the peer-connected
    // half, the chip would light up green at app launch even if the
    // extension isn't installed (or has crashed, or hasn't finished
    // connecting yet), which gave a false sense of "working."
    readonly property bool _bridgeOn: Backend.bridgeEnabled && Backend.bridgePeerConnected
    readonly property bool _bridgeDisabled: !Backend.bridgeEnabled

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
                color: root._bridgeOn ? Theme.statusChipStrongTop : Theme.statusChipTop
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
            GradientStop {
                position: 1
                color: root._bridgeOn ? Theme.statusChipStrongEnd : Theme.statusChipEnd
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }
        }
        border.width: 1
        border.color: chipMouse.containsMouse
                      ? Theme.borderHighlight
                      : (root._bridgeOn ? Theme.statusChipStrongBorder : Theme.statusChipBorder)
        Behavior on border.color { ColorAnimation { duration: Theme.hoverDuration } }

        scale: chipMouse.pressed ? 0.97 : 1.0
        Behavior on scale {
            NumberAnimation { duration: 160; easing.type: Easing.OutBack; easing.overshoot: 1.5 }
        }

        Row {
            id: chipRow
            anchors.centerIn: parent
            spacing: 6

            // Sole state indicator. Green when the bridge is accepting
            // extension reports, red when no peer is connected or the
            // bridge is disabled (M8 panic mode). Both colors are pulled
            // from the theme's textSuccess / textError tokens so they
            // adapt to dark and light themes.
            //
            // Visual: a solid inner dot wrapped in a feathered halo that
            // pulses size + opacity together. The halo is assembled from
            // seven concentric translucent rings of decreasing opacity
            // from inside out, so its outer edge dissolves smoothly
            // into the chip background instead of presenting as a
            // second hard-edged circle (which was the bug a single
            // Rectangle halo showed -- at any opacity it still had a
            // crisp boundary the eye could pick out, and the pulse-in
            // animation revealed it as the disc shrank back).
            Item {
                id: dotContainer
                width: 14
                height: 14
                anchors.verticalCenter: parent.verticalCenter

                readonly property color statusColor:
                    root._bridgeOn ? Theme.textSuccess : Theme.textError

                // Single shared pulse driver in [0, 1]. Every ring
                // binds its size and opacity to this so the whole halo
                // breathes as one body; 700 ms each direction matches
                // the previous design's 1.4 s full cycle.
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
                // opacity from outside in. Per-ring alphas are kept
                // deliberately low (~2 % outer, ~9 % inner) so the
                // alpha-composited stack peaks at ~0.34 just outside
                // the central dot -- clearly subordinate to the dot's
                // solid 1.0 so the dot reads as the focal point and
                // the halo only as a glow around it. Drawn back-to-
                // front by Repeater order (largest first), so the
                // more-opaque inner rings paint on top of the dim
                // outer ones.
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
                // keeps a stable focal point even at the moment the
                // halo dims furthest.
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

            // Chrome brand glyph. The asset must live at assets/brands/chrome.svg;
            // rendered in the chip's current text color so the icon + label read
            // as one unit even as the chip background shifts between on/off.
            SvgIcon {
                source: "qrc:/qt/qml/seal/assets/brands/chrome.svg"
                width: Theme.px(11)
                height: Theme.px(11)
                anchors.verticalCenter: parent.verticalCenter
                color: root._bridgeOn ? Theme.statusChipStrongText : Theme.statusChipText
                Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            }

            Text {
                text: "Google Chrome"
                font.family: Theme.fontFamily
                font.pixelSize: Theme.fontSizeSmall
                font.weight: Font.Medium
                color: root._bridgeOn ? Theme.statusChipStrongText : Theme.statusChipText
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
            // backoff. Both buttons are accepted so we can route by
            // mouse.button rather than relying on a Qt modifier flag.
            acceptedButtons: Qt.LeftButton | Qt.RightButton
            onClicked: (mouse) => {
                if (mouse.button === Qt.RightButton) {
                    Backend.setBridgeEnabled(!root._bridgeOn);
                } else {
                    Backend.runBridgeDiagnose();
                }
            }
        }

        ToolTip.visible: chipMouse.containsMouse
        ToolTip.delay: 600
        ToolTip.text: (root._bridgeDisabled
                       ? "Bridge disabled (M8 panic). Right-click to re-enable."
                       : root._bridgeOn
                           ? "Bridge active. Browser extension connected."
                           : "Bridge enabled but waiting for the extension to connect.") +
                      "\nClick: dry-run probe (Ctrl+Click any field to test detection)." +
                      "\nRight-click: toggle bridge enable / M8 panic mode."
    }
}
