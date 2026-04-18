import QtQuick
import QtQuick.Layouts
import QtQuick.Window
import QtQuick.Shapes
import QtQuick.Effects

// Top header bar. Layout: [narwhal icon] [title] [theme toggle] ... [Load] [Save] [Unload]
//
// Save and Unload are disabled until a vault is loaded (bound to vaultLoaded).
// Load is always enabled so the user can open a vault from any state.
//
// All three vault buttons use the neutral iconBtn palette (same hue, different
// states) because they're utilities rather than primary actions like Add/Edit/Delete.

Item {
    id: root
    implicitHeight: headerRow.implicitHeight
    implicitWidth: headerRow.implicitWidth

    signal loadClicked()
    signal saveClicked()
    signal unloadClicked()

    property bool vaultLoaded: false

    // Title bar drag area: wraps the header row so unhandled clicks
    // (on empty space between buttons) bubble up here and start a
    // native window drag. Interactive children consume their own events.
    MouseArea {
        id: dragArea
        anchors.fill: parent
        acceptedButtons: Qt.LeftButton
        onPressed: function(mouse) {
            Backend.startWindowDrag()
        }
        onDoubleClicked: function(mouse) {
            var w = root.Window.window
            if (w.visibility === Window.Maximized)
                w.showNormal()
            else
                w.showMaximized()
        }

    RowLayout {
        id: headerRow
        anchors.fill: parent
        spacing: Theme.spacingMedium

    // App identity icon. Clicking triggers a sonar-pulse rainbow easter egg:
    // a ring expands outward from the icon while its color sweeps through
    // the spectrum, then returns to the theme accent.
    //
    // Wrapped in an Item so the rings (siblings before the icon) render
    // behind the narwhal silhouette instead of on top of it.
    Item {
        Layout.preferredWidth: narwhalIcon.width
        Layout.preferredHeight: narwhalIcon.height

        // Sonar rings - GPU-rendered vector arcs via QtQuick.Shapes.
        // Each ring is a donut (two concentric circular paths with OddEvenFill)
        // filled with a conic gradient. No Canvas rasterization, no onPaint -
        // the scene graph handles anti-aliasing natively.
        // Declared before the icon so they render behind it.
        Shape {
            id: ringWarm
            anchors.centerIn: narwhalIcon
            width: 0; height: width; opacity: 0
            readonly property real strokeW: 4.5
            readonly property real outerR: Math.max(1, width / 2)
            readonly property real innerR: Math.max(0, outerR - strokeW)
            readonly property real cx: width / 2
            readonly property real cy: width / 2
            layer.enabled: true; layer.samples: 4; layer.smooth: true
            layer.textureSize: Qt.size(Math.max(1, width * 5), Math.max(1, height * 5))

            ShapePath {
                fillRule: ShapePath.OddEvenFill
                strokeWidth: -1
                fillGradient: ConicalGradient {
                    centerX: ringWarm.cx; centerY: ringWarm.cy; angle: 0
                    GradientStop { position: 0.00; color: "#ff0044" }
                    GradientStop { position: 0.16; color: "#ff8800" }
                    GradientStop { position: 0.33; color: "#ffee00" }
                    GradientStop { position: 0.50; color: "#00dd66" }
                    GradientStop { position: 0.66; color: "#0088ff" }
                    GradientStop { position: 0.83; color: "#aa00ff" }
                    GradientStop { position: 1.00; color: "#ff0044" }
                }
                startX: ringWarm.cx + ringWarm.outerR; startY: ringWarm.cy
                PathArc { x: ringWarm.cx - ringWarm.outerR; y: ringWarm.cy; radiusX: ringWarm.outerR; radiusY: ringWarm.outerR }
                PathArc { x: ringWarm.cx + ringWarm.outerR; y: ringWarm.cy; radiusX: ringWarm.outerR; radiusY: ringWarm.outerR }
                PathMove { x: ringWarm.cx + ringWarm.innerR; y: ringWarm.cy }
                PathArc { x: ringWarm.cx - ringWarm.innerR; y: ringWarm.cy; radiusX: ringWarm.innerR; radiusY: ringWarm.innerR }
                PathArc { x: ringWarm.cx + ringWarm.innerR; y: ringWarm.cy; radiusX: ringWarm.innerR; radiusY: ringWarm.innerR }
            }
        }
        Shape {
            id: ringMid
            anchors.centerIn: narwhalIcon
            width: 0; height: width; opacity: 0
            readonly property real strokeW: 3.0
            readonly property real outerR: Math.max(1, width / 2)
            readonly property real innerR: Math.max(0, outerR - strokeW)
            readonly property real cx: width / 2
            readonly property real cy: width / 2
            layer.enabled: true; layer.samples: 4; layer.smooth: true
            layer.textureSize: Qt.size(Math.max(1, width * 5), Math.max(1, height * 5))

            ShapePath {
                fillRule: ShapePath.OddEvenFill
                strokeWidth: -1
                fillGradient: ConicalGradient {
                    centerX: ringMid.cx; centerY: ringMid.cy; angle: 120
                    GradientStop { position: 0.00; color: "#00ff88" }
                    GradientStop { position: 0.17; color: "#00ddcc" }
                    GradientStop { position: 0.33; color: "#22aaff" }
                    GradientStop { position: 0.50; color: "#6644ff" }
                    GradientStop { position: 0.67; color: "#aa44ff" }
                    GradientStop { position: 0.83; color: "#44ddaa" }
                    GradientStop { position: 1.00; color: "#00ff88" }
                }
                startX: ringMid.cx + ringMid.outerR; startY: ringMid.cy
                PathArc { x: ringMid.cx - ringMid.outerR; y: ringMid.cy; radiusX: ringMid.outerR; radiusY: ringMid.outerR }
                PathArc { x: ringMid.cx + ringMid.outerR; y: ringMid.cy; radiusX: ringMid.outerR; radiusY: ringMid.outerR }
                PathMove { x: ringMid.cx + ringMid.innerR; y: ringMid.cy }
                PathArc { x: ringMid.cx - ringMid.innerR; y: ringMid.cy; radiusX: ringMid.innerR; radiusY: ringMid.innerR }
                PathArc { x: ringMid.cx + ringMid.innerR; y: ringMid.cy; radiusX: ringMid.innerR; radiusY: ringMid.innerR }
            }
        }
        Shape {
            id: ringCool
            anchors.centerIn: narwhalIcon
            width: 0; height: width; opacity: 0
            readonly property real strokeW: 2.0
            readonly property real outerR: Math.max(1, width / 2)
            readonly property real innerR: Math.max(0, outerR - strokeW)
            readonly property real cx: width / 2
            readonly property real cy: width / 2
            layer.enabled: true; layer.samples: 4; layer.smooth: true
            layer.textureSize: Qt.size(Math.max(1, width * 5), Math.max(1, height * 5))

            ShapePath {
                fillRule: ShapePath.OddEvenFill
                strokeWidth: -1
                fillGradient: ConicalGradient {
                    centerX: ringCool.cx; centerY: ringCool.cy; angle: 240
                    GradientStop { position: 0.00; color: "#44ffcc" }
                    GradientStop { position: 0.17; color: "#2288ff" }
                    GradientStop { position: 0.33; color: "#6644ff" }
                    GradientStop { position: 0.50; color: "#cc44ff" }
                    GradientStop { position: 0.67; color: "#ff44aa" }
                    GradientStop { position: 0.83; color: "#ff8866" }
                    GradientStop { position: 1.00; color: "#44ffcc" }
                }
                startX: ringCool.cx + ringCool.outerR; startY: ringCool.cy
                PathArc { x: ringCool.cx - ringCool.outerR; y: ringCool.cy; radiusX: ringCool.outerR; radiusY: ringCool.outerR }
                PathArc { x: ringCool.cx + ringCool.outerR; y: ringCool.cy; radiusX: ringCool.outerR; radiusY: ringCool.outerR }
                PathMove { x: ringCool.cx + ringCool.innerR; y: ringCool.cy }
                PathArc { x: ringCool.cx - ringCool.innerR; y: ringCool.cy; radiusX: ringCool.innerR; radiusY: ringCool.innerR }
                PathArc { x: ringCool.cx + ringCool.innerR; y: ringCool.cy; radiusX: ringCool.innerR; radiusY: ringCool.innerR }
            }
        }

        SvgIcon {
            id: narwhalIcon
            source: Theme.iconNarwhal
            width: Theme.px(32)
            height: Theme.px(32)
            color: Theme.accent
            anchors.centerIn: parent

            property bool active: false
            readonly property real auroraTextureScale: Math.max(4, Screen.devicePixelRatio * 4)
            property real auroraShift: -0.22
            property real sheenShift: -0.18

            // Keep the effect low-frequency and directional so it still reads
            // cleanly at 32 px; the base icon provides the silhouette detail.
            Item {
                id: auroraGradient
                anchors.centerIn: parent
                width: parent.width; height: parent.height
                visible: false
                layer.enabled: true; layer.samples: 4; layer.smooth: true; layer.mipmap: true
                layer.textureSize: Qt.size(Math.max(1, Math.ceil(width * narwhalIcon.auroraTextureScale)),
                                           Math.max(1, Math.ceil(height * narwhalIcon.auroraTextureScale)))

                Shape {
                    anchors.fill: parent
                    ShapePath {
                        strokeWidth: -1
                        fillGradient: LinearGradient {
                            x1: auroraGradient.width * (-0.20 + narwhalIcon.auroraShift)
                            y1: auroraGradient.height * 0.08
                            x2: auroraGradient.width * (0.95 + narwhalIcon.auroraShift)
                            y2: auroraGradient.height * 0.95
                            GradientStop { position: 0.00; color: Qt.rgba(0.05, 0.98, 0.78, 0.00) }
                            GradientStop { position: 0.20; color: Qt.rgba(0.05, 0.98, 0.78, 0.16) }
                            GradientStop { position: 0.50; color: Qt.rgba(0.10, 0.78, 1.00, 0.34) }
                            GradientStop { position: 0.78; color: Qt.rgba(0.68, 0.30, 1.00, 0.28) }
                            GradientStop { position: 1.00; color: Qt.rgba(0.95, 0.34, 0.82, 0.00) }
                        }
                        startX: 0; startY: 0
                        PathLine { x: auroraGradient.width; y: 0 }
                        PathLine { x: auroraGradient.width; y: auroraGradient.height }
                        PathLine { x: 0; y: auroraGradient.height }
                        PathLine { x: 0; y: 0 }
                    }

                    ShapePath {
                        strokeWidth: -1
                        fillGradient: LinearGradient {
                            x1: auroraGradient.width * (0.10 + narwhalIcon.auroraShift * 0.55)
                            y1: auroraGradient.height * -0.05
                            x2: auroraGradient.width * (0.82 + narwhalIcon.auroraShift * 0.55)
                            y2: auroraGradient.height * 1.05
                            GradientStop { position: 0.00; color: Qt.rgba(0.10, 1.00, 0.84, 0.00) }
                            GradientStop { position: 0.38; color: Qt.rgba(0.10, 1.00, 0.84, 0.00) }
                            GradientStop { position: 0.58; color: Qt.rgba(0.16, 0.96, 0.92, 0.18) }
                            GradientStop { position: 0.80; color: Qt.rgba(0.94, 0.52, 0.74, 0.20) }
                            GradientStop { position: 1.00; color: Qt.rgba(0.94, 0.52, 0.74, 0.00) }
                        }
                        startX: 0; startY: 0
                        PathLine { x: auroraGradient.width; y: 0 }
                        PathLine { x: auroraGradient.width; y: auroraGradient.height }
                        PathLine { x: 0; y: auroraGradient.height }
                        PathLine { x: 0; y: 0 }
                    }

                    ShapePath {
                        strokeWidth: -1
                        fillGradient: LinearGradient {
                            x1: auroraGradient.width * (0.06 + narwhalIcon.sheenShift)
                            y1: 0
                            x2: auroraGradient.width * (0.42 + narwhalIcon.sheenShift)
                            y2: auroraGradient.height
                            GradientStop { position: 0.00; color: Qt.rgba(1.00, 1.00, 1.00, 0.00) }
                            GradientStop { position: 0.42; color: Qt.rgba(1.00, 1.00, 1.00, 0.00) }
                            GradientStop { position: 0.56; color: Qt.rgba(1.00, 1.00, 1.00, 0.28) }
                            GradientStop { position: 0.68; color: Qt.rgba(1.00, 1.00, 1.00, 0.04) }
                            GradientStop { position: 1.00; color: Qt.rgba(1.00, 1.00, 1.00, 0.00) }
                        }
                        startX: 0; startY: 0
                        PathLine { x: auroraGradient.width; y: 0 }
                        PathLine { x: auroraGradient.width; y: auroraGradient.height }
                        PathLine { x: 0; y: auroraGradient.height }
                        PathLine { x: 0; y: 0 }
                    }
                }
            }

            Item {
                id: auroraMask
                anchors.centerIn: parent
                width: parent.width; height: parent.height
                visible: false
                layer.enabled: true; layer.samples: 4; layer.smooth: true; layer.mipmap: true
                layer.textureSize: Qt.size(Math.max(1, Math.ceil(width * narwhalIcon.auroraTextureScale)),
                                           Math.max(1, Math.ceil(height * narwhalIcon.auroraTextureScale)))

                Image {
                    anchors.fill: parent
                    source: Theme.iconNarwhal
                    smooth: true
                    mipmap: true
                    fillMode: Image.PreserveAspectFit
                    sourceSize: Qt.size(Math.max(1, Math.ceil(parent.width * narwhalIcon.auroraTextureScale)),
                                        Math.max(1, Math.ceil(parent.height * narwhalIcon.auroraTextureScale)))
                }
            }

            MultiEffect {
                id: iconAurora
                anchors.centerIn: parent
                width: narwhalIcon.width; height: narwhalIcon.height
                source: auroraGradient
                maskEnabled: true
                maskSource: auroraMask
                maskThresholdMin: 0.15
                maskSpreadAtMin: 0.15
                autoPaddingEnabled: false
                visible: false
            }

            SvgIcon {
                id: auroraSheen
                anchors.fill: parent
                source: Theme.iconNarwhal
                color: "#ffffff"
                opacity: 0
                visible: opacity > 0
            }
        } // SvgIcon

        SequentialAnimation {
            id: easterEgg

            // Nudge each ring's center by a small random offset so the ripples
            // don't share a single perfectly concentric origin - like droplets
            // on a water surface that land slightly apart.
            ScriptAction {
                script: {
                    function jitter() { return (Math.random() - 0.5) * Theme.px(5); }
                    ringWarm.anchors.horizontalCenterOffset = jitter();
                    ringWarm.anchors.verticalCenterOffset   = jitter();
                    ringMid.anchors.horizontalCenterOffset   = jitter();
                    ringMid.anchors.verticalCenterOffset     = jitter();
                    ringCool.anchors.horizontalCenterOffset   = jitter();
                    ringCool.anchors.verticalCenterOffset     = jitter();
                }
            }

            ParallelAnimation {
                // Ring 1 - full rainbow, expands furthest, thickest stroke
                NumberAnimation { target: ringWarm; property: "width";   from: Theme.px(12); to: Theme.px(180); duration: 2200; easing.type: Easing.OutCubic }
                NumberAnimation { target: ringWarm; property: "opacity"; from: 0.70;          to: 0;             duration: 2200; easing.type: Easing.InQuad }

                // Ring 2 - aurora, staggered 400ms, mid reach, gradient rotated 120 deg
                SequentialAnimation {
                    PauseAnimation { duration: 400 }
                    ParallelAnimation {
                        NumberAnimation { target: ringMid; property: "width";   from: Theme.px(8); to: Theme.px(120); duration: 1900; easing.type: Easing.OutCubic }
                        NumberAnimation { target: ringMid; property: "opacity"; from: 0.50;          to: 0;             duration: 1900; easing.type: Easing.InQuad }
                    }
                }

                // Ring 3 - cool aurora, staggered 800ms, least reach, gradient rotated 240 deg
                SequentialAnimation {
                    PauseAnimation { duration: 800 }
                    ParallelAnimation {
                        NumberAnimation { target: ringCool; property: "width";   from: Theme.px(6); to: Theme.px(72); duration: 1600; easing.type: Easing.OutCubic }
                        NumberAnimation { target: ringCool; property: "opacity"; from: 0.35;          to: 0;            duration: 1600; easing.type: Easing.InQuad }
                    }
                }

                // Aurora shimmer on icon - directional sweep, then clean fade-out.
                SequentialAnimation {
                    PropertyAction  { target: iconAurora; property: "visible"; value: true }
                    PropertyAction  { target: iconAurora; property: "opacity"; value: 0 }
                    PropertyAction  { target: narwhalIcon; property: "auroraShift"; value: -0.22 }
                    PropertyAction  { target: narwhalIcon; property: "sheenShift"; value: -0.18 }
                    ParallelAnimation {
                        SequentialAnimation {
                            NumberAnimation { target: iconAurora; property: "opacity"; to: 0.85; duration: 240; easing.type: Easing.OutQuad }
                            PauseAnimation  { duration: 1550 }
                            NumberAnimation { target: iconAurora; property: "opacity"; to: 0; duration: 520; easing.type: Easing.InQuad }
                        }
                        NumberAnimation { target: narwhalIcon; property: "auroraShift"; to: 0.18; duration: 2100; easing.type: Easing.OutCubic }
                        NumberAnimation { target: narwhalIcon; property: "sheenShift"; to: 0.24; duration: 1350; easing.type: Easing.OutQuad }
                        SequentialAnimation {
                            NumberAnimation { target: auroraSheen; property: "opacity"; to: 0.14; duration: 160; easing.type: Easing.OutQuad }
                            NumberAnimation { target: auroraSheen; property: "opacity"; to: 0; duration: 900; easing.type: Easing.InQuad }
                        }
                    }
                    PropertyAction  { target: iconAurora; property: "visible"; value: false }
                }
            }

            // Reset ring offsets so they return to centered.
            ScriptAction {
                script: {
                    ringWarm.anchors.horizontalCenterOffset = 0;
                    ringWarm.anchors.verticalCenterOffset   = 0;
                    ringMid.anchors.horizontalCenterOffset   = 0;
                    ringMid.anchors.verticalCenterOffset     = 0;
                    ringCool.anchors.horizontalCenterOffset   = 0;
                    ringCool.anchors.verticalCenterOffset     = 0;
                    narwhalIcon.auroraShift = -0.22;
                    narwhalIcon.sheenShift = -0.18;
                    auroraSheen.opacity = 0;
                }
            }

            onFinished: {
                narwhalIcon.active = false;
            }
        }

        MouseArea {
            anchors.fill: narwhalIcon
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                if (narwhalIcon.active) return;
                narwhalIcon.active = true;
                easterEgg.start();
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
            text: root.vaultLoaded ? "Password Manager" : "Open a vault or create your first account"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSubtitle
            font.weight: root.vaultLoaded ? Font.Normal : Font.Medium
            color: root.vaultLoaded ? Theme.accent2Dim : Theme.textSubtle
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        }
    }

    // Theme toggle: sun in dark mode, moon in light mode.
    Item {
        implicitWidth: 30
        implicitHeight: 30

        SvgIcon {
            anchors.centerIn: parent
            source: Theme.dark ? Theme.iconSun : Theme.iconMoon
            width: Theme.iconSizeMedium
            height: Theme.iconSizeMedium
            color: themeArea.containsMouse ? Theme.accent : Theme.accentDim
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
        }

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

    // Vault control buttons use the shared TintedButton with the iconBtn palette.
    TintedButton {
        text: "Load"
        faIcon: Theme.iconFolderOpen
        tintTop:       Theme.iconBtnTop
        tintEnd:       Theme.iconBtnEnd
        tintHoverTop:  Theme.iconBtnHoverTop
        tintHoverEnd:  Theme.iconBtnHoverEnd
        tintPressed:   Theme.iconBtnPressed
        tintText:      root.vaultLoaded ? Theme.textIcon : Theme.accent
        tintTextHover: root.vaultLoaded ? Theme.textSecondary : Theme.accentBright
        background.implicitWidth: root.vaultLoaded ? 100 : 108
        onClicked: root.loadClicked()
    }

    TintedButton {
        text: "Save"
        faIcon: Theme.iconFloppyDisk
        enabled: root.vaultLoaded
        tintTop:       Theme.iconBtnTop
        tintEnd:       Theme.iconBtnEnd
        tintHoverTop:  Theme.iconBtnHoverTop
        tintHoverEnd:  Theme.iconBtnHoverEnd
        tintPressed:   Theme.iconBtnPressed
        tintText:      Theme.textIcon
        tintTextHover: Theme.textSecondary
        background.implicitWidth: 100
        onClicked: root.saveClicked()
    }

    TintedButton {
        text: "Unload"
        faIcon: Theme.iconEject
        enabled: root.vaultLoaded
        tintTop:       Theme.iconBtnTop
        tintEnd:       Theme.iconBtnEnd
        tintHoverTop:  Theme.iconBtnHoverTop
        tintHoverEnd:  Theme.iconBtnHoverEnd
        tintPressed:   Theme.iconBtnPressed
        tintText:      Theme.textIcon
        tintTextHover: Theme.textSecondary
        background.implicitWidth: 100
        onClicked: root.unloadClicked()
    }
    }  // RowLayout
    }  // MouseArea
}  // Item root
