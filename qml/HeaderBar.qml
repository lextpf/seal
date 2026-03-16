import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window

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
    SvgIcon {
        id: narwhalIcon
        source: Theme.iconNarwhal
        width: Theme.px(32)
        height: Theme.px(32)
        color: Theme.accent

        property bool active: false

        // Staggered sonar rings - three concentric rings with conic
        // rainbow / aurora gradients rippling outward from the icon center.
        Canvas {
            id: ringWarm
            anchors.centerIn: parent
            width: 0; height: width; opacity: 0
            onPaint: {
                var ctx = getContext("2d"); ctx.reset();
                if (width < 4) return;
                var cx = width/2, cy = height/2, r = Math.max(1, width/2 - 1.5);
                var g = ctx.createConicalGradient(cx, cy, 0);
                g.addColorStop(0.00, "#ff0044");
                g.addColorStop(0.16, "#ff8800");
                g.addColorStop(0.33, "#ffee00");
                g.addColorStop(0.50, "#00dd66");
                g.addColorStop(0.66, "#0088ff");
                g.addColorStop(0.83, "#aa00ff");
                g.addColorStop(1.00, "#ff0044");
                ctx.beginPath(); ctx.arc(cx, cy, r, 0, 2*Math.PI);
                ctx.lineWidth = 2.5; ctx.strokeStyle = g; ctx.stroke();
            }
            onWidthChanged: requestPaint()
        }
        Canvas {
            id: ringMid
            anchors.centerIn: parent
            width: 0; height: width; opacity: 0
            onPaint: {
                var ctx = getContext("2d"); ctx.reset();
                if (width < 4) return;
                var cx = width/2, cy = height/2, r = Math.max(1, width/2 - 1.5);
                var g = ctx.createConicalGradient(cx, cy, 0);
                g.addColorStop(0.00, "#00ff88");
                g.addColorStop(0.25, "#00ddcc");
                g.addColorStop(0.50, "#4488ff");
                g.addColorStop(0.75, "#aa44ff");
                g.addColorStop(1.00, "#00ff88");
                ctx.beginPath(); ctx.arc(cx, cy, r, 0, 2*Math.PI);
                ctx.lineWidth = 2.5; ctx.strokeStyle = g; ctx.stroke();
            }
            onWidthChanged: requestPaint()
        }
        Canvas {
            id: ringCool
            anchors.centerIn: parent
            width: 0; height: width; opacity: 0
            onPaint: {
                var ctx = getContext("2d"); ctx.reset();
                if (width < 4) return;
                var cx = width/2, cy = height/2, r = Math.max(1, width/2 - 1.5);
                var g = ctx.createConicalGradient(cx, cy, 0);
                g.addColorStop(0.00, "#44ffcc");
                g.addColorStop(0.25, "#4466ff");
                g.addColorStop(0.50, "#cc44ff");
                g.addColorStop(0.75, "#ff44aa");
                g.addColorStop(1.00, "#44ffcc");
                ctx.beginPath(); ctx.arc(cx, cy, r, 0, 2*Math.PI);
                ctx.lineWidth = 2.5; ctx.strokeStyle = g; ctx.stroke();
            }
            onWidthChanged: requestPaint()
        }

        // Conic aurora gradient overlay - masked to the icon silhouette
        // via Canvas compositing (destination-in). Shown during the easter
        // egg animation in place of the flat icon color.
        Canvas {
            id: iconAurora
            readonly property int ss: 3
            anchors.centerIn: parent
            width: parent.width * ss; height: parent.height * ss
            scale: 1.0 / ss
            visible: false
            property bool loaded: false

            Component.onCompleted: loadImage(Theme.iconNarwhal)
            onImageLoaded: loaded = true
            onVisibleChanged: if (visible) requestPaint()

            onPaint: {
                var ctx = getContext("2d"); ctx.reset();
                if (!loaded || width < 1) return;
                var g = ctx.createConicalGradient(width/2, height/2, 0);
                g.addColorStop(0.00, "#00ff88");
                g.addColorStop(0.15, "#00ddcc");
                g.addColorStop(0.30, "#4488ff");
                g.addColorStop(0.50, "#aa44ff");
                g.addColorStop(0.70, "#ff44aa");
                g.addColorStop(0.85, "#ff8844");
                g.addColorStop(1.00, "#00ff88");
                ctx.fillStyle = g;
                ctx.fillRect(0, 0, width, height);
                ctx.globalCompositeOperation = "destination-in";
                ctx.drawImage(Theme.iconNarwhal, 0, 0, width, height);
            }
        }

        SequentialAnimation {
            id: easterEgg

            ParallelAnimation {
                // Ring 1 - full rainbow, expands furthest
                NumberAnimation { target: ringWarm; property: "width";   from: Theme.px(18); to: Theme.px(130); duration: 1400; easing.type: Easing.OutQuad }
                NumberAnimation { target: ringWarm; property: "opacity"; from: 0.45;          to: 0;             duration: 1400; easing.type: Easing.InQuad }

                // Ring 2 - aurora, staggered 300ms, mid reach
                SequentialAnimation {
                    PauseAnimation { duration: 300 }
                    ParallelAnimation {
                        NumberAnimation { target: ringMid; property: "width";   from: Theme.px(14); to: Theme.px(88); duration: 1300; easing.type: Easing.OutQuad }
                        NumberAnimation { target: ringMid; property: "opacity"; from: 0.35;          to: 0;            duration: 1300; easing.type: Easing.InQuad }
                    }
                }

                // Ring 3 - cool aurora, staggered 600ms, least reach
                SequentialAnimation {
                    PauseAnimation { duration: 600 }
                    ParallelAnimation {
                        NumberAnimation { target: ringCool; property: "width";   from: Theme.px(10); to: Theme.px(55); duration: 1200; easing.type: Easing.OutQuad }
                        NumberAnimation { target: ringCool; property: "opacity"; from: 0.25;          to: 0;            duration: 1200; easing.type: Easing.InQuad }
                    }
                }

                // Conic aurora gradient on icon - rendered once, GPU-animated opacity.
                SequentialAnimation {
                    PropertyAction  { target: iconAurora; property: "visible"; value: true }
                    PropertyAction  { target: iconAurora; property: "opacity"; value: 0.75 }
                    PauseAnimation  { duration: 1600 }
                    NumberAnimation { target: iconAurora; property: "opacity"; to: 0; duration: 200 }
                    PropertyAction  { target: iconAurora; property: "visible"; value: false }
                }
            }

            onFinished: {
                narwhalIcon.active = false;
            }
        }

        MouseArea {
            anchors.fill: parent
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
            text: "Password Manager"
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeSubtitle
            color: Theme.accent2Dim
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
            clip: true
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
            clip: true
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
            clip: true
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
    }  // RowLayout
    }  // MouseArea
}  // Item root
