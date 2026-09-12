import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Window
import QtQuick.Shapes
import QtQuick.Effects

/*!
 * \qmltype HeaderBar
 * \inqmlmodule seal
 * \brief Present vault commands, search, and the window drag surface.
 *
 * Author: \l {https://github.com/lextpf}{Lextpf}.
 *
 * Main handles vault, folder-protection, and search requests. Browser controls
 * call Bridge directly; theme changes call Theme. Uncovered header space starts
 * native window dragging, and a double-click toggles maximization.
 *
 * Compact mode hides utility toggles and vault commands. CLI mode replaces search
 * with a spacer that preserves the drag surface. Width thresholds use logical
 * pixels and apply only after the control receives a positive width:
 *
 * \table
 * \header
 *     \li Width
 *     \li Layout adjustment
 * \row
 *     \li Below 1200
 *     \li Reduce group and button spacing.
 * \row
 *     \li Below 1120
 *     \li Hide vault-action labels and retain their tooltips.
 * \row
 *     \li Below 960
 *     \li Reduce toggle size and spacing further.
 * \endtable
 */
Item {
    id: root

    /*!
     * \brief Request the owner's vault-open flow.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal loadClicked()
    /*!
     * \brief Request saving of the loaded vault.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal saveClicked()
    /*!
     * \brief Request the owner's vault-unload flow.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal unloadClicked()
    /*!
     * \brief Request a password change for the vault or protected folder.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    signal rekeyClicked()
    /*!
     * \brief Request a change to protection of the portable folder.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * When \a enabled is true, the owner must run preflight and confirmation before
     * arming protection. The request does not update the displayed armed state.
     */
    signal protectFolderToggled(bool enabled)
    /*!
     * \brief Forward the search field's delayed filter request.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     *
     * The \a text value keeps its original whitespace. SearchBar waits 200 ms after
     * the latest text change; the owner applies the filter.
     */
    signal searchRequested(string text)

    /*!
     * Enable save, unload, rekey, and search. Folder protection can also enable rekey.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool vaultLoaded: false
    /*!
     * Owner-confirmed folder protection state; also permits rekey without an open vault.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool protectFolderEnabled: false
    /*!
     * Hide utility toggles and vault commands, and reduce vertical spacing.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool isCompact: false
    /*!
     * Replace the search field with a spacer while the command panel is shown.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property bool isCliMode: false
    /*!
     * Left and right content margins in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property int sideMargin: Theme.spacingXL
    /*!
     * \qmlproperty string HeaderBar::searchText
     * Search input. Assignments use the same 200 ms delay as typed text.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property alias searchText: searchField.text
    /*!
     * \qmlproperty int HeaderBar::resultCount
     * Visible row count supplied to SearchBar after filtering.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    property alias resultCount: searchField.resultCount

    // Keep thresholds consistent with the layout cases in the type contract.
    readonly property bool narrowLayout:    width > 0 && width < 1200
    readonly property bool iconOnlyActions: width > 0 && width < 1120
    readonly property bool tightLayout:     width > 0 && width < 960

    /*!
     * Content row height in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int rowHeight:    44
    /*!
     * Gap below the chrome strip in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int rowTopGap:    isCompact ? 6 : 8
    /*!
     * Gap below the content row in logical pixels.
     *
     * Author: \l {https://github.com/lextpf}{Lextpf}.
     */
    readonly property int rowBottomGap: isCompact ? 6 : 14
    readonly property int groupGap: tightLayout ? Theme.spacingSmall
                                  : narrowLayout ? Theme.spacingMedium
                                  : Theme.spacingLarge
    readonly property int toggleSize:    tightLayout ? 30 : 32
    readonly property int toggleSpacing: tightLayout ? 0 : 2
    readonly property int buttonSpacing: tightLayout ? 6 : narrowLayout ? 8 : Theme.spacingSmall
    readonly property int actionButtonWidth: iconOnlyActions ? 44 : 100
    // Equal padding centers the icon within a vault action.
    readonly property int actionButtonPadding:
        iconOnlyActions ? Math.round((actionButtonWidth - Theme.iconSizeMedium) / 2)
                        : narrowLayout ? 10 : 14

    // Include the chrome strip and both content gaps in the height.
    implicitHeight: Theme.chromeHeight + rowTopGap + rowHeight + rowBottomGap

    // Use button text for tooltips when vault actions hide their labels.
    component VaultActionButton: TintedButton {
        id: vaultButton
        iconOnly: root.iconOnlyActions
        leftPadding: root.actionButtonPadding
        rightPadding: root.actionButtonPadding
        background.implicitWidth: root.actionButtonWidth

        ToolTip.visible: root.iconOnlyActions && hovered
        ToolTip.delay: 600
        ToolTip.text: vaultButton.text
    }

    // Duotone glyphs have 0.4 alpha. Four layers give 1 - 0.6^4 = 87 % coverage
    // when armed; copies track the primary color and rotation.
    component UtilityToggle: Item {
        id: toggle

        // IconImage resolves source late; copies read this property instead of the primary icon.
        property url iconSource
        property alias iconRotation: toggleIcon.rotation
        property color iconColor: Theme.textMuted
        property real iconOpacity: 1.0
        property bool armed: false
        property string tooltip: ""
        readonly property bool hovered: toggleArea.containsMouse
        signal activated()

        implicitWidth: root.toggleSize
        implicitHeight: root.toggleSize

        scale: toggleArea.pressed ? 0.94 : 1.0
        Behavior on scale {
            NumberAnimation { duration: 200; easing.type: Easing.OutBack; easing.overshoot: 2.0 }
        }

        SvgIcon {
            id: toggleIcon
            anchors.centerIn: parent
            width: Theme.iconSizeMedium
            height: Theme.iconSizeMedium
            source: toggle.iconSource
            color: toggle.iconColor
            opacity: toggle.iconOpacity
            Behavior on color { ColorAnimation { duration: Theme.hoverDuration } }
            Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
            Behavior on rotation { NumberAnimation { duration: 300; easing.type: Easing.OutBack } }
        }

        Repeater {
            model: 3
            delegate: SvgIcon {
                anchors.centerIn: toggle
                width: toggleIcon.width; height: toggleIcon.height
                source: toggle.iconSource; color: toggleIcon.color; rotation: toggleIcon.rotation
                opacity: toggle.armed ? toggle.iconOpacity : 0
                visible: opacity > 0
                Behavior on opacity { NumberAnimation { duration: Theme.hoverDuration } }
            }
        }

        MouseArea {
            id: toggleArea
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: toggle.activated()
        }

        ToolTip.visible: toggle.tooltip !== "" && toggle.hovered
        ToolTip.delay: 600
        ToolTip.text: toggle.tooltip
    }

    // Keep drag calls on uncovered MouseArea items; the window has no native title bar.
    MouseArea {
        id: dragArea
        anchors.fill: parent
        acceptedButtons: Qt.LeftButton
        onPressed: function(mouse) {
            WindowVM.startWindowDrag()
        }
        onDoubleClicked: function(mouse) {
            var w = root.Window.window
            if (w.visibility === Window.Maximized)
                w.showNormal()
            else
                w.showMaximized()
        }

        RowLayout {
            id: headingRow
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: root.sideMargin
            anchors.rightMargin: root.sideMargin
            anchors.top: parent.top
            anchors.topMargin: Theme.chromeHeight + root.rowTopGap
            height: root.rowHeight
            spacing: root.groupGap

            // Only search and the CLI spacer take spare width from the nested groups.
            RowLayout {
                id: lockup
                Layout.fillWidth: false
                spacing: Theme.spacingSmall

                Item {
                    Layout.preferredWidth: narwhalIcon.width
                    Layout.preferredHeight: narwhalIcon.height

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
                    }

                    // Prevent overlapping decorative sequences while the icon is active.
                    SequentialAnimation {
                        id: easterEgg

                        ScriptAction {
                            script: {
                                // Offset each ring by up to 2.5 scaled logical pixels.
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
                            NumberAnimation { target: ringWarm; property: "width";   from: Theme.px(12); to: Theme.px(180); duration: 2200; easing.type: Easing.OutCubic }
                            NumberAnimation { target: ringWarm; property: "opacity"; from: 0.70;          to: 0;             duration: 2200; easing.type: Easing.InQuad }

                            SequentialAnimation {
                                PauseAnimation { duration: 400 }
                                ParallelAnimation {
                                    NumberAnimation { target: ringMid; property: "width";   from: Theme.px(8); to: Theme.px(120); duration: 1900; easing.type: Easing.OutCubic }
                                    NumberAnimation { target: ringMid; property: "opacity"; from: 0.50;          to: 0;             duration: 1900; easing.type: Easing.InQuad }
                                }
                            }

                            SequentialAnimation {
                                PauseAnimation { duration: 800 }
                                ParallelAnimation {
                                    NumberAnimation { target: ringCool; property: "width";   from: Theme.px(6); to: Theme.px(72); duration: 1600; easing.type: Easing.OutCubic }
                                    NumberAnimation { target: ringCool; property: "opacity"; from: 0.35;          to: 0;            duration: 1600; easing.type: Easing.InQuad }
                                }
                            }

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

                Text {
                    text: "seal"
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontSizeTitle
                    font.bold: true
                    font.letterSpacing: Theme.pxf(-0.5)
                    color: Theme.accent
                    Layout.alignment: Qt.AlignVCenter
                }
            }

            RowLayout {
                id: utilityToggles
                Layout.fillWidth: false
                Layout.alignment: Qt.AlignVCenter
                spacing: root.toggleSpacing
                visible: !root.isCompact

                // Navigation staging is opt-in.
                UtilityToggle {
                    id: autoStageToggle
                    iconSource: Bridge.autoStageEnabled ? Theme.iconBolt : Theme.iconBoltSlash
                    iconColor: Bridge.autoStageEnabled
                               ? (autoStageToggle.hovered ? Theme.accentBright : Theme.accent)
                               : (autoStageToggle.hovered ? Theme.accent : Theme.textMuted)
                    armed: Bridge.autoStageEnabled
                    tooltip: (Bridge.autoStageEnabled ? "Staged auto-fill is on."
                                                      : "Staged auto-fill is off.") +
                             "\nWhen on, seal pre-arms a matching record on navigation;" +
                             "\na plain click into the login field completes the fill." +
                             "\nThe password is never sent to the browser."
                    onActivated: Bridge.setAutoStageEnabled(!Bridge.autoStageEnabled)
                }

                // Arming requires AppViewModel preflight and confirmation.
                UtilityToggle {
                    id: protectFolderToggle
                    iconSource: Theme.iconShieldHalved
                    iconColor: root.protectFolderEnabled
                               ? (protectFolderToggle.hovered ? Theme.accentBright : Theme.accent)
                               : (protectFolderToggle.hovered ? Theme.accent : Theme.textMuted)
                    iconOpacity: root.protectFolderEnabled ? 1.0 : 0.72
                    armed: root.protectFolderEnabled
                    tooltip: root.protectFolderEnabled
                             ? "Folder protection is armed.\nClick to leave files decrypted and stop future exit protection."
                             : "Protect this portable seal folder on exit.\nA static-build preflight and exact file preview run before arming."
                    onActivated: root.protectFolderToggled(!root.protectFolderEnabled)
                }

                UtilityToggle {
                    id: themeToggle
                    iconSource: Theme.dark ? Theme.iconSun : Theme.iconMoon
                    iconColor: themeToggle.hovered ? Theme.accent : Theme.accentDim
                    iconRotation: Theme.dark ? 180 : 0
                    onActivated: Theme.toggle()
                }
            }

            SearchBar {
                id: searchField
                Layout.fillWidth: true
                Layout.minimumWidth: 160
                // A fixed preferred width keeps input text from changing layout hints.
                Layout.preferredWidth: 160
                Layout.preferredHeight: 40
                Layout.alignment: Qt.AlignVCenter
                visible: !root.isCliMode
                vaultLoaded: root.vaultLoaded
                onSearchRequested: function(text) { root.searchRequested(text) }
            }

            // The CLI spacer also preserves the drag surface.
            Item {
                Layout.fillWidth: true
                visible: root.isCliMode
            }

            RowLayout {
                id: vaultActions
                Layout.fillWidth: false
                Layout.alignment: Qt.AlignVCenter
                spacing: root.buttonSpacing
                visible: !root.isCompact

                VaultActionButton {
                    text: "Load"
                    faIcon: Theme.iconFolderOpen
                    tintTop:         Theme.btnLoadTop
                    tintEnd:         Theme.btnLoadEnd
                    tintHoverTop:    Theme.btnLoadHoverTop
                    tintHoverEnd:    Theme.btnLoadHoverEnd
                    tintPressed:     Theme.btnLoadPressed
                    tintText:        Theme.btnLoadText
                    tintTextHover:   Theme.btnLoadTextHover
                    onClicked: root.loadClicked()
                }

                VaultActionButton {
                    text: "Save"
                    faIcon: Theme.iconFloppyDisk
                    enabled: root.vaultLoaded
                    tintTop:         Theme.btnSaveTop
                    tintEnd:         Theme.btnSaveEnd
                    tintHoverTop:    Theme.btnSaveHoverTop
                    tintHoverEnd:    Theme.btnSaveHoverEnd
                    tintPressed:     Theme.btnSavePressed
                    tintText:        Theme.btnSaveText
                    tintTextHover:   Theme.btnSaveTextHover
                    onClicked: root.saveClicked()
                }

                VaultActionButton {
                    text: "Unload"
                    faIcon: Theme.iconEject
                    enabled: root.vaultLoaded
                    leftPadding: root.iconOnlyActions ? root.actionButtonPadding : 10
                    rightPadding: root.iconOnlyActions ? root.actionButtonPadding : 10
                    tintTop:         Theme.btnUnloadTop
                    tintEnd:         Theme.btnUnloadEnd
                    tintHoverTop:    Theme.btnUnloadHoverTop
                    tintHoverEnd:    Theme.btnUnloadHoverEnd
                    tintPressed:     Theme.btnUnloadPressed
                    tintText:        Theme.btnUnloadText
                    tintTextHover:   Theme.btnUnloadTextHover
                    onClicked: root.unloadClicked()
                }

                VaultActionButton {
                    text: "Rekey"
                    faIcon: Theme.iconKey
                    enabled: root.vaultLoaded || root.protectFolderEnabled
                    tintTop:         Theme.btnRekeyTop
                    tintEnd:         Theme.btnRekeyEnd
                    tintHoverTop:    Theme.btnRekeyHoverTop
                    tintHoverEnd:    Theme.btnRekeyHoverEnd
                    tintPressed:     Theme.btnRekeyPressed
                    tintText:        Theme.btnRekeyText
                    tintTextHover:   Theme.btnRekeyTextHover
                    onClicked: root.rekeyClicked()
                }

                VaultActionButton {
                    id: setupButton
                    text: "Setup"
                    faIcon: Theme.iconBrowsers
                    tintTop:         Theme.btnSetupTop
                    tintEnd:         Theme.btnSetupEnd
                    tintHoverTop:    Theme.btnSetupHoverTop
                    tintHoverEnd:    Theme.btnSetupHoverEnd
                    tintPressed:     Theme.btnSetupPressed
                    tintText:        Theme.btnSetupText
                    tintTextHover:   Theme.btnSetupTextHover
                    onClicked: setupMenu.open()

                    ToolTip.visible: hovered
                    ToolTip.delay: 600
                    ToolTip.text: Bridge.bridgeStatusText !== ""
                                      ? Bridge.bridgeStatusText
                                      : "Install, repair, or remove the browser companion setup."

                    Menu {
                        id: setupMenu
                        x: setupButton.width - width
                        y: setupButton.height + 4

                        MenuItem {
                            text: "Install or repair companion"
                            onTriggered: Bridge.runInstallBrowserExtension()
                        }

                        MenuItem {
                            text: "Unregister companion"
                            onTriggered: Bridge.runUninstallBrowserExtension()
                        }
                    }
                }
            }
        }
    }
}
